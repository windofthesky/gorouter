package registry

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/uber-go/zap"

	"code.cloudfoundry.org/gorouter/config"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics"
	"code.cloudfoundry.org/gorouter/networking_policy"
	"code.cloudfoundry.org/gorouter/registry/container"
	"code.cloudfoundry.org/gorouter/route"
)

//go:generate counterfeiter -o fakes/fake_registry.go . Registry
type Registry interface {
	Register(uri route.Uri, endpoint *route.Endpoint)
	Unregister(uri route.Uri, endpoint *route.Endpoint)
	Lookup(uri route.Uri) *route.Pool
	LookupWithInstance(uri route.Uri, appID, appIndex string) *route.Pool
	StartPruningCycle()
	StopPruningCycle()
	NumUris() int
	NumEndpoints() int
	MarshalJSON() ([]byte, error)
}

type PruneStatus int

const (
	CONNECTED = PruneStatus(iota)
	DISCONNECTED
)

type RouteRegistry struct {
	sync.RWMutex

	logger logger.Logger

	// Access to the Trie datastructure should be governed by the RWMutex of RouteRegistry
	byURI *container.Trie

	// used for ability to suspend pruning
	suspendPruning func() bool
	pruningStatus  PruneStatus

	pruneStaleDropletsInterval time.Duration
	dropletStaleThreshold      time.Duration

	reporter metrics.RouteRegistryReporter

	ticker           *time.Ticker
	timeOfLastUpdate time.Time

	routingTableShardingMode string
	isolationSegments        []string
	policyClientConfig       *networking_policy.PolicyClientConfig

	enforcer *networking_policy.Enforcer
	chain    networking_policy.Chain
	ruleMap  map[string]networking_policy.IPTablesRule
	ipt      *iptables.IPTables
}

func NewRouteRegistry(logger logger.Logger, c *config.Config, reporter metrics.RouteRegistryReporter) *RouteRegistry {
	r := &RouteRegistry{}
	r.logger = logger
	r.byURI = container.NewTrie()

	r.pruneStaleDropletsInterval = c.PruneStaleDropletsInterval
	r.dropletStaleThreshold = c.DropletStaleThreshold
	r.suspendPruning = func() bool { return false }

	r.reporter = reporter

	r.routingTableShardingMode = c.RoutingTableShardingMode
	r.isolationSegments = c.IsolationSegments
	r.policyClientConfig = networking_policy.NewPolicyClientConfig(c.NetworkPolicyServer, logger)

	// construct network policy obj
	restorer := &networking_policy.Restorer{}
	var err error
	r.ipt, err = iptables.New()
	if err != nil {
		logger.Error("failed-to-create-iptables", zap.Error(err))
	}
	iptLocker := &networking_policy.IPTablesLocker{
		FileLocker: &networking_policy.Locker{Path: c.NetworkPolicyServer.LockFile},
		Mutex:      &sync.Mutex{},
	}
	lockedIPTables := &networking_policy.LockedIPTables{
		IPTables: r.ipt,
		Locker:   iptLocker,
		Restorer: restorer,
	}
	timestamper := &networking_policy.Timestamper{}
	r.enforcer = networking_policy.NewEnforcer(
		r.policyClientConfig.Logger.Session("rules-enforcer"),
		timestamper,
		lockedIPTables,
	)
	r.chain = networking_policy.Chain{
		Table:       "filter",
		ParentChain: "OUTPUT",
		Prefix:      "marks--",
	}
	r.ruleMap = map[string]networking_policy.IPTablesRule{}
	// actual implementation: only add the rule if it doesn't already exist
	routerToOverlayNetworkRule := networking_policy.NewAllowTrafficRule("10.255.0.0/16", "marks--foo")
	err = r.ipt.Append("filter", "OUTPUT", routerToOverlayNetworkRule...)
	if err != nil {
		logger.Error("failed-to-create-base-iptable-rule", zap.Error(err))
	}
	return r
}

// iterator for the rule map
func (r *RouteRegistry) listAllRules() []networking_policy.IPTablesRule {
	var rulesList []networking_policy.IPTablesRule
	for _, v := range r.ruleMap {
		rulesList = append(rulesList, v)
	}
	return rulesList
}

func (r *RouteRegistry) Register(uri route.Uri, endpoint *route.Endpoint) {
	if !r.endpointInRouterShard(endpoint) {
		return
	}

	t := time.Now()

	r.Lock()

	routekey := uri.RouteKey()

	pool := r.byURI.Find(routekey)
	if pool == nil {
		contextPath := parseContextPath(uri)
		pool = route.NewPool(r.dropletStaleThreshold/4, contextPath)
		r.byURI.Insert(routekey, pool)
		r.logger.Debug("uri-added", zap.Stringer("uri", routekey))
	}
	endpointAdded := pool.Put(endpoint)

	// if endpoint has been added or updated
	if endpointAdded {
		host, _, err := net.SplitHostPort(endpoint.CanonicalAddr())
		if err != nil {
			r.logger.Error("failed-to-split-host-and-port", zap.Error(err))
		}

		// do not create iptables rules for internal components - hardcoded for bosh-lite
		internalComponent := strings.HasPrefix(host, "10.244.0")
		if !internalComponent {
			r.logger.Info("checking-if-iptables-rule-exists")
			_, port, err := net.SplitHostPort(endpoint.CanonicalAddr())
			if err != nil {
				r.logger.Error("register-parsing-url", zap.Error(err))
			}

			tag, err := r.policyClientConfig.Register(endpoint.ApplicationId, port)
			if err != nil {
				r.logger.Error("failed-to-create-tag", zap.Error(err))
			}

			ipRule := networking_policy.NewEgressMarkRule(host, tag)

			// check if rule exists before adding - could be better to check in-memory map
			exists, err := r.ipt.Exists("filter", "marks--foo", ipRule...)
			if err != nil {
				r.logger.Error("iptables-exists-error", zap.Error(err))
			}
			if !exists {
				list, err := r.ipt.List("filter", "marks--foo")
				if err != nil {
					r.logger.Error("iptables-retrieving-list-error", zap.Error(err))
				}

				r.logger.Info("RULE DOES NOT EXIST, CREATING RULE",
					zap.Object("full-list", list),
					zap.Object("searched-for", ipRule))
				//	appid+backendIP
				r.ruleMap[fmt.Sprintf("%s+%s", endpoint.ApplicationId, endpoint.CanonicalAddr())] = ipRule

				// map iterator to give list of all ip rules
				rulesWithChain := networking_policy.RulesWithChain{
					Chain: r.chain,
					Rules: r.listAllRules(),
				}
				err = r.enforcer.EnforceRulesAndChain(rulesWithChain)
				if err != nil {
					r.logger.Error("endpoint-register-enforce-rules-error", zap.Error(err))
				}
			}
		}
	}
	r.timeOfLastUpdate = t
	r.Unlock()

	r.reporter.CaptureRegistryMessage(endpoint)

	if endpointAdded {
		r.logger.Debug("endpoint-registered", zapData(uri, endpoint)...)
	} else {
		r.logger.Debug("endpoint-not-registered", zapData(uri, endpoint)...)
	}
}

func (r *RouteRegistry) Unregister(uri route.Uri, endpoint *route.Endpoint) {
	if !r.endpointInRouterShard(endpoint) {
		return
	}

	r.Lock()

	uri = uri.RouteKey()

	pool := r.byURI.Find(uri)
	if pool != nil {
		endpointRemoved := pool.Remove(endpoint)
		if endpointRemoved {
			rule := r.ruleMap[fmt.Sprintf("%s+%s", endpoint.ApplicationId, endpoint.CanonicalAddr())]
			// ipt.Delete only deletes one entry of the rule, if duplicates exist then
			// undesired artifacts could remain
			err := r.ipt.Delete("filter", "marks--foo", rule...)
			if err != nil {
				r.logger.Error("removing-rule-from-iptables-error", zap.Error(err))
			}
			delete(r.ruleMap, fmt.Sprintf("%s+%s", endpoint.ApplicationId, endpoint.CanonicalAddr()))
			// could also delete policy
			r.logger.Debug("endpoint-unregistered", zapData(uri, endpoint)...)
		} else {
			r.logger.Debug("endpoint-not-unregistered", zapData(uri, endpoint)...)
		}

		if pool.IsEmpty() {
			r.byURI.Delete(uri)
		}
	}

	r.Unlock()
	r.reporter.CaptureUnregistryMessage(endpoint)
}

func (r *RouteRegistry) Lookup(uri route.Uri) *route.Pool {
	started := time.Now()

	r.RLock()

	uri = uri.RouteKey()
	var err error
	pool := r.byURI.MatchUri(uri)
	for pool == nil && err == nil {
		uri, err = uri.NextWildcard()
		pool = r.byURI.MatchUri(uri)
	}

	r.RUnlock()
	endLookup := time.Now()
	r.reporter.CaptureLookupTime(endLookup.Sub(started))
	return pool
}

func (r *RouteRegistry) endpointInRouterShard(endpoint *route.Endpoint) bool {
	if r.routingTableShardingMode == config.SHARD_ALL {
		return true
	}

	if r.routingTableShardingMode == config.SHARD_SHARED_AND_SEGMENTS && endpoint.IsolationSegment == "" {
		return true
	}

	for _, v := range r.isolationSegments {
		if endpoint.IsolationSegment == v {
			return true
		}
	}

	return false
}

func (r *RouteRegistry) LookupWithInstance(uri route.Uri, appID string, appIndex string) *route.Pool {
	uri = uri.RouteKey()
	p := r.Lookup(uri)

	if p == nil {
		return nil
	}

	var surgicalPool *route.Pool

	p.Each(func(e *route.Endpoint) {
		if (e.ApplicationId == appID) && (e.PrivateInstanceIndex == appIndex) {
			surgicalPool = route.NewPool(0, "")
			surgicalPool.Put(e)
		}
	})
	return surgicalPool
}

func (r *RouteRegistry) StartPruningCycle() {
	if r.pruneStaleDropletsInterval > 0 {
		r.Lock()
		r.ticker = time.NewTicker(r.pruneStaleDropletsInterval)
		r.Unlock()

		go func() {
			for {
				select {
				case <-r.ticker.C:
					r.logger.Info("start-pruning-routes")
					r.pruneStaleDroplets()
					r.logger.Info("finished-pruning-routes")
					msSinceLastUpdate := uint64(time.Since(r.TimeOfLastUpdate()) / time.Millisecond)
					r.reporter.CaptureRouteStats(r.NumUris(), msSinceLastUpdate)
				}
			}
		}()
	}
}

func (r *RouteRegistry) StopPruningCycle() {
	r.Lock()
	if r.ticker != nil {
		r.ticker.Stop()
	}
	r.Unlock()
}

func (registry *RouteRegistry) NumUris() int {
	registry.RLock()
	uriCount := registry.byURI.PoolCount()
	registry.RUnlock()

	return uriCount
}

func (r *RouteRegistry) TimeOfLastUpdate() time.Time {
	r.RLock()
	t := r.timeOfLastUpdate
	r.RUnlock()

	return t
}

func (r *RouteRegistry) NumEndpoints() int {
	r.RLock()
	count := r.byURI.EndpointCount()
	r.RUnlock()

	return count
}

func (r *RouteRegistry) MarshalJSON() ([]byte, error) {
	r.RLock()
	defer r.RUnlock()

	return json.Marshal(r.byURI.ToMap())
}

func (r *RouteRegistry) pruneStaleDroplets() {
	r.Lock()
	defer r.Unlock()

	// suspend pruning if option enabled and if NATS is unavailable
	if r.suspendPruning() {
		r.logger.Info("prune-suspended")
		r.pruningStatus = DISCONNECTED
		return
	}
	if r.pruningStatus == DISCONNECTED {
		// if we are coming back from being disconnected from source,
		// bulk update routes / mark updated to avoid pruning right away
		r.logger.Debug("prune-unsuspended-refresh-routes-start")
		r.freshenRoutes()
		r.logger.Debug("prune-unsuspended-refresh-routes-complete")
	}
	r.pruningStatus = CONNECTED

	r.byURI.EachNodeWithPool(func(t *container.Trie) {
		endpoints := t.Pool.PruneEndpoints(r.dropletStaleThreshold)
		t.Snip()
		if len(endpoints) > 0 {
			addresses := []string{}
			for _, e := range endpoints {
				addresses = append(addresses, e.CanonicalAddr())

				rule := r.ruleMap[fmt.Sprintf("%s+%s", e.ApplicationId, e.CanonicalAddr())]
				err := r.ipt.Delete("filter", "marks--foo", rule...)
				if err != nil {
					r.logger.Error("removing-rule-from-iptables-error", zap.Error(err))
				}
				delete(r.ruleMap, fmt.Sprintf("%s+%s", e.ApplicationId, e.CanonicalAddr()))
				// could also delete policy
			}
			isolationSegment := endpoints[0].IsolationSegment
			if isolationSegment == "" {
				isolationSegment = "-"
			}
			r.logger.Info("pruned-route",
				zap.String("uri", t.ToPath()),
				zap.Object("endpoints", addresses),
				zap.Object("isolation_segment", isolationSegment),
			)
		}
	})
}

func (r *RouteRegistry) SuspendPruning(f func() bool) {
	r.Lock()
	r.suspendPruning = f
	r.Unlock()
}

// bulk update to mark pool / endpoints as updated
func (r *RouteRegistry) freshenRoutes() {
	now := time.Now()
	r.byURI.EachNodeWithPool(func(t *container.Trie) {
		t.Pool.MarkUpdated(now)
	})
}

func parseContextPath(uri route.Uri) string {
	contextPath := "/"
	split := strings.SplitN(strings.TrimPrefix(uri.String(), "/"), "/", 2)

	if len(split) > 1 {
		contextPath += split[1]
	}

	if idx := strings.Index(string(contextPath), "?"); idx >= 0 {
		contextPath = contextPath[0:idx]
	}

	return contextPath
}

func zapData(uri route.Uri, endpoint *route.Endpoint) []zap.Field {
	isoSegField := zap.String("isolation_segment", "-")
	if endpoint.IsolationSegment != "" {
		isoSegField = zap.String("isolation_segment", endpoint.IsolationSegment)
	}
	return []zap.Field{
		zap.Stringer("uri", uri),
		zap.String("backend", endpoint.CanonicalAddr()),
		zap.Object("modification_tag", endpoint.ModificationTag),
		isoSegField,
	}
}
