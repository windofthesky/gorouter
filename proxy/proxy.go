package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"code.cloudfoundry.org/gorouter/access_log"
	"code.cloudfoundry.org/gorouter/common/secure"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/metrics/reporter"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/routeservice"
	"code.cloudfoundry.org/lager"
	"github.com/urfave/negroni"
)

const (
	VcapCookieId    = "__VCAP_ID__"
	StickyCookieKey = "JSESSIONID"
)

type LookupRegistry interface {
	Lookup(uri route.Uri) *route.Pool
	LookupWithInstance(uri route.Uri, appId string, appIndex string) *route.Pool
}

type Proxy interface {
	ServeHTTP(responseWriter http.ResponseWriter, request *http.Request)
}

type ProxyArgs struct {
	EndpointTimeout            time.Duration
	Ip                         string
	TraceKey                   string
	Registry                   LookupRegistry
	Reporter                   reporter.ProxyReporter
	AccessLogger               access_log.AccessLogger
	SecureCookies              bool
	TLSConfig                  *tls.Config
	RouteServiceEnabled        bool
	RouteServiceTimeout        time.Duration
	RouteServiceRecommendHttps bool
	Crypto                     secure.Crypto
	CryptoPrev                 secure.Crypto
	ExtraHeadersToLog          *[]string
	Logger                     lager.Logger
	HealthCheckUserAgent       string
	HeartbeatOK                *int32
	EnableZipkin               bool
	ForceForwardedProtoHttps   bool
	DefaultLoadBalance         string
}

type proxyHandler struct {
	handlers *negroni.Negroni
	proxy    *proxy
}

func (p *proxyHandler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	p.handlers.ServeHTTP(responseWriter, request)
}

type proxyWriterHandler struct{}

// ServeHTTP wraps the responseWriter in a ProxyResponseWriter
func (p *proxyWriterHandler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request, next http.HandlerFunc) {
	proxyWriter := utils.NewProxyResponseWriter(responseWriter)
	next(proxyWriter, request)
}

type proxy struct {
	ip                         string
	traceKey                   string
	logger                     lager.Logger
	registry                   LookupRegistry
	reporter                   reporter.ProxyReporter
	accessLogger               access_log.AccessLogger
	transport                  *http.Transport
	secureCookies              bool
	heartbeatOK                *int32
	routeServiceConfig         *routeservice.RouteServiceConfig
	extraHeadersToLog          *[]string
	routeServiceRecommendHttps bool
	healthCheckUserAgent       string
	forceForwardedProtoHttps   bool
	defaultLoadBalance         string
	fastProxy                  *FastReverseProxy
}

func NewProxy(args ProxyArgs) Proxy {
	routeServiceConfig := routeservice.NewRouteServiceConfig(args.Logger, args.RouteServiceEnabled, args.RouteServiceTimeout, args.Crypto, args.CryptoPrev, args.RouteServiceRecommendHttps)

	p := &proxy{
		accessLogger: args.AccessLogger,
		traceKey:     args.TraceKey,
		ip:           args.Ip,
		logger:       args.Logger,
		registry:     args.Registry,
		reporter:     args.Reporter,
		transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(network, addr, 5*time.Second)
				if err != nil {
					return conn, err
				}
				if args.EndpointTimeout > 0 {
					err = conn.SetDeadline(time.Now().Add(args.EndpointTimeout))
				}
				return conn, err
			},
			DisableKeepAlives:  true,
			DisableCompression: true,
			TLSClientConfig:    args.TLSConfig,
		},
		secureCookies:              args.SecureCookies,
		heartbeatOK:                args.HeartbeatOK, // 1->true, 0->false
		routeServiceConfig:         routeServiceConfig,
		extraHeadersToLog:          args.ExtraHeadersToLog,
		routeServiceRecommendHttps: args.RouteServiceRecommendHttps,
		healthCheckUserAgent:       args.HealthCheckUserAgent,
		forceForwardedProtoHttps:   args.ForceForwardedProtoHttps,
		defaultLoadBalance:         args.DefaultLoadBalance,
		fastProxy:                  NewFastReverseProxy(args.Registry),
	}

	n := negroni.New()
	n.Use(&proxyWriterHandler{})
	n.Use(handlers.NewAccessLog(args.AccessLogger, args.ExtraHeadersToLog))
	n.Use(handlers.NewHealthcheck(args.HealthCheckUserAgent, p.heartbeatOK, args.Logger))
	n.Use(handlers.NewZipkin(args.EnableZipkin, args.ExtraHeadersToLog, args.Logger))
	n.Use(p.fastProxy)

	handlers := &proxyHandler{
		handlers: n,
		proxy:    p,
	}

	return handlers
}
