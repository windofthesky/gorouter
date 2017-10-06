package mbus

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"code.cloudfoundry.org/gorouter/common"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/registry"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/localip"
	"code.cloudfoundry.org/routing-api/models"

	"sync"

	"github.com/nats-io/nats"
	"github.com/uber-go/zap"
	"fmt"
)

// RegistryMessage defines the format of a route registration/unregistration
type RegistryMessage struct {
	Host                    string            `json:"host"`
	Port                    uint16            `json:"port"`
	TLSPort                 uint16            `json:"tls_port"`
	Uris                    []route.Uri       `json:"uris"`
	Tags                    map[string]string `json:"tags"`
	App                     string            `json:"app"`
	StaleThresholdInSeconds int               `json:"stale_threshold_in_seconds"`
	RouteServiceURL         string            `json:"route_service_url"`
	PrivateInstanceID       string            `json:"private_instance_id"`
	PrivateInstanceIndex    string            `json:"private_instance_index"`
	IsolationSegment        string            `json:"isolation_segment"`
}

func (rm *RegistryMessage) makeEndpoint(acceptTLS bool) (*route.Endpoint, error) {
	port, useTls, err := rm.port(acceptTLS)
	if err != nil {
		return nil, err
	}
	return route.NewEndpoint(
		rm.App,
		rm.Host,
		port,
		rm.PrivateInstanceID,
		rm.PrivateInstanceIndex,
		rm.Tags,
		rm.StaleThresholdInSeconds,
		rm.RouteServiceURL,
		models.ModificationTag{},
		rm.IsolationSegment,
		useTls,
	), nil
}

// ValidateMessage checks to ensure the registry message is valid
func (rm *RegistryMessage) ValidateMessage() bool {
	return rm.RouteServiceURL == "" || strings.HasPrefix(rm.RouteServiceURL, "https")
}

// Prefer TLS Port instead of HTTP Port in Registrty Message
func (rm *RegistryMessage) port(acceptTLS bool) (uint16, bool, error) {
	if !acceptTLS && rm.Port == 0 {
		return 0, false, errors.New("Invalid registry message: backend tls is not enabled")
	} else if acceptTLS && rm.TLSPort != 0 {
		return rm.TLSPort, true, nil
	}
	return rm.Port, false, nil
}

type msgPool struct {
	sync.RWMutex
	slice []*RegistryMessage
	count int
}

func (mp *msgPool) Get() *RegistryMessage {
	mp.Lock()
	if mp.count > 0 {

		mp.count--
		return mp.slice[mp.count]
	}
	mp.Unlock()
	return &RegistryMessage{}
}

func (mp *msgPool) Put(msg *RegistryMessage) {
	mp.Lock()
	mp.slice = append(mp.slice, msg)
	mp.count++
	mp.Unlock()
}

// Subscriber subscribes to NATS for all router.* messages and handles them
type Subscriber struct {
	logger        logger.Logger
	natsClient    *nats.Conn
	startMsgChan  <-chan struct{}
	opts          *SubscriberOpts
	routeRegistry registry.Registry
	msgBufferPool msgPool
}

// SubscriberOpts contains configuration for Subscriber struct
type SubscriberOpts struct {
	ID                               string
	MinimumRegisterIntervalInSeconds int
	PruneThresholdInSeconds          int
	AcceptTLS                        bool
}

// NewSubscriber returns a new Subscriber
func NewSubscriber(
	logger logger.Logger,
	natsClient *nats.Conn,
	routeRegistry registry.Registry,
	startMsgChan <-chan struct{},
	opts *SubscriberOpts,
) *Subscriber {
	return &Subscriber{
		logger:        logger,
		natsClient:    natsClient,
		routeRegistry: routeRegistry,
		startMsgChan:  startMsgChan,
		opts:          opts,
		msgBufferPool: msgPool{
			count: 0,
			slice: make([]*RegistryMessage, 0, 10000),
		},
	}
}

// Run manages the lifecycle of the subscriber process
func (s *Subscriber) Run(signals <-chan os.Signal, ready chan<- struct{}) error {
	s.logger.Info("subscriber-starting")
	err := s.sendStartMessage()
	if err != nil {
		return err
	}
	err = s.subscribeToGreetMessage()
	if err != nil {
		return err
	}
	err = s.subscribeRoutes()
	if err != nil {
		return err
	}

	close(ready)
	s.logger.Info("subscriber-started")
	for {
		select {
		case <-s.startMsgChan:
			err := s.sendStartMessage()
			if err != nil {
				s.logger.Error("failed-to-send-start-message", zap.Error(err))
			}
		case <-signals:
			s.logger.Info("exited")
			return nil
		}
	}
}

func (s *Subscriber) subscribeToGreetMessage() error {
	_, err := s.natsClient.Subscribe("router.greet", func(msg *nats.Msg) {
		response, _ := s.startMessage()
		_ = s.natsClient.Publish(msg.Reply, response)
	})

	return err
}

func (s *Subscriber) subscribeRoutes() error {
	natsSubscriber, err := s.natsClient.Subscribe("router.*", func(message *nats.Msg) {
		msg := s.msgBufferPool.Get()
		defer s.msgBufferPool.Put(msg)
		regErr := createRegistryMessage(message.Data, msg)
		if regErr != nil {
			s.logger.Error("validation-error",
				zap.Error(regErr),
				zap.String("payload", string(message.Data)),
				zap.String("subject", message.Subject),
			)
			return
		}
		switch message.Subject {
		case "router.register":
			s.registerEndpoint(msg)
		case "router.unregister":
			s.unregisterEndpoint(msg)
			s.logger.Info("unregister-route", zap.String("message", string(message.Data)))
		default:
		}
	})

	// Pending limits are set to twice the defaults
	natsSubscriber.SetPendingLimits(131072, 131072*1024)
	return err
}

func (s *Subscriber) registerEndpoint(msg *RegistryMessage) {
	endpoint, err := msg.makeEndpoint(s.opts.AcceptTLS)
	fmt.Printf("registerEndpoint\n %#v\n %#v\n", msg, endpoint)
	if err != nil {
		s.logger.Error("Unable to register route",
			zap.Error(err),
			zap.Object("message", msg),
		)
		return
	}

	for _, uri := range msg.Uris {
		s.routeRegistry.Register(uri, endpoint)
	}
}

func (s *Subscriber) unregisterEndpoint(msg *RegistryMessage) {
	endpoint, err := msg.makeEndpoint(s.opts.AcceptTLS)
	if err != nil {
		s.logger.Error("Unable to unregister route",
			zap.Error(err),
			zap.Object("message", msg),
		)
		return
	}
	for _, uri := range msg.Uris {
		s.routeRegistry.Unregister(uri, endpoint)
	}
}

func (s *Subscriber) startMessage() ([]byte, error) {
	host, err := localip.LocalIP()
	if err != nil {
		return nil, err
	}

	d := common.RouterStart{
		Id:    s.opts.ID,
		Hosts: []string{host},
		MinimumRegisterIntervalInSeconds: s.opts.MinimumRegisterIntervalInSeconds,
		PruneThresholdInSeconds:          s.opts.PruneThresholdInSeconds,
	}
	message, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}

	return message, nil
}

func (s *Subscriber) sendStartMessage() error {
	message, err := s.startMessage()
	if err != nil {
		return err
	}
	// Send start message once at start
	return s.natsClient.Publish("router.start", message)
}

func createRegistryMessage(data []byte, msg *RegistryMessage) error {

	jsonErr := json.Unmarshal(data, msg)
	if jsonErr != nil {
		return jsonErr
	}

	if !msg.ValidateMessage() {
		return errors.New("Unable to validate message. route_service_url must be https")
	}

	return nil
}
