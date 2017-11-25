package main

import (
	"crypto/tls"
	"errors"

	"code.cloudfoundry.org/clock"
	"code.cloudfoundry.org/debugserver"
	"code.cloudfoundry.org/gorouter/access_log"
	"code.cloudfoundry.org/gorouter/common/schema"
	"code.cloudfoundry.org/gorouter/common/secure"
	"code.cloudfoundry.org/gorouter/config"
	goRouterLogger "code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/mbus"
	"code.cloudfoundry.org/gorouter/metrics/monitor"
	"code.cloudfoundry.org/gorouter/proxy"
	rregistry "code.cloudfoundry.org/gorouter/registry"
	"code.cloudfoundry.org/gorouter/route_fetcher"
	"code.cloudfoundry.org/gorouter/router"
	"code.cloudfoundry.org/gorouter/routeservice"
	rvarz "code.cloudfoundry.org/gorouter/varz"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/routing-api"
	uaa_client "code.cloudfoundry.org/uaa-go-client"
	uaa_config "code.cloudfoundry.org/uaa-go-client/config"
	"github.com/cloudfoundry/dropsonde"
	"github.com/cloudfoundry/dropsonde/metric_sender"
	"github.com/cloudfoundry/dropsonde/metricbatcher"
	"github.com/nats-io/nats"
	"github.com/uber-go/zap"

	"flag"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"

	"code.cloudfoundry.org/gorouter/metrics"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/grouper"
	"github.com/tedsuo/ifrit/sigmon"
)

var (
	configFile  string
	healthCheck int32
)

func main() {
	flag.StringVar(&configFile, "c", "", "Configuration File")
	flag.Parse()

	c, err := config.DefaultConfig()
	if err != nil {
		fmt.Println("Error loading config:", err)
		os.Exit(1)
	}

	if configFile != "" {
		c, err = config.InitConfigFromFile(configFile)
		if err != nil {
			fmt.Println("Error loading config:", err)
			os.Exit(1)
		}
	}

	logCounter := schema.NewLogCounter()

	prefix := "gorouter.stdout"
	if c.Logging.Syslog != "" {
		prefix = c.Logging.Syslog
	}
	logger, minLagerLogLevel := createLogger(prefix, c.Logging.Level)

	logger.Info("starting")

	err = dropsonde.Initialize(c.Logging.MetronAddress, c.Logging.JobName)
	if err != nil {
		logger.Fatal("dropsonde-initialize-error", zap.Error(err))
	}

	logger.Info("retrieved-isolation-segments",
		zap.Object("isolation_segments", c.IsolationSegments),
		zap.Object("routing_table_sharding_mode", c.RoutingTableShardingMode),
	)

	// setup number of procs
	if c.GoMaxProcs != 0 {
		runtime.GOMAXPROCS(c.GoMaxProcs)
	}

	if c.DebugAddr != "" {
		reconfigurableSink := lager.NewReconfigurableSink(lager.NewWriterSink(os.Stdout, lager.DEBUG), minLagerLogLevel)
		debugserver.Run(c.DebugAddr, reconfigurableSink)
	}

	logger.Info("setting-up-nats-connection")
	natsReconnected := make(chan mbus.Signal)
	natsClient := mbus.Connect(c, natsReconnected, logger.Session("nats"))

	var routingAPIClient routing_api.Client

	if c.RoutingApiEnabled() {
		logger.Info("setting-up-routing-api")

		routingAPIClient, err = setupRoutingAPIClient(logger, c)
		if err != nil {
			logger.Fatal("routing-api-connection-failed", zap.Error(err))
		}

	}

	sender := metric_sender.NewMetricSender(dropsonde.AutowiredEmitter())
	metricsReporter := initializeMetrics(sender)
	fdMonitor := initializeFDMonitor(sender, logger)
	registry := rregistry.NewRouteRegistry(logger.Session("registry"), c, metricsReporter)
	if c.SuspendPruningIfNatsUnavailable {
		registry.SuspendPruning(func() bool { return !(natsClient.Status() == nats.CONNECTED) })
	}

	varz := rvarz.NewVarz(registry)
	compositeReporter := &metrics.CompositeReporter{VarzReporter: varz, ProxyReporter: metricsReporter}

	accessLogger, err := access_log.CreateRunningAccessLogger(logger.Session("access-log"), c)
	if err != nil {
		logger.Fatal("error-creating-access-logger", zap.Error(err))
	}

	var crypto secure.Crypto
	var cryptoPrev secure.Crypto
	if c.RouteServiceEnabled {
		crypto = createCrypto(logger, c.RouteServiceSecret)
		if c.RouteServiceSecretPrev != "" {
			cryptoPrev = createCrypto(logger, c.RouteServiceSecretPrev)
		}
	}

	proxy := buildProxy(logger.Session("proxy"), c, registry, accessLogger, compositeReporter, crypto, cryptoPrev)
	healthCheck = 0
	router, err := router.NewRouter(logger.Session("router"), c, proxy, natsClient, registry, varz, &healthCheck, logCounter, nil)
	if err != nil {
		logger.Fatal("initialize-router-error", zap.Error(err))
	}
	members := grouper.Members{}

	if c.RoutingApiEnabled() {
		routeFetcher := setupRouteFetcher(logger.Session("route-fetcher"), c, registry, routingAPIClient)
		members = append(members, grouper.Member{Name: "router-fetcher", Runner: routeFetcher})
	}

	subscriber := mbus.NewSubscriber(natsClient, registry, sender, c, natsReconnected, logger.Session("subscriber"))

	members = append(members, grouper.Member{Name: "fdMonitor", Runner: fdMonitor})
	members = append(members, grouper.Member{Name: "subscriber", Runner: subscriber})
	members = append(members, grouper.Member{Name: "router", Runner: router})

	group := grouper.NewOrdered(os.Interrupt, members)

	monitor := ifrit.Invoke(sigmon.New(group, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1))

	err = <-monitor.Wait()
	if err != nil {
		logger.Error("gorouter.exited-with-failure", zap.Error(err))
		os.Exit(1)
	}

	os.Exit(0)
}

func initializeFDMonitor(sender *metric_sender.MetricSender, logger goRouterLogger.Logger) *monitor.FileDescriptor {
	pid := os.Getpid()
	path := fmt.Sprintf("/proc/%d/fd", pid)
	ticker := time.NewTicker(time.Second * 5)
	return monitor.NewFileDescriptor(path, ticker.C, sender, logger.Session("FileDescriptor"))
}

func initializeMetrics(sender *metric_sender.MetricSender) *metrics.MetricsReporter {
	// 5 sec is dropsonde default batching interval
	batcher := metricbatcher.New(sender, 5*time.Second)
	batcher.AddConsistentlyEmittedMetrics("bad_gateways",
		"backend_exhausted_conns",
		"backend_invalid_id",
		"backend_invalid_tls_cert",
		"backend_tls_handshake_failed",
		"rejected_requests",
		"total_requests",
		"responses",
		"responses.2xx",
		"responses.3xx",
		"responses.4xx",
		"responses.5xx",
		"responses.xxx",
		"routed_app_requests",
		"routes_pruned",
		"websocket_failures",
		"websocket_upgrades",
	)

	return &metrics.MetricsReporter{Sender: sender, Batcher: batcher}
}

func createCrypto(logger goRouterLogger.Logger, secret string) *secure.AesGCM {
	// generate secure encryption key using key derivation function (pbkdf2)
	secretPbkdf2 := secure.NewPbkdf2([]byte(secret), 16)
	crypto, err := secure.NewAesGCM(secretPbkdf2)
	if err != nil {
		logger.Fatal("error-creating-route-service-crypto", zap.Error(err))
	}
	return crypto
}

func buildProxy(logger goRouterLogger.Logger, c *config.Config, registry rregistry.Registry,
	accessLogger access_log.AccessLogger, reporter metrics.ProxyReporter,
	crypto secure.Crypto, cryptoPrev secure.Crypto) proxy.Proxy {

	routeServiceConfig := routeservice.NewRouteServiceConfig(
		logger,
		c.RouteServiceEnabled,
		c.RouteServiceTimeout,
		crypto,
		cryptoPrev,
		c.RouteServiceRecommendHttps,
	)

	backendTLSConfig := &tls.Config{
		CipherSuites:       c.CipherSuites,
		InsecureSkipVerify: c.SkipSSLValidation,
		RootCAs:            c.CAPool,
		Certificates:       []tls.Certificate{c.Backends.ClientAuthCertificate},
	}

	return proxy.NewProxy(logger, accessLogger, c, registry,
		reporter, routeServiceConfig, backendTLSConfig, &healthCheck)
}

func setupRoutingAPIClient(logger goRouterLogger.Logger, c *config.Config) (routing_api.Client, error) {
	routingAPIURI := fmt.Sprintf("%s:%d", c.RoutingApi.Uri, c.RoutingApi.Port)
	client := routing_api.NewClient(routingAPIURI, false)

	logger.Debug("fetching-token")
	clock := clock.NewClock()

	uaaClient := newUaaClient(logger, clock, c)

	if !c.RoutingApi.AuthDisabled {
		token, err := uaaClient.FetchToken(true)
		if err != nil {
			return nil, fmt.Errorf("unable-to-fetch-token: %s", err.Error())
		}
		if token.AccessToken == "" {
			return nil, fmt.Errorf("empty token fetched")
		}
		client.SetToken(token.AccessToken)
	}
	// Test connectivity
	_, err := client.Routes()
	if err != nil {
		return nil, err
	}

	return client, nil
}

func setupRouteFetcher(logger goRouterLogger.Logger, c *config.Config, registry rregistry.Registry, routingAPIClient routing_api.Client) *route_fetcher.RouteFetcher {
	clock := clock.NewClock()

	uaaClient := newUaaClient(logger, clock, c)

	_, err := uaaClient.FetchToken(true)
	if err != nil {
		logger.Fatal("unable-to-fetch-token", zap.Error(err))
	}

	routeFetcher := route_fetcher.NewRouteFetcher(logger, uaaClient, registry, c, routingAPIClient, 1, clock)
	return routeFetcher
}

func newUaaClient(logger goRouterLogger.Logger, clock clock.Clock, c *config.Config) uaa_client.Client {
	if c.RoutingApi.AuthDisabled {
		logger.Info("using-noop-token-fetcher")
		return uaa_client.NewNoOpUaaClient()
	}

	if c.OAuth.Port == -1 {
		logger.Fatal(
			"tls-not-enabled",
			zap.Error(errors.New("GoRouter requires TLS enabled to get OAuth token")),
			zap.String("token-endpoint", c.OAuth.TokenEndpoint),
			zap.Int("port", c.OAuth.Port),
		)
	}

	tokenURL := fmt.Sprintf("https://%s:%d", c.OAuth.TokenEndpoint, c.OAuth.Port)

	cfg := &uaa_config.Config{
		UaaEndpoint:           tokenURL,
		SkipVerification:      c.OAuth.SkipSSLValidation,
		ClientName:            c.OAuth.ClientName,
		ClientSecret:          c.OAuth.ClientSecret,
		CACerts:               c.OAuth.CACerts,
		MaxNumberOfRetries:    c.TokenFetcherMaxRetries,
		RetryInterval:         c.TokenFetcherRetryInterval,
		ExpirationBufferInSec: c.TokenFetcherExpirationBufferTimeInSeconds,
	}

	uaaClient, err := uaa_client.NewClient(goRouterLogger.NewLagerAdapter(logger), cfg, clock)
	if err != nil {
		logger.Fatal("initialize-token-fetcher-error", zap.Error(err))
	}
	return uaaClient
}

func createLogger(component string, level string) (goRouterLogger.Logger, lager.LogLevel) {
	var logLevel zap.Level
	logLevel.UnmarshalText([]byte(level))

	var minLagerLogLevel lager.LogLevel
	switch minLagerLogLevel {
	case lager.DEBUG:
		minLagerLogLevel = lager.DEBUG
	case lager.INFO:
		minLagerLogLevel = lager.INFO
	case lager.ERROR:
		minLagerLogLevel = lager.ERROR
	case lager.FATAL:
		minLagerLogLevel = lager.FATAL
	default:
		panic(fmt.Errorf("unknown log level: %s", level))
	}

	lggr := goRouterLogger.NewLogger(component, logLevel, zap.Output(os.Stdout))
	return lggr, minLagerLogLevel
}
