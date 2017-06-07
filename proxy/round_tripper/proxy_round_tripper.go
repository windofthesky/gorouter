package round_tripper

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/uber-go/zap"

	router_http "code.cloudfoundry.org/gorouter/common/http"
	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics"
	"code.cloudfoundry.org/gorouter/proxy/handler"
	"code.cloudfoundry.org/gorouter/route"
)

const (
	VcapCookieId      = "__VCAP_ID__"
	StickyCookieKey   = "JSESSIONID"
	CookieHeader      = "Set-Cookie"
	BadGatewayMessage = "502 Bad Gateway: Registered endpoint failed to handle the request."
)

//go:generate counterfeiter -o fakes/fake_proxy_round_tripper.go . ProxyRoundTripper
type ProxyRoundTripper interface {
	http.RoundTripper
	CancelRequest(*http.Request)
}

type AfterRoundTrip func(req *http.Request, rsp *http.Response, endpoint *route.Endpoint, err error)

type roundTripper struct {
	transport          ProxyRoundTripper
	logger             logger.Logger
	traceKey           string
	routerIP           string
	defaultLoadBalance string
	combinedReporter   metrics.CombinedReporter
	secureCookies      bool
	localPort          uint16
	rootCACrt          *x509.Certificate
	rootCAKey          *rsa.PrivateKey
}

func NewProxyRoundTripper(
	transport ProxyRoundTripper,
	logger logger.Logger,
	traceKey string,
	routerIP string,
	defaultLoadBalance string,
	combinedReporter metrics.CombinedReporter,
	secureCookies bool,
	localPort uint16,
) ProxyRoundTripper {
	rt := &roundTripper{
		logger:             logger,
		transport:          transport,
		traceKey:           traceKey,
		routerIP:           routerIP,
		defaultLoadBalance: defaultLoadBalance,
		combinedReporter:   combinedReporter,
		secureCookies:      secureCookies,
		localPort:          localPort,
	}
	cert, key := rt.rootCert()
	rt.rootCACrt = cert
	rt.rootCAKey = key
	return rt
}

func (rt *roundTripper) rootCert() (*x509.Certificate, *rsa.PrivateKey) {
	rootCAPath := os.Getenv("ROOT_CA")
	if rootCAPath == "" {
		rt.logger.Error("loading-root-CA-failed")
	}
	rootCrt, err := ioutil.ReadFile(filepath.Join(rootCAPath, "rootCa.crt"))
	if err != nil {
		rt.logger.Error("reading-root-crt-file", zap.Error(err))
	}
	rootkey, err := ioutil.ReadFile(filepath.Join(rootCAPath, "rootCa.key"))
	if err != nil {
		rt.logger.Error("reading-rootca-key-file", zap.Error(err))
	}

	crtBlock, _ := pem.Decode(rootCrt)
	if crtBlock == nil {
		rt.logger.Error("decoding-root-crt-pem-failed")
	}
	rootCrtPEM, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		rt.logger.Error("parsing-root-crt-pem-failed", zap.Error(err))
	}

	keyBlock, _ := pem.Decode(rootkey)
	if keyBlock == nil {
		rt.logger.Error("decoding-root-key-pem-failed")
	}
	rootKeyPem, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		rt.logger.Error("parsing-root-key-pem-failed", zap.Error(err))
	}
	return rootCrtPEM, rootKeyPem
}

func (rt *roundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	var err error
	var res *http.Response
	var endpoint *route.Endpoint

	if request.Body != nil {
		closer := request.Body
		request.Body = ioutil.NopCloser(request.Body)
		defer func() {
			closer.Close()
		}()
	}

	reqInfo, err := handlers.ContextRequestInfo(request)
	if err != nil {
		return nil, err
	}
	if reqInfo.RoutePool == nil {
		return nil, errors.New("RoutePool not set on context")
	}

	if reqInfo.ProxyResponseWriter == nil {
		return nil, errors.New("ProxyResponseWriter not set on context")
	}

	stickyEndpointID := getStickySession(request)
	iter := reqInfo.RoutePool.Endpoints(rt.defaultLoadBalance, stickyEndpointID)

	verifyBackEnd := func(conn *tls.Conn) error {
		connState := conn.ConnectionState()
		for _, cert := range connState.PeerCertificates {
			cn := cert.Subject.CommonName
			log.Printf("Found common name in cert %s", cn)
			// this does not have to be app guid
			if cn != "appGuid123" {
				return errors.New("Failed to verify backEnd")
			}
		}
		return nil
	}
	logger := rt.logger
	for retry := 0; retry < handler.MaxRetries; retry++ {

		if reqInfo.RouteServiceURL == nil {
			logger.Debug("backend", zap.Int("attempt", retry))
			endpoint, err = rt.selectEndpoint(iter, request)
			if err != nil {
				break
			}

			_, port, err := net.SplitHostPort(endpoint.CanonicalAddr())
			if err != nil {
				logger.Error("spliting-CanonicalAddr-failed", zap.Error(err))
			}

			//verify tls_port
			if port == "7777" {
				logger.Info("making-back-end-tls-connection")
				caCertPool := x509.NewCertPool()
				caCertPool.AddCert(rt.rootCACrt)

				tlsConfig := &tls.Config{
					RootCAs: caCertPool,
				}

				// call the app on it's TLS endpoint
				// Ideally this connection should get re-used
				// need to figure out how transition tls.Conn to transport Roundtrip
				conn, err := tls.Dial("tcp", "127.0.0.1:4443", tlsConfig)
				if err != nil {
					rt.logger.Error("connection to backend tls failed :%v", zap.Error(err))
				}
				defer conn.Close()
				if err := verifyBackEnd(conn); err != nil {
					// try another endpiont
					break
				}

			}

			logger = logger.With(zap.Nest("route-endpoint", endpoint.ToLogData()...))
			res, err = rt.backendRoundTrip(request, endpoint, iter)
			if err == nil || !retryableError(err) {
				break
			}
			iter.EndpointFailed()
			logger.Error("backend-endpoint-failed", zap.Error(err))
		} else {
			logger.Debug(
				"route-service",
				zap.Object("route-service-url", reqInfo.RouteServiceURL),
				zap.Int("attempt", retry),
			)
			// TODO: confirm if the endpoint port is the tls_port & use round trip wrapped in TLS???
			endpoint = newRouteServiceEndpoint()
			request.Host = reqInfo.RouteServiceURL.Host
			request.URL = new(url.URL)
			*request.URL = *reqInfo.RouteServiceURL
			if reqInfo.IsInternalRouteService {
				request.URL.Scheme = "http"
				request.URL.Host = fmt.Sprintf("localhost:%d", rt.localPort)
			}

			res, err = rt.transport.RoundTrip(request)
			if err == nil {
				if res != nil && (res.StatusCode < 200 || res.StatusCode >= 300) {
					logger.Info(
						"route-service-response",
						zap.String("endpoint", request.URL.String()),
						zap.Int("status-code", res.StatusCode),
					)
				}
				break
			}
			if !retryableError(err) {
				break
			}
			logger.Error("route-service-connection-failed", zap.Error(err))
		}
	}

	reqInfo.RouteEndpoint = endpoint
	reqInfo.StoppedAt = time.Now()

	if err != nil {
		responseWriter := reqInfo.ProxyResponseWriter
		responseWriter.Header().Set(router_http.CfRouterError, "endpoint_failure")

		logger.Info("status", zap.String("body", BadGatewayMessage))

		http.Error(responseWriter, BadGatewayMessage, http.StatusBadGateway)
		responseWriter.Header().Del("Connection")

		logger.Error("endpoint-failed", zap.Error(err))

		rt.combinedReporter.CaptureBadGateway()

		responseWriter.Done()

		return nil, err
	}

	if rt.traceKey != "" && request.Header.Get(router_http.VcapTraceHeader) == rt.traceKey {
		if res != nil && endpoint != nil {
			res.Header.Set(router_http.VcapRouterHeader, rt.routerIP)
			res.Header.Set(router_http.VcapBackendHeader, endpoint.CanonicalAddr())
			res.Header.Set(router_http.CfRouteEndpointHeader, endpoint.CanonicalAddr())
		}
	}

	if res != nil && endpoint.PrivateInstanceId != "" {
		setupStickySession(
			res, endpoint, stickyEndpointID, rt.secureCookies,
			reqInfo.RoutePool.ContextPath(),
		)
	}

	return res, nil
}

func (rt *roundTripper) CancelRequest(request *http.Request) {
	rt.transport.CancelRequest(request)
}

func (rt *roundTripper) backendRoundTrip(
	request *http.Request,
	endpoint *route.Endpoint,
	iter route.EndpointIterator,
) (*http.Response, error) {
	request.URL.Host = endpoint.CanonicalAddr()
	request.Header.Set("X-CF-ApplicationID", endpoint.ApplicationId)
	request.Header.Set("X-CF-InstanceIndex", endpoint.PrivateInstanceIndex)
	handler.SetRequestXCfInstanceId(request, endpoint)

	// increment connection stats
	iter.PreRequest(endpoint)

	rt.combinedReporter.CaptureRoutingRequest(endpoint)
	res, err := rt.transport.RoundTrip(request)

	// decrement connection stats
	iter.PostRequest(endpoint)
	return res, err
}

func (rt *roundTripper) selectEndpoint(iter route.EndpointIterator, request *http.Request) (*route.Endpoint, error) {
	endpoint := iter.Next()
	if endpoint == nil {
		return nil, handler.NoEndpointsAvailable
	}

	return endpoint, nil
}

func setupStickySession(
	response *http.Response,
	endpoint *route.Endpoint,
	originalEndpointId string,
	secureCookies bool,
	path string,
) {
	secure := false
	maxAge := 0

	// did the endpoint change?
	sticky := originalEndpointId != "" && originalEndpointId != endpoint.PrivateInstanceId

	for _, v := range response.Cookies() {
		if v.Name == StickyCookieKey {
			sticky = true
			if v.MaxAge < 0 {
				maxAge = v.MaxAge
			}
			secure = v.Secure
			break
		}
	}

	if sticky {
		// right now secure attribute would as equal to the JSESSION ID cookie (if present),
		// but override if set to true in config
		if secureCookies {
			secure = true
		}

		cookie := &http.Cookie{
			Name:     VcapCookieId,
			Value:    endpoint.PrivateInstanceId,
			Path:     path,
			MaxAge:   maxAge,
			HttpOnly: true,
			Secure:   secure,
		}

		if v := cookie.String(); v != "" {
			response.Header.Add(CookieHeader, v)
		}
	}
}

func getStickySession(request *http.Request) string {
	// Try choosing a backend using sticky session
	if _, err := request.Cookie(StickyCookieKey); err == nil {
		if sticky, err := request.Cookie(VcapCookieId); err == nil {
			return sticky.Value
		}
	}
	return ""
}

func retryableError(err error) bool {
	ne, netErr := err.(*net.OpError)
	if netErr && (ne.Op == "dial" || ne.Op == "read" && ne.Err.Error() == "read: connection reset by peer") {
		return true
	}
	return false
}

func newRouteServiceEndpoint() *route.Endpoint {
	return &route.Endpoint{
		Tags: map[string]string{},
	}
}
