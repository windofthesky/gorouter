package round_tripper

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
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
		rt.logger.Error("decoding-root-ca-pem-failed")
	}
	rootCrtPEM, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		rt.logger.Error("parsing-root-crt-pem-failed", zap.Error(err))
	}

	rootKeyPem, err := x509.ParsePKCS1PrivateKey(rootkey)
	if err != nil {
		rt.logger.Error("parsing-root-key-pem-failed", zap.Error(err))
	}
	return rootCrtPEM, rootKeyPem
}

func (rt *roundTripper) generateBackendTLS() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		rt.logger.Error("generating-backend-private-key-error", zap.Error(err))
	}
	backendCertTmpl, err := CertTemplate()
	if err != nil {
		rt.logger.Error("creating-backend-cert-template-error", zap.Error(err))
	}
	backendCertTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	backendCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	backendCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} // for NOW we can hardcode to localhost

	_, backEndCrtPem, err := CreateCert(backendCertTmpl, rt.rootCACrt, &key.PublicKey, rt.rootCAKey)
	if err != nil {
		rt.logger.Error("creating-backend-cert-PEM-error", zap.Error(err))
	}

	backEndKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	backEndTLSCert, err := tls.X509KeyPair(backEndCrtPem, backEndKeyPem)
	if err != nil {
		rt.logger.Error("creating-TLS-cert-error", zap.Error(err))
	}
	return &tls.Config{
		Certificates: []tls.Certificate{backEndTLSCert},
	}
}

func CreateCert(template, parent *x509.Certificate, pub, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	//PEM encoded cert (standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

// helper func to crate cert template with a serial number and other fields
func CertTemplate() (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Ninoski, Inc."}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}
	return &tmpl, nil

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
			if port == "7777" {
				logger.Info("making-back-end-tls-connection")
				tlsConfig := rt.generateBackendTLS()
				caCertPool := x509.NewCertPool()
				caCertPool.AddCert(rt.rootCACrt)
				tlsConfig.RootCAs = caCertPool
				tlsTransport := &http.Transport{TLSClientConfig: tlsConfig}
				client := http.Client{Transport: tlsTransport}
				res, err := client.Get("https://" + endpoint.CanonicalAddr())
				if err != nil {
					logger.Error("backend-tls-connection-failed", zap.Error(err))
				}
				return res, nil

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
