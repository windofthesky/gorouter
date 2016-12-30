package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	router_http "code.cloudfoundry.org/gorouter/common/http"
	"code.cloudfoundry.org/gorouter/metrics/reporter"
	"code.cloudfoundry.org/gorouter/proxy/handler"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/routeservice"
	"code.cloudfoundry.org/lager"

	"github.com/valyala/fasthttp"
)

// HopHeaders are hop-by-hop headers that are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var HopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

var xForwardedForKey = []byte(`X-Forwarded-For`)

const (
	maxRetries = 3
)

// FastReverseProxy is responsible for proxying requests to the backend using
// fasthttp
type FastReverseProxy struct {
	registry                 LookupRegistry
	logger                   lager.Logger
	reporter                 reporter.ProxyReporter
	routeServiceConfig       *routeservice.RouteServiceConfig
	defaultLoadBalance       string
	forceForwardedProtoHttps bool
	traceKey                 string
	ip                       string
	secureCookies            bool
}

// NewFastReverseProxy creates a new FastReverseProxy
func NewFastReverseProxy(registry LookupRegistry, logger lager.Logger,
	reporter reporter.ProxyReporter, routeServiceConfig *routeservice.RouteServiceConfig,
	forceForwardedProtoHttps bool,
	traceKey string, defaultLoadBalance string,
	ip string, secureCookies bool) *FastReverseProxy {

	//	routeServiceConfig := routeservice.NewRouteServiceConfig(logger, routeServiceEnabled, routeServiceTimeout, crypto, cryptoPrev, routeServiceRecommendHttps)

	return &FastReverseProxy{
		registry:                 registry,
		logger:                   logger,
		reporter:                 reporter,
		forceForwardedProtoHttps: forceForwardedProtoHttps,
		routeServiceConfig:       routeServiceConfig,
		traceKey:                 traceKey,
		ip:                       ip,
		defaultLoadBalance:       defaultLoadBalance,
		//		secureCookies:            secureCookies,
	}
}

func (f *FastReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	backendReq := fasthttp.AcquireRequest()
	backendResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(backendReq)
	defer fasthttp.ReleaseResponse(backendResp)

	proxyWriter := rw.(utils.ProxyResponseWriter)
	alr := proxyWriter.Context().Value("AccessLogRecord")
	if alr == nil {
		fmt.Printf("AccessLogRecord not set on context", errors.New("failed-to-access-LogRecord"))
	}
	accessLog := alr.(*schema.AccessLogRecord)
	handler := handler.NewRequestHandler(req, proxyWriter, f.reporter, accessLog, f.logger)

	copyRequest(req, backendReq)

	for _, h := range HopHeaders {
		backendReq.Header.Del(h)
	}
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		var clientIPBytes []byte
		prior := backendReq.Header.PeekBytes(xForwardedForKey)
		if len(prior) != 0 {
			clientIPBytes = append(prior, ',', ' ')
			clientIPBytes = append(clientIPBytes, []byte(clientIP)...)
		} else {
			clientIPBytes = []byte(clientIP)
		}
		backendReq.Header.SetBytesKV(xForwardedForKey, clientIPBytes)
	}
	// else {
	// 	fmt.Printf("got an error %s\n", err.Error())
	// }

	if !isProtocolSupported(req) {
		handler.HandleUnsupportedProtocol()
		return
	}

	requestPath := req.URL.EscapedPath()
	uri := route.Uri(hostWithoutPort(req) + requestPath)
	pool := f.registry.Lookup(uri)
	if pool == nil {
		//		fmt.Println("no route present")
		handler.HandleMissingRoute()
		return
	}

	stickyEndpointId := getStickySession(req)
	iter := &wrappedIterator{
		//"round-robin": defaultLoadBalance
		nested: pool.Endpoints(f.defaultLoadBalance, stickyEndpointId),

		afterNext: func(endpoint *route.Endpoint) {
			if endpoint != nil {
				accessLog.RouteEndpoint = endpoint
				f.reporter.CaptureRoutingRequest(endpoint, req)
			}
		},
	}

	if isTcpUpgrade(req) {
		handler.HandleTcpRequest(iter)
		return
	}

	if isWebSocketUpgrade(req) {
		handler.HandleWebSocketRequest(iter)
		return
	}

	//backend := true
	//route service stuff
	// routeServiceUrl := pool.RouteServiceUrl()
	// router_service.ForwardRouter(routerServiceUrl, f.routeServiceConfig)

	timedOut := true
	var endpoint *route.Endpoint
	var err error
	for retry := 0; retry < maxRetries; retry++ {
		endpoint, err = selectEndpoint(iter)

		if err != nil {
			break
		}

		setupRequest(backendReq, endpoint)

		iter.PreRequest(endpoint)
		err = fasthttp.Do(backendReq, backendResp)
		if err == nil {
			timedOut = false
			break
		}
		iter.PostRequest(endpoint)
		if err == nil || !retryableError(err) {
			break
		}

		// if err != fasthttp.ErrDialTimeout {
		// 	rw.WriteHeader(http.StatusBadGateway)
		// 	rw.Write([]byte(fmt.Sprintf("Error connecting to backend: %s", err.Error())))
		// 	return
		// }
		// TODO: Log error timed out connecting to backends
	}

	if timedOut {
		rw.WriteHeader(http.StatusBadGateway)
		rw.Write([]byte("Exceeded max retries: Timed out connecting to backends."))
		return
	}

	// TODO: add trailers?
	for _, h := range HopHeaders {
		backendResp.Header.Del(h)
	}
	backendResp.Header.VisitAll(func(key []byte, value []byte) {
		rw.Header().Add(string(key), string(value))
	})
	rw.WriteHeader(backendResp.StatusCode())

	err = backendResp.BodyWriteTo(rw)
	if err != nil {
		// TODO: How do we handle this case?
		fmt.Printf("Error writing response: %s\n", err.Error())
		return
	}

	buf := new(bytes.Buffer)
	backendResp.WriteTo(buf)
	// fmt.Println(buf.String())

	next(rw, req)

	//		accessLog.FirstByteAt = time.Now()
	if backendResp != nil {
		accessLog.StatusCode = backendResp.StatusCode()
	}

	if f.traceKey != "" && endpoint != nil && req.Header.Get(router_http.VcapTraceHeader) == f.traceKey {
		router_http.SetTraceHeaders(rw, f.ip, endpoint.CanonicalAddr())
	}

	//	latency := time.Since(accessLog.StartedAt)

	//	f.reporter.CaptureRoutingResponse(endpoint, backendResp, accessLog.StartedAt, latency)

	if endpoint.PrivateInstanceId != "" {
		setupStickySession(backendResp.Header, endpoint,
			stickyEndpointId, f.secureCookies, pool.ContextPath())
	}

	// if Content-Type not in response, nil out to suppress Go's auto-detect
	if ok := backendResp.Header.Peek("Content-Type"); len(ok) == 0 {
		rw.Header().Del("Content-Type")
	}
}

func retryableError(err error) bool {
	if err == fasthttp.ErrDialTimeout {
		return true
	}
	return false
}

func setupStickySession(respHeader fasthttp.ResponseHeader,
	endpoint *route.Endpoint,
	originalEndpointId string,
	secureCookies bool,
	path string) {
	//	secure := false
	//	maxAge := 0
	//time.Date()

	// did the endpoint change?
	sticky := originalEndpointId != "" && originalEndpointId != endpoint.PrivateInstanceId

	cookieFunc := func(key, value []byte) {
		if string(key) == StickyCookieKey {
			sticky = true
			//	if v.MaxAge < 0 {
			//			maxAge = v.MaxAge
			//		}
			//		secure = v.Secure
			//			break
		}
	}

	respHeader.VisitAllCookie(cookieFunc)
	if sticky {
		// right now secure attribute would as equal to the JSESSION ID cookie (if present),
		// but override if set to true in config
		fcookie := fasthttp.AcquireCookie()
		defer fasthttp.ReleaseCookie(fcookie)

		if secureCookies {
			fcookie.Secure()
			//	secure = true
		}
		fcookie.SetKey(VcapCookieId)
		fcookie.SetValue(endpoint.PrivateInstanceId)
		fcookie.SetPath(path)
		fcookie.SetHTTPOnly(true)
		//	fcookie.SetExpire(time.Time(maxAge))
		respHeader.SetCookie(fcookie)
	}
}
func copyRequest(req *http.Request, newreq *fasthttp.Request) error {
	buf := new(bytes.Buffer)
	err := req.Write(buf)
	if err != nil {
		return err
	}

	return newreq.Read(bufio.NewReader(buf))
}
func setupRequest(request *fasthttp.Request, endpoint *route.Endpoint) {
	request.Header.SetHost(endpoint.CanonicalAddr())
	request.Header.Set("X-CF-ApplicationID", endpoint.ApplicationId)
	//handler.SetRequestXCfInstanceId(request, endpoint)
}

func hostWithoutPort(req *http.Request) string {
	host := req.Host

	// Remove :<port>
	pos := strings.Index(host, ":")
	if pos >= 0 {
		host = host[0:pos]
	}

	return host
}

func selectEndpoint(iter *wrappedIterator) (*route.Endpoint, error) {
	endpoint := iter.Next()
	if endpoint == nil {
		return nil, handler.NoEndpointsAvailable
	}

	//	rt.logger = rt.logger.WithData(lager.Data{"route-endpoint": endpoint.ToLogData()})
	return endpoint, nil
}

func isProtocolSupported(request *http.Request) bool {
	return request.ProtoMajor == 1 && (request.ProtoMinor == 0 || request.ProtoMinor == 1)
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

func isWebSocketUpgrade(request *http.Request) bool {
	// websocket should be case insensitive per RFC6455 4.2.1
	return strings.ToLower(upgradeHeader(request)) == "websocket"
}

func isTcpUpgrade(request *http.Request) bool {
	return upgradeHeader(request) == "tcp"
}
