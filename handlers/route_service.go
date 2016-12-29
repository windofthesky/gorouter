package handlers

import (
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	router_http "code.cloudfoundry.org/gorouter/common/http"

	"code.cloudfoundry.org/gorouter/proxy/handler"
	"code.cloudfoundry.org/gorouter/proxy/round_tripper"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/routeservice"
	"github.com/cloudfoundry/dropsonde"
)

// check if route service configured
//  - if yes make the request to rs and call the next ()
//     validate all rs signature stuff
//
type RouteService struct {
}

func NewRouteService() {
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

func hasBeenToRouteService(rsUrl, sigHeader string) bool {
	return sigHeader != "" && rsUrl != ""
}

func ForwardRoute(routeServiceUrl string, routeServiceConfig *routeservice.RouteServiceConfig,
	handle handler.RequestHandler, req *http.Request,
	timeout time.Duration, forceForwardedProtoHttps bool,
	responseWriter http.ResponseWriter) {

	if routeServiceUrl != "" && !routeServiceConfig.RouteServiceEnabled() {
		handle.HandleUnsupportedRouteService()
		return
	}

	var routeServiceArgs routeservice.RouteServiceRequest
	if routeServiceUrl != "" {
		rsSignature := req.Header.Get(routeservice.RouteServiceSignature)

		var recommendedScheme string

		if routeServiceConfig.RouteServiceRecommendHttps() {
			recommendedScheme = "https"
		} else {
			recommendedScheme = "http"
		}

		forwardedUrlRaw := recommendedScheme + "://" + hostWithoutPort(req) + req.RequestURI
		if hasBeenToRouteService(routeServiceUrl, rsSignature) {
			// A request from a route service destined for a backend instances
			routeServiceArgs.URLString = routeServiceUrl
			err := routeServiceConfig.ValidateSignature(&req.Header, forwardedUrlRaw)
			if err != nil {
				handle.HandleBadSignature(err)
				return
			}
		} else {
			var err error
			routeServiceArgs, err = routeServiceConfig.Request(routeServiceUrl, forwardedUrlRaw)
			//			backend = false
			if err != nil {
				handle.HandleRouteServiceFailure(err)
				return
			}
		}

		rtransport := &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(network, addr, 5*time.Second)
				if err != nil {
					return conn, err
				}
				if timeout > 0 {
					err = conn.SetDeadline(time.Now().Add(timeout))
				}
				return conn, err
			},
		}
		after := func(rsp *http.Response, endpoint *route.Endpoint, err error) {
			// do nothing
		}
		proxyWriter := responseWriter.(utils.ProxyResponseWriter)

		roundTripper := round_tripper.NewRouteServiceRoundTripper(
			dropsonde.InstrumentedRoundTripper(rtransport), handle.Logger(), after)
		newReverseProxy(roundTripper, req, routeServiceArgs, routeServiceConfig, forceForwardedProtoHttps).ServeHTTP(proxyWriter, req)
	}
}

func newReverseProxy(proxyTransport http.RoundTripper, req *http.Request,
	routeServiceArgs routeservice.RouteServiceRequest,
	routeServiceConfig *routeservice.RouteServiceConfig,
	forceForwardedProtoHttps bool) http.Handler {
	rproxy := &httputil.ReverseProxy{
		Director: func(request *http.Request) {
			setupProxyRequest(req, request, forceForwardedProtoHttps)
			handleRouteServiceIntegration(request, routeServiceArgs, routeServiceConfig)
		},
		Transport:     proxyTransport,
		FlushInterval: 50 * time.Millisecond,
	}

	return rproxy
}

func handleRouteServiceIntegration(
	target *http.Request,
	routeServiceArgs routeservice.RouteServiceRequest,
	routeServiceConfig *routeservice.RouteServiceConfig,
) {
	sig := target.Header.Get(routeservice.RouteServiceSignature)
	if forwardingToRouteService(routeServiceArgs.URLString, sig) {
		// An endpoint has a route service and this request did not come from the service
		target.Header.Set(routeservice.RouteServiceSignature, routeServiceArgs.Signature)
		target.Header.Set(routeservice.RouteServiceMetadata, routeServiceArgs.Metadata)
		target.Header.Set(routeservice.RouteServiceForwardedURL, routeServiceArgs.ForwardedURL)

		target.Host = routeServiceArgs.ParsedUrl.Host
		target.URL = routeServiceArgs.ParsedUrl
	} else if hasBeenToRouteService(routeServiceArgs.URLString, sig) {
		// Remove the headers since the backend should not see it
		target.Header.Del(routeservice.RouteServiceSignature)
		target.Header.Del(routeservice.RouteServiceMetadata)
		target.Header.Del(routeservice.RouteServiceForwardedURL)
	}
}

func forwardingToRouteService(rsUrl, sigHeader string) bool {
	return sigHeader == "" && rsUrl != ""
}

func setupProxyRequest(source *http.Request, target *http.Request, forceForwardedProtoHttps bool) {
	if forceForwardedProtoHttps {
		target.Header.Set("X-Forwarded-Proto", "https")
	} else if source.Header.Get("X-Forwarded-Proto") == "" {
		scheme := "http"
		if source.TLS != nil {
			scheme = "https"
		}
		target.Header.Set("X-Forwarded-Proto", scheme)
	}

	target.URL.Scheme = "http"
	target.URL.Host = source.Host
	target.URL.Opaque = source.RequestURI
	target.URL.RawQuery = ""

	handler.SetRequestXRequestStart(source)
	target.Header.Del(router_http.CfAppInstance)
}
