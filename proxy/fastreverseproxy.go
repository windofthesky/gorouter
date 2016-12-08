package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"

	"code.cloudfoundry.org/gorouter/route"

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

const (
	maxRetries = 3
)

// FastReverseProxy is responsible for proxying requests to the backend using
// fasthttp
type FastReverseProxy struct {
	registry LookupRegistry
}

// NewFastReverseProxy creates a new FastReverseProxy
func NewFastReverseProxy(registry LookupRegistry) *FastReverseProxy {
	return &FastReverseProxy{
		registry: registry,
	}
}

func (f *FastReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
	backendReq := fasthttp.AcquireRequest()
	backendResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(backendReq)
	defer fasthttp.ReleaseResponse(backendResp)

	copyRequest(req, backendReq)

	for _, h := range HopHeaders {
		backendReq.Header.Del(h)
	}
	requestPath := req.URL.EscapedPath()
	uri := route.Uri(hostWithoutPort(req) + requestPath)
	pool := f.registry.Lookup(uri)
	endpoints := pool.Endpoints("", "")

	for retry := 0; retry < maxRetries; retry++ {
		endpoint := endpoints.Next()
		if endpoint == nil {
			rw.WriteHeader(http.StatusBadGateway)
			fmt.Printf("http: no endpoints available for %s\n", uri)
			// TODO: Message for no endpoints available
			return
		}
		// TODO: Log endpoint?

		backendReq.SetHost(endpoint.CanonicalAddr())

		err := fasthttp.Do(backendReq, backendResp)
		if err == nil {
			break
		}
		if err != fasthttp.ErrDialTimeout {
			panic(err)
		}
		// TODO: Log error timed out connecting to backends
		rw.WriteHeader(http.StatusBadGateway)
	}

	// TODO: add trailers?
	for _, h := range HopHeaders {
		backendResp.Header.Del(h)
	}
	backendResp.Header.VisitAll(func(key []byte, value []byte) {
		rw.Header().Add(string(key), string(value))
	})
	rw.WriteHeader(backendResp.StatusCode())
	err := backendResp.BodyWriteTo(rw)
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		// TODO: How do we handle this case?
	}

	next(rw, req)
}

func copyRequest(req *http.Request, newreq *fasthttp.Request) error {
	buf := new(bytes.Buffer)
	err := req.Write(buf)
	if err != nil {
		return err
	}

	return newreq.Read(bufio.NewReader(buf))
}
