package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"

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

var xForwardedForKey = []byte(`X-Forwarded-For`)

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

	requestPath := req.URL.EscapedPath()
	uri := route.Uri(hostWithoutPort(req) + requestPath)
	pool := f.registry.Lookup(uri)
	if pool == nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	endpoints := pool.Endpoints("", "")

	timedOut := true
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
			timedOut = false
			break
		}
		if err != fasthttp.ErrDialTimeout {
			rw.WriteHeader(http.StatusBadGateway)
			rw.Write([]byte(fmt.Sprintf("Error connecting to backend: %s", err.Error())))
			return
		}
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

	err := backendResp.BodyWriteTo(rw)
	if err != nil {
		// TODO: How do we handle this case?
		fmt.Printf("Error writing response: %s\n", err.Error())
		return
	}

	buf := new(bytes.Buffer)
	backendResp.WriteTo(buf)
	fmt.Println(buf.String())

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

func hostWithoutPort(req *http.Request) string {
	host := req.Host

	// Remove :<port>
	pos := strings.Index(host, ":")
	if pos >= 0 {
		host = host[0:pos]
	}

	return host
}
