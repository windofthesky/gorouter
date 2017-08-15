package handlers

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"time"

	"github.com/uber-go/zap"

	router_http "code.cloudfoundry.org/gorouter/common/http"
	"code.cloudfoundry.org/gorouter/config"
	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics"
)

type roundTrip struct {
	c         *config.Config
	tlsConfig *tls.Config
	logger    logger.Logger
	reporter  metrics.CombinedReporter
}

func NewRoundTrip(c *config.Config,
	logger logger.Logger, reporter metrics.CombinedReporter) *roundTrip {
	return &roundTrip{
		c: c,
		//	tlsConfig: tlsConfig,
		logger:   logger,
		reporter: reporter,
	}
}

func (r *roundTrip) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqInfo, err := ContextRequestInfo(req)
	if err != nil {
		r.logger.Fatal("request-info-err", zap.Error(err))
		return
	}
	var instanceId string

	if reqInfo.RoutePool != nil {
		r.logger.Info("setting the instance ID")
		// pool
		// endpoints
		// next()
		// for res(?) {
		// next()
		// }
		// for each endpoint you will set the transport
		// // newIter handler -- > pool --> endpoint
		// roundtrip --> req_info --> make a conn to endpoint
		// next endpoint ..? / 1 endpoint .. mark(endpoint)
		instanceId = reqInfo.RouteEndpoint.PrivateInstanceId
	}
	tlsConfig := &tls.Config{
		CipherSuites:       r.c.CipherSuites,
		InsecureSkipVerify: false,
		RootCAs:            r.c.CAPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		ServerName:         instanceId,
	}

	httpTransport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err := net.DialTimeout(network, addr, 5*time.Second)
			if err != nil {
				return conn, err
			}
			if r.c.EndpointTimeout > 0 {
				err = conn.SetDeadline(time.Now().Add(r.c.EndpointTimeout))
			}
			return conn, err
		},
		DisableKeepAlives:   r.c.DisableKeepAlives,
		MaxIdleConns:        r.c.MaxIdleConns,
		IdleConnTimeout:     90 * time.Second, // setting the value to golang default transport
		MaxIdleConnsPerHost: r.c.MaxIdleConnsPerHost,
		DisableCompression:  true,
		TLSClientConfig:     tlsConfig,
	}

	rproxy := &httputil.ReverseProxy{
		Director:      r.setupProxyRequest,
		Transport:     r.proxyRoundTripper(httpTransport, r.c.Port),
		FlushInterval: 50 * time.Millisecond,
		BufferPool:    NewBufferPool(),
		//		ModifyResponse: p.modifyResponse,
	}
	rproxy.ServeHTTP(rw, req)
}

func (r *roundTrip) proxyRoundTripper(transport ProxyRoundTripper, port uint16) ProxyRoundTripper {
	return NewProxyRoundTripper(
		NewDropsondeRoundTripper(transport),
		r.logger, r.c.TraceKey,
		r.c.Ip, r.c.LoadBalance,
		r.reporter, r.c.SecureCookies,
		port,
	)
}
func (r *roundTrip) setupProxyRequest(target *http.Request) {
	if r.c.ForceForwardedProtoHttps {
		target.Header.Set("X-Forwarded-Proto", "https")
	} else if target.Header.Get("X-Forwarded-Proto") == "" {
		scheme := "http"
		if target.TLS != nil {
			scheme = "https"
		}
		target.Header.Set("X-Forwarded-Proto", scheme)
	}

	target.URL.Scheme = "http"
	target.URL.Host = target.Host
	target.URL.Opaque = target.RequestURI
	target.URL.RawQuery = ""
	target.URL.ForceQuery = false

	SetRequestXRequestStart(target)
	target.Header.Del(router_http.CfAppInstance)
}

func SetRequestXRequestStart(request *http.Request) {
	if _, ok := request.Header[http.CanonicalHeaderKey("X-Request-Start")]; !ok {
		request.Header.Set("X-Request-Start", strconv.FormatInt(time.Now().UnixNano()/1e6, 10))
	}
}

type bufferPool struct {
	pool *sync.Pool
}

func NewBufferPool() httputil.BufferPool {
	return &bufferPool{
		pool: new(sync.Pool),
	}
}

func (b *bufferPool) Get() []byte {
	buf := b.pool.Get()
	if buf == nil {
		return make([]byte, 8192)
	}
	return buf.([]byte)
}

func (b *bufferPool) Put(buf []byte) {
	b.pool.Put(buf)
}
