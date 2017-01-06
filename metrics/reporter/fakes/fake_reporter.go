// This file was generated by counterfeiter
package fakes

import (
	"net/http"
	"sync"
	"time"

	"code.cloudfoundry.org/gorouter/metrics/reporter"
	"code.cloudfoundry.org/gorouter/route"
	"github.com/valyala/fasthttp"
)

type FakeProxyReporter struct {
	CaptureBadRequestStub        func(req *http.Request)
	captureBadRequestMutex       sync.RWMutex
	captureBadRequestArgsForCall []struct {
		req *http.Request
	}
	CaptureBadGatewayStub        func(req *http.Request)
	captureBadGatewayMutex       sync.RWMutex
	captureBadGatewayArgsForCall []struct {
		req *http.Request
	}
	CaptureRoutingRequestStub        func(b *route.Endpoint, req *http.Request)
	captureRoutingRequestMutex       sync.RWMutex
	captureRoutingRequestArgsForCall []struct {
		b   *route.Endpoint
		req *http.Request
	}
	CaptureRoutingResponseStub        func(b *route.Endpoint, res *fasthttp.Response, t time.Time, d time.Duration)
	captureRoutingResponseMutex       sync.RWMutex
	captureRoutingResponseArgsForCall []struct {
		b   *route.Endpoint
		res *fasthttp.Response
		t   time.Time
		d   time.Duration
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeProxyReporter) CaptureBadRequest(req *http.Request) {
	fake.captureBadRequestMutex.Lock()
	fake.captureBadRequestArgsForCall = append(fake.captureBadRequestArgsForCall, struct {
		req *http.Request
	}{req})
	fake.recordInvocation("CaptureBadRequest", []interface{}{req})
	fake.captureBadRequestMutex.Unlock()
	if fake.CaptureBadRequestStub != nil {
		fake.CaptureBadRequestStub(req)
	}
}

func (fake *FakeProxyReporter) CaptureBadRequestCallCount() int {
	fake.captureBadRequestMutex.RLock()
	defer fake.captureBadRequestMutex.RUnlock()
	return len(fake.captureBadRequestArgsForCall)
}

func (fake *FakeProxyReporter) CaptureBadRequestArgsForCall(i int) *http.Request {
	fake.captureBadRequestMutex.RLock()
	defer fake.captureBadRequestMutex.RUnlock()
	return fake.captureBadRequestArgsForCall[i].req
}

func (fake *FakeProxyReporter) CaptureBadGateway(req *http.Request) {
	fake.captureBadGatewayMutex.Lock()
	fake.captureBadGatewayArgsForCall = append(fake.captureBadGatewayArgsForCall, struct {
		req *http.Request
	}{req})
	fake.recordInvocation("CaptureBadGateway", []interface{}{req})
	fake.captureBadGatewayMutex.Unlock()
	if fake.CaptureBadGatewayStub != nil {
		fake.CaptureBadGatewayStub(req)
	}
}

func (fake *FakeProxyReporter) CaptureBadGatewayCallCount() int {
	fake.captureBadGatewayMutex.RLock()
	defer fake.captureBadGatewayMutex.RUnlock()
	return len(fake.captureBadGatewayArgsForCall)
}

func (fake *FakeProxyReporter) CaptureBadGatewayArgsForCall(i int) *http.Request {
	fake.captureBadGatewayMutex.RLock()
	defer fake.captureBadGatewayMutex.RUnlock()
	return fake.captureBadGatewayArgsForCall[i].req
}

func (fake *FakeProxyReporter) CaptureRoutingRequest(b *route.Endpoint, req *http.Request) {
	fake.captureRoutingRequestMutex.Lock()
	fake.captureRoutingRequestArgsForCall = append(fake.captureRoutingRequestArgsForCall, struct {
		b   *route.Endpoint
		req *http.Request
	}{b, req})
	fake.recordInvocation("CaptureRoutingRequest", []interface{}{b, req})
	fake.captureRoutingRequestMutex.Unlock()
	if fake.CaptureRoutingRequestStub != nil {
		fake.CaptureRoutingRequestStub(b, req)
	}
}

func (fake *FakeProxyReporter) CaptureRoutingRequestCallCount() int {
	fake.captureRoutingRequestMutex.RLock()
	defer fake.captureRoutingRequestMutex.RUnlock()
	return len(fake.captureRoutingRequestArgsForCall)
}

func (fake *FakeProxyReporter) CaptureRoutingRequestArgsForCall(i int) (*route.Endpoint, *http.Request) {
	fake.captureRoutingRequestMutex.RLock()
	defer fake.captureRoutingRequestMutex.RUnlock()
	return fake.captureRoutingRequestArgsForCall[i].b, fake.captureRoutingRequestArgsForCall[i].req
}

func (fake *FakeProxyReporter) CaptureRoutingResponse(b *route.Endpoint, res *fasthttp.Response, t time.Time, d time.Duration) {
	fake.captureRoutingResponseMutex.Lock()
	fake.captureRoutingResponseArgsForCall = append(fake.captureRoutingResponseArgsForCall, struct {
		b   *route.Endpoint
		res *fasthttp.Response
		t   time.Time
		d   time.Duration
	}{b, res, t, d})
	fake.recordInvocation("CaptureRoutingResponse", []interface{}{b, res, t, d})
	fake.captureRoutingResponseMutex.Unlock()
	if fake.CaptureRoutingResponseStub != nil {
		fake.CaptureRoutingResponseStub(b, res, t, d)
	}
}

func (fake *FakeProxyReporter) CaptureRoutingResponseCallCount() int {
	fake.captureRoutingResponseMutex.RLock()
	defer fake.captureRoutingResponseMutex.RUnlock()
	return len(fake.captureRoutingResponseArgsForCall)
}

func (fake *FakeProxyReporter) CaptureRoutingResponseArgsForCall(i int) (*route.Endpoint, *fasthttp.Response, time.Time, time.Duration) {
	fake.captureRoutingResponseMutex.RLock()
	defer fake.captureRoutingResponseMutex.RUnlock()
	return fake.captureRoutingResponseArgsForCall[i].b, fake.captureRoutingResponseArgsForCall[i].res, fake.captureRoutingResponseArgsForCall[i].t, fake.captureRoutingResponseArgsForCall[i].d
}

func (fake *FakeProxyReporter) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.captureBadRequestMutex.RLock()
	defer fake.captureBadRequestMutex.RUnlock()
	fake.captureBadGatewayMutex.RLock()
	defer fake.captureBadGatewayMutex.RUnlock()
	fake.captureRoutingRequestMutex.RLock()
	defer fake.captureRoutingRequestMutex.RUnlock()
	fake.captureRoutingResponseMutex.RLock()
	defer fake.captureRoutingResponseMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeProxyReporter) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ reporter.ProxyReporter = new(FakeProxyReporter)
