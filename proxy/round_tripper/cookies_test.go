package round_tripper_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/metrics/fakes"
	"code.cloudfoundry.org/gorouter/proxy/round_tripper"
	roundtripperfakes "code.cloudfoundry.org/gorouter/proxy/round_tripper/fakes"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/gorouter/test_util"
	"code.cloudfoundry.org/routing-api/models"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cookie handling", func() {
	Context("when sticky session", func() {
		var (
			transport                *roundtripperfakes.FakeProxyRoundTripper
			backendSetResponseCookie *http.Cookie
		)

		BeforeEach(func() {
			transport = new(roundtripperfakes.FakeProxyRoundTripper)
			backendSetResponseCookie = &http.Cookie{
				Name:  "JSESSIONID",
				Value: "backend-set-this",
			}
			transport.RoundTripStub = roundTripStubWithCookie(backendSetResponseCookie)
		})

		Context("with no previous session", func() {
			It("will select an endpoint and add a cookie header with the privateInstanceId", func() {
				req := test_util.NewRequest("GET", "myapp.com", "/", nil)
				resp, err := testRoundTrip(transport, req)
				Expect(err).ToNot(HaveOccurred())

				receivedRespCookies := resp.Cookies()
				Expect(receivedRespCookies).To(HaveLen(2))
				Expect(receivedRespCookies[0].Raw).To(Equal(backendSetResponseCookie.String()))
				Expect(receivedRespCookies[1].Name).To(Equal(round_tripper.VcapCookieId))
				Expect(receivedRespCookies[1].Value).To(SatisfyAny(
					Equal("id-1"),
					Equal("id-2")))
			})
		})

		Context("with previous session where client sends JSESSIONID set to some value", func() {
			var req *http.Request
			BeforeEach(func() {
				req = test_util.NewRequest("GET", "myapp.com", "/", nil)
				req.AddCookie(&http.Cookie{
					Name:  "JSESSIONID",
					Value: "client-provided-value",
				})
				req.AddCookie(&http.Cookie{
					Name:  "__VCAP_ID__",
					Value: "id-2",
				})
			})

			FIt("will return a response including the JSESSIONID set by the backend and with the __VCAP_ID__ set to the backend instance id", func() {
				fmt.Printf("\n\n REQUEST HAS COOKIE:\n%s\n\n", req.Cookies()[0].String())

				resp, err := testRoundTrip(transport, req)
				Expect(err).ToNot(HaveOccurred())

				receivedRespCookies := resp.Cookies()
				Expect(receivedRespCookies).To(HaveLen(2))

				//JSESSIONID should be the same
				Expect(receivedRespCookies[0].Name).To(Equal("JSESSIONID"))
				Expect(receivedRespCookies[0].Value).To(Equal("backend-set-this"))
				Expect(receivedRespCookies[1].Name).To(Equal("__VCAP_ID__"))
				Expect(receivedRespCookies[1].Value).To(Equal("id-2"))
			})

			It("will select the correct backend", func() {})
			It("will include the JSESSIONID provided by the backend's response", func() {})
			It("will set the __VCAP_ID__ cookie on the response", func() {

			})

			// Context("when the previous endpoints cannot be reached", func() {
			// 	BeforeEach(func() {
			// 		removed := routePool.Remove(endpoint1)
			// 		Expect(removed).To(BeTrue())

			// 		removed = routePool.Remove(endpoint2)
			// 		Expect(removed).To(BeTrue())

			// 		new_endpoint := route.NewEndpoint("appId", "1.1.1.1", uint16(9091), "id-5", "2",
			// 			map[string]string{}, 0, "route-service.com", models.ModificationTag{}, "", false)
			// 		added := routePool.Put(new_endpoint)
			// 		Expect(added).To(BeTrue())
			// 	})

			// 	It("will select a new backend and update the vcap cookie id", func() {
			// 		resp, err := proxyRoundTripper.RoundTrip(req)
			// 		Expect(err).ToNot(HaveOccurred())

			// 		newCookies := resp.Cookies()
			// 		Expect(newCookies).To(HaveLen(2))

			// 		//JSESSIONID should be the same
			// 		Expect(newCookies[0]).To(Equal(cookies[0]))

			// 		Expect(newCookies[1].Value).To(Equal("id-5"))
			// 	})
			// })
		})
	})
})

func roundTripStubWithCookie(cookie *http.Cookie) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		resp := &http.Response{StatusCode: http.StatusTeapot, Header: make(map[string][]string)}

		resp.Header.Add(round_tripper.CookieHeader, cookie.String())
		fmt.Printf("\n\n SETTING COOKIE:\n%s\n\n", cookie.String())
		return resp, nil
	}
}

func testRoundTrip(transport round_tripper.ProxyRoundTripper, req *http.Request) (*http.Response, error) {
	routePool := route.NewPool(1*time.Second, "", "")
	resp := httptest.NewRecorder()
	proxyWriter := utils.NewProxyResponseWriter(resp)
	req.URL.Scheme = "http"

	handlers.NewRequestInfo().ServeHTTP(nil, req, func(_ http.ResponseWriter, transformedReq *http.Request) {
		req = transformedReq
	})

	reqInfo, err := handlers.ContextRequestInfo(req)
	Expect(err).ToNot(HaveOccurred())

	reqInfo.RoutePool = routePool
	reqInfo.ProxyResponseWriter = proxyWriter

	endpoint1 := route.NewEndpoint("appId", "1.1.1.1", uint16(9091), "id-1", "2",
		map[string]string{}, 0, "route-service.com", models.ModificationTag{}, "", false)
	endpoint2 := route.NewEndpoint("appId", "1.1.1.1", uint16(9092), "id-2", "3",
		map[string]string{}, 0, "route-service.com", models.ModificationTag{}, "", false)

	added := routePool.Put(endpoint1)
	Expect(added).To(BeTrue())
	added = routePool.Put(endpoint2)
	Expect(added).To(BeTrue())

	const routerIP = "127.0.0.1"
	logger := test_util.NewTestZapLogger("test")
	combinedReporter := new(fakes.FakeCombinedReporter)
	proxyRoundTripper := round_tripper.NewProxyRoundTripper(
		transport, logger, "my_trace_key", routerIP, "",
		combinedReporter, false,
		1234,
	)
	return proxyRoundTripper.RoundTrip(req)
}
