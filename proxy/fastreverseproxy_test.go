package proxy_test

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"code.cloudfoundry.org/gorouter/access_log/schema"
	"code.cloudfoundry.org/gorouter/metrics/reporter/fakes"
	"code.cloudfoundry.org/gorouter/proxy/utils"
	registryfakes "code.cloudfoundry.org/gorouter/registry/fakes"
	"code.cloudfoundry.org/gorouter/route"
	"code.cloudfoundry.org/routing-api/models"

	"code.cloudfoundry.org/gorouter/proxy"
	"code.cloudfoundry.org/gorouter/test_util"
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
	"github.com/urfave/negroni"
)

var _ = FDescribe("FastReverseProxy", func() {
	var (
		handler            negroni.Handler
		testServer         *ghttp.Server
		testServerRoute    string
		testServerEndpoint *route.Endpoint
		nextCalled         bool
		resp               *httptest.ResponseRecorder
		proxyWriter        utils.ProxyResponseWriter
		reg                *registryfakes.FakeRegistryInterface
		logger             lager.Logger
	)

	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Body != nil {
			_, err := ioutil.ReadAll(req.Body)
			Expect(err).NotTo(HaveOccurred())
		}

		rw.WriteHeader(http.StatusTeapot)

		nextCalled = true
	})

	BeforeEach(func() {
		testServer = ghttp.NewServer()
		resp = httptest.NewRecorder()

		proxyWriter = utils.NewProxyResponseWriter(resp)
		alr := &schema.AccessLogRecord{}
		proxyWriter.AddToContext("AccessLogRecord", alr)

		testServerRoute = "foo.com"

		logger = lagertest.NewTestLogger("fastreverseproxy-test")

		// Set up route registry
		reg = new(registryfakes.FakeRegistryInterface)
		pool := route.NewPool(1*time.Second, "")
		host, strPort, err := net.SplitHostPort(testServer.Addr())
		Expect(err).ToNot(HaveOccurred())
		port, err := strconv.Atoi(strPort)
		Expect(err).ToNot(HaveOccurred())
		testServerEndpoint = route.NewEndpoint("foo", host, uint16(port), "", "", nil, -1, "", models.ModificationTag{})
		_ = pool.Put(testServerEndpoint)
		reg.LookupStub = func(uri route.Uri) *route.Pool {
			if uri.String() == testServerRoute {
				return pool
			}
			return nil
		}

		handler = proxy.NewFastReverseProxy(reg, logger, new(fakes.FakeProxyReporter), nil, false, "", "", "local", false)
		nextCalled = false
	})

	AfterEach(func() {
		testServer.Close()
	})

	It("routes the request to the correct backend", func() {
		testBody := "Successfully got foo."
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/foo"),
				ghttp.RespondWith(200, testBody),
			),
		)
		req := test_util.NewRequest("GET", testServerRoute, "/foo", nil)
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(resp.Code).To(Equal(http.StatusOK))

		Expect(resp.Body.String()).To(Equal(testBody))
		Expect(nextCalled).To(BeTrue())
	})

	It("does not overwrite the host header", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/"),
				func(rw http.ResponseWriter, req *http.Request) {
					Expect(req.Host).To(Equal(testServerRoute))
				},
				ghttp.RespondWith(200, nil),
			),
		)
		req := test_util.NewRequest("GET", testServerRoute, "/", nil)
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(resp.Code).To(Equal(http.StatusOK))

		Expect(nextCalled).To(BeTrue())
	})

	It("transparently sends end-to-end headers to the backend", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/"),
				ghttp.VerifyHeaderKV("X-Foo-Header", "foo"),
				ghttp.VerifyHeaderKV("X-Bar-Header", "bar"),
				ghttp.RespondWith(200, nil),
			),
		)
		req := test_util.NewRequest("GET", testServerRoute, "/", nil)
		req.Header.Add("X-Foo-Header", "foo")
		req.Header.Add("X-Bar-Header", "bar")
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
	})

	It("transparently returns end-to-end headers from the backend", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/"),
				func(w http.ResponseWriter, req *http.Request) {
					w.Header().Add("X-Foo-Header", "foo")
					w.Header().Add("X-Bar-Header", "bar")
					w.WriteHeader(200)
				},
			),
		)
		req := test_util.NewRequest("GET", testServerRoute, "/", nil)
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(resp.Code).To(Equal(http.StatusOK))
		Expect(resp.Header().Get("X-Foo-Header")).To(Equal("foo"))
		Expect(resp.Header().Get("X-Bar-Header")).To(Equal("bar"))
		Expect(nextCalled).To(BeTrue())
	})

	FIt("can handle multipart form data", func() {
		expectedBody := []byte(strings.Repeat("Z", 1024))
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/"),
				func(w http.ResponseWriter, req *http.Request) {
					buf := new(bytes.Buffer)
					err := req.Write(buf)
					Expect(err).ToNot(HaveOccurred())
					fmt.Println("RECEIVED REQUEST", buf.String())

					Expect(req.Header.Get("Content-Type")).To(ContainSubstring("multipart/form-data"))

					reader, err := req.MultipartReader()
					Expect(err).ToNot(HaveOccurred())
					part, err := reader.NextPart()
					Expect(err).ToNot(HaveOccurred())
					Expect(part.FormName()).To(Equal("input"))
					Expect(part.FileName()).To(Equal("testfile"))
					body, err := ioutil.ReadAll(part)
					Expect(err).ToNot(HaveOccurred())
					Expect(body).To(Equal(expectedBody))
				},
				ghttp.RespondWith(http.StatusCreated, nil),
			),
		)
		body := new(bytes.Buffer)
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("input", "testfile")
		Expect(err).ToNot(HaveOccurred())
		_, err = io.Copy(part, bytes.NewBuffer(expectedBody))
		Expect(err).ToNot(HaveOccurred())
		err = writer.Close()
		Expect(err).ToNot(HaveOccurred())
		req := test_util.NewRequest("POST", testServerRoute, "/", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(resp.Code).To(Equal(http.StatusOK))
		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(nextCalled).To(BeTrue())
	})

	XIt("can handle chunked transfer encoding in the response", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/"),
				func(w http.ResponseWriter, req *http.Request) {
					flusher, ok := w.(http.Flusher)
					Expect(ok).To(BeTrue(), "Expected http.ResponseWriter to be an http.Flusher")

					for i := 0; i < 5; i++ {
						fmt.Fprintf(w, "Chunk %d\n", i)
						flusher.Flush()
						time.Sleep(1000 * time.Millisecond)
					}
				},
			),
		)
		req := test_util.NewRequest("POST", testServerRoute, "/", nil)
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(resp.Code).To(Equal(http.StatusOK))
		Expect(resp.Result().TransferEncoding).To(Equal([]string{"chunked"}))
		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(nextCalled).To(BeTrue())
	})
	XIt("transparently returns trailers from the backend", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("POST", "/"),
				func(w http.ResponseWriter, req *http.Request) {
					w.Header().Set("Trailer", "X-Foo-Trailer")
					w.WriteHeader(200)
					w.Header().Set("X-Foo-Trailer", "foo")
				},
			),
		)
		req := test_util.NewRequest("POST", testServerRoute, "/", nil)
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(resp.Code).To(Equal(http.StatusOK))
		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(resp.Result().Trailer.Get("X-Foo-Trailer")).To(Equal("foo"))
		Expect(nextCalled).To(BeTrue())
	})

	It("strips hop-by-hop headers from the incoming request", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/"),
				func(w http.ResponseWriter, req *http.Request) {
					for _, h := range proxy.HopHeaders {
						key := http.CanonicalHeaderKey(h)
						Expect(req.Header).ToNot(HaveKey(key), "Found unwanted key `%s` in request", key)
					}
				},
				ghttp.RespondWith(200, nil),
			),
		)
		req := test_util.NewRequest("GET", testServerRoute, "/", nil)
		for _, h := range proxy.HopHeaders {
			req.Header.Add(h, "some-value")
		}
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(nextCalled).To(BeTrue())
	})

	It("adds X-Forwarded-For to the request", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/"),
				ghttp.VerifyHeaderKV("X-Forwarded-For", "192.0.2.255"),
				ghttp.RespondWith(200, nil),
			),
		)
		req := test_util.NewRequest("GET", testServerRoute, "/", nil)
		req.RemoteAddr = "192.0.2.255:8709"
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(nextCalled).To(BeTrue())
	})

	It("appends to X-Forwarded-For to the request if the header already exists", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/"),
				ghttp.VerifyHeaderKV("X-Forwarded-For", "192.0.2.254, 192.0.2.255"),
				ghttp.RespondWith(200, nil),
			),
		)
		req := test_util.NewRequest("GET", testServerRoute, "/", nil)
		req.Header.Set("X-Forwarded-For", "192.0.2.254")
		req.RemoteAddr = "192.0.2.255:8080"
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(nextCalled).To(BeTrue())
	})

	It("strips hop-by-hop headers from the response", func() {
		testServer.AppendHandlers(
			ghttp.CombineHandlers(
				ghttp.VerifyRequest("GET", "/"),
				func(w http.ResponseWriter, req *http.Request) {
					for _, h := range proxy.HopHeaders {
						w.Header().Add(h, "some-value")
					}
				},
			),
		)
		req := test_util.NewRequest("GET", testServerRoute, "/", nil)
		handler.ServeHTTP(proxyWriter, req, nextHandler)

		Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		Expect(resp.Code).To(Equal(http.StatusOK))
		for _, h := range proxy.HopHeaders {
			Expect(resp.Header()).ToNot(HaveKey(h))
		}
		Expect(nextCalled).To(BeTrue())
	})

	Context("when there are no backends present", func() {
		BeforeEach(func() {
			reg.LookupStub = func(uri route.Uri) *route.Pool {
				return nil
			}
		})
		It("fails with 404 Not Found", func() {
			req := test_util.NewRequest("GET", testServerRoute, "/", nil)
			handler.ServeHTTP(proxyWriter, req, nextHandler)

			Expect(testServer.ReceivedRequests()).To(HaveLen(0))
			Expect(resp.Code).To(Equal(http.StatusNotFound))
			Expect(nextCalled).To(BeFalse())
		})
	})

	Context("when a connection attempt to a backend fails", func() {
		BeforeEach(func() {
			pool := route.NewPool(1*time.Second, "")
			badEndpoint1 := route.NewEndpoint("foo", "192.0.2.1", uint16(80), "", "", nil, -1, "", models.ModificationTag{})
			badEndpoint2 := route.NewEndpoint("foo", "192.0.2.2", uint16(80), "", "", nil, -1, "", models.ModificationTag{})
			_ = pool.Put(badEndpoint1)
			_ = pool.Put(badEndpoint2)
			_ = pool.Put(testServerEndpoint)
			reg.LookupStub = func(uri route.Uri) *route.Pool {
				if uri.String() == testServerRoute {
					return pool
				}
				return nil
			}
		})
		AfterEach(func() {
			Expect(nextCalled).To(BeTrue())
		})
		It("retries the connection with other backends", func() {
			testServer.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", "/"),
					ghttp.RespondWith(200, nil),
				),
			)
			req := test_util.NewRequest("GET", testServerRoute, "/", nil)
			handler.ServeHTTP(proxyWriter, req, nextHandler)
			Expect(testServer.ReceivedRequests()).To(HaveLen(1))
		})
	})

	Context("when the backend request fails for reasons other than dial timeout", func() {
		BeforeEach(func() {
			pool := route.NewPool(1*time.Second, "")
			badEndpoint := route.NewEndpoint("foo", "non-existent.foo", uint16(80), "", "", nil, -1, "", models.ModificationTag{})
			_ = pool.Put(badEndpoint)
			reg.LookupStub = func(uri route.Uri) *route.Pool {
				if uri.String() == testServerRoute {
					return pool
				}
				return nil
			}
		})
		AfterEach(func() {
			Expect(nextCalled).To(BeFalse())
		})
		It("fails with 502 Bad Gateway", func() {
			req := test_util.NewRequest("GET", testServerRoute, "/", nil)
			handler.ServeHTTP(proxyWriter, req, nextHandler)

			Expect(testServer.ReceivedRequests()).To(BeEmpty())
			Expect(resp.Code).To(Equal(http.StatusBadGateway))
		})
	})

	Context("when all connection attempts to backends fail", func() {
		BeforeEach(func() {
			pool := route.NewPool(1*time.Second, "")
			badEndpoint := route.NewEndpoint("foo", "192.0.2.1", uint16(80), "", "", nil, -1, "", models.ModificationTag{})
			_ = pool.Put(badEndpoint)
			reg.LookupStub = func(uri route.Uri) *route.Pool {
				if uri.String() == testServerRoute {
					return pool
				}
				return nil
			}
		})
		AfterEach(func() {
			Expect(nextCalled).To(BeFalse())
		})
		It("fails with 502 Bad Gateway", func() {
			req := test_util.NewRequest("GET", testServerRoute, "/", nil)
			handler.ServeHTTP(proxyWriter, req, nextHandler)

			Expect(testServer.ReceivedRequests()).To(BeEmpty())
			Expect(resp.Code).To(Equal(http.StatusBadGateway))
		})
	})

	Context("when no endpoints are available for the route", func() {
		BeforeEach(func() {
			pool := route.NewPool(1*time.Second, "")
			reg.LookupStub = func(uri route.Uri) *route.Pool {
				if uri.String() == testServerRoute {
					return pool
				}
				return nil
			}
		})
		AfterEach(func() {
			Expect(nextCalled).To(BeFalse())
		})
		It("fails with 502 Bad Gateway", func() {
			req := test_util.NewRequest("GET", testServerRoute, "/", nil)
			handler.ServeHTTP(proxyWriter, req, nextHandler)

			Expect(testServer.ReceivedRequests()).To(BeEmpty())
			Expect(resp.Code).To(Equal(http.StatusBadGateway))
		})
	})
})
