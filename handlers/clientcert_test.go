package handlers_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"

	"code.cloudfoundry.org/gorouter/handlers"
	"code.cloudfoundry.org/gorouter/test_util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/urfave/negroni"
)

var _ = Describe("Clientcert", func() {
	var (
		nextReq           *http.Request
		n                 *negroni.Negroni
		clientCertHandler negroni.Handler
		nextHandler       http.HandlerFunc
	)

	BeforeEach(func() {
		nextReq = &http.Request{}
		clientCertHandler = handlers.NewClientCert()
		n = negroni.New()
		n.Use(clientCertHandler)
		nextHandler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			nextReq = r
		})
		n.UseHandlerFunc(nextHandler)

	})

	Context("when there is no tls connection", func() {
		var req *http.Request
		BeforeEach(func() {
			req = test_util.NewRequest("GET", "xyz.com", "", nil)
			req.Header.Add("X-Forwarded-Client-Cert", "fake-cert")
			req.Header.Add("X-Forwarded-Client-Cert", "other-fake-cert")
		})

		It("strips any xfcc headers in the request", func() {
			rw := httptest.NewRecorder()
			clientCertHandler.ServeHTTP(rw, req, nextHandler)
			Expect(nextReq.Header["X-Forwarded-Client-Cert"]).To(BeEmpty())
		})
	})

	Context("when there is a tls connection with no client certs", func() {
		var (
			tlsConfig  *tls.Config
			httpClient *http.Client
		)
		BeforeEach(func() {
			httpClient = &http.Client{}
		})

		It("strips the xfcc headers from the request", func() {

			tlsCert1 := test_util.CreateCert("client_cert.com")

			servertlsConfig := &tls.Config{
				Certificates: []tls.Certificate{tlsCert1},
			}
			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
			}

			server := httptest.NewUnstartedServer(n)
			server.TLS = servertlsConfig

			server.StartTLS()
			defer server.Close()

			transport := &http.Transport{
				TLSClientConfig: tlsConfig,
			}

			req, err := http.NewRequest("GET", server.URL, nil)
			Expect(err).NotTo(HaveOccurred())

			// set original req x-for-cert
			req.Header.Add("X-Forwarded-Client-Cert", "fake-cert")
			req.Header.Add("X-Forwarded-Client-Cert", "fake-cert2")

			client := &http.Client{Transport: transport}
			_, err = client.Do(req)
			Expect(err).ToNot(HaveOccurred())

			headerCerts := nextReq.Header["X-Forwarded-Client-Cert"]
			Expect(headerCerts).To(BeEmpty())

		})
	})

	Context("when there is a mtls connection with client certs", func() {
		var (
			tlsConfig  *tls.Config
			httpClient *http.Client
		)
		BeforeEach(func() {
			httpClient = &http.Client{}
		})

		It("sanitizes the xfcc headers from the request", func() {
			privKey, certDER := test_util.CreateCertDER("client_cert1.com")

			key, cert := test_util.CreateKeyPairFromDER(certDER, privKey)

			tlsCert, err := tls.X509KeyPair(cert, key)
			Expect(err).ToNot(HaveOccurred())

			c1, err := x509.ParseCertificate(certDER)
			Expect(err).ToNot(HaveOccurred())

			certPool := x509.NewCertPool()
			certPool.AddCert(c1)

			servertlsConfig := &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				ClientCAs:    certPool,
				ClientAuth:   tls.RequestClientCert,
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				RootCAs:      certPool,
			}

			server := httptest.NewUnstartedServer(n)
			server.TLS = servertlsConfig

			server.StartTLS()
			defer server.Close()

			transport := &http.Transport{
				TLSClientConfig: tlsConfig,
			}

			req, err := http.NewRequest("GET", server.URL, nil)
			Expect(err).NotTo(HaveOccurred())

			// set original req x-for-cert
			req.Header.Add("X-Forwarded-Client-Cert", "fake-cert")
			req.Header.Add("X-Forwarded-Client-Cert", "fake-cert2")

			client := &http.Client{Transport: transport}
			_, err = client.Do(req)
			Expect(err).ToNot(HaveOccurred())

			headerCerts := nextReq.Header["X-Forwarded-Client-Cert"]
			Expect(headerCerts).To(ConsistOf(encodeBase64(c1.Raw)))

		})
	})

	Context("when sanitizing header", func() {
		It("adds the client cert chain", func() {
			certChain := test_util.CreateSignedCertWithRootCA("foo")

			leaf, err := x509.ParseCertificate(certChain.CertDER)
			Expect(err).ToNot(HaveOccurred())
			rootCA, err := x509.ParseCertificate(certChain.CACertDER)
			Expect(err).ToNot(HaveOccurred())

			req := &http.Request{
				TLS: &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{
						leaf, rootCA,
					},
				},
				Header: make(http.Header),
			}
			rw := httptest.NewRecorder()
			clientCertHandler.ServeHTTP(rw, req, nextHandler)
			headerCerts := nextReq.Header["X-Forwarded-Client-Cert"]
			Expect(headerCerts).To(ConsistOf(encodeBase64(leaf.Raw), encodeBase64(rootCA.Raw)))
		})

		It("respects the order of certificate chain", func() {
			certChain := test_util.CreateSignedCertWithRootCA("foo")

			leaf, err := x509.ParseCertificate(certChain.CertDER)
			Expect(err).ToNot(HaveOccurred())
			rootCA, err := x509.ParseCertificate(certChain.CACertDER)
			Expect(err).ToNot(HaveOccurred())

			req := &http.Request{
				TLS: &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{
						leaf, rootCA,
					},
				},
				Header: make(http.Header),
			}
			rw := httptest.NewRecorder()
			clientCertHandler.ServeHTTP(rw, req, nextHandler)
			headerCerts := nextReq.Header["X-Forwarded-Client-Cert"]
			Expect(headerCerts[0]).To(Equal(encodeBase64(leaf.Raw)))
			Expect(headerCerts[1]).To(Equal(encodeBase64(rootCA.Raw)))
		})
	})

})

func encodeBase64(cert []byte) string {
	s := string(cert)
	r := strings.NewReplacer("-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "")
	s = r.Replace(s)
	return base64.StdEncoding.EncodeToString([]byte(s))
}
