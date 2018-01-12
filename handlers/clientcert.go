package handlers

import (
	"encoding/pem"
	"net/http"
	"strings"

	"code.cloudfoundry.org/gorouter/config"

	"github.com/urfave/negroni"
)

const xfcc = "X-Forwarded-Client-Cert"

type clientCert struct {
	forwardingMode string
	// not sure what type this should actually be
	gorouterToken string
}

func NewClientCert(forwardingMode, gorouterToken string) negroni.Handler {
	return &clientCert{
		forwardingMode: forwardingMode,
		gorouterToken:  gorouterToken,
	}
}

func (c *clientCert) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if r.Header.Get("X-CF-Proxy-Token") == c.gorouterToken {
		// the desired XFCC behavior has already happened,
		// so we should just forward the existing header
		next(rw, r)
	}

	if c.forwardingMode == config.FORWARD {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			r.Header.Del(xfcc)
		}
	}

	if c.forwardingMode == config.SANITIZE_SET {
		r.Header.Del(xfcc)
		if r.TLS != nil {
			sanitizeHeader(r)
		}
	}
	next(rw, r)
}

func sanitizeHeader(r *http.Request) {
	// we only care about the first cert at this moment
	if len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		b := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		certPEM := pem.EncodeToMemory(&b)
		r.Header.Add(xfcc, sanitize(certPEM))
	}
}

func sanitize(cert []byte) string {
	s := string(cert)
	r := strings.NewReplacer("-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "")
	return r.Replace(s)
}
