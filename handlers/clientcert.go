package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/urfave/negroni"
)

const xfcc = "X-Forwarded-Client-Cert"

type clientCert struct{}

func NewClientCert() negroni.Handler {
	return &clientCert{}
}

func (c *clientCert) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	r.Header.Del(xfcc)
	if r.TLS != nil {
		sanitizeHeader(r)
	}
	next(rw, r)
}

func sanitizeHeader(r *http.Request) {
	for _, cert := range r.TLS.PeerCertificates {
		r.Header.Add(xfcc, sanitize(cert.Raw))
	}
}

func sanitize(cert []byte) string {
	s := string(cert)
	r := strings.NewReplacer("-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "")
	s = r.Replace(s)
	return base64.StdEncoding.EncodeToString([]byte(s))
}
