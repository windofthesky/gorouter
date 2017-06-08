package handlers

import (
	"net/http"

	"code.cloudfoundry.org/gorouter/common/uuid"
	"code.cloudfoundry.org/gorouter/logger"
	"github.com/uber-go/zap"
	"github.com/urfave/negroni"
)

const (
	VcapRequestIdHeader = "X-Vcap-Request-Id"
)

type setVcapRequestIdHeader struct {
	logger          logger.Logger
	clientKeepAlive bool
}

func NewsetVcapRequestIdHeader(logger logger.Logger, clientKeepAlive bool) negroni.Handler {
	return &setVcapRequestIdHeader{
		logger:          logger,
		clientKeepAlive: clientKeepAlive,
	}
}

func (s *setVcapRequestIdHeader) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// The X-Vcap-Request-Id must be set before the request is passed into the
	// dropsonde InstrumentedHandler

	guid, err := uuid.GenerateUUID()
	if err == nil {
		r.Header.Set(VcapRequestIdHeader, guid)
		s.logger.Debug("vcap-request-id-header-set", zap.String("VcapRequestIdHeader", guid))
	} else {
		s.logger.Error("failed-to-set-vcap-request-id-header", zap.Error(err))
	}
	s.logger.Info("in requestID with keepAlive", zap.Bool("keep-alive", s.clientKeepAlive))
	if !s.clientKeepAlive {
		s.logger.Error("setting connection closed !!!!!!!!!!!!!!!!!!!!!")
		rw.Header().Set("Connection", "close")
	}
	next(rw, r)
}
