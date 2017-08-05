package routeservice

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/uber-go/zap"

	"code.cloudfoundry.org/gorouter/common/secure"
	"code.cloudfoundry.org/gorouter/logger"
)

const (
	HeaderKeySignature    = "X-CF-Proxy-Signature"
	HeaderKeyForwardedURL = "X-CF-Forwarded-Url"
	HeaderKeyMetadata     = "X-CF-Proxy-Metadata"
)

var ErrExpired = errors.New("route service request expired")
var ErrForwardedURLMismatch = errors.New("route service forwarded url mismatch")

type RouteServiceConfig struct {
	routeServiceEnabled bool
	routeServiceTimeout time.Duration
	crypto              secure.Crypto
	cryptoPrev          secure.Crypto
	logger              logger.Logger
	recommendHttps      bool
}

type RouteServiceRequest struct {
	URLString      string
	ParsedUrl      *url.URL
	Signature      string
	Metadata       string
	ForwardedURL   string
	RecommendHttps bool
}

func NewRouteServiceConfig(
	logger logger.Logger,
	enabled bool,
	timeout time.Duration,
	crypto secure.Crypto,
	cryptoPrev secure.Crypto,
	recommendHttps bool,
) *RouteServiceConfig {
	return &RouteServiceConfig{
		routeServiceEnabled: enabled,
		routeServiceTimeout: timeout,
		crypto:              crypto,
		cryptoPrev:          cryptoPrev,
		logger:              logger,
		recommendHttps:      recommendHttps,
	}
}

func (rs *RouteServiceConfig) RouteServiceEnabled() bool {
	return rs.routeServiceEnabled
}

func (rs *RouteServiceConfig) RouteServiceRecommendHttps() bool {
	return rs.recommendHttps
}

func (rs *RouteServiceConfig) Request(rsUrl, forwardedUrl string) (RouteServiceRequest, error) {
	var routeServiceArgs RouteServiceRequest
	sig, metadata, err := rs.generateSignatureAndMetadata(forwardedUrl)
	if err != nil {
		return routeServiceArgs, err
	}

	routeServiceArgs.URLString = rsUrl
	routeServiceArgs.Signature = sig
	routeServiceArgs.Metadata = metadata
	routeServiceArgs.ForwardedURL = forwardedUrl

	rsURL, err := url.Parse(rsUrl)
	if err != nil {
		return routeServiceArgs, err
	}
	routeServiceArgs.ParsedUrl = rsURL

	return routeServiceArgs, nil
}

func (rs *RouteServiceConfig) ValidatedSignature(headers *http.Header, requestUrl string) (*Signature, error) {
	metadataHeader := headers.Get(HeaderKeyMetadata)
	signatureHeader := headers.Get(HeaderKeySignature)

	signature, err := SignatureFromHeaders(signatureHeader, metadataHeader, rs.crypto)
	if err != nil {
		if rs.cryptoPrev == nil {
			rs.logger.Error("proxy-route-service-current-key", zap.Error(err))
			return nil, err
		}

		rs.logger.Debug("proxy-route-service-current-key", zap.String("message", "Decrypt-only secret used to validate route service signature header"))
		// Decrypt the head again trying to use the old key.
		signature, err = SignatureFromHeaders(signatureHeader, metadataHeader, rs.cryptoPrev)

		if err != nil {
			rs.logger.Error("proxy-route-service-previous-key", zap.Error(err))
			return nil, err
		}
	}

	err = rs.validateSignatureTimeout(signature)
	if err != nil {
		return nil, err
	}

	return &signature, nil
}

func (rs *RouteServiceConfig) generateSignatureAndMetadata(forwardedUrlRaw string) (string, string, error) {
	decodedURL, err := url.QueryUnescape(forwardedUrlRaw)
	if err != nil {
		rs.logger.Error("proxy-route-service-invalidForwardedURL", zap.Error(err))
		return "", "", err
	}
	signature := &Signature{
		RequestedTime: time.Now(),
		ForwardedUrl:  decodedURL,
	}

	signatureHeader, metadataHeader, err := BuildSignatureAndMetadata(rs.crypto, signature)
	if err != nil {
		return "", "", err
	}
	return signatureHeader, metadataHeader, nil
}

func (rs *RouteServiceConfig) validateSignatureTimeout(signature Signature) error {
	if time.Since(signature.RequestedTime) > rs.routeServiceTimeout {
		rs.logger.Error("proxy-route-service-timeout",
			zap.Error(ErrExpired),
			zap.String("forwarded-url", signature.ForwardedUrl),
			zap.Time("request-time", signature.RequestedTime),
		)
		return ErrExpired
	}
	return nil
}

// func (rs *RouteServiceConfig) validateForwardedURL(signature Signature, requestUrlString string) error {
// 	var err error
// 	forwardedUrl, requestUrl, err := parseURLs(signature.ForwardedUrl, requestUrlString)
// 	if err != nil {
// 		rsErr := fmt.Errorf("%s: %s", RouteServiceForwardedURLMismatch, err)
// 		rs.logger.Error("proxy-route-service-forwarded-url-mismatch", zap.Error(rsErr))
// 		return err
// 	}
//
// 	if requestUrl.Host != forwardedUrl.Host {
// 		var err = RouteServiceForwardedURLMismatch
// 		rs.logger.Error("proxy-route-service-forwarded-url-mismatch", zap.Error(err),
// 			zap.String("request-url", requestUrl.String()),
// 			zap.String("forwarded-url", forwardedUrl.String()),
// 		)
// 		return err
// 	}
// 	return nil
// }
//
// func parseURLs(forwardUrlString, requestUrlString string) (forwardUrl, requestUrl *url.URL, err error) {
// 	var terr error
// 	forwardUrl, terr = url.Parse(forwardUrlString)
// 	if terr != nil {
// 		err = terr
// 	}
//
// 	requestUrl, terr = url.Parse(requestUrlString)
// 	if terr != nil {
// 		err = terr
// 	}
//
// 	return forwardUrl, requestUrl, err
// }
