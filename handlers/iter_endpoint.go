package handlers

import (
	"net/http"

	"code.cloudfoundry.org/gorouter/config"
)

// fetch route pool
// choose endpoint
// retry backends
//
const (
	MaxRetries = 3
)

type iterHandler struct {
	defaultLoadBalance string
}

func NewIterHandler(c *config.Config) *iterHandler {
	return &iterHandler{
		defaultLoadBalance: c.LoadBalance,
	}
}
func (i *iterHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {

	//	reqInfo, err := ContextRequestInfo(r)
	//	if err != nil {
	//		return
	//	}
	//	if reqInfo.RoutePool == nil {
	//		return
	//	}
	//
	//	if reqInfo.ProxyResponseWriter == nil {
	//		return
	//	}
	//
	//	stickyEndpointID := getStickySession(r)
	//	iter := reqInfo.RoutePool.Endpoints(i.defaultLoadBalance, stickyEndpointID)
}

//	for retry := 0; retry < MaxRetries; retry++ {
// func getStickySession(request *http.Request) string {
// 	// Try choosing a backend using sticky session
// 	if _, err := request.Cookie(StickyCookieKey); err == nil {
// 		if sticky, err := request.Cookie(VcapCookieId); err == nil {
// 			return sticky.Value
// 		}
// 	}
// 	return ""
// }
