package networking_policy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"code.cloudfoundry.org/gorouter/logger"

	"github.com/uber-go/zap"

	"code.cloudfoundry.org/gorouter/config"
	"code.cloudfoundry.org/lager"

	"code.cloudfoundry.org/go-db-helpers/json_client"
	"code.cloudfoundry.org/go-db-helpers/mutualtls"
)

type Source struct {
	ID  string `json:"id"`
	Tag string `json:"tag,omitempty"`
}

type Destination struct {
	ID       string `json:"id"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}
type Policy struct {
	Source      Source      `json:"source"`
	Destination Destination `json:"destination"`
}

var policies struct {
	Policies []Policy `json:"policies"`
}

type PolicyClientConfig struct {
	networkPolicyServerConfig config.NetworkPolicyServerConfig
	// using lager just for policy client
	Logger    lager.Logger
	tlsConfig *tls.Config
	// use zlogger for all error and info logging
	zlogger logger.Logger
}

func NewPolicyClientConfig(networkPolicyServer config.NetworkPolicyServerConfig, zlogger logger.Logger) *PolicyClientConfig {
	policyClientLogger := lager.NewLogger("network-policy-client")
	policyClientLogger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.INFO))

	if (networkPolicyServer.ClientCertFile != "") &&
		networkPolicyServer.ClientKeyFile != "" && networkPolicyServer.ServerCACertFile != "" {

		clientTLSConfig, err := mutualtls.NewClientTLSConfig(
			networkPolicyServer.ClientCertFile,
			networkPolicyServer.ClientKeyFile,
			networkPolicyServer.ServerCACertFile,
		)
		if err != nil {
			zlogger.Fatal("failed-to-configure-mutual-tls", zap.Error(err))
		}
		return &PolicyClientConfig{
			tlsConfig: clientTLSConfig,
			Logger:    policyClientLogger,
			networkPolicyServerConfig: networkPolicyServer,
			zlogger:                   zlogger,
		}
	}
	return nil
}

type PolicyReg struct {
	Id   string
	Port int
}

type Tag struct {
	Tag string
}

func (p *PolicyClientConfig) Register(appId, port string) (string, error) {
	networkPolicyHTTPClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: p.tlsConfig,
		},
		Timeout: time.Duration(5) * time.Second,
	}
	policyClient := json_client.New(
		p.Logger,
		networkPolicyHTTPClient,
		fmt.Sprintf("https://%s:%d", p.networkPolicyServerConfig.Host, p.networkPolicyServerConfig.Port),
	)
	portInt, err := strconv.Atoi(port)
	if err != nil {
		p.zlogger.Error("error parsing port in Register", zap.Error(err))
	}
	policyRegistered := PolicyReg{Id: appId, Port: portInt}
	var tag Tag
	err = policyClient.Do("POST", "/networking/v0/internal/create-self-policy", policyRegistered, &tag, "")
	if err != nil {
		p.zlogger.Error("policy-client-error", zap.Error(err), zap.Object("data", policyRegistered))
		return "", err
	}
	p.zlogger.Info("created-tag", zap.Object("tag", tag))
	return tag.Tag, nil
}

// Runs the ifrit process
func (p *PolicyClientConfig) Run(signals <-chan os.Signal, ready chan<- struct{}) error {
	ticker := time.NewTicker(time.Millisecond * 500)

	networkPolicyHTTPClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: p.tlsConfig,
		},
		Timeout: time.Duration(5) * time.Second,
	}
	policyClient := json_client.New(
		p.Logger,
		networkPolicyHTTPClient,
		fmt.Sprintf("https://%s:%d", p.networkPolicyServerConfig.Host, p.networkPolicyServerConfig.Port),
	)
	close(ready)
	var err error
	for {
		select {
		case <-ticker.C:
			err = policyClient.Do("GET", "/networking/v0/internal/policies", nil, &policies, "")
			if err != nil {
				p.zlogger.Fatal("policy-client-error", zap.Error(err))
			}
			p.zlogger.Info("got-polices", zap.Object("policies", policies))
		case <-signals:
			return nil
		}
	}
}
