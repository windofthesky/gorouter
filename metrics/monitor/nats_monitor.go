package monitor

import (
	"time"

	"code.cloudfoundry.org/gorouter/logger"
	"github.com/cloudfoundry/dropsonde/metrics"
	"github.com/uber-go/zap"
)

//go:generate counterfeiter -o ../fakes/fake_nats_subscription.go . NATSsubscription
type NATSsubscription interface {
	Pending() (int, int, error)
}

type NATSMonitor struct {
	Subscription NATSsubscription
	Sender       metrics.MetricSender
	TickChan     <-chan time.Time
	Logger       logger.Logger
}

func (n *NATSMonitor) Run() {
	for {
		select {
		case <-n.TickChan:
			queuedMsgs, _, err := n.Subscription.Pending()
			if err != nil {
				n.Logger.Error("error-retrieving-nats-subscription-pending-messages", zap.Error(err))
			}
			chainer := n.Sender.Value("buffered_messages", float64(queuedMsgs), "")
			err = chainer.Send()
			if err != nil {
				n.Logger.Error("error-sending-nats-monitor-metric", zap.Error(err))
			}
		}
	}
}
