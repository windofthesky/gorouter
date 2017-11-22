package monitor

import (
	"os"
	"time"

	"github.com/cloudfoundry/dropsonde/metrics"
)

type NATSMonitor struct {
	Sender   metrics.MetricSender
	TickChan chan time.Time
}

func (n *NATSMonitor) Run(signals <-chan os.Signal, ready chan<- struct{}) error {
	close(ready)
	for {
		select {
		case <-n.TickChan:
			//get the valude from nats subscriber.Pending()
			// send the valude using dropsonde value chainer Send()
			pending := 1
			chainer := n.Sender.Value("buffered_messages", float64(pending), "")
			err := chainer.Send()
			if err != nil {
				panic("panic")
			}
		}
	}
}
