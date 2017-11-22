package monitor

import "time"

type NATSMonitor struct {
	Sender   Metrics.MetricSender
	TickChan chan time.Time
}

func (n *NATSMonitor) Run() error {
	for {
		select {
		case n.TickChan:
			//get the valude from nats subscriber.Pending()
			// send the valude using dropsonde value chainer Send()
			//n.Sender.Value()

		}

	}
}
