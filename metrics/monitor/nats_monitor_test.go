package monitor_test

import (
	"time"

	"code.cloudfoundry.org/gorouter/metrics/fakes"
	"code.cloudfoundry.org/gorouter/metrics/monitor"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NATSMonitor", func() {
	var (
		sender *fakes.MetricSender
	)

	It("sends a metric on a time interval", func() {
		ch := make(chan time.Time)

		sender := new(fakes.MetricSender)

		natsMonitor := monitor.NATSMonitor{
			Sender:   sender,
			TickChan: ch,
		}

		Expect(natsMonitor.Run()).To(Succeed())
		Expect(sender.ValueCallCount()).To(Equal(1))
		name, _, unit := sender.ValueArgsForCall()
		Expect(name).To(Equal("buffered_messages"))
		Expect(unit).To(Equal(""))
	})
})
