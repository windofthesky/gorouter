package monitor_test

import (
	"errors"
	"time"

	"code.cloudfoundry.org/gorouter/metrics/fakes"
	"code.cloudfoundry.org/gorouter/metrics/monitor"
	"github.com/cloudfoundry/dropsonde/metric_sender"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tedsuo/ifrit"
)

type FakeValueChainer struct {
	SendCall struct {
		CallCount int
		Returns   struct {
			Error error
		}
	}
}

func (v *FakeValueChainer) Send() error {
	v.SendCall.CallCount++
	return v.SendCall.Returns.Error
}

func (v *FakeValueChainer) SetTag(key, value string) metric_sender.ValueChainer {
	return nil
}

var _ = Describe("NATSMonitor", func() {
	var (
		sender           *fakes.MetricSender
		ch               chan time.Time
		fakeValueChainer *FakeValueChainer
		natsMonitor      *monitor.NATSMonitor
	)
	BeforeEach(func() {
		ch = make(chan time.Time)

		sender = new(fakes.MetricSender)
		fakeValueChainer = &FakeValueChainer{}

		sender.ValueStub = func(metric string, value float64, unit string) metric_sender.ValueChainer {
			return fakeValueChainer
		}
		natsMonitor = &monitor.NATSMonitor{
			Sender:   sender,
			TickChan: ch,
		}
	})

	FIt("sends a metric on a time interval", func() {
		process := ifrit.Invoke(natsMonitor)
		Eventually(process.Ready()).Should(BeClosed())

		ch <- time.Time{}
		ch <- time.Time{}

		Eventually(sender.ValueCallCount()).Should(BeNumerically(">", 0))
		name, _, unit := sender.ValueArgsForCall(0)
		Expect(name).To(Equal("buffered_messages"))
		Expect(unit).To(Equal(""))
		Expect(fakeValueChainer.SendCall.CallCount).To(BeNumerically(">", 0))
	})

	It("should log an error when Send fails", func() {
		fakeValueChainer.SendCall.Returns.Error = errors.New("send failed")
		process := ifrit.Invoke(natsMonitor)
		Eventually(process.Ready()).Should(BeClosed())
		ch <- time.Time{}
		ch <- time.Time{}

		Eventually(sender.ValueCallCount()).Should(BeNumerically(">", 0))
	})
})
