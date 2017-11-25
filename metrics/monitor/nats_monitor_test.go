package monitor_test

import (
	"errors"
	"sync"
	"time"

	"code.cloudfoundry.org/gorouter/logger"
	"code.cloudfoundry.org/gorouter/metrics/fakes"
	"code.cloudfoundry.org/gorouter/metrics/monitor"
	"code.cloudfoundry.org/gorouter/test_util"
	"github.com/cloudfoundry/dropsonde/metric_sender"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var _ = FDescribe("NATSMonitor", func() {
	var (
		fakeSubscription *fakes.FakeNATSsubscription
		chainerMux       sync.Mutex
		fakeValueChainer *fakes.FakeValueChainer
		sender           *fakes.MetricSender
		ch               chan time.Time
		natsMonitor      *monitor.NATSMonitor
		lgr              logger.Logger
	)
	BeforeEach(func() {
		ch = make(chan time.Time)

		fakeSubscription = new(fakes.FakeNATSsubscription)

		sender = new(fakes.MetricSender)

		fakeValueChainer = new(fakes.FakeValueChainer)
		sender.ValueStub = func(metric string, value float64, unit string) metric_sender.ValueChainer {
			return fakeValueChainer
		}

		lgr = test_util.NewTestZapLogger("test")

		natsMonitor = &monitor.NATSMonitor{
			Subscription: fakeSubscription,
			Sender:       sender,
			TickChan:     ch,
			Logger:       lgr,
		}
	})

	It("sends a metric on a time interval", func() {

		go natsMonitor.Run()

		ch <- time.Time{}
		ch <- time.Time{}
		ch <- time.Time{}

		Expect(sender.ValueCallCount()).To(BeNumerically(">=", 2))
		name, _, unit := sender.ValueArgsForCall(0)
		Expect(name).To(Equal("buffered_messages"))
		Expect(unit).To(Equal(""))

		Expect(fakeValueChainer.SendCallCount()).To(BeNumerically(">=", 2))
	})

	It("should log an error when Send fails", func() {
		fakeValueChainer.SendStub = func() error {
			return errors.New("send failed")
		}

		go natsMonitor.Run()

		ch <- time.Time{}
		ch <- time.Time{} // an extra tick is to make sure the time ticked at least onece

		Expect(lgr).To(gbytes.Say("error-sending-nats-monitor-metric"))
	})

	It("gets the number of queued messages for a given NATS subscription", func() {
		go natsMonitor.Run()

		ch <- time.Time{}
		ch <- time.Time{}

		Expect(fakeSubscription.PendingCallCount()).To(BeNumerically(">=", 1))
	})

	It("passes a correct value for pending messages to the metric Sender", func() {
		go natsMonitor.Run()
		fakeSubscription.PendingStub = func() (int, int, error) {
			return 1000, 0, nil
		}

		ch <- time.Time{}
		ch <- time.Time{}

		Expect(sender.ValueCallCount()).To(BeNumerically(">=", 1))
		_, val, _ := sender.ValueArgsForCall(0)

		Expect(fakeSubscription.PendingCallCount()).To(BeNumerically(">=", 1))
		Expect(val).To(Equal(float64(1000)))

	})

	It("should log an error when it fails to retrieve queued messages", func() {
		go natsMonitor.Run()

		fakeSubscription.PendingStub = func() (int, int, error) {
			return 1000, 0, errors.New("failed")
		}

		ch <- time.Time{}
		ch <- time.Time{} // an extra tick is to make sure the time ticked at least onece

		Expect(lgr).To(gbytes.Say("error-retrieving-nats-subscription-pending-messages"))
	})
})
