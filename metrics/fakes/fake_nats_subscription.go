// This file was generated by counterfeiter
package fakes

import (
	"sync"

	"code.cloudfoundry.org/gorouter/metrics/monitor"
)

type FakeNATSsubscription struct {
	PendingStub        func() (int, int, error)
	pendingMutex       sync.RWMutex
	pendingArgsForCall []struct{}
	pendingReturns     struct {
		result1 int
		result2 int
		result3 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeNATSsubscription) Pending() (int, int, error) {
	fake.pendingMutex.Lock()
	fake.pendingArgsForCall = append(fake.pendingArgsForCall, struct{}{})
	fake.recordInvocation("Pending", []interface{}{})
	fake.pendingMutex.Unlock()
	if fake.PendingStub != nil {
		return fake.PendingStub()
	}
	return fake.pendingReturns.result1, fake.pendingReturns.result2, fake.pendingReturns.result3
}

func (fake *FakeNATSsubscription) PendingCallCount() int {
	fake.pendingMutex.RLock()
	defer fake.pendingMutex.RUnlock()
	return len(fake.pendingArgsForCall)
}

func (fake *FakeNATSsubscription) PendingReturns(result1 int, result2 int, result3 error) {
	fake.PendingStub = nil
	fake.pendingReturns = struct {
		result1 int
		result2 int
		result3 error
	}{result1, result2, result3}
}

func (fake *FakeNATSsubscription) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.pendingMutex.RLock()
	defer fake.pendingMutex.RUnlock()
	return fake.invocations
}

func (fake *FakeNATSsubscription) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ monitor.NATSsubscription = new(FakeNATSsubscription)
