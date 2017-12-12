// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"
	"time"

	"code.cloudfoundry.org/gorouter/metrics"
)

type FakeRouteRegistryReporter struct {
	CaptureRouteStatsStub        func(totalRoutes int, msSinceLastUpdate uint64)
	captureRouteStatsMutex       sync.RWMutex
	captureRouteStatsArgsForCall []struct {
		totalRoutes       int
		msSinceLastUpdate uint64
	}
	CaptureRoutesPrunedStub        func(prunedRoutes uint64)
	captureRoutesPrunedMutex       sync.RWMutex
	captureRoutesPrunedArgsForCall []struct {
		prunedRoutes uint64
	}
	CaptureLookupTimeStub        func(t time.Duration)
	captureLookupTimeMutex       sync.RWMutex
	captureLookupTimeArgsForCall []struct {
		t time.Duration
	}
	CaptureRegistryMessageStub        func(msg metrics.ComponentTagged)
	captureRegistryMessageMutex       sync.RWMutex
	captureRegistryMessageArgsForCall []struct {
		msg metrics.ComponentTagged
	}
	CaptureRouteRegistrationLatencyStub        func(t time.Duration)
	captureRouteRegistrationLatencyMutex       sync.RWMutex
	captureRouteRegistrationLatencyArgsForCall []struct {
		t time.Duration
	}
	MuzzleRouteRegistrationLatencyStub          func()
	muzzleRouteRegistrationLatencyMutex         sync.RWMutex
	muzzleRouteRegistrationLatencyArgsForCall   []struct{}
	UnmuzzleRouteRegistrationLatencyStub        func()
	unmuzzleRouteRegistrationLatencyMutex       sync.RWMutex
	unmuzzleRouteRegistrationLatencyArgsForCall []struct{}
	CaptureUnregistryMessageStub                func(msg metrics.ComponentTagged)
	captureUnregistryMessageMutex               sync.RWMutex
	captureUnregistryMessageArgsForCall         []struct {
		msg metrics.ComponentTagged
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeRouteRegistryReporter) CaptureRouteStats(totalRoutes int, msSinceLastUpdate uint64) {
	fake.captureRouteStatsMutex.Lock()
	fake.captureRouteStatsArgsForCall = append(fake.captureRouteStatsArgsForCall, struct {
		totalRoutes       int
		msSinceLastUpdate uint64
	}{totalRoutes, msSinceLastUpdate})
	fake.recordInvocation("CaptureRouteStats", []interface{}{totalRoutes, msSinceLastUpdate})
	fake.captureRouteStatsMutex.Unlock()
	if fake.CaptureRouteStatsStub != nil {
		fake.CaptureRouteStatsStub(totalRoutes, msSinceLastUpdate)
	}
}

func (fake *FakeRouteRegistryReporter) CaptureRouteStatsCallCount() int {
	fake.captureRouteStatsMutex.RLock()
	defer fake.captureRouteStatsMutex.RUnlock()
	return len(fake.captureRouteStatsArgsForCall)
}

func (fake *FakeRouteRegistryReporter) CaptureRouteStatsArgsForCall(i int) (int, uint64) {
	fake.captureRouteStatsMutex.RLock()
	defer fake.captureRouteStatsMutex.RUnlock()
	return fake.captureRouteStatsArgsForCall[i].totalRoutes, fake.captureRouteStatsArgsForCall[i].msSinceLastUpdate
}

func (fake *FakeRouteRegistryReporter) CaptureRoutesPruned(prunedRoutes uint64) {
	fake.captureRoutesPrunedMutex.Lock()
	fake.captureRoutesPrunedArgsForCall = append(fake.captureRoutesPrunedArgsForCall, struct {
		prunedRoutes uint64
	}{prunedRoutes})
	fake.recordInvocation("CaptureRoutesPruned", []interface{}{prunedRoutes})
	fake.captureRoutesPrunedMutex.Unlock()
	if fake.CaptureRoutesPrunedStub != nil {
		fake.CaptureRoutesPrunedStub(prunedRoutes)
	}
}

func (fake *FakeRouteRegistryReporter) CaptureRoutesPrunedCallCount() int {
	fake.captureRoutesPrunedMutex.RLock()
	defer fake.captureRoutesPrunedMutex.RUnlock()
	return len(fake.captureRoutesPrunedArgsForCall)
}

func (fake *FakeRouteRegistryReporter) CaptureRoutesPrunedArgsForCall(i int) uint64 {
	fake.captureRoutesPrunedMutex.RLock()
	defer fake.captureRoutesPrunedMutex.RUnlock()
	return fake.captureRoutesPrunedArgsForCall[i].prunedRoutes
}

func (fake *FakeRouteRegistryReporter) CaptureLookupTime(t time.Duration) {
	fake.captureLookupTimeMutex.Lock()
	fake.captureLookupTimeArgsForCall = append(fake.captureLookupTimeArgsForCall, struct {
		t time.Duration
	}{t})
	fake.recordInvocation("CaptureLookupTime", []interface{}{t})
	fake.captureLookupTimeMutex.Unlock()
	if fake.CaptureLookupTimeStub != nil {
		fake.CaptureLookupTimeStub(t)
	}
}

func (fake *FakeRouteRegistryReporter) CaptureLookupTimeCallCount() int {
	fake.captureLookupTimeMutex.RLock()
	defer fake.captureLookupTimeMutex.RUnlock()
	return len(fake.captureLookupTimeArgsForCall)
}

func (fake *FakeRouteRegistryReporter) CaptureLookupTimeArgsForCall(i int) time.Duration {
	fake.captureLookupTimeMutex.RLock()
	defer fake.captureLookupTimeMutex.RUnlock()
	return fake.captureLookupTimeArgsForCall[i].t
}

func (fake *FakeRouteRegistryReporter) CaptureRegistryMessage(msg metrics.ComponentTagged) {
	fake.captureRegistryMessageMutex.Lock()
	fake.captureRegistryMessageArgsForCall = append(fake.captureRegistryMessageArgsForCall, struct {
		msg metrics.ComponentTagged
	}{msg})
	fake.recordInvocation("CaptureRegistryMessage", []interface{}{msg})
	fake.captureRegistryMessageMutex.Unlock()
	if fake.CaptureRegistryMessageStub != nil {
		fake.CaptureRegistryMessageStub(msg)
	}
}

func (fake *FakeRouteRegistryReporter) CaptureRegistryMessageCallCount() int {
	fake.captureRegistryMessageMutex.RLock()
	defer fake.captureRegistryMessageMutex.RUnlock()
	return len(fake.captureRegistryMessageArgsForCall)
}

func (fake *FakeRouteRegistryReporter) CaptureRegistryMessageArgsForCall(i int) metrics.ComponentTagged {
	fake.captureRegistryMessageMutex.RLock()
	defer fake.captureRegistryMessageMutex.RUnlock()
	return fake.captureRegistryMessageArgsForCall[i].msg
}

func (fake *FakeRouteRegistryReporter) CaptureRouteRegistrationLatency(t time.Duration) {
	fake.captureRouteRegistrationLatencyMutex.Lock()
	fake.captureRouteRegistrationLatencyArgsForCall = append(fake.captureRouteRegistrationLatencyArgsForCall, struct {
		t time.Duration
	}{t})
	fake.recordInvocation("CaptureRouteRegistrationLatency", []interface{}{t})
	fake.captureRouteRegistrationLatencyMutex.Unlock()
	if fake.CaptureRouteRegistrationLatencyStub != nil {
		fake.CaptureRouteRegistrationLatencyStub(t)
	}
}

func (fake *FakeRouteRegistryReporter) CaptureRouteRegistrationLatencyCallCount() int {
	fake.captureRouteRegistrationLatencyMutex.RLock()
	defer fake.captureRouteRegistrationLatencyMutex.RUnlock()
	return len(fake.captureRouteRegistrationLatencyArgsForCall)
}

func (fake *FakeRouteRegistryReporter) CaptureRouteRegistrationLatencyArgsForCall(i int) time.Duration {
	fake.captureRouteRegistrationLatencyMutex.RLock()
	defer fake.captureRouteRegistrationLatencyMutex.RUnlock()
	return fake.captureRouteRegistrationLatencyArgsForCall[i].t
}

func (fake *FakeRouteRegistryReporter) MuzzleRouteRegistrationLatency() {
	fake.muzzleRouteRegistrationLatencyMutex.Lock()
	fake.muzzleRouteRegistrationLatencyArgsForCall = append(fake.muzzleRouteRegistrationLatencyArgsForCall, struct{}{})
	fake.recordInvocation("MuzzleRouteRegistrationLatency", []interface{}{})
	fake.muzzleRouteRegistrationLatencyMutex.Unlock()
	if fake.MuzzleRouteRegistrationLatencyStub != nil {
		fake.MuzzleRouteRegistrationLatencyStub()
	}
}

func (fake *FakeRouteRegistryReporter) MuzzleRouteRegistrationLatencyCallCount() int {
	fake.muzzleRouteRegistrationLatencyMutex.RLock()
	defer fake.muzzleRouteRegistrationLatencyMutex.RUnlock()
	return len(fake.muzzleRouteRegistrationLatencyArgsForCall)
}

func (fake *FakeRouteRegistryReporter) UnmuzzleRouteRegistrationLatency() {
	fake.unmuzzleRouteRegistrationLatencyMutex.Lock()
	fake.unmuzzleRouteRegistrationLatencyArgsForCall = append(fake.unmuzzleRouteRegistrationLatencyArgsForCall, struct{}{})
	fake.recordInvocation("UnmuzzleRouteRegistrationLatency", []interface{}{})
	fake.unmuzzleRouteRegistrationLatencyMutex.Unlock()
	if fake.UnmuzzleRouteRegistrationLatencyStub != nil {
		fake.UnmuzzleRouteRegistrationLatencyStub()
	}
}

func (fake *FakeRouteRegistryReporter) UnmuzzleRouteRegistrationLatencyCallCount() int {
	fake.unmuzzleRouteRegistrationLatencyMutex.RLock()
	defer fake.unmuzzleRouteRegistrationLatencyMutex.RUnlock()
	return len(fake.unmuzzleRouteRegistrationLatencyArgsForCall)
}

func (fake *FakeRouteRegistryReporter) CaptureUnregistryMessage(msg metrics.ComponentTagged) {
	fake.captureUnregistryMessageMutex.Lock()
	fake.captureUnregistryMessageArgsForCall = append(fake.captureUnregistryMessageArgsForCall, struct {
		msg metrics.ComponentTagged
	}{msg})
	fake.recordInvocation("CaptureUnregistryMessage", []interface{}{msg})
	fake.captureUnregistryMessageMutex.Unlock()
	if fake.CaptureUnregistryMessageStub != nil {
		fake.CaptureUnregistryMessageStub(msg)
	}
}

func (fake *FakeRouteRegistryReporter) CaptureUnregistryMessageCallCount() int {
	fake.captureUnregistryMessageMutex.RLock()
	defer fake.captureUnregistryMessageMutex.RUnlock()
	return len(fake.captureUnregistryMessageArgsForCall)
}

func (fake *FakeRouteRegistryReporter) CaptureUnregistryMessageArgsForCall(i int) metrics.ComponentTagged {
	fake.captureUnregistryMessageMutex.RLock()
	defer fake.captureUnregistryMessageMutex.RUnlock()
	return fake.captureUnregistryMessageArgsForCall[i].msg
}

func (fake *FakeRouteRegistryReporter) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.captureRouteStatsMutex.RLock()
	defer fake.captureRouteStatsMutex.RUnlock()
	fake.captureRoutesPrunedMutex.RLock()
	defer fake.captureRoutesPrunedMutex.RUnlock()
	fake.captureLookupTimeMutex.RLock()
	defer fake.captureLookupTimeMutex.RUnlock()
	fake.captureRegistryMessageMutex.RLock()
	defer fake.captureRegistryMessageMutex.RUnlock()
	fake.captureRouteRegistrationLatencyMutex.RLock()
	defer fake.captureRouteRegistrationLatencyMutex.RUnlock()
	fake.muzzleRouteRegistrationLatencyMutex.RLock()
	defer fake.muzzleRouteRegistrationLatencyMutex.RUnlock()
	fake.unmuzzleRouteRegistrationLatencyMutex.RLock()
	defer fake.unmuzzleRouteRegistrationLatencyMutex.RUnlock()
	fake.captureUnregistryMessageMutex.RLock()
	defer fake.captureUnregistryMessageMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeRouteRegistryReporter) recordInvocation(key string, args []interface{}) {
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

var _ metrics.RouteRegistryReporter = new(FakeRouteRegistryReporter)
