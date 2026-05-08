package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestMemoryRecorderSnapshotCopiesState(t *testing.T) {
	rec := NewRecorder(NopLogger())
	rec.Inc("events", map[string]string{"kind": "accepted"}, 2)
	rec.SetGauge("active", nil, 3)
	rec.ObserveDuration("run", map[string]string{"capability": "gogo"}, time.Second)
	rec.Event(context.Background(), Event{Name: "started", Labels: map[string]string{"mode": "test"}})

	snap := rec.Snapshot()
	if snap.Counters["events|kind=accepted"] != 2 {
		t.Fatalf("counter = %#v", snap.Counters)
	}
	if snap.Gauges["active"] != 3 {
		t.Fatalf("gauge = %#v", snap.Gauges)
	}
	if len(snap.Durations["run|capability=gogo"]) != 1 {
		t.Fatalf("durations = %#v", snap.Durations)
	}
	if len(snap.Events) != 1 || snap.Events[0].Labels["mode"] != "test" {
		t.Fatalf("events = %#v", snap.Events)
	}

	snap.Counters["events|kind=accepted"] = 99
	snap.Events[0].Labels["mode"] = "mutated"
	next := rec.Snapshot()
	if next.Counters["events|kind=accepted"] != 2 || next.Events[0].Labels["mode"] != "test" {
		t.Fatalf("snapshot was not isolated: %#v %#v", next.Counters, next.Events)
	}
}

func TestMetricKeySortsLabels(t *testing.T) {
	key := metricKey("metric", map[string]string{"b": "2", "a": "1"})
	if key != "metric|a=1|b=2" {
		t.Fatalf("key = %q", key)
	}
}
