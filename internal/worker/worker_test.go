package worker

import (
    "runtime"
    "testing"
)

func TestWorkerLimit(t *testing.T) {
    original := runtime.GOMAXPROCS(0)
    t.Cleanup(func() { runtime.GOMAXPROCS(original) })

    runtime.GOMAXPROCS(4)

    if got := WorkerLimit(0); got != 1 {
        t.Fatalf("expected 1 for zero total, got %d", got)
    }
    if got := WorkerLimit(-5); got != 1 {
        t.Fatalf("expected 1 for negative total, got %d", got)
    }
    if got := WorkerLimit(2); got != 2 {
        t.Fatalf("expected 2 when total < GOMAXPROCS, got %d", got)
    }
    if got := WorkerLimit(10); got != 4 {
        t.Fatalf("expected 4 when total > GOMAXPROCS, got %d", got)
    }
}
