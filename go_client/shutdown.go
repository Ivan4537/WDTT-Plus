package main

import (
	"context"
	"os"
	"time"
)

// STOP and EOF cancel ctx just like SIGTERM. Keep handling termination after
// cancellation: some Android Process implementations send SIGTERM even from
// destroyForcibly. A stuck provider read must not prevent the next generation
// from starting. Normal deferred cleanup has time to release TURN allocations;
// the deadline stays within the Android parent's graceful shutdown budget.
func runNativeShutdownGuard(ctx context.Context, cancel context.CancelFunc, signals <-chan os.Signal, exit func(int), grace time.Duration) {
	select {
	case <-signals:
		if ctx.Err() != nil {
			exit(1)
			return
		}
		cancel()
	case <-ctx.Done():
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-signals:
		exit(1)
	case <-timer.C:
		exit(0)
	}
}
