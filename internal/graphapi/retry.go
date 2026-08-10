package graphapi

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

const (
	// maxRetries bounds throttle retries per request. Graph's own guidance is
	// to honour Retry-After; a bound stops a persistently throttled tenant
	// from hanging an apply indefinitely.
	maxRetries = 4

	// defaultRetryDelay applies when Retry-After is absent or unparseable.
	defaultRetryDelay = 2 * time.Second

	// maxRetryDelay caps an absurd Retry-After so one request cannot stall an
	// apply for minutes.
	maxRetryDelay = 30 * time.Second
)

// parseRetryAfter reads the delta-seconds form of Retry-After. Graph sends
// that form; the HTTP-date form is not handled and falls back to the default.
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return defaultRetryDelay
	}
	seconds, err := strconv.Atoi(header)
	if err != nil {
		return defaultRetryDelay
	}
	if seconds < 0 {
		return 0
	}
	delay := time.Duration(seconds) * time.Second
	if delay > maxRetryDelay {
		return maxRetryDelay
	}
	return delay
}

// wait sleeps for delay unless the context ends first.
func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// throttled reports whether a status warrants a Retry-After pause.
func throttled(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}
