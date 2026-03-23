package checker

import (
	"context"
	"errors"
	"math/rand"
	"strconv"
	"time"
)

const (
	retryBaseDelay = time.Second
	retryMaxDelay  = 30 * time.Second
)

// retryWithBackoff calls fn up to maxRetries times, sleeping between attempts
// using exponential backoff with jitter. It stops early if:
//   - fn returns nil (success)
//   - fn returns a non-retryable error (ErrInvalidURL)
//   - ctx is cancelled or times out
//
// ErrRateLimited and ErrAPIUnavailable are considered transient and will be retried.
// If ErrRateLimited carries a Retry-After value, that delay is used instead of backoff.
func retryWithBackoff(ctx context.Context, maxRetries int, fn func() error) error {
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}

		var invalidErr *ErrInvalidURL
		if errors.As(err, &invalidErr) {
			return err
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if attempt == maxRetries-1 {
			break
		}

		select {
		case <-time.After(backoffDelay(attempt, err)):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// backoffDelay returns the duration to wait before the next attempt.
// If the error is an ErrRateLimited with a parseable Retry-After header value,
// that value takes precedence. Otherwise exponential backoff with up to 20% jitter.
func backoffDelay(attempt int, err error) time.Duration {
	var rateLimitErr *ErrRateLimited
	if errors.As(err, &rateLimitErr) && rateLimitErr.RetryAfter != "" {
		if secs, parseErr := strconv.Atoi(rateLimitErr.RetryAfter); parseErr == nil {
			return time.Duration(secs) * time.Second
		}
	}

	delay := retryBaseDelay * (1 << attempt)
	if delay > retryMaxDelay {
		delay = retryMaxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(delay / 5)))
	return delay + jitter
}
