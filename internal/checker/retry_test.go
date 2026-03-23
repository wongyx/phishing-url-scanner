package checker

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryWithBackoff_SuccessOnFirstCall(t *testing.T) {
	calls := 0
	err := retryWithBackoff(context.Background(), 3, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Errorf("retryWithBackoff() = %v; want nil", err)
	}
	if calls != 1 {
		t.Errorf("fn called %d times; want 1", calls)
	}
}

func TestRetryWithBackoff_NonRetryableErrorShortCircuits(t *testing.T) {
	calls := 0
	invalidErr := &ErrInvalidURL{URL: "http://example.com", Reason: "test"}
	err := retryWithBackoff(context.Background(), 3, func() error {
		calls++
		return invalidErr
	})
	if !errors.Is(err, invalidErr) {
		t.Errorf("retryWithBackoff() = %v; want %v", err, invalidErr)
	}
	if calls != 1 {
		t.Errorf("fn called %d times; want 1 (no retries for non-retryable error)", calls)
	}
}

func TestRetryWithBackoff_ContextAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling

	calls := 0
	err := retryWithBackoff(ctx, 3, func() error {
		calls++
		return errors.New("transient error")
	})
	if err == nil {
		t.Error("retryWithBackoff() = nil; want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("retryWithBackoff() = %v; want context.Canceled", err)
	}
}

func TestRetryWithBackoff_ContextCancelledDuringSleep(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Always return a transient error so the function will sleep between retries.
	// The context timeout will fire during the sleep.
	transientErr := &ErrAPIUnavailable{API: "test", Status: 503}
	err := retryWithBackoff(ctx, 5, func() error {
		return transientErr
	})

	if err == nil {
		t.Error("expected error due to context timeout, got nil")
	}
	// Should return either context error or the last transient error
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, transientErr) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRetryWithBackoff_MaxRetriesExhausted(t *testing.T) {
	// Use a very short context to avoid waiting on backoff sleeps
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	sentinel := errors.New("persistent error")
	err := retryWithBackoff(ctx, 1, func() error {
		return sentinel
	})
	if err == nil {
		t.Error("retryWithBackoff() = nil; want error after max retries")
	}
}

func TestRetryWithBackoff_SuccessAfterTransientError(t *testing.T) {
	// The function succeeds on attempt 2. We use maxRetries=2 so only one
	// backoff sleep (between attempt 0 and 1). Override with a short context
	// that still allows the fn to succeed quickly.
	calls := 0
	err := retryWithBackoff(context.Background(), 2, func() error {
		calls++
		if calls == 1 {
			// Return ErrRateLimited with a RetryAfter of 0 so the backoff
			// delay is parsed as 0 seconds — no actual sleep.
			return &ErrRateLimited{API: "test", RetryAfter: "0"}
		}
		return nil
	})
	if err != nil {
		t.Errorf("retryWithBackoff() = %v; want nil", err)
	}
	if calls != 2 {
		t.Errorf("fn called %d times; want 2", calls)
	}
}

func TestBackoffDelay_RateLimitedWithRetryAfter(t *testing.T) {
	err := &ErrRateLimited{API: "test", RetryAfter: "5"}
	delay := backoffDelay(0, err)
	if delay != 5*time.Second {
		t.Errorf("backoffDelay() = %v; want %v", delay, 5*time.Second)
	}
}

func TestBackoffDelay_RateLimitedWithInvalidRetryAfter(t *testing.T) {
	err := &ErrRateLimited{API: "test", RetryAfter: "invalid"}
	// Falls back to exponential backoff for attempt 0: base delay = 1s
	delay := backoffDelay(0, err)
	if delay < time.Second {
		t.Errorf("backoffDelay() = %v; want >= 1s", delay)
	}
}

func TestBackoffDelay_ExponentialBackoff(t *testing.T) {
	genericErr := errors.New("generic")

	// attempt 0 → base*1 = 1s (+jitter)
	d0 := backoffDelay(0, genericErr)
	// attempt 1 → base*2 = 2s (+jitter)
	d1 := backoffDelay(1, genericErr)
	// attempt 2 → base*4 = 4s (+jitter)
	d2 := backoffDelay(2, genericErr)

	if d0 < time.Second {
		t.Errorf("attempt 0 delay = %v; want >= 1s", d0)
	}
	if d1 < 2*time.Second {
		t.Errorf("attempt 1 delay = %v; want >= 2s", d1)
	}
	if d2 < 4*time.Second {
		t.Errorf("attempt 2 delay = %v; want >= 4s", d2)
	}
}

func TestBackoffDelay_CapAtMaxDelay(t *testing.T) {
	genericErr := errors.New("generic")
	// attempt 10 would produce base*1024 >> retryMaxDelay (30s)
	delay := backoffDelay(10, genericErr)
	// Should be capped at retryMaxDelay plus up to 20% jitter
	maxExpected := retryMaxDelay + retryMaxDelay/5
	if delay > maxExpected {
		t.Errorf("backoffDelay(10) = %v; want <= %v", delay, maxExpected)
	}
}

func TestBackoffDelay_EmptyRetryAfter(t *testing.T) {
	err := &ErrRateLimited{API: "test", RetryAfter: ""}
	// Empty RetryAfter falls back to exponential backoff
	delay := backoffDelay(0, err)
	if delay < time.Second {
		t.Errorf("backoffDelay() = %v; want >= 1s", delay)
	}
}
