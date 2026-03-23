package checker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSafeBrowsingClient_Check_NoHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and content type
		if r.Method != http.MethodPost {
			t.Errorf("method = %s; want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %s; want application/json", r.Header.Get("Content-Type"))
		}

		// Empty matches = no hit
		resp := SafeBrowsingResponse{Matches: nil}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &SafeBrowsingClient{
		apiKey:     "test-key",
		httpClient: redirectHTTPClient(srv),
	}

	result, err := client.Check(context.Background(), "http://example.com")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result == nil {
		t.Fatal("Check() returned nil result")
	}
	if result.SafeBrowsingHit == nil {
		t.Fatal("SafeBrowsingHit is nil")
	}
	if *result.SafeBrowsingHit {
		t.Error("SafeBrowsingHit = true; want false for clean URL")
	}
	if len(result.ThreatTypes) != 0 {
		t.Errorf("ThreatTypes = %v; want empty", result.ThreatTypes)
	}
}

func TestSafeBrowsingClient_Check_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := SafeBrowsingResponse{
			Matches: []ThreatMatch{
				{ThreatType: "MALWARE"},
				{ThreatType: "SOCIAL_ENGINEERING"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &SafeBrowsingClient{
		apiKey:     "test-key",
		httpClient: redirectHTTPClient(srv),
	}

	result, err := client.Check(context.Background(), "http://phishing.example.com")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result.SafeBrowsingHit == nil || !*result.SafeBrowsingHit {
		t.Error("SafeBrowsingHit = false; want true")
	}
	if len(result.ThreatTypes) != 2 {
		t.Errorf("ThreatTypes length = %d; want 2", len(result.ThreatTypes))
	}
	if result.ThreatTypes[0] != "MALWARE" {
		t.Errorf("ThreatTypes[0] = %q; want %q", result.ThreatTypes[0], "MALWARE")
	}
	if result.ThreatTypes[1] != "SOCIAL_ENGINEERING" {
		t.Errorf("ThreatTypes[1] = %q; want %q", result.ThreatTypes[1], "SOCIAL_ENGINEERING")
	}
}

func TestSafeBrowsingClient_Check_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := &SafeBrowsingClient{
		apiKey:     "test-key",
		httpClient: redirectHTTPClient(srv),
	}

	_, err := client.Check(context.Background(), "http://example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var rateLimitErr *ErrRateLimited
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("expected *ErrRateLimited, got %T: %v", err, err)
	}
	if rateLimitErr.API != "safebrowsing" {
		t.Errorf("API = %q; want %q", rateLimitErr.API, "safebrowsing")
	}
	if rateLimitErr.RetryAfter != "60" {
		t.Errorf("RetryAfter = %q; want %q", rateLimitErr.RetryAfter, "60")
	}
}

func TestSafeBrowsingClient_Check_APIUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"internal server error", http.StatusInternalServerError},
		{"bad gateway", http.StatusBadGateway},
		{"forbidden", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			client := &SafeBrowsingClient{
				apiKey:     "test-key",
				httpClient: redirectHTTPClient(srv),
			}

			_, err := client.Check(context.Background(), "http://example.com")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var apiErr *ErrAPIUnavailable
			if !errors.As(err, &apiErr) {
				t.Errorf("expected *ErrAPIUnavailable, got %T: %v", err, err)
			}
			if apiErr.Status != tt.status {
				t.Errorf("Status = %d; want %d", apiErr.Status, tt.status)
			}
		})
	}
}

func TestSafeBrowsingClient_Check_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer srv.Close()

	client := &SafeBrowsingClient{
		apiKey:     "test-key",
		httpClient: redirectHTTPClient(srv),
	}

	_, err := client.Check(context.Background(), "http://example.com")
	if err == nil {
		t.Error("expected error for invalid JSON response, got nil")
	}
}

func TestSafeBrowsingClient_Check_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow response
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := &SafeBrowsingClient{
		apiKey:     "test-key",
		httpClient: srv.Client(),
	}

	_, err := client.Check(ctx, "http://example.com")
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}
