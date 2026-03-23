package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExtractRegistrationDate(t *testing.T) {
	tests := []struct {
		name    string
		events  []rdapEvent
		want    time.Time
		wantErr bool
	}{
		{
			name: "finds registration event",
			events: []rdapEvent{
				{Action: "expiration", Date: "2030-01-01T00:00:00Z"},
				{Action: "registration", Date: "2020-06-15T12:00:00Z"},
			},
			want: time.Date(2020, 6, 15, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "registration is first event",
			events: []rdapEvent{
				{Action: "registration", Date: "2019-03-01T00:00:00Z"},
			},
			want: time.Date(2019, 3, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:    "no registration event",
			events:  []rdapEvent{{Action: "expiration", Date: "2030-01-01T00:00:00Z"}},
			wantErr: true,
		},
		{
			name:    "empty events",
			events:  []rdapEvent{},
			wantErr: true,
		},
		{
			name: "invalid date format",
			events: []rdapEvent{
				{Action: "registration", Date: "not-a-date"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractRegistrationDate(tt.events)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("extractRegistrationDate() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestWHOISClient_Check_Success(t *testing.T) {
	// Domain registered 60 days ago — should not be flagged
	registeredAt := time.Now().UTC().Add(-60 * 24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := rdapResponse{
			Events: []rdapEvent{
				{Action: "registration", Date: registeredAt.Format(time.RFC3339)},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Point the client at the test server by patching the base URL via a
	// custom RoundTripper that rewrites the host.
	client := &WHOISClient{httpClient: redirectHTTPClient(srv)}

	result, err := client.Check(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if result == nil {
		t.Fatal("Check() returned nil result")
	}
	if result.AgeDays == nil {
		t.Fatal("AgeDays is nil")
	}
	if *result.AgeDays < 59 || *result.AgeDays > 61 {
		t.Errorf("AgeDays = %d; want ~60", *result.AgeDays)
	}
	if result.AgeFlag {
		t.Error("AgeFlag = true; want false for 60-day-old domain")
	}
	if result.CreatedAt == nil {
		t.Error("CreatedAt is nil")
	}
}

func TestWHOISClient_Check_YoungDomainFlag(t *testing.T) {
	// Domain registered 10 days ago — should be flagged
	registeredAt := time.Now().UTC().Add(-10 * 24 * time.Hour)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := rdapResponse{
			Events: []rdapEvent{
				{Action: "registration", Date: registeredAt.Format(time.RFC3339)},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &WHOISClient{httpClient: redirectHTTPClient(srv)}

	result, err := client.Check(context.Background(), "newdomain.com")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.AgeFlag {
		t.Errorf("AgeFlag = false; want true for %d-day-old domain", *result.AgeDays)
	}
}

func TestWHOISClient_Check_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := &WHOISClient{httpClient: redirectHTTPClient(srv)}

	_, err := client.Check(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var rateLimitErr *ErrRateLimited
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("expected *ErrRateLimited, got %T: %v", err, err)
	}
	if rateLimitErr.RetryAfter != "30" {
		t.Errorf("RetryAfter = %q; want %q", rateLimitErr.RetryAfter, "30")
	}
}

func TestWHOISClient_Check_APIUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := &WHOISClient{httpClient: redirectHTTPClient(srv)}

	_, err := client.Check(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *ErrAPIUnavailable
	if !errors.As(err, &apiErr) {
		t.Errorf("expected *ErrAPIUnavailable, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d; want %d", apiErr.Status, http.StatusServiceUnavailable)
	}
}

func TestWHOISClient_Check_NoRegistrationEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := rdapResponse{
			Events: []rdapEvent{
				{Action: "expiration", Date: "2030-01-01T00:00:00Z"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &WHOISClient{httpClient: redirectHTTPClient(srv)}

	_, err := client.Check(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error for missing registration event, got nil")
	}
}

func TestWHOISClient_Check_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "not json{{{")
	}))
	defer srv.Close()

	client := &WHOISClient{httpClient: redirectHTTPClient(srv)}

	_, err := client.Check(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// redirectHTTPClient returns an *http.Client whose transport rewrites all
// request URLs to point at the given test server, preserving path and query.
func redirectHTTPClient(srv *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &rewriteTransport{target: srv.URL, base: srv.Client().Transport},
	}
}

type rewriteTransport struct {
	target string
	base   http.RoundTripper
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = "http"
	cloned.URL.Host = rt.target[len("http://"):]
	if rt.base != nil {
		return rt.base.RoundTrip(cloned)
	}
	return http.DefaultTransport.RoundTrip(cloned)
}
