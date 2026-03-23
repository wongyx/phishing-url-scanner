package checker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"
)

// newTestVTClient creates a VirusTotalClient pointing at the given test server
// with rate limiting disabled so tests run immediately.
func newTestVTClient(srv *httptest.Server) *VirusTotalClient {
	return NewVirusTotalClient("test-key", redirectHTTPClient(srv), WithRateLimit(rate.Inf, 1000), WithPollInterval(0))
}

func TestVirusTotalClient_CheckExisting_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s; want GET", r.Method)
		}
		if r.Header.Get("x-apikey") != "test-key" {
			t.Errorf("x-apikey = %q; want %q", r.Header.Get("x-apikey"), "test-key")
		}
		resp := VirusTotalURLResponse{
			Data: URLData{
				Attributes: URLAttributes{
					LastAnalysisStats: Stats{Malicious: 3, Suspicious: 2},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	result, err := vt.checkExisting(context.Background(), "http://example.com")
	if err != nil {
		t.Fatalf("checkExisting() error = %v", err)
	}
	if result == nil {
		t.Fatal("checkExisting() returned nil result")
	}
	if result.VirusTotalScore == nil {
		t.Fatal("VirusTotalScore is nil")
	}
	if *result.VirusTotalScore != 5 { // 3 malicious + 2 suspicious
		t.Errorf("VirusTotalScore = %d; want 5", *result.VirusTotalScore)
	}
	if result.VirusTotalLink == nil || *result.VirusTotalLink == "" {
		t.Error("VirusTotalLink is nil or empty")
	}
}

func TestVirusTotalClient_CheckExisting_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	result, err := vt.checkExisting(context.Background(), "http://example.com")
	if err != nil {
		t.Fatalf("checkExisting() error = %v; want nil for 404", err)
	}
	if result != nil {
		t.Errorf("checkExisting() = %v; want nil for 404", result)
	}
}

func TestVirusTotalClient_CheckExisting_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	_, err := vt.checkExisting(context.Background(), "http://example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var rateLimitErr *ErrRateLimited
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("expected *ErrRateLimited, got %T: %v", err, err)
	}
	if rateLimitErr.RetryAfter != "15" {
		t.Errorf("RetryAfter = %q; want %q", rateLimitErr.RetryAfter, "15")
	}
}

func TestVirusTotalClient_CheckExisting_APIUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	_, err := vt.checkExisting(context.Background(), "http://example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var apiErr *ErrAPIUnavailable
	if !errors.As(err, &apiErr) {
		t.Errorf("expected *ErrAPIUnavailable, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d; want %d", apiErr.Status, http.StatusInternalServerError)
	}
}

func TestVirusTotalClient_SubmitScan_Success(t *testing.T) {
	const wantID = "analysis-abc123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s; want POST", r.Method)
		}
		resp := VirusTotalScanResponse{
			Data: ScanData{ID: wantID},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	id, err := vt.submitScan(context.Background(), "http://example.com")
	if err != nil {
		t.Fatalf("submitScan() error = %v", err)
	}
	if id != wantID {
		t.Errorf("submitScan() id = %q; want %q", id, wantID)
	}
}

func TestVirusTotalClient_SubmitScan_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	_, err := vt.submitScan(context.Background(), "http://example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var rateLimitErr *ErrRateLimited
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("expected *ErrRateLimited, got %T: %v", err, err)
	}
}

func TestVirusTotalClient_PollAnalysis_CompletedImmediately(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := VirusTotalAnalysisResponse{
			Data: AnalysisData{
				Status: "completed",
				Stats:  Stats{Malicious: 7, Suspicious: 1},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	result, err := vt.pollAnalysis(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("pollAnalysis() error = %v", err)
	}
	if result == nil {
		t.Fatal("pollAnalysis() returned nil result")
	}
	if *result.VirusTotalScore != 8 { // 7+1
		t.Errorf("VirusTotalScore = %d; want 8", *result.VirusTotalScore)
	}
}

func TestVirusTotalClient_PollAnalysis_NeverCompletes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return "queued" — never completes
		resp := VirusTotalAnalysisResponse{
			Data: AnalysisData{Status: "queued"},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	_, err := vt.pollAnalysis(context.Background(), "test-id")
	if err == nil {
		t.Fatal("expected error when analysis never completes, got nil")
	}
}

func TestVirusTotalClient_PollAnalysis_EventuallyCompletes(t *testing.T) {
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		status := "queued"
		if callCount >= 3 {
			status = "completed"
		}
		resp := VirusTotalAnalysisResponse{
			Data: AnalysisData{
				Status: status,
				Stats:  Stats{Malicious: 2},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	result, err := vt.pollAnalysis(context.Background(), "test-id")
	if err != nil {
		t.Fatalf("pollAnalysis() error = %v", err)
	}
	if *result.VirusTotalScore != 2 {
		t.Errorf("VirusTotalScore = %d; want 2", *result.VirusTotalScore)
	}
	if callCount < 3 {
		t.Errorf("called %d times; want >= 3", callCount)
	}
}

func TestVirusTotalClient_Check_ExistingURLReturnsImmediately(t *testing.T) {
	// checkExisting returns a result → submitScan and pollAnalysis are not called
	callCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodGet {
			resp := VirusTotalURLResponse{
				Data: URLData{
					Attributes: URLAttributes{
						LastAnalysisStats: Stats{Malicious: 1},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		t.Errorf("unexpected %s request — should not reach submitScan", r.Method)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	vt := newTestVTClient(srv)
	result, err := vt.Check(context.Background(), "http://example.com")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("API called %d times; want 1", callCount)
	}
	if *result.VirusTotalScore != 1 {
		t.Errorf("VirusTotalScore = %d; want 1", *result.VirusTotalScore)
	}
}
