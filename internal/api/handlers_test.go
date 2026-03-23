package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/wongyx/phishing-url-scanner/internal/checker"
	"github.com/wongyx/phishing-url-scanner/internal/models"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockScanner is a test double for the Scanner interface.
type mockScanner struct {
	result *models.Scan
	err    error
}

func (m *mockScanner) Scan(_ context.Context, _ string) (*models.Scan, error) {
	return m.result, m.err
}

// newTestHandler returns a Handler with a nil DB (safe for tests that don't
// reach the database) and a no-op logger.
func newTestHandler(scanner Scanner) *Handler {
	return &Handler{
		db:      nil,
		scanner: scanner,
		logger:  slog.Default(),
	}
}

func performRequest(r http.Handler, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/scan", &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestScanURL_InvalidJSON(t *testing.T) {
	h := newTestHandler(&mockScanner{})
	r := gin.New()
	r.POST("/api/scan", h.ScanURL)

	req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestScanURL_MissingURL(t *testing.T) {
	h := newTestHandler(&mockScanner{})
	r := gin.New()
	r.POST("/api/scan", h.ScanURL)

	w := performRequest(r, map[string]string{})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestScanURL_InvalidURLFormat(t *testing.T) {
	h := newTestHandler(&mockScanner{})
	r := gin.New()
	r.POST("/api/scan", h.ScanURL)

	w := performRequest(r, map[string]string{"url": "not-a-valid-url"})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestScanURL_ScannerReturnsErrInvalidURL(t *testing.T) {
	invalidErr := &checker.ErrInvalidURL{URL: "http://127.0.0.1", Reason: "host resolves to loopback address"}
	h := newTestHandler(&mockScanner{err: invalidErr})
	r := gin.New()
	r.POST("/api/scan", h.ScanURL)

	w := performRequest(r, map[string]string{"url": "http://127.0.0.1"})

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestScanURL_ScannerReturnsErrRateLimited(t *testing.T) {
	rateLimitErr := &checker.ErrRateLimited{API: "virustotal", RetryAfter: "60"}
	h := newTestHandler(&mockScanner{err: rateLimitErr})
	r := gin.New()
	r.POST("/api/scan", h.ScanURL)

	w := performRequest(r, map[string]string{"url": "http://example.com"})

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d; want %d", w.Code, http.StatusTooManyRequests)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestScanURL_ScannerReturnsGenericError(t *testing.T) {
	h := newTestHandler(&mockScanner{err: errors.New("unexpected failure")})
	r := gin.New()
	r.POST("/api/scan", h.ScanURL)

	w := performRequest(r, map[string]string{"url": "http://example.com"})

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want %d", w.Code, http.StatusInternalServerError)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Generic errors must NOT expose internal detail to the client
	if resp.Error != "scan failed" {
		t.Errorf("error = %q; want %q", resp.Error, "scan failed")
	}
}

func TestHealth(t *testing.T) {
	h := newTestHandler(nil)
	r := gin.New()
	r.GET("/health", h.Health)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q; want %q", body["status"], "ok")
	}
}

func TestScanURL_RequestBodyVerification(t *testing.T) {
	// Verify that the URL from the request body is passed to the scanner.
	const wantURL = "http://example.com/path?q=1"
	var gotURL string

	scanner := &mockScanner{
		err: errors.New("stop after capture"), // prevent reaching db
	}
	// We use a custom scanner that captures the URL
	capturingScanner := &capturingMockScanner{capturedURL: &gotURL, base: scanner}

	h := newTestHandler(capturingScanner)
	r := gin.New()
	r.POST("/api/scan", h.ScanURL)

	performRequest(r, map[string]string{"url": wantURL})

	if gotURL != wantURL {
		t.Errorf("scanner received URL %q; want %q", gotURL, wantURL)
	}
}

type capturingMockScanner struct {
	capturedURL *string
	base        Scanner
}

func (s *capturingMockScanner) Scan(ctx context.Context, rawURL string) (*models.Scan, error) {
	*s.capturedURL = rawURL
	return s.base.Scan(ctx, rawURL)
}
