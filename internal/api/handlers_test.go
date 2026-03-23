package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyx/phishing-url-scanner/internal/checker"
	"github.com/wongyx/phishing-url-scanner/internal/models"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ── test doubles ──────────────────────────────────────────────────────────────

type mockScanner struct {
	result *models.Scan
	err    error
}

func (m *mockScanner) Scan(_ context.Context, _ string) (*models.Scan, error) {
	return m.result, m.err
}

type capturingMockScanner struct {
	capturedURL *string
	base        Scanner
}

func (s *capturingMockScanner) Scan(ctx context.Context, rawURL string) (*models.Scan, error) {
	*s.capturedURL = rawURL
	return s.base.Scan(ctx, rawURL)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newTestHandler returns a Handler with a nil DB (safe for tests that do not
// reach the database) and the default logger.
func newTestHandler(scanner Scanner) *Handler {
	return &Handler{
		db:      nil,
		scanner: scanner,
		logger:  slog.Default(),
	}
}

// newTestRouter wires the full middleware stack used in production so that
// domain errors attached via c.Error() are mapped to the correct HTTP status.
func newTestRouter(h *Handler) *gin.Engine {
	r := gin.New()
	r.Use(ErrorMiddleware(h.logger))
	r.POST("/api/scan", h.ScanURL)
	r.GET("/api/scans", h.ListScans)
	r.GET("/api/scans/:id", h.GetScan)
	return r
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

// ── ScanURL ───────────────────────────────────────────────────────────────────

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

// The three tests below require ErrorMiddleware because ScanURL now delegates
// error responses to it via c.Error() + c.Abort().

func TestScanURL_ScannerReturnsErrInvalidURL(t *testing.T) {
	invalidErr := &checker.ErrInvalidURL{URL: "http://127.0.0.1", Reason: "host resolves to loopback address"}
	h := newTestHandler(&mockScanner{err: invalidErr})
	r := newTestRouter(h)

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
	r := newTestRouter(h)

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
	r := newTestRouter(h)

	w := performRequest(r, map[string]string{"url": "http://example.com"})

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want %d", w.Code, http.StatusInternalServerError)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Generic errors must NOT expose internal detail to the client.
	if resp.Error != "internal server error" {
		t.Errorf("error = %q; want %q", resp.Error, "internal server error")
	}
}

func TestScanURL_RequestBodyVerification(t *testing.T) {
	const wantURL = "http://example.com/path?q=1"
	var gotURL string

	scanner := &mockScanner{err: errors.New("stop after capture")}
	h := newTestHandler(&capturingMockScanner{capturedURL: &gotURL, base: scanner})
	r := newTestRouter(h)

	performRequest(r, map[string]string{"url": wantURL})

	if gotURL != wantURL {
		t.Errorf("scanner received URL %q; want %q", gotURL, wantURL)
	}
}

// ── Health ────────────────────────────────────────────────────────────────────

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

// ── ErrorMiddleware ───────────────────────────────────────────────────────────

// newMiddlewareRouter builds a minimal router that runs ErrorMiddleware and
// then calls the provided handler at GET /test.
func newMiddlewareRouter(handlerFn gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(ErrorMiddleware(slog.Default()))
	r.GET("/test", handlerFn)
	return r
}

func middlewareGET(r http.Handler) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))
	return w
}

func TestErrorMiddleware_NoError(t *testing.T) {
	r := newMiddlewareRouter(func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := middlewareGET(r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}
}

func TestErrorMiddleware_RateLimited(t *testing.T) {
	r := newMiddlewareRouter(func(c *gin.Context) {
		_ = c.Error(&checker.ErrRateLimited{API: "virustotal", RetryAfter: "60"})
		c.Abort()
	})

	w := middlewareGET(r)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d; want %d", w.Code, http.StatusTooManyRequests)
	}
	var resp ErrorResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != "rate limit exceeded, try again later" {
		t.Errorf("error = %q; want %q", resp.Error, "rate limit exceeded, try again later")
	}
}

func TestErrorMiddleware_InvalidURL(t *testing.T) {
	r := newMiddlewareRouter(func(c *gin.Context) {
		_ = c.Error(&checker.ErrInvalidURL{URL: "http://bad", Reason: "blocked"})
		c.Abort()
	})

	w := middlewareGET(r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
	var resp ErrorResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestErrorMiddleware_APIUnavailable(t *testing.T) {
	r := newMiddlewareRouter(func(c *gin.Context) {
		_ = c.Error(&checker.ErrAPIUnavailable{API: "virustotal", Status: 503})
		c.Abort()
	})

	w := middlewareGET(r)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadGateway)
	}
	var resp ErrorResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != "upstream service unavailable" {
		t.Errorf("error = %q; want %q", resp.Error, "upstream service unavailable")
	}
}

func TestErrorMiddleware_GenericError(t *testing.T) {
	r := newMiddlewareRouter(func(c *gin.Context) {
		_ = c.Error(errors.New("something internal"))
		c.Abort()
	})

	w := middlewareGET(r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want %d", w.Code, http.StatusInternalServerError)
	}
	var resp ErrorResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != "internal server error" {
		t.Errorf("error = %q; want %q", resp.Error, "internal server error")
	}
}
