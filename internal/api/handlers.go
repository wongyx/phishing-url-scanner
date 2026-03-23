package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyx/phishing-url-scanner/internal/checker"
	"github.com/wongyx/phishing-url-scanner/internal/models"
	"gorm.io/gorm"
)

type Scanner interface {
	Scan(ctx context.Context, rawURL string) (*models.Scan, error)
}

type Handler struct {
	db      *gorm.DB
	scanner Scanner
	logger  *slog.Logger
}

func NewHandler(db *gorm.DB, scanner Scanner, logger *slog.Logger) *Handler {
	return &Handler{db: db, scanner: scanner, logger: logger}
}

type ScanRequest struct {
	URL string `json:"url" binding:"required,url"`
}

func (h *Handler) ScanURL(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	scan, err := h.scanner.Scan(c.Request.Context(), req.URL)
	if err != nil {
		h.logger.Error("scan failed", "url", req.URL, "error", err)

		var rateLimitErr *checker.ErrRateLimited
		if errors.As(err, &rateLimitErr) {
			c.JSON(http.StatusTooManyRequests, ErrorResponse{Error: "rate limit exceeded, try again later"})
			return
		}
		var invalidErr *checker.ErrInvalidURL
		if errors.As(err, &invalidErr) {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: invalidErr.Error()})
			return
		}

		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "scan failed"})
		return
	}

	if err := h.db.WithContext(c.Request.Context()).Create(scan).Error; err != nil {
		h.logger.Error("failed to save scan", "url", req.URL, "error", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to save scan result"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

func (h *Handler) ListScans(c *gin.Context) {
	// TODO: implement pagination and status filter
}

func (h *Handler) GetScan(c *gin.Context) {
	// TODO: implement single scan lookup by ID
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) Ready(c *gin.Context) {
	sqlDB, err := h.db.DB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{Error: "database unavailable"})
		return
	}
	if err := sqlDB.Ping(); err != nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{Error: "database unreachable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
