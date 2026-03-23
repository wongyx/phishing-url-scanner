package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
		_ = c.Error(err)
		c.Abort()
		return
	}

	if err := h.db.WithContext(c.Request.Context()).Create(scan).Error; err != nil {
		h.logger.Error("failed to save scan", "url", req.URL, "error", err)
		_ = c.Error(err)
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, scan)
}

func (h *Handler) ListScans(c *gin.Context) {
	page, limit := 1, 20
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}

	q := h.db.WithContext(c.Request.Context()).Model(&models.Scan{})
	if status := c.Query("status"); status != "" {
		switch models.ScanStatus(status) {
		case models.StatusSafe, models.StatusSuspicious, models.StatusMalicious, models.StatusUnknown, models.StatusError:
			q = q.Where("status = ?", status)
		default:
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid status filter"})
			return
		}
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		h.logger.Error("failed to count scans", "error", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to retrieve scans"})
		return
	}

	scans := []models.Scan{}
	offset := (page - 1) * limit
	if err := q.Order("scanned_at DESC").Limit(limit).Offset(offset).Find(&scans).Error; err != nil {
		h.logger.Error("failed to list scans", "error", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to retrieve scans"})
		return
	}

	c.JSON(http.StatusOK, PaginatedResponse[models.Scan]{
		Data:  scans,
		Total: int(total),
		Page:  page,
		Limit: limit,
	})
}

func (h *Handler) GetScan(c *gin.Context) {
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid scan ID"})
		return
	}

	var scan models.Scan
	if err := h.db.WithContext(c.Request.Context()).First(&scan, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "scan not found"})
			return
		}
		h.logger.Error("failed to get scan", "id", id, "error", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to retrieve scan"})
		return
	}

	c.JSON(http.StatusOK, scan)
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
