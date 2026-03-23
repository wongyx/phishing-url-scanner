package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wongyx/phishing-url-scanner/internal/checker"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type PaginatedResponse[T any] struct {
	Data  []T `json:"data"`
	Total int `json:"total"`
	Page  int `json:"page"`
	Limit int `json:"limit"`
}

// ErrorMiddleware maps domain errors attached via c.Error() to HTTP responses.
// Handlers should call c.Error(err) then c.Abort() to use this middleware.
func ErrorMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) == 0 {
			return
		}

		err := c.Errors.Last().Err

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

		var unavailableErr *checker.ErrAPIUnavailable
		if errors.As(err, &unavailableErr) {
			logger.Error("upstream API unavailable", "api", unavailableErr.API, "status", unavailableErr.Status)
			c.JSON(http.StatusBadGateway, ErrorResponse{Error: "upstream service unavailable"})
			return
		}

		logger.Error("unhandled error", "error", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "internal server error"})
	}
}
