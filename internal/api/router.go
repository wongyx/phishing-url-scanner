package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func NewRouter(h *Handler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(ErrorMiddleware(h.logger))

	// Kubernetes probes
	r.GET("/health", h.Health)
	r.GET("/ready", h.Ready)

	api := r.Group("/api")
	api.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20) // Limit request body to 1MB
		c.Next()
	})
	{
		api.POST("/scan", h.ScanURL)
		api.GET("/scans", h.ListScans)
		api.GET("/scans/:id", h.GetScan)
	}

	// Serve the frontend
	r.Static("/static", "./static")
	r.StaticFile("/", "./static/index.html")

	return r
}
