package api

import "github.com/gin-gonic/gin"

func NewRouter(h *Handler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Kubernetes probes
	r.GET("/health", h.Health)
	r.GET("/ready", h.Ready)

	api := r.Group("/api")
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
