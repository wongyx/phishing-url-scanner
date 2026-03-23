package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wongyx/phishing-url-scanner/internal/api"
	"github.com/wongyx/phishing-url-scanner/internal/checker"
	"github.com/wongyx/phishing-url-scanner/internal/config"
	"github.com/wongyx/phishing-url-scanner/internal/db"
	"github.com/wongyx/phishing-url-scanner/internal/logger"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	log := logger.NewLogger(cfg.App.Env)
	slog.SetDefault(log)
	slog.Info("config loaded", "env", cfg.App.Env, "port", cfg.App.Port)

	database, err := db.Connect(cfg.DB)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}

	ch := checker.NewChecker(
		cfg.API.VirusTotalKey,
		cfg.API.SafeBrowsingKey,
		checker.WithLogger(log),
		checker.WithScanTimeout(cfg.App.ScanTimeout),
	)

	handler := api.NewHandler(database, ch, log)
	router := api.NewRouter(handler)

	srv := &http.Server{
		Addr:    ":" + cfg.App.Port,
		Handler: router,
	}

	go func() {
		slog.Info("server starting", "port", cfg.App.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	sqlDB, err := database.DB()
	if err == nil {
		_ = sqlDB.Close()
	}

	slog.Info("server stopped")
}
