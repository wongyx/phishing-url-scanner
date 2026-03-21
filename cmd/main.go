package main

import (
	"context" // remove when handler is implemented
	"log/slog"
	"os"

	"github.com/wongyx/phishing-url-scanner/internal/checker"
	"github.com/wongyx/phishing-url-scanner/internal/config"

	// "github.com/wongyx/phishing-url-scanner/internal/db"
	"github.com/wongyx/phishing-url-scanner/internal/logger"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := logger.NewLogger(cfg.App.Env)
	slog.SetDefault(logger)
	slog.Info("config loaded", "env", cfg.App.Env, "port", cfg.App.Port)

	// database, err := db.Connect(cfg.DB)
	// if err != nil {
	// 	slog.Error("failed to connect to database", "error", err)
	// 	os.Exit(1)
	// }

	ch := checker.NewChecker(
		cfg.API.VirusTotalKey,
		cfg.API.SafeBrowsingKey,
		checker.WithLogger(logger),
	)

	result, err := ch.Scan(context.Background(), "https://www.google.com")
	if err != nil {
		slog.Error("scan failed", "error", err)
		os.Exit(1)
	}

	slog.Info("scan result",
		"url", result.URL,
		"domain", result.Domain,
		"status", result.Status,
		"safe_browsing_hit", *result.SafeBrowsingHit,
		"threat_type", result.ThreatTypes,
		"domain_age_days", result.DomainAgeDays,
		"domain_created_at", result.DomainCreatedAt,
		"domain_age_flag", result.DomainAgeFlag,
		"status", result.Status,
	)
}
