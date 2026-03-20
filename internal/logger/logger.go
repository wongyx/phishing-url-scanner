package logger

import (
	"log/slog"
	"os"

	"github.com/wongyx/phishing-url-scanner/internal/config"
)

func NewLogger(cfg *config.App) *slog.Logger {
	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
	}

	if cfg.Env == "development" {
		opts.Level = slog.LevelDebug
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}
