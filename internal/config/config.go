package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	App *App
	API *API
	DB  *DB
}

type App struct {
	Env         string
	Port        string
	ScanTimeout time.Duration
}

type API struct {
	VirusTotalKey   string
	SafeBrowsingKey string
}

type DB struct {
	User     string
	Password string
	Host     string
	Name     string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	var errs []string

	app := &App{
		Env:         getEnv("APP_ENV", "development"),
		Port:        getEnv("PORT", "8080"),
		ScanTimeout: 45 * time.Second,
	}

	api := &API{
		VirusTotalKey:   requireEnv("VIRUSTOTAL_API_KEY", &errs),
		SafeBrowsingKey: requireEnv("SAFE_BROWSING_API_KEY", &errs),
	}

	db := &DB{
		User:     requireEnv("DB_USER", &errs),
		Password: requireEnv("DB_PASSWORD", &errs),
		Host:     getEnv("DB_HOST", "db"),
		Name:     getEnv("DB_NAME", "phishingchecker"),
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("config errors: %s", strings.Join(errs, ", "))
	}

	return &Config{
		App: app,
		API: api,
		DB:  db,
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(key string, errs *[]string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	*errs = append(*errs, fmt.Sprintf("%s is required", key))
	return ""
}
