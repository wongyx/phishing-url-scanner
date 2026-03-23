package config

import (
	"os"
	"testing"
)

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("os.Unsetenv(%q): %v", key, err)
	}
}

func TestLoad_AllRequiredVarsPresent(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key-123")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key-456")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v; want nil", err)
	}
	if cfg.API.VirusTotalKey != "vt-key-123" {
		t.Errorf("VirusTotalKey = %q; want %q", cfg.API.VirusTotalKey, "vt-key-123")
	}
	if cfg.API.SafeBrowsingKey != "sb-key-456" {
		t.Errorf("SafeBrowsingKey = %q; want %q", cfg.API.SafeBrowsingKey, "sb-key-456")
	}
	if cfg.DB.User != "postgres" {
		t.Errorf("DB.User = %q; want %q", cfg.DB.User, "postgres")
	}
	if cfg.DB.Password != "secret" {
		t.Errorf("DB.Password = %q; want %q", cfg.DB.Password, "secret")
	}
}

func TestLoad_DefaultPort(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")
	// PORT not set

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.App.Port != "8080" {
		t.Errorf("Port = %q; want %q", cfg.App.Port, "8080")
	}
}

func TestLoad_CustomPort(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")
	setEnv(t, "PORT", "9090")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.App.Port != "9090" {
		t.Errorf("Port = %q; want %q", cfg.App.Port, "9090")
	}
}

func TestLoad_DefaultDBHost(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DB.Host != "db" {
		t.Errorf("DB.Host = %q; want %q", cfg.DB.Host, "db")
	}
	if cfg.DB.Name != "phishingchecker" {
		t.Errorf("DB.Name = %q; want %q", cfg.DB.Name, "phishingchecker")
	}
}

func TestLoad_CustomDBHostAndName(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")
	setEnv(t, "DB_HOST", "mydbhost")
	setEnv(t, "DB_NAME", "mydb")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DB.Host != "mydbhost" {
		t.Errorf("DB.Host = %q; want %q", cfg.DB.Host, "mydbhost")
	}
	if cfg.DB.Name != "mydb" {
		t.Errorf("DB.Name = %q; want %q", cfg.DB.Name, "mydb")
	}
}

func TestLoad_MissingVirusTotalKey(t *testing.T) {
	unsetEnv(t, "VIRUSTOTAL_API_KEY")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")

	_, err := Load()
	if err == nil {
		t.Error("Load() = nil; want error for missing VIRUSTOTAL_API_KEY")
	}
}

func TestLoad_MissingSafeBrowsingKey(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	unsetEnv(t, "SAFE_BROWSING_API_KEY")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")

	_, err := Load()
	if err == nil {
		t.Error("Load() = nil; want error for missing SAFE_BROWSING_API_KEY")
	}
}

func TestLoad_MissingDBUser(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	unsetEnv(t, "DB_USER")
	setEnv(t, "DB_PASSWORD", "secret")

	_, err := Load()
	if err == nil {
		t.Error("Load() = nil; want error for missing DB_USER")
	}
}

func TestLoad_MissingDBPassword(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	setEnv(t, "DB_USER", "postgres")
	unsetEnv(t, "DB_PASSWORD")

	_, err := Load()
	if err == nil {
		t.Error("Load() = nil; want error for missing DB_PASSWORD")
	}
}

func TestLoad_MultipleRequiredVarsMissing(t *testing.T) {
	unsetEnv(t, "VIRUSTOTAL_API_KEY")
	unsetEnv(t, "SAFE_BROWSING_API_KEY")
	unsetEnv(t, "DB_USER")
	unsetEnv(t, "DB_PASSWORD")

	_, err := Load()
	if err == nil {
		t.Error("Load() = nil; want error when all required vars missing")
	}
}

func TestLoad_DefaultAppEnv(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")
	unsetEnv(t, "APP_ENV")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.App.Env != "development" {
		t.Errorf("App.Env = %q; want %q", cfg.App.Env, "development")
	}
}

func TestLoad_CustomAppEnv(t *testing.T) {
	setEnv(t, "VIRUSTOTAL_API_KEY", "vt-key")
	setEnv(t, "SAFE_BROWSING_API_KEY", "sb-key")
	setEnv(t, "DB_USER", "postgres")
	setEnv(t, "DB_PASSWORD", "secret")
	setEnv(t, "APP_ENV", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.App.Env != "production" {
		t.Errorf("App.Env = %q; want %q", cfg.App.Env, "production")
	}
}

func TestGetEnv_ReturnsValueWhenSet(t *testing.T) {
	setEnv(t, "TEST_KEY_XYZ", "my-value")
	got := getEnv("TEST_KEY_XYZ", "default")
	if got != "my-value" {
		t.Errorf("getEnv() = %q; want %q", got, "my-value")
	}
}

func TestGetEnv_ReturnsFallbackWhenNotSet(t *testing.T) {
	unsetEnv(t, "TEST_KEY_NOTSET")
	got := getEnv("TEST_KEY_NOTSET", "fallback-value")
	if got != "fallback-value" {
		t.Errorf("getEnv() = %q; want %q", got, "fallback-value")
	}
}

func TestRequireEnv_ReturnsValueWhenSet(t *testing.T) {
	setEnv(t, "TEST_REQUIRED_KEY", "required-value")
	var errs []string
	got := requireEnv("TEST_REQUIRED_KEY", &errs)
	if got != "required-value" {
		t.Errorf("requireEnv() = %q; want %q", got, "required-value")
	}
	if len(errs) != 0 {
		t.Errorf("errs = %v; want empty", errs)
	}
}

func TestRequireEnv_AppendsErrorWhenNotSet(t *testing.T) {
	unsetEnv(t, "TEST_REQUIRED_MISSING")
	var errs []string
	got := requireEnv("TEST_REQUIRED_MISSING", &errs)
	if got != "" {
		t.Errorf("requireEnv() = %q; want empty string", got)
	}
	if len(errs) != 1 {
		t.Errorf("errs length = %d; want 1", len(errs))
	}
}
