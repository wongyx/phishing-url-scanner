package checker

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestCheckIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
		reason  string
	}{
		// Loopback
		{"ipv4 loopback", "127.0.0.1", true, "loopback"},
		{"ipv4 loopback 2", "127.0.0.2", true, "loopback"},
		{"ipv6 loopback", "::1", true, "loopback"},

		// Private RFC 1918
		{"private 10.x", "10.0.0.1", true, "private"},
		{"private 172.16.x", "172.16.0.1", true, "private"},
		{"private 192.168.x", "192.168.1.1", true, "private"},

		// Link-local
		{"link-local ipv4", "169.254.1.1", true, "link-local"},
		{"link-local ipv6", "fe80::1", true, "link-local"},

		// Multicast (239.0.0.1 is site-local multicast, not link-local)
		{"multicast ipv4", "239.0.0.1", true, "multicast"},

		// Unspecified
		{"unspecified ipv4", "0.0.0.0", true, "unspecified"},

		// Blocked CIDRs
		{"shared address space 100.64.x", "100.64.0.1", true, "blocked range"},
		{"TEST-NET-1 192.0.2.x", "192.0.2.1", true, "blocked range"},
		{"TEST-NET-2 198.51.100.x", "198.51.100.1", true, "blocked range"},
		{"TEST-NET-3 203.0.113.x", "203.0.113.1", true, "blocked range"},
		{"reserved 240.x", "240.0.0.1", true, "blocked range"},

		// Valid public IPs
		{"google dns", "8.8.8.8", false, ""},
		{"cloudflare dns", "1.1.1.1", false, ""},
		{"public ipv6", "2001:4860:4860::8888", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid test IP: %s", tt.ip)
			}
			err := checkIP(ip, "http://test.example.com")
			if tt.wantErr {
				if err == nil {
					t.Errorf("checkIP(%s) = nil; want error containing %q", tt.ip, tt.reason)
					return
				}
				var invalidErr *ErrInvalidURL
				if !errors.As(err, &invalidErr) {
					t.Errorf("checkIP(%s) returned wrong error type: %T", tt.ip, err)
					return
				}
				if tt.reason != "" && !strings.Contains(invalidErr.Reason, tt.reason) {
					t.Errorf("checkIP(%s) reason = %q; want it to contain %q", tt.ip, invalidErr.Reason, tt.reason)
				}
			} else {
				if err != nil {
					t.Errorf("checkIP(%s) = %v; want nil", tt.ip, err)
				}
			}
		})
	}
}

func TestValidateURL_Scheme(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"http scheme", "http://8.8.8.8", false},
		{"https scheme", "https://8.8.8.8", false},
		{"ftp scheme", "ftp://example.com", true},
		{"no scheme", "example.com", true},
		{"javascript scheme", "javascript://alert(1)", true},
		{"file scheme", "file:///etc/passwd", true},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURL(ctx, tt.url)
			if tt.wantErr && err == nil {
				t.Errorf("validateURL(%q) = nil; want error", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateURL(%q) = %v; want nil", tt.url, err)
			}
		})
	}
}

func TestValidateURL_TooLong(t *testing.T) {
	long := "http://example.com/" + strings.Repeat("a", maxURLLength)
	err := validateURL(context.Background(), long)
	if err == nil {
		t.Error("validateURL(too long URL) = nil; want error")
	}
	var invalidErr *ErrInvalidURL
	if !errors.As(err, &invalidErr) {
		t.Errorf("wrong error type: %T", err)
	}
	if !strings.Contains(invalidErr.Reason, "exceeds maximum length") {
		t.Errorf("reason = %q; want to contain %q", invalidErr.Reason, "exceeds maximum length")
	}
}

func TestValidateURL_MissingHost(t *testing.T) {
	err := validateURL(context.Background(), "http://")
	if err == nil {
		t.Error("validateURL(missing host) = nil; want error")
	}
}

func TestValidateURL_LiteralPrivateIP(t *testing.T) {
	tests := []struct {
		url string
	}{
		{"http://127.0.0.1"},
		{"https://192.168.0.1"},
		{"http://10.10.10.10"},
		{"https://[::1]"},
	}
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateURL(ctx, tt.url)
			if err == nil {
				t.Errorf("validateURL(%q) = nil; want error for private/loopback IP", tt.url)
			}
		})
	}
}

func TestValidateURL_LiteralPublicIP(t *testing.T) {
	// A literal public IP should pass scheme + IP checks (no DNS involved)
	err := validateURL(context.Background(), "http://8.8.8.8")
	if err != nil {
		t.Errorf("validateURL(public IP) = %v; want nil", err)
	}
}
