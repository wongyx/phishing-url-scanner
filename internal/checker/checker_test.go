package checker

import (
	"testing"
	"time"

	"github.com/wongyx/phishing-url-scanner/internal/models"
)

func ptr[T any](v T) *T { return &v }

func TestDetermineStatus(t *testing.T) {
	tests := []struct {
		name string
		scan *models.Scan
		want models.ScanStatus
	}{
		{
			name: "all checks errored returns unknown",
			scan: &models.Scan{
				SafeBrowsingHit: nil,
				VirusTotalScore: nil,
				DomainAgeDays:   nil,
			},
			want: models.StatusUnknown,
		},
		{
			name: "safe browsing hit returns malicious",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(true),
				VirusTotalScore: ptr(0),
				DomainAgeDays:   ptr(365),
			},
			want: models.StatusMalicious,
		},
		{
			name: "safe browsing not hit does not trigger malicious",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(false),
				VirusTotalScore: ptr(0),
				DomainAgeDays:   ptr(365),
			},
			want: models.StatusSafe,
		},
		{
			name: "virustotal score >= 5 returns malicious",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(false),
				VirusTotalScore: ptr(5),
				DomainAgeDays:   ptr(365),
			},
			want: models.StatusMalicious,
		},
		{
			name: "virustotal score > 5 returns malicious",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(false),
				VirusTotalScore: ptr(10),
				DomainAgeDays:   ptr(365),
			},
			want: models.StatusMalicious,
		},
		{
			name: "virustotal score == 1 returns suspicious",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(false),
				VirusTotalScore: ptr(1),
				DomainAgeDays:   ptr(365),
			},
			want: models.StatusSuspicious,
		},
		{
			name: "virustotal score == 4 returns suspicious",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(false),
				VirusTotalScore: ptr(4),
				DomainAgeDays:   ptr(365),
			},
			want: models.StatusSuspicious,
		},
		{
			name: "domain age flag with no other threat returns suspicious",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(false),
				VirusTotalScore: ptr(0),
				DomainAgeDays:   ptr(5),
				DomainAgeFlag:   true,
			},
			want: models.StatusSuspicious,
		},
		{
			name: "safe browsing overrides domain age flag",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(true),
				VirusTotalScore: ptr(0),
				DomainAgeDays:   ptr(5),
				DomainAgeFlag:   true,
			},
			want: models.StatusMalicious,
		},
		{
			name: "all clear returns safe",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(false),
				VirusTotalScore: ptr(0),
				DomainAgeDays:   ptr(365),
				DomainAgeFlag:   false,
			},
			want: models.StatusSafe,
		},
		{
			name: "only virustotal available and score 0 returns safe",
			scan: &models.Scan{
				SafeBrowsingHit: nil,
				VirusTotalScore: ptr(0),
				DomainAgeDays:   nil,
			},
			want: models.StatusSafe,
		},
		{
			name: "only domain age available and flagged returns suspicious",
			scan: &models.Scan{
				SafeBrowsingHit: nil,
				VirusTotalScore: nil,
				DomainAgeDays:   ptr(3),
				DomainAgeFlag:   true,
			},
			want: models.StatusSuspicious,
		},
		{
			name: "only safe browsing available and not hit returns safe",
			scan: &models.Scan{
				SafeBrowsingHit: ptr(false),
				VirusTotalScore: nil,
				DomainAgeDays:   nil,
			},
			want: models.StatusSafe,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineStatus(tt.scan)
			if got != tt.want {
				t.Errorf("determineStatus() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestNewChecker_Defaults(t *testing.T) {
	ch := NewChecker("vt-key", "sb-key")
	if ch == nil {
		t.Fatal("NewChecker returned nil")
	}
	if ch.vtClient == nil {
		t.Error("vtClient is nil")
	}
	if ch.sbClient == nil {
		t.Error("sbClient is nil")
	}
	if ch.whoisClient == nil {
		t.Error("whoisClient is nil")
	}
	if ch.scanTimeout != 180*time.Second {
		t.Errorf("scanTimeout = %v; want %v", ch.scanTimeout, 180*time.Second)
	}
	if ch.logger == nil {
		t.Error("logger is nil")
	}
}

func TestNewChecker_WithScanTimeout(t *testing.T) {
	ch := NewChecker("vt-key", "sb-key", WithScanTimeout(10*time.Second))
	if ch.scanTimeout != 10*time.Second {
		t.Errorf("scanTimeout = %v; want %v", ch.scanTimeout, 10*time.Second)
	}
}
