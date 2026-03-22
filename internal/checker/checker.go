package checker

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lib/pq"
	"github.com/wongyx/phishing-url-scanner/internal/models"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

type Checker struct {
	vtClient    *VirusTotalClient
	sbClient    *SafeBrowsingClient
	whoisClient *WHOISClient
	scanTimeout time.Duration
	logger      *slog.Logger
}

type Option func(*Checker)

func WithHTTPClient(c *http.Client) Option {
	return func(ch *Checker) {
		ch.vtClient.httpClient = c
		ch.sbClient.httpClient = c
		ch.whoisClient.httpClient = c
	}
}

// WithVirusTotalRateLimit overrides the default VirusTotal rate limit (4 req/min, free tier).
// Use this when on a paid plan, e.g. WithVirusTotalRateLimit(rate.Every(60*time.Millisecond), 1000) for 1000 req/min.
func WithVirusTotalRateLimit(r rate.Limit, burst int) Option {
	return func(ch *Checker) {
		WithRateLimit(r, burst)(ch.vtClient)
	}
}

func WithScanTimeout(d time.Duration) Option {
	return func(ch *Checker) {
		ch.scanTimeout = d
	}
}

func WithLogger(l *slog.Logger) Option {
	return func(ch *Checker) {
		ch.logger = l
	}
}

func NewChecker(vtKey, sbKey string, opts ...Option) *Checker {
	defaultClient := &http.Client{Timeout: 30 * time.Second}
	ch := &Checker{
		vtClient:    NewVirusTotalClient(vtKey, defaultClient),
		sbClient:    NewSafeBrowsingClient(sbKey, defaultClient),
		whoisClient: NewWHOISClient(defaultClient),
		scanTimeout: 180 * time.Second,
		logger:      slog.Default(),
	}
	for _, opt := range opts {
		opt(ch)
	}
	return ch
}

func (ch *Checker) Scan(ctx context.Context, rawURL string) (*models.Scan, error) {
	ctx, cancel := context.WithTimeout(ctx, ch.scanTimeout)
	defer cancel()

	if err := validateURL(ctx, rawURL); err != nil {
		return nil, err
	}

	parsed, _ := url.Parse(rawURL)
	domain, err := publicsuffix.EffectiveTLDPlusOne(parsed.Hostname())
	if err != nil {
		return nil, &ErrInvalidURL{URL: rawURL, Reason: "could not extract domain"}
	}

	scan := &models.Scan{
		URL:    rawURL,
		Domain: domain,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// VirusTotal check
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := ch.vtClient.Check(ctx, rawURL)
		if err != nil {
			ch.logger.Warn("virustotal check failed", "url", rawURL, "error", err)
			return
		}
		mu.Lock()
		scan.VirusTotalScore = result.VirusTotalScore
		scan.VirusTotalLink = result.VirusTotalLink
		mu.Unlock()
	}()

	// Safe Browsing check
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := ch.sbClient.Check(ctx, rawURL)
		if err != nil {
			ch.logger.Warn("safebrowsing check failed", "url", rawURL, "error", err)
		}
		mu.Lock()
		scan.SafeBrowsingHit = result.SafeBrowsingHit
		scan.ThreatTypes = pq.StringArray(result.ThreatTypes)
		mu.Unlock()
	}()

	// RDAP domain age check
	wg.Add(1)
	go func() {
		defer wg.Done()
		result, err := ch.whoisClient.Check(ctx, domain)
		if err != nil {
			ch.logger.Warn("rdap check failed", "domain", domain, "error", err)
			return
		}
		mu.Lock()
		scan.DomainAgeDays = result.AgeDays
		scan.DomainCreatedAt = result.CreatedAt
		scan.DomainAgeFlag = result.AgeFlag
		mu.Unlock()
	}()

	wg.Wait()

	scan.Status = determineStatus(scan)
	return scan, nil
}

func determineStatus(scan *models.Scan) models.ScanStatus {
	// Safe Browsing hit takes highest priority
	if scan.SafeBrowsingHit != nil && *scan.SafeBrowsingHit {
		return models.StatusMalicious
	}

	// VirusTotal score
	if scan.VirusTotalScore != nil {
		if *scan.VirusTotalScore >= 5 {
			return models.StatusMalicious
		}
		if *scan.VirusTotalScore >= 1 {
			return models.StatusSuspicious
		}
	}

	// Domain age flag — cannot override malicious
	if scan.DomainAgeFlag {
		return models.StatusSuspicious
	}

	// All checks errored (all nullable fields still nil)
	if scan.SafeBrowsingHit == nil && scan.VirusTotalScore == nil && scan.DomainAgeDays == nil {
		return models.StatusUnknown
	}

	return models.StatusSafe
}
