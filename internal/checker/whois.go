package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	rdapBaseURL       = "https://rdap.org/domain/"
	domainAgeFlagDays = 30
)

type WHOISClient struct {
	httpClient *http.Client
}

func NewWHOISClient(httpClient *http.Client) *WHOISClient {
	return &WHOISClient{httpClient: httpClient}
}

type DomainAgeResult struct {
	AgeDays   *int
	CreatedAt *time.Time
	AgeFlag   bool
}

type rdapResponse struct {
	Events []rdapEvent `json:"events"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

// Check queries rdap.org for the registration date of domain and returns a
// DomainAgeResult. If the lookup fails for any reason, it returns a nil result
// and a non-nil error — the caller should store nulls and continue.
func (w *WHOISClient) Check(ctx context.Context, domain string) (*DomainAgeResult, error) {
	apiURL := rdapBaseURL + domain

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("rdap: build request for %s: %w", domain, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap: request for %s: %w", domain, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &ErrRateLimited{API: "rdap", RetryAfter: resp.Header.Get("Retry-After")}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &ErrAPIUnavailable{API: "rdap", Status: resp.StatusCode}
	}

	var rdap rdapResponse
	if err = json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
		return nil, fmt.Errorf("rdap: decode response for %s: %w", domain, err)
	}

	createdAt, err := extractRegistrationDate(rdap.Events)
	if err != nil {
		return nil, fmt.Errorf("rdap: %s: %w", domain, err)
	}

	ageDays := int(time.Since(createdAt).Hours() / 24)

	return &DomainAgeResult{
		AgeDays:   &ageDays,
		CreatedAt: &createdAt,
		AgeFlag:   ageDays < domainAgeFlagDays,
	}, nil
}

func extractRegistrationDate(events []rdapEvent) (time.Time, error) {
	for _, e := range events {
		if e.Action == "registration" {
			t, err := time.Parse(time.RFC3339, e.Date)
			if err != nil {
				return time.Time{}, fmt.Errorf("parse registration date %q: %w", e.Date, err)
			}
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("no registration event found")
}
