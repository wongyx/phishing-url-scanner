package checker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	virusTotalBaseURL     = "https://www.virustotal.com/api/v3/urls"
	virusTotalAnalysisURL = "https://www.virustotal.com/api/v3/analyses/"
	virusTotalGUIURL      = "https://www.virustotal.com/gui/analyses/"
	virusTotalURLGUIURL   = "https://www.virustotal.com/gui/url/"
	virusTotalMaxPolls    = 10
)

type VirusTotalClient struct {
	httpClient *http.Client
	apiKey     string
	limiter    *rate.Limiter
}

type VirusTotalOption func(*VirusTotalClient)

func WithRateLimit(r rate.Limit, burst int) VirusTotalOption {
	return func(vt *VirusTotalClient) {
		vt.limiter = rate.NewLimiter(r, burst)
	}
}

func NewVirusTotalClient(apiKey string, httpClient *http.Client, opts ...VirusTotalOption) *VirusTotalClient {
	vt := &VirusTotalClient{
		apiKey:     apiKey,
		httpClient: httpClient,
		limiter:    rate.NewLimiter(rate.Every(15*time.Second), 4),
	}
	for _, opt := range opts {
		opt(vt)
	}
	return vt
}

type VirusTotalScanResponse struct {
	Data ScanData `json:"data"`
}

type ScanData struct {
	ID string `json:"id"`
}

type VirusTotalAnalysisResponse struct {
	Data AnalysisData `json:"data"`
}

type AnalysisData struct {
	Status string `json:"status"`
	Stats  Stats  `json:"stats"`
}

type Stats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
}

type VirusTotalURLResponse struct {
	Data URLData `json:"data"`
}

type URLData struct {
	Attributes URLAttributes `json:"attributes"`
}

type URLAttributes struct {
	LastAnalysisStats Stats `json:"last_analysis_stats"`
}

type VirusTotalResult struct {
	VirusTotalScore *int
	VirusTotalLink  *string
}

func (vt *VirusTotalClient) Check(ctx context.Context, rawURL string) (*VirusTotalResult, error) {
	result, err := vt.checkExisting(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	if result != nil {
		return result, nil
	}

	id, err := vt.submitScan(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	return vt.pollAnalysis(ctx, id)
}

func (vt *VirusTotalClient) checkExisting(ctx context.Context, rawURL string) (*VirusTotalResult, error) {
	urlID := base64.RawURLEncoding.EncodeToString([]byte(rawURL))
	apiURL := virusTotalBaseURL + "/" + urlID

	if err := vt.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("virustotal: rate limiter: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("virustotal: build request for %s: %w", apiURL, err)
	}
	req.Header.Set("x-apikey", vt.apiKey)

	resp, err := vt.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal: request for %s: %w", apiURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &ErrRateLimited{API: "virustotal", RetryAfter: resp.Header.Get("Retry-After")}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &ErrAPIUnavailable{API: "virustotal", Status: resp.StatusCode}
	}

	var urlResp VirusTotalURLResponse
	if err = json.NewDecoder(resp.Body).Decode(&urlResp); err != nil {
		return nil, fmt.Errorf("virustotal: decode response for %s: %w", apiURL, err)
	}

	score := urlResp.Data.Attributes.LastAnalysisStats.Malicious + urlResp.Data.Attributes.LastAnalysisStats.Suspicious
	link := virusTotalURLGUIURL + urlID
	return &VirusTotalResult{
		VirusTotalScore: &score,
		VirusTotalLink:  &link,
	}, nil
}

func (vt *VirusTotalClient) submitScan(ctx context.Context, rawURL string) (string, error) {
	if err := vt.limiter.Wait(ctx); err != nil {
		return "", fmt.Errorf("virustotal: rate limiter: %w", err)
	}

	body := url.Values{"url": {rawURL}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, virusTotalBaseURL, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("virustotal: build request for %s: %w", rawURL, err)
	}
	req.Header.Set("x-apikey", vt.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := vt.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("virustotal: request for %s: %w", rawURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", &ErrRateLimited{API: "virustotal", RetryAfter: resp.Header.Get("Retry-After")}
	}
	if resp.StatusCode != http.StatusOK {
		return "", &ErrAPIUnavailable{API: "virustotal", Status: resp.StatusCode}
	}

	var vtScanResp VirusTotalScanResponse
	if err = json.NewDecoder(resp.Body).Decode(&vtScanResp); err != nil {
		return "", fmt.Errorf("virustotal: decode response for %s: %w", rawURL, err)
	}

	return vtScanResp.Data.ID, nil
}

func (vt *VirusTotalClient) pollAnalysis(ctx context.Context, id string) (*VirusTotalResult, error) {
	apiURL := virusTotalAnalysisURL + id

	for i := 0; i < virusTotalMaxPolls; i++ {
		if err := vt.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("virustotal: rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("virustotal: build request for %s: %w", apiURL, err)
		}
		req.Header.Set("x-apikey", vt.apiKey)

		resp, err := vt.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("virustotal: request for %s: %w", apiURL, err)
		}

		var vtAnalysisResponse VirusTotalAnalysisResponse
		err = json.NewDecoder(resp.Body).Decode(&vtAnalysisResponse)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("virustotal: decode response for %s: %w", apiURL, err)
		}

		if vtAnalysisResponse.Data.Status == "completed" {
			score := vtAnalysisResponse.Data.Stats.Malicious + vtAnalysisResponse.Data.Stats.Suspicious
			link := virusTotalGUIURL + id
			return &VirusTotalResult{
				VirusTotalScore: &score,
				VirusTotalLink:  &link,
			}, nil
		}
	}

	return nil, fmt.Errorf("virustotal: analysis %s did not complete after %d polls", id, virusTotalMaxPolls)
}
