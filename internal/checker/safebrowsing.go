package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	safeBrowsingBaseURL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
)

type SafeBrowsingClient struct {
	httpClient *http.Client
	apiKey     string
}

func NewSafeBrowsingClient(apiKey string, httpClient *http.Client) *SafeBrowsingClient {
	return &SafeBrowsingClient{
		apiKey:     apiKey,
		httpClient: httpClient,
	}
}

type SafeBrowsingRequest struct {
	Client     ClientInfo `json:"client"`
	ThreatInfo ThreatInfo `json:"threatInfo"`
}

type ClientInfo struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type ThreatInfo struct {
	ThreatTypes      []string      `json:"threatTypes"`
	PlatformTypes    []string      `json:"platformTypes"`
	ThreatEntryTypes []string      `json:"threatEntryTypes"`
	ThreatEntries    []ThreatEntry `json:"threatEntries"`
}

type ThreatEntry struct {
	URL string `json:"url"`
}

type SafeBrowsingResponse struct {
	Matches []ThreatMatch `json:"matches"`
}

type ThreatMatch struct {
	ThreatType string `json:"threatType"`
}

type SafeBrowsingResult struct {
	SafeBrowsingHit *bool
	ThreatTypes     []string
}

func (sb *SafeBrowsingClient) Check(ctx context.Context, rawURL string) (*SafeBrowsingResult, error) {
	apiURL := safeBrowsingBaseURL + sb.apiKey

	reqBody := SafeBrowsingRequest{
		Client: ClientInfo{
			ClientID:      "phishing-url-scanner",
			ClientVersion: "1.0.0",
		},
		ThreatInfo: ThreatInfo{
			ThreatTypes:      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			PlatformTypes:    []string{"ANY_PLATFORM"},
			ThreatEntryTypes: []string{"URL"},
			ThreatEntries: []ThreatEntry{
				{URL: rawURL},
			},
		},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("safebrowsing: marshal request for %s: %w", rawURL, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("safebrowsing: build request for %s: %w", rawURL, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sb.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("safebrowsing: request for %s: %w", rawURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("safebrowsing: unexpected status %d for %s", resp.StatusCode, rawURL)
	}

	var sbResp SafeBrowsingResponse
	if err = json.NewDecoder(resp.Body).Decode(&sbResp); err != nil {
		return nil, fmt.Errorf("safebrowsing: decode response for %s: %w", rawURL, err)
	}

	hit := len(sbResp.Matches) > 0
	result := &SafeBrowsingResult{
		SafeBrowsingHit: &hit,
	}
	if hit {
		threatTypes := make([]string, 0, len(sbResp.Matches))
		for _, m := range sbResp.Matches {
			threatTypes = append(threatTypes, m.ThreatType)
		}
		result.ThreatTypes = threatTypes
	}

	return result, nil
}
