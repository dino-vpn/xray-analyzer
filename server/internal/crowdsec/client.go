// Package crowdsec is a minimal CrowdSec LAPI watcher client used by the
// Attacks tab to ban a user's source IP centrally. It talks to the same
// CrowdSec LAPI the ansible repo deploys (crowd.devaleto.com).
//
// Adding decisions requires a *machine* (watcher) credential, not a bouncer
// key: we log in at /v1/watchers/login for a short-lived JWT, then POST a
// manual alert carrying a single decision to /v1/alerts — exactly what
// `cscli decisions add` does under the hood. Unbanning is a DELETE on
// /v1/decisions filtered by IP.
package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is a thread-safe CrowdSec LAPI watcher client with JWT caching.
type Client struct {
	baseURL   string
	machineID string
	password  string

	httpClient *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewClient builds a CrowdSec client. baseURL is the LAPI root (no trailing
// /v1), e.g. "https://crowd.devaleto.com".
func NewClient(baseURL, machineID, password string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		machineID:  machineID,
		password:   password,
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

// IsConfigured reports whether banning is possible (creds present).
func (c *Client) IsConfigured() bool {
	return c.baseURL != "" && c.machineID != "" && c.password != ""
}

// loginResponse is the /v1/watchers/login payload.
type loginResponse struct {
	Code   int    `json:"code"`
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

// token returns a valid JWT, logging in (and caching) when needed. CrowdSec
// JWTs live ~1h; we refresh ~5min early.
func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExp.Add(-5*time.Minute)) {
		return c.token, nil
	}

	body, _ := json.Marshal(map[string]string{
		"machine_id": c.machineID,
		"password":   c.password,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/watchers/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("crowdsec: create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdsec: login request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("crowdsec: login failed: status %d, body: %s", resp.StatusCode, string(data))
	}

	var lr loginResponse
	if err := json.Unmarshal(data, &lr); err != nil {
		return "", fmt.Errorf("crowdsec: parse login response: %w", err)
	}
	if lr.Token == "" {
		return "", fmt.Errorf("crowdsec: empty token in login response")
	}

	c.token = lr.Token
	// Parse expiry; fall back to a conservative 45min if it doesn't parse.
	if exp, err := time.Parse(time.RFC3339, lr.Expire); err == nil {
		c.tokenExp = exp
	} else {
		c.tokenExp = time.Now().Add(45 * time.Minute)
	}
	return c.token, nil
}

// authedRequest performs a JWT-authenticated request, retrying once on 401/403
// after forcing a fresh login (the cached token may have been revoked).
func (c *Client) authedRequest(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	do := func(tok string) ([]byte, int, error) {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, r)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return data, resp.StatusCode, nil
	}

	tok, err := c.ensureToken(ctx)
	if err != nil {
		return nil, 0, err
	}
	data, status, err := do(tok)
	if err != nil {
		return nil, 0, err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		// Force re-login and retry once.
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		if tok, err = c.ensureToken(ctx); err != nil {
			return nil, 0, err
		}
		data, status, err = do(tok)
		if err != nil {
			return nil, 0, err
		}
	}
	return data, status, nil
}

// decision mirrors a CrowdSec decision object.
type decision struct {
	Duration string `json:"duration"`
	Origin   string `json:"origin"`
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Value    string `json:"value"`
}

// alertSource mirrors a CrowdSec alert source.
type alertSource struct {
	Scope string `json:"scope"`
	Value string `json:"value"`
}

// alert is the minimal manual alert accepted by POST /v1/alerts, matching the
// shape `cscli decisions add` produces.
type alert struct {
	Capacity        int           `json:"capacity"`
	Decisions       []decision    `json:"decisions"`
	Events          []interface{} `json:"events"`
	EventsCount     int           `json:"events_count"`
	Leakspeed       string        `json:"leakspeed"`
	Message         string        `json:"message"`
	Scenario        string        `json:"scenario"`
	ScenarioHash    string        `json:"scenario_hash"`
	ScenarioVersion string        `json:"scenario_version"`
	Simulated       bool          `json:"simulated"`
	Source          alertSource   `json:"source"`
	StartAt         string        `json:"start_at"`
	StopAt          string        `json:"stop_at"`
}

// BanIP adds a manual "ban" decision for a single IP for the given duration
// (CrowdSec duration string, e.g. "30m", "1h"). It returns the LAPI alert id
// reference, when available, so callers can record it.
func (c *Client) BanIP(ctx context.Context, ip, duration, reason string) (string, error) {
	if !c.IsConfigured() {
		return "", fmt.Errorf("crowdsec: not configured")
	}
	if reason == "" {
		reason = "manual ban from xa-fork"
	}
	scenario := "xa-fork/manual-ban"
	now := time.Now().UTC()
	a := alert{
		Capacity: 0,
		Decisions: []decision{{
			Duration: duration,
			Origin:   "cscli",
			Scenario: reason,
			Scope:    "Ip",
			Type:     "ban",
			Value:    ip,
		}},
		Events:          []interface{}{},
		EventsCount:     1,
		Leakspeed:       "0",
		Message:         fmt.Sprintf("manual 'ban' for ip '%s': %s", ip, reason),
		Scenario:        scenario,
		ScenarioHash:    "",
		ScenarioVersion: "",
		Simulated:       false,
		Source:          alertSource{Scope: "Ip", Value: ip},
		StartAt:         now.Format(time.RFC3339),
		StopAt:          now.Format(time.RFC3339),
	}

	body, _ := json.Marshal([]alert{a})
	data, status, err := c.authedRequest(ctx, http.MethodPost, "/v1/alerts", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return "", fmt.Errorf("crowdsec: ban failed: status %d, body: %s", status, string(data))
	}

	// /v1/alerts returns a JSON array of created alert ids (strings).
	var ids []string
	if err := json.Unmarshal(data, &ids); err == nil && len(ids) > 0 {
		return ids[0], nil
	}
	return "", nil
}

// UnbanIP deletes all decisions for the given IP. Returns the number deleted.
func (c *Client) UnbanIP(ctx context.Context, ip string) (int, error) {
	if !c.IsConfigured() {
		return 0, fmt.Errorf("crowdsec: not configured")
	}
	path := "/v1/decisions?ip=" + url.QueryEscape(ip)
	data, status, err := c.authedRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("crowdsec: unban failed: status %d, body: %s", status, string(data))
	}
	var res struct {
		NbDeleted string `json:"nbDeleted"`
	}
	_ = json.Unmarshal(data, &res)
	n := 0
	fmt.Sscanf(res.NbDeleted, "%d", &n)
	return n, nil
}
