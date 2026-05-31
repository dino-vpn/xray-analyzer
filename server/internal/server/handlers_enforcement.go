package server

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xray-log-analyzer/server/internal/storage"
)

// allowedBanDurations is the white-list of ban presets the UI offers. Keys are
// the CrowdSec duration strings; banning with anything else is rejected.
var allowedBanDurations = map[string]bool{
	"30m": true,
	"1h":  true,
	"3h":  true,
	"6h":  true,
	"12h": true,
	"24h": true,
}

// writeJSONStatus writes a JSON body with an explicit HTTP status code.
func writeJSONStatus(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// recordAction persists an enforcement action, logging (but not failing) if the
// audit write itself errors — the action already happened.
func (s *Server) recordAction(ctx context.Context, a *storage.EnforcementAction) {
	if err := s.storage.RecordEnforcementAction(ctx, a); err != nil {
		log.Printf("[enforcement] failed to record action %s ip=%s user=%s: %v",
			a.ActionType, a.TargetIP, a.UserEmail, err)
	}
}

// validUUID returns the trimmed value if it parses as a UUID, else "".
func validUUID(s string) string {
	s = strings.TrimSpace(s)
	if _, err := uuid.Parse(s); err != nil {
		return ""
	}
	return s
}

// handleUserDetections returns the full per-user detection history for the
// Attacks-tab drill-down: anomalies, threat matches, the user's source IPs
// (candidates for an IP ban), the enforcement action log, and active bans.
// It also reports which integrations are configured so the UI can gate buttons.
//
// Query params: user_email (required, UUID), since (duration, default 720h).
func (s *Server) handleUserDetections(w http.ResponseWriter, r *http.Request) {
	userEmail := validUUID(r.URL.Query().Get("user_email"))
	if userEmail == "" {
		http.Error(w, "user_email (uuid) required", http.StatusBadRequest)
		return
	}
	since := 30 * 24 * time.Hour
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			since = d
		}
	}
	ctx := r.Context()

	anomalies, err := s.storage.GetAnomaliesByUser(ctx, userEmail, since, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	matches, err := s.storage.GetThreatMatchesByUser(ctx, userEmail, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ips, err := s.storage.GetUserIPHistory(ctx, userEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	actions, err := s.storage.GetEnforcementActions(ctx, userEmail, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	activeBans, err := s.storage.GetActiveIPBans(ctx, userEmail)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := ""
	if names, nerr := s.storage.ResolveUUIDUsernames(ctx, []string{userEmail}); nerr == nil {
		username = names[userEmail]
	}
	if username == "" && s.remnawave != nil {
		if resolved := s.remnawave.ResolveUsername(ctx, userEmail); resolved != userEmail {
			username = resolved
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"user_email":        userEmail,
		"username":          username,
		"anomalies":         anomalies,
		"threat_matches":    matches,
		"ips":               ips,
		"actions":           actions,
		"active_bans":       activeBans,
		"remnawave_enabled": s.remnawave != nil && s.remnawave.IsConfigured(),
		"crowdsec_enabled":  s.crowdsec != nil && s.crowdsec.IsConfigured(),
	})
}

// handleEnforcementActions returns the enforcement audit log, optionally scoped
// to a user via ?user_email=. Read-only.
func (s *Server) handleEnforcementActions(w http.ResponseWriter, r *http.Request) {
	userEmail := strings.TrimSpace(r.URL.Query().Get("user_email"))
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	actions, err := s.storage.GetEnforcementActions(r.Context(), userEmail, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(actions),
		"actions": actions,
	})
}

// handleRemnawaveDisable disables a user on the Remnawave panel and records the
// action. POST {user_email}.
func (s *Server) handleRemnawaveDisable(w http.ResponseWriter, r *http.Request) {
	s.handleRemnawaveAction(w, r, "remna_disable")
}

// handleRemnawaveDelete permanently deletes a user on the Remnawave panel and
// records the action. POST {user_email}.
func (s *Server) handleRemnawaveDelete(w http.ResponseWriter, r *http.Request) {
	s.handleRemnawaveAction(w, r, "remna_delete")
}

// handleRemnawaveAction is the shared body for disable/delete.
func (s *Server) handleRemnawaveAction(w http.ResponseWriter, r *http.Request, actionType string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UserEmail string `json:"user_email"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	userEmail := validUUID(req.UserEmail)
	if userEmail == "" {
		http.Error(w, "user_email (uuid) required", http.StatusBadRequest)
		return
	}
	if s.remnawave == nil || !s.remnawave.IsConfigured() {
		http.Error(w, "remnawave not configured", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	var actErr error
	if actionType == "remna_delete" {
		actErr = s.remnawave.DeleteUser(ctx, userEmail)
	} else {
		actErr = s.remnawave.DisableUser(ctx, userEmail)
	}

	rec := &storage.EnforcementAction{
		ActionType: actionType,
		UserEmail:  userEmail,
		Reason:     req.Reason,
		Status:     "success",
	}
	if actErr != nil {
		rec.Status = "failed"
		rec.Error = actErr.Error()
	}
	s.recordAction(ctx, rec)

	if actErr != nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]interface{}{
			"status": "failed",
			"error":  actErr.Error(),
		})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]interface{}{"status": "success"})
}

// handleIPBan bans one or more of a user's source IPs via CrowdSec for the
// chosen preset duration. POST {user_email, ips:[], duration, reason}.
func (s *Server) handleIPBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UserEmail string   `json:"user_email"`
		IPs       []string `json:"ips"`
		Duration  string   `json:"duration"`
		Reason    string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if s.crowdsec == nil || !s.crowdsec.IsConfigured() {
		http.Error(w, "crowdsec not configured", http.StatusServiceUnavailable)
		return
	}
	userEmail := validUUID(req.UserEmail) // may be "" — bans still allowed, just not user-scoped
	duration := strings.TrimSpace(req.Duration)
	if !allowedBanDurations[duration] {
		http.Error(w, "duration must be one of 30m,1h,3h,6h,12h,24h", http.StatusBadRequest)
		return
	}
	if len(req.IPs) == 0 {
		http.Error(w, "ips required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	results := make([]map[string]interface{}, 0, len(req.IPs))
	for _, raw := range req.IPs {
		ip := strings.TrimSpace(raw)
		if net.ParseIP(ip) == nil {
			results = append(results, map[string]interface{}{"ip": ip, "status": "failed", "error": "invalid ip"})
			continue
		}
		ref, banErr := s.crowdsec.BanIP(ctx, ip, duration, req.Reason)
		rec := &storage.EnforcementAction{
			ActionType:  "ip_ban",
			UserEmail:   userEmail,
			TargetIP:    ip,
			Duration:    duration,
			Reason:      req.Reason,
			Status:      "success",
			DecisionRef: ref,
		}
		res := map[string]interface{}{"ip": ip, "status": "success"}
		if banErr != nil {
			rec.Status = "failed"
			rec.Error = banErr.Error()
			res["status"] = "failed"
			res["error"] = banErr.Error()
		}
		s.recordAction(ctx, rec)
		results = append(results, res)
	}

	writeJSONStatus(w, http.StatusOK, map[string]interface{}{"results": results})
}

// handleIPUnban lifts CrowdSec bans on the given IPs. POST {user_email?, ips:[]}.
func (s *Server) handleIPUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UserEmail string   `json:"user_email"`
		IPs       []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if s.crowdsec == nil || !s.crowdsec.IsConfigured() {
		http.Error(w, "crowdsec not configured", http.StatusServiceUnavailable)
		return
	}
	if len(req.IPs) == 0 {
		http.Error(w, "ips required", http.StatusBadRequest)
		return
	}
	userEmail := validUUID(req.UserEmail)

	ctx := r.Context()
	results := make([]map[string]interface{}, 0, len(req.IPs))
	for _, raw := range req.IPs {
		ip := strings.TrimSpace(raw)
		if net.ParseIP(ip) == nil {
			results = append(results, map[string]interface{}{"ip": ip, "status": "failed", "error": "invalid ip"})
			continue
		}
		n, unbanErr := s.crowdsec.UnbanIP(ctx, ip)
		rec := &storage.EnforcementAction{
			ActionType: "ip_unban",
			UserEmail:  userEmail,
			TargetIP:   ip,
			Status:     "success",
		}
		res := map[string]interface{}{"ip": ip, "status": "success", "deleted": n}
		if unbanErr != nil {
			rec.Status = "failed"
			rec.Error = unbanErr.Error()
			res["status"] = "failed"
			res["error"] = unbanErr.Error()
		}
		s.recordAction(ctx, rec)
		results = append(results, res)
	}

	writeJSONStatus(w, http.StatusOK, map[string]interface{}{"results": results})
}
