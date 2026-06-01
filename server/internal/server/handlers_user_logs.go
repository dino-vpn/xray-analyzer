package server

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
	"github.com/xray-log-analyzer/server/internal/storage"
)

// userLogKinds is the white-list of event-kind filters the logs endpoint accepts.
var userLogKinds = map[string]bool{"all": true, "threat": true, "blacklist": true, "anomaly": true}

// userEmailFromLogPath extracts the {email} segment from /api/users/{email}/logs
// or /api/users/{email}/logs/export.
func userEmailFromLogPath(p string) (string, bool) {
	p = strings.TrimSuffix(p, "/export")
	p = strings.TrimSuffix(p, "/logs")
	const prefix = "/api/users/"
	if !strings.HasPrefix(p, prefix) || len(p) <= len(prefix) {
		return "", false
	}
	email, err := url.QueryUnescape(strings.TrimPrefix(p, prefix))
	if err != nil || email == "" {
		return "", false
	}
	return email, true
}

// parseUserLogFilter builds a storage.UserLogFilter from the request query.
// Time range comes from explicit from/to (RFC3339) when present, else from the
// period preset (default 24h; "all" disables the lower bound).
func parseUserLogFilter(r *http.Request) storage.UserLogFilter {
	q := r.URL.Query()

	f := storage.UserLogFilter{
		Kind:  "all",
		Sort:  q.Get("sort"),
		Order: q.Get("order"),
		Query: strings.TrimSpace(q.Get("q")),
		Node:  strings.TrimSpace(q.Get("node")),
	}
	if k := q.Get("kind"); userLogKinds[k] {
		f.Kind = k
	}

	// Time range.
	f.Since = time.Now().Add(-24 * time.Hour)
	switch q.Get("period") {
	case "1h":
		f.Since = time.Now().Add(-1 * time.Hour)
	case "6h":
		f.Since = time.Now().Add(-6 * time.Hour)
	case "24h", "":
		// default
	case "7d":
		f.Since = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		f.Since = time.Now().Add(-30 * 24 * time.Hour)
	case "all":
		f.Since = time.Time{}
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = &t
		}
	}
	return f
}

// handleUserLogs serves a paginated page of the unified per-user event log.
// GET /api/users/{email}/logs?period=&kind=&q=&node=&sort=&order=&page=&page_size=
func (s *Server) handleUserLogs(w http.ResponseWriter, r *http.Request) {
	email, ok := userEmailFromLogPath(r.URL.Path)
	if !ok {
		http.Error(w, "user email required", http.StatusBadRequest)
		return
	}

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	pageSize := 50
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if n, err := strconv.Atoi(ps); err == nil && n > 0 && n <= 200 {
			pageSize = n
		}
	}

	f := parseUserLogFilter(r)
	f.Limit = pageSize
	f.Offset = (page - 1) * pageSize

	events, total, err := s.storage.GetUserEventLog(r.Context(), email, f)
	if err != nil {
		log.Printf("Error getting user event log: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(models.UserLogsResponse{
		Events:     events,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// handleUserLogsExport streams the unified event log as CSV for the current
// filter (no pagination, capped). GET /api/users/{email}/logs/export
func (s *Server) handleUserLogsExport(w http.ResponseWriter, r *http.Request) {
	email, ok := userEmailFromLogPath(r.URL.Path)
	if !ok {
		http.Error(w, "user email required", http.StatusBadRequest)
		return
	}

	f := parseUserLogFilter(r)
	f.Limit = 50000
	f.Offset = 0

	events, _, err := s.storage.GetUserEventLog(r.Context(), email, f)
	if err != nil {
		log.Printf("Error exporting user event log: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fname := "user-logs.csv"
	if len(email) >= 8 {
		fname = "user-" + sanitizeFilename(email[:8]) + "-logs.csv"
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+fname+"\"")

	// UTF-8 BOM so Excel reads Cyrillic descriptions correctly.
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "kind", "category", "ip", "destination", "node", "source", "severity", "confidence", "description"})
	for _, e := range events {
		node := e.NodeName
		if node == "" {
			node = e.NodeID
		}
		_ = cw.Write([]string{
			e.TS.Format(time.RFC3339),
			e.Kind,
			e.Category,
			e.SourceIP,
			e.Destination,
			node,
			e.Source,
			e.Severity,
			strconv.Itoa(e.Confidence),
			e.Description,
		})
	}
	cw.Flush()
}

// sanitizeFilename keeps the Content-Disposition filename safe (alnum/dash only).
func sanitizeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			return r
		default:
			return '-'
		}
	}, s)
}
