package storage

import (
	"context"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// EnforcementAction is one operator action taken from the Attacks tab:
// a Remnawave disable/delete or a CrowdSec IP ban/unban. Persisted to
// enforcement_actions for the "Журнал действий" panel and active-ban display.
type EnforcementAction struct {
	ID          int64     `json:"id"`
	ActionType  string    `json:"action_type"` // remna_disable|remna_delete|ip_ban|ip_unban
	UserEmail   string    `json:"user_email,omitempty"`
	TargetIP    string    `json:"target_ip,omitempty"`
	Duration    string    `json:"duration,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Status      string    `json:"status"` // success|failed
	Error       string    `json:"error,omitempty"`
	DecisionRef string    `json:"decision_ref,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// nullableUUID returns the parsed uuid or nil so an empty/invalid value maps to
// SQL NULL on the uuid column.
func nullableUUID(s string) interface{} {
	if s == "" {
		return nil
	}
	if u, err := uuid.Parse(s); err == nil {
		return u
	}
	return nil
}

func nullableStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// RecordEnforcementAction inserts an action row and fills in ID/CreatedAt.
func (s *Storage) RecordEnforcementAction(ctx context.Context, a *EnforcementAction) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO enforcement_actions
			(action_type, user_email, target_ip, duration, reason, status, error, decision_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at
	`,
		a.ActionType,
		nullableUUID(a.UserEmail),
		nullableStr(a.TargetIP),
		nullableStr(a.Duration),
		nullableStr(a.Reason),
		a.Status,
		nullableStr(a.Error),
		nullableStr(a.DecisionRef),
	).Scan(&a.ID, &a.CreatedAt)
}

// GetEnforcementActions returns the action log, newest first, optionally scoped
// to a single user (empty userEmail = all users).
func (s *Storage) GetEnforcementActions(ctx context.Context, userEmail string, limit int) ([]*EnforcementAction, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `
		SELECT id, action_type, COALESCE(user_email::text, ''), COALESCE(host(target_ip), ''),
		       COALESCE(duration, ''), COALESCE(reason, ''), status, COALESCE(error, ''),
		       COALESCE(decision_ref, ''), created_at
		FROM enforcement_actions
	`
	args := []interface{}{}
	if userEmail != "" {
		uid := nullableUUID(userEmail)
		if uid == nil {
			return []*EnforcementAction{}, nil
		}
		args = append(args, uid)
		query += " WHERE user_email = $1"
	}
	args = append(args, limit)
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*EnforcementAction{}
	for rows.Next() {
		a := &EnforcementAction{}
		if err := rows.Scan(&a.ID, &a.ActionType, &a.UserEmail, &a.TargetIP,
			&a.Duration, &a.Reason, &a.Status, &a.Error, &a.DecisionRef, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetActiveIPBans returns IPs of a user that have a successful ip_ban with no
// later successful ip_unban — i.e. the bans the operator can still lift. Note
// CrowdSec expires bans on its own; this reflects what we initiated, so the UI
// should treat it as best-effort.
func (s *Storage) GetActiveIPBans(ctx context.Context, userEmail string) ([]*EnforcementAction, error) {
	uid := nullableUUID(userEmail)
	if uid == nil {
		return []*EnforcementAction{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		WITH bans AS (
			SELECT DISTINCT ON (host(target_ip))
			       id, host(target_ip) AS ip, COALESCE(duration, '') AS duration,
			       COALESCE(reason, '') AS reason, COALESCE(decision_ref, '') AS decision_ref, created_at
			FROM enforcement_actions
			WHERE user_email = $1 AND action_type = 'ip_ban' AND status = 'success' AND target_ip IS NOT NULL
			ORDER BY host(target_ip), created_at DESC
		),
		unbans AS (
			SELECT host(target_ip) AS ip, MAX(created_at) AS unbanned_at
			FROM enforcement_actions
			WHERE user_email = $1 AND action_type = 'ip_unban' AND status = 'success' AND target_ip IS NOT NULL
			GROUP BY host(target_ip)
		)
		SELECT b.id, b.ip, b.duration, b.reason, b.decision_ref, b.created_at
		FROM bans b
		LEFT JOIN unbans u ON u.ip = b.ip
		WHERE u.unbanned_at IS NULL OR u.unbanned_at < b.created_at
		ORDER BY b.created_at DESC
	`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*EnforcementAction{}
	for rows.Next() {
		a := &EnforcementAction{ActionType: "ip_ban", Status: "success", UserEmail: userEmail}
		if err := rows.Scan(&a.ID, &a.TargetIP, &a.Duration, &a.Reason, &a.DecisionRef, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
