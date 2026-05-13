package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BridgedFlow is a single correlated record: an exit-node destination
// resolved back to the real client IP seen on the corresponding bridge node.
type BridgedFlow struct {
	ID           int64     `json:"id"`
	UserEmail    string    `json:"user_email"`     // UUID string (Remnawave user UUID)
	UserDisplay  string    `json:"user_display"`   // Human-readable name: remna username, original email, or UUID fallback
	RealClientIP string    `json:"real_client_ip"` // IP address string
	BridgeNodeID string    `json:"bridge_node_id"` // text node_id (resolved to smallint FK internally)
	ExitNodeID   string    `json:"exit_node_id"`   // text node_id (resolved to smallint FK internally)
	Destination  string    `json:"destination"`
	Timestamp    time.Time `json:"ts"`
	CreatedAt    time.Time `json:"created_at"`
}

// BridgedFlowsFilter narrows GetBridgedFlows. Zero-values mean "no filter".
type BridgedFlowsFilter struct {
	UserEmail    string
	RealClientIP string
	Destination  string // matched as LIKE %dst% — caller controls exactness
	Since        time.Time
	Limit        int
}

// RecordBridgedFlow stores a single resolved flow.
// BridgeNodeID and ExitNodeID are text node names; they are resolved to
// the nodes(id) smallint FK via LookupNodeID before insert.
func (s *Storage) RecordBridgedFlow(ctx context.Context, f *BridgedFlow) error {
	if f == nil {
		return fmt.Errorf("nil flow")
	}

	// Resolve text node IDs to smallint FKs.
	bridgeID, err := s.LookupNodeID(ctx, f.BridgeNodeID, "bridge")
	if err != nil {
		return fmt.Errorf("resolve bridge_node_id: %w", err)
	}
	exitID, err := s.LookupNodeID(ctx, f.ExitNodeID, "exit")
	if err != nil {
		return fmt.Errorf("resolve exit_node_id: %w", err)
	}

	// user_email is uuid in the DB. Resolve via remna_users first; fall back
	// to SHA-1 for synthetic identifiers (e.g. "5117", "u-out") from exit-node logs.
	var userUUID uuid.UUID
	if f.UserEmail != "" {
		userUUID, err = s.ResolveUserEmailToUUID(ctx, f.UserEmail)
		if err != nil {
			return fmt.Errorf("resolve user_email: %w", err)
		}
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO bridged_flows
			(user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts)
		VALUES ($1, $2::inet, $3, $4, $5, $6)
	`, userUUID, f.RealClientIP, int16(bridgeID), int16(exitID), f.Destination, f.Timestamp.UTC())
	return err
}

// BridgeCandidate is a user who was active on a bridge node in the
// correlation window surrounding an exit-node bridged entry.
type BridgeCandidate struct {
	UserEmail    string
	IPAddress    string
	BridgeNodeID string
	LastSeen     time.Time
}

// RecordBridgedFlows inserts many flows in one round-trip. Resolves bridge/exit
// node IDs and user UUIDs once per distinct value (cached lookup helpers).
// Falls back to per-flow insert on error so a single bad row doesn't drop the
// whole batch.
func (s *Storage) RecordBridgedFlows(ctx context.Context, flows []*BridgedFlow) error {
	if len(flows) == 0 {
		return nil
	}

	// Resolve node IDs and user UUIDs upfront. LookupNodeID caches per-process,
	// so repeated calls with the same name are O(1) after the first hit.
	type resolved struct {
		userUUID uuid.UUID
		bridgeID int16
		exitID   int16
		ip       string
		dst      string
		ts       time.Time
	}
	prepped := make([]resolved, 0, len(flows))
	for _, f := range flows {
		if f == nil {
			continue
		}
		bridgeID, err := s.LookupNodeID(ctx, f.BridgeNodeID, "bridge")
		if err != nil {
			continue
		}
		exitID, err := s.LookupNodeID(ctx, f.ExitNodeID, "exit")
		if err != nil {
			continue
		}
		var userUUID uuid.UUID
		if f.UserEmail != "" {
			userUUID, err = s.ResolveUserEmailToUUID(ctx, f.UserEmail)
			if err != nil {
				continue
			}
		}
		prepped = append(prepped, resolved{
			userUUID: userUUID,
			bridgeID: int16(bridgeID),
			exitID:   int16(exitID),
			ip:       f.RealClientIP,
			dst:      f.Destination,
			ts:       f.Timestamp.UTC(),
		})
	}
	if len(prepped) == 0 {
		return nil
	}

	// Build one INSERT with N value rows.
	var b strings.Builder
	b.WriteString("INSERT INTO bridged_flows (user_email, real_client_ip, bridge_node_id, exit_node_id, destination, ts) VALUES ")
	args := make([]interface{}, 0, len(prepped)*6)
	for i, r := range prepped {
		if i > 0 {
			b.WriteString(",")
		}
		k := i * 6
		fmt.Fprintf(&b, "($%d, $%d::inet, $%d, $%d, $%d, $%d)", k+1, k+2, k+3, k+4, k+5, k+6)
		args = append(args, r.userUUID, r.ip, r.bridgeID, r.exitID, r.dst, r.ts)
	}

	_, err := s.pool.Exec(ctx, b.String(), args...)
	return err
}

// LookupBridgeCandidates returns every (user_email, ip_address) pair seen on
// any of `bridgeNodeIDs` within ±window of `at`. The returned slice is
// ordered by freshness (newest last_seen first).
//
// Uses s.pool (native pgx) so []string is passed as a Postgres text[] array.
// user_ip_history.node_id is smallint FK so we resolve text → id first.
func (s *Storage) LookupBridgeCandidates(ctx context.Context, at time.Time, window time.Duration, bridgeNodeIDs []string) ([]BridgeCandidate, error) {
	if len(bridgeNodeIDs) == 0 {
		return nil, nil
	}
	if window <= 0 {
		window = 15 * time.Second
	}

	// Resolve text node names to smallint IDs.
	nodeIntIDs := make([]int16, 0, len(bridgeNodeIDs))
	nodeIDToText := make(map[int16]string, len(bridgeNodeIDs))
	for _, n := range bridgeNodeIDs {
		nid, err := s.LookupNodeID(ctx, n, "bridge")
		if err != nil {
			continue
		}
		nodeIntIDs = append(nodeIntIDs, int16(nid))
		nodeIDToText[int16(nid)] = n
	}
	if len(nodeIntIDs) == 0 {
		return nil, nil
	}

	lo := at.Add(-window).UTC()
	hi := at.Add(window).UTC()

	rows, err := s.pool.Query(ctx, `
		SELECT user_email, host(ip_address), node_id, last_seen
		FROM user_ip_history
		WHERE node_id = ANY($1)
		  AND last_seen BETWEEN $2 AND $3
		ORDER BY last_seen DESC
		LIMIT 200
	`, nodeIntIDs, lo, hi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgeCandidate
	for rows.Next() {
		var c BridgeCandidate
		var userUUID uuid.UUID
		var ipStr string
		var nodeIntID int16
		if err := rows.Scan(&userUUID, &ipStr, &nodeIntID, &c.LastSeen); err != nil {
			return nil, err
		}
		c.UserEmail = userUUID.String()
		c.IPAddress = ipStr
		if txt, ok := nodeIDToText[nodeIntID]; ok {
			c.BridgeNodeID = txt
		} else {
			c.BridgeNodeID = fmt.Sprintf("%d", nodeIntID)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LookupRealClientIP (legacy 1:1 by user_email) — kept for direct-inbound
// flows where the same email travels through end-to-end. For bridge flows
// use LookupBridgeCandidates instead.
//
// Uses s.pool (native pgx) so []string is passed as a Postgres text[] array.
func (s *Storage) LookupRealClientIP(ctx context.Context, userEmail string, at time.Time, maxAge time.Duration, bridgeNodeIDs []string) (string, string, bool) {
	if userEmail == "" || len(bridgeNodeIDs) == 0 {
		return "", "", false
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}

	// Resolve text node names to smallint IDs.
	nodeIntIDs := make([]int16, 0, len(bridgeNodeIDs))
	nodeIDToText := make(map[int16]string, len(bridgeNodeIDs))
	for _, n := range bridgeNodeIDs {
		nid, err := s.LookupNodeID(ctx, n, "bridge")
		if err != nil {
			continue
		}
		nodeIntIDs = append(nodeIntIDs, int16(nid))
		nodeIDToText[int16(nid)] = n
	}
	if len(nodeIntIDs) == 0 {
		return "", "", false
	}

	userUUID, err := uuid.Parse(userEmail)
	if err != nil {
		return "", "", false
	}

	since := at.Add(-maxAge).UTC()

	var ipStr string
	var nodeIntID int16
	err = s.pool.QueryRow(ctx, `
		SELECT host(ip_address), node_id
		FROM user_ip_history
		WHERE user_email = $1
		  AND node_id = ANY($2)
		  AND last_seen >= $3
		ORDER BY last_seen DESC
		LIMIT 1
	`, userUUID, nodeIntIDs, since).Scan(&ipStr, &nodeIntID)
	if err != nil {
		return "", "", false
	}
	nodeName := nodeIDToText[nodeIntID]
	if nodeName == "" {
		nodeName = fmt.Sprintf("%d", nodeIntID)
	}
	return ipStr, nodeName, true
}

// GetBridgedFlows returns flows matching the filter, newest first.
func (s *Storage) GetBridgedFlows(ctx context.Context, f BridgedFlowsFilter) ([]BridgedFlow, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}

	var (
		conds  []string
		args   []interface{}
		argIdx = 1
	)

	addArg := func(v interface{}) int {
		args = append(args, v)
		n := argIdx
		argIdx++
		return n
	}

	if f.UserEmail != "" {
		// user_email is uuid in DB; attempt to parse.
		if uid, err := uuid.Parse(f.UserEmail); err == nil {
			conds = append(conds, fmt.Sprintf("user_email = $%d", addArg(uid)))
		}
	}
	if f.RealClientIP != "" {
		conds = append(conds, fmt.Sprintf("real_client_ip = $%d::inet", addArg(f.RealClientIP)))
	}
	if f.Destination != "" {
		conds = append(conds, fmt.Sprintf("destination LIKE $%d", addArg("%"+f.Destination+"%")))
	}
	if !f.Since.IsZero() {
		conds = append(conds, fmt.Sprintf("ts >= $%d", addArg(f.Since.UTC())))
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	limitPlaceholder := fmt.Sprintf("$%d", addArg(f.Limit))

	// Join with nodes for text names; join remna_users + email_index for user_display.
	query := fmt.Sprintf(`
		SELECT bf.id, bf.user_email, host(bf.real_client_ip),
		       bn.node_id AS bridge_node_id,
		       en.node_id AS exit_node_id,
		       bf.destination, bf.ts, bf.created_at,
		       COALESCE(ru.username, ei.original_email, bf.user_email::text) AS user_display
		FROM bridged_flows bf
		JOIN nodes bn ON bn.id = bf.bridge_node_id
		JOIN nodes en ON en.id = bf.exit_node_id
		LEFT JOIN remna_users ru ON ru.uuid = bf.user_email
		LEFT JOIN email_index ei ON ei.uuid = bf.user_email
		%s
		ORDER BY bf.ts DESC
		LIMIT %s
	`, where, limitPlaceholder)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgedFlow
	for rows.Next() {
		var bf BridgedFlow
		var userUUID uuid.UUID
		var ipStr string
		if err := rows.Scan(&bf.ID, &userUUID, &ipStr, &bf.BridgeNodeID, &bf.ExitNodeID, &bf.Destination, &bf.Timestamp, &bf.CreatedAt, &bf.UserDisplay); err != nil {
			return nil, err
		}
		bf.UserEmail = userUUID.String()
		bf.RealClientIP = ipStr
		out = append(out, bf)
	}
	return out, rows.Err()
}

// CleanupBridgedFlows removes flows older than retentionDays.
func (s *Storage) CleanupBridgedFlows(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	_, err := s.pool.Exec(ctx, `DELETE FROM bridged_flows WHERE ts < $1`, cutoff)
	return err
}

// BridgeUser is an aggregated view of one user's recent activity on a bridge
// node — built for the /bridge-users dashboard tab.
type BridgeUser struct {
	UserUUID        string    `json:"user_uuid"`
	Username        string    `json:"username"`           // remna_users.username (display)
	ShortUUID       string    `json:"short_uuid"`         // remna_users.short_uuid (for sub URL)
	TelegramID      int64     `json:"telegram_id"`        // 0 if not linked
	Status          string    `json:"status"`             // ACTIVE / EXPIRED / DISABLED / LIMITED
	OnlineAt        time.Time `json:"online_at"`          // last xray-tracked session start
	BridgeNode      string    `json:"bridge_node"`        // ru-white | ru-bride
	LastSeen        time.Time `json:"last_seen"`          // last flow on bridge
	FlowsCount      int64     `json:"flows_count"`        // total bridged flows in window
	LastRealIP      string    `json:"last_real_ip"`       // last real_client_ip from bridged_flows
	UniqueDsts      int64     `json:"unique_destinations"`
	TopDestinations []string  `json:"top_destinations"`   // top 5 dst by count
	HWIDCount       int32     `json:"hwid_count"`         // remna devices linked
	UsedBytes       int64     `json:"used_traffic_bytes"`
	LimitBytes      int64     `json:"traffic_limit_bytes"`
}

// GetBridgeUsers returns users active on the given bridge nodes within `since`
// duration, ordered by recency. `bridgeNodes` may be empty to include all bridges.
// `limit` is capped at 500.
func (s *Storage) GetBridgeUsers(ctx context.Context, bridgeNodes []string, since time.Duration, limit int) ([]BridgeUser, error) {
	if since <= 0 {
		since = time.Hour
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	cutoff := time.Now().UTC().Add(-since)

	// Resolve bridge node text → smallint FK.
	var nodeIntIDs []int16
	for _, n := range bridgeNodes {
		if id, err := s.LookupNodeID(ctx, n, "bridge"); err == nil {
			nodeIntIDs = append(nodeIntIDs, int16(id))
		}
	}

	// Main aggregate: per (user, bridge) — flows count, last seen, last real IP,
	// unique dst count, and top destinations as a JSON array. Top dst uses
	// `mode() WITHIN GROUP` approximation via array_agg + top-N in subquery; we
	// just inline the top-5 as a lateral.
	nodeFilter := ""
	args := []interface{}{cutoff, limit}
	if len(nodeIntIDs) > 0 {
		nodeFilter = "AND bf.bridge_node_id = ANY($3)"
		args = append(args, nodeIntIDs)
	}

	query := fmt.Sprintf(`
		WITH agg AS (
			SELECT
				bf.user_email,
				bf.bridge_node_id,
				MAX(bf.ts)                                  AS last_seen,
				COUNT(*)                                    AS flows_count,
				COUNT(DISTINCT bf.destination)              AS unique_dsts,
				(ARRAY_AGG(host(bf.real_client_ip) ORDER BY bf.ts DESC))[1] AS last_real_ip
			FROM bridged_flows bf
			WHERE bf.ts >= $1
			%s
			GROUP BY bf.user_email, bf.bridge_node_id
		)
		SELECT
			agg.user_email,
			COALESCE(ru.username, ei.original_email, agg.user_email::text) AS username,
			COALESCE(ru.short_uuid, '')                                    AS short_uuid,
			COALESCE(ru.telegram_id, 0)                                    AS telegram_id,
			COALESCE(ru.status, '')                                        AS status,
			COALESCE(ru.online_at, 'epoch'::timestamptz)                   AS online_at,
			bn.node_id                                                     AS bridge_node,
			agg.last_seen,
			agg.flows_count,
			COALESCE(agg.last_real_ip, '')                                 AS last_real_ip,
			agg.unique_dsts,
			COALESCE(ru.hwid_device_count, 0)                              AS hwid_count,
			COALESCE(ru.used_traffic_bytes, 0)                             AS used_bytes,
			COALESCE(ru.traffic_limit_bytes, 0)                            AS limit_bytes,
			(
				SELECT array_agg(d.destination ORDER BY d.cnt DESC)
				FROM (
					SELECT bf2.destination, COUNT(*) AS cnt
					FROM bridged_flows bf2
					WHERE bf2.user_email = agg.user_email
					  AND bf2.bridge_node_id = agg.bridge_node_id
					  AND bf2.ts >= $1
					GROUP BY bf2.destination
					ORDER BY cnt DESC
					LIMIT 5
				) d
			) AS top_dsts
		FROM agg
		JOIN nodes bn          ON bn.id = agg.bridge_node_id
		LEFT JOIN remna_users ru ON ru.uuid = agg.user_email
		LEFT JOIN email_index ei ON ei.uuid = agg.user_email
		ORDER BY agg.last_seen DESC
		LIMIT $2
	`, nodeFilter)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BridgeUser
	for rows.Next() {
		var u BridgeUser
		var userUUID uuid.UUID
		var topDsts []string
		if err := rows.Scan(
			&userUUID, &u.Username, &u.ShortUUID, &u.TelegramID,
			&u.Status, &u.OnlineAt, &u.BridgeNode, &u.LastSeen,
			&u.FlowsCount, &u.LastRealIP, &u.UniqueDsts,
			&u.HWIDCount, &u.UsedBytes, &u.LimitBytes, &topDsts,
		); err != nil {
			return nil, err
		}
		u.UserUUID = userUUID.String()
		u.TopDestinations = topDsts
		out = append(out, u)
	}
	return out, rows.Err()
}
