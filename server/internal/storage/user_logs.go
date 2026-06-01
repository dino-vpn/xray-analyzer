package storage

import (
	"context"
	"strings"
	"time"

	"github.com/xray-log-analyzer/server/internal/models"
)

// UserLogFilter parameterizes the unified per-user event log query.
// Since is an inclusive lower bound on ts; Until (optional) an exclusive upper
// bound. Kind selects which source tables to include. Query is a free-text
// substring matched against IP / destination / category / description. Node
// filters on the analyzer text node_id. Sort/Order control ordering.
type UserLogFilter struct {
	Since  time.Time
	Until  *time.Time
	Kind   string // all|threat|blacklist|anomaly
	Query  string // substring search (raw, wrapped with % internally)
	Node   string // text node_id filter
	Sort   string // ts|category|ip|destination|node
	Order  string // asc|desc
	Limit  int
	Offset int
}

// Shared params across every branch: $1=uuids, $2=since, $3=until, $4=q, $5=node.
// Explicit casts on every projected column keep the UNION column types stable
// regardless of which branches are included.
const userLogThreatBranch = `
	SELECT tm.ts AS ts,
	       'threat'::text AS kind,
	       tm.threat_type::text AS category,
	       COALESCE(host(tm.source_ip), '')::text AS source_ip,
	       tm.destination::text AS destination,
	       COALESCE(n.node_id, '')::text AS node_id,
	       tm.source::text AS source,
	       0::smallint AS severity,
	       tm.confidence::integer AS confidence,
	       COALESCE(tm.description, '')::text AS description
	FROM threat_matches tm
	LEFT JOIN nodes n ON n.id = tm.node_id
	WHERE tm.user_email = ANY($1) AND tm.ts >= $2
	  AND ($3::timestamptz IS NULL OR tm.ts < $3)
	  AND ($4::text IS NULL OR host(tm.source_ip) ILIKE $4 OR tm.destination ILIKE $4 OR tm.threat_type ILIKE $4)
	  AND ($5::text IS NULL OR n.node_id = $5)`

const userLogBlacklistBranch = `
	SELECT bm.ts AS ts,
	       'blacklist'::text AS kind,
	       bm.matched_rule::text AS category,
	       COALESCE(host(bm.source_ip), '')::text AS source_ip,
	       bm.destination::text AS destination,
	       COALESCE(n.node_id, '')::text AS node_id,
	       ''::text AS source,
	       0::smallint AS severity,
	       0::integer AS confidence,
	       ''::text AS description
	FROM blacklist_matches bm
	LEFT JOIN nodes n ON n.id = bm.node_id
	WHERE bm.user_email = ANY($1) AND bm.ts >= $2
	  AND ($3::timestamptz IS NULL OR bm.ts < $3)
	  AND ($4::text IS NULL OR host(bm.source_ip) ILIKE $4 OR bm.destination ILIKE $4 OR bm.matched_rule ILIKE $4)
	  AND ($5::text IS NULL OR n.node_id = $5)`

// Anomalies carry no source_ip / destination / node, so the node filter ($5)
// excludes them entirely when set.
const userLogAnomalyBranch = `
	SELECT a.ts AS ts,
	       'anomaly'::text AS kind,
	       a.type::text AS category,
	       ''::text AS source_ip,
	       ''::text AS destination,
	       ''::text AS node_id,
	       ''::text AS source,
	       a.severity::smallint AS severity,
	       0::integer AS confidence,
	       COALESCE(a.description, '')::text AS description
	FROM anomalies a
	WHERE a.user_email = ANY($1) AND a.ts >= $2
	  AND ($3::timestamptz IS NULL OR a.ts < $3)
	  AND ($4::text IS NULL OR a.type ILIKE $4 OR a.description ILIKE $4)
	  AND ($5::text IS NULL)`

// userLogSortExpr maps a whitelisted sort key to a column of the UNION.
var userLogSortExpr = map[string]string{
	"ts":          "ts",
	"category":    "category",
	"ip":          "source_ip",
	"destination": "destination",
	"node":        "node_id",
}

// branchesForKind returns the SQL branches included for the requested kind.
func branchesForKind(kind string) []string {
	switch kind {
	case "threat":
		return []string{userLogThreatBranch}
	case "blacklist":
		return []string{userLogBlacklistBranch}
	case "anomaly":
		return []string{userLogAnomalyBranch}
	default:
		return []string{userLogThreatBranch, userLogBlacklistBranch, userLogAnomalyBranch}
	}
}

// GetUserEventLog returns one page of the unified per-user event log plus the
// total row count for the same filter. The email is resolved to its canonical
// UUID(s) first (the schema-v2 hot tables key on user_email uuid).
func (s *Storage) GetUserEventLog(ctx context.Context, userEmail string, f UserLogFilter) ([]models.UserLogEvent, int, error) {
	uuids := s.buildBlacklistSearchUUIDs(ctx, userEmail)
	if len(uuids) == 0 {
		return []models.UserLogEvent{}, 0, nil
	}

	// Shared filter params $1..$5.
	var until interface{}
	if f.Until != nil {
		until = f.Until.UTC()
	}
	var q interface{}
	if f.Query != "" {
		q = "%" + f.Query + "%"
	}
	var node interface{}
	if f.Node != "" {
		node = f.Node
	}
	args := []interface{}{uuids, f.Since.UTC(), until, q, node}

	union := strings.Join(branchesForKind(f.Kind), "\nUNION ALL\n")

	// Total count over the same union.
	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM (\n"+union+"\n) e", args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Ordering: whitelisted column + direction, ts as deterministic tiebreak.
	sortCol, ok := userLogSortExpr[f.Sort]
	if !ok {
		sortCol = "ts"
	}
	dir := "DESC"
	if strings.EqualFold(f.Order, "asc") {
		dir = "ASC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	dataSQL := "SELECT ts, kind, category, source_ip, destination, node_id, source, severity, confidence, description FROM (\n" +
		union + "\n) e ORDER BY " + sortCol + " " + dir + ", ts DESC LIMIT $6 OFFSET $7"
	rows, err := s.pool.Query(ctx, dataSQL, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	events := []models.UserLogEvent{}
	for rows.Next() {
		var e models.UserLogEvent
		var sev int16
		if err := rows.Scan(&e.TS, &e.Kind, &e.Category, &e.SourceIP, &e.Destination,
			&e.NodeID, &e.Source, &sev, &e.Confidence, &e.Description); err != nil {
			return nil, 0, err
		}
		if e.NodeID != "" {
			e.NodeName = s.nodeName(e.NodeID)
		}
		if e.Kind == "anomaly" {
			e.Severity = string(intToSeverity(sev))
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return events, total, nil
}
