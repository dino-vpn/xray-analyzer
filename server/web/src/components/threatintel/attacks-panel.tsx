"use client";

import { Fragment, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { authFetch } from "@/contexts/auth-context";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Swords, RefreshCw, Target, Crosshair, Check, Copy, ChevronRight, ChevronDown, Server } from "lucide-react";
import { formatDistanceToNow, format } from "date-fns";
import { StatCard, StatCardGrid } from "./stat-card";
import { EnforcementDrill } from "./enforcement-drill";

// Incident = one attack detection. Shape mirrors /api/threatintel/attacks.
type AttackDetails = {
  port?: string;
  unique_ips?: number;
  unique_destinations?: number;
  target_subnet?: string;
  window_minutes?: number;
};

type Attack = {
  id: string;
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  user_email: string;
  username?: string;
  description: string;
  details?: AttackDetails | Record<string, unknown>;
  detected_at: string;
  resolved: boolean;
};

// One concrete destination behind an attack. Mirrors /api/threatintel/attacks/destinations.
type DestRow = {
  node_id: string;
  destination: string;
  request_count: number;
  first_seen: string;
  last_seen: string;
};

type DrillState = { loading: boolean; error?: boolean; rows?: DestRow[] };

const severityBadge: Record<string, string> = {
  low: "bg-blue-500/15 text-blue-700 dark:text-blue-300 border-blue-500/30",
  medium: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
  high: "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30",
  critical: "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30",
};

const typeLabel: Record<string, { label: string; icon: React.ReactNode }> = {
  port_scan: { label: "Port scan", icon: <Crosshair className="h-3.5 w-3.5" /> },
  abuse_port_flood: { label: "Brute-force / flood", icon: <Swords className="h-3.5 w-3.5" /> },
  burst_scan: { label: "Burst scan", icon: <Target className="h-3.5 w-3.5" /> },
};

const SINCE_OPTIONS = [
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7 days" },
];

// fmtTs renders an absolute UTC-local timestamp for forensic copy/paste.
function fmtTs(iso: string): string {
  try {
    return format(new Date(iso), "yyyy-MM-dd HH:mm:ss");
  } catch {
    return iso;
  }
}

// CopyButton copies `text` to the clipboard and flips to a checkmark briefly.
function CopyButton({ text, label, className }: { text: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className={`h-6 gap-1 px-1.5 text-xs ${className ?? ""}`}
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        } catch {
          /* clipboard unavailable (insecure context) — ignore */
        }
      }}
    >
      {copied ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
      {label}
    </Button>
  );
}

export function AttacksPanel() {
  const [since, setSince] = useState("24h");
  const [attacks, setAttacks] = useState<Attack[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [resolvingIds, setResolvingIds] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<string | null>(null);
  const [drill, setDrill] = useState<Record<string, DrillState>>({});

  const fetchAttacks = useCallback(async () => {
    setLoading(true);
    try {
      const res = await authFetch(`/api/threatintel/attacks?since=${since}&limit=200`);
      if (!res.ok) {
        console.error("attacks fetch failed:", res.status);
        setAttacks([]);
        return;
      }
      const json = await res.json();
      setAttacks(json.attacks || []);
    } catch (err) {
      console.error("attacks fetch error:", err);
      setAttacks([]);
    } finally {
      setLoading(false);
    }
  }, [since]);

  useEffect(() => {
    fetchAttacks();
    const t = setInterval(fetchAttacks, 60_000);
    return () => clearInterval(t);
  }, [fetchAttacks]);

  // loadDestinations fetches the per-destination breakdown for one attack and
  // stores it in `drill`. Shared by the expand handler and the retry button.
  const loadDestinations = useCallback(async (a: Attack) => {
    setDrill((p) => ({ ...p, [a.id]: { loading: true } }));
    try {
      const d = (a.details ?? {}) as AttackDetails;
      const params = new URLSearchParams({ user_email: a.user_email, detected_at: a.detected_at });
      if (d.port) params.set("port", String(d.port));
      if (d.target_subnet) params.set("subnet", String(d.target_subnet));
      if (d.window_minutes) params.set("window", String(d.window_minutes));
      const res = await authFetch(`/api/threatintel/attacks/destinations?${params.toString()}`);
      if (!res.ok) {
        setDrill((p) => ({ ...p, [a.id]: { loading: false, error: true } }));
        return;
      }
      const json = await res.json();
      setDrill((p) => ({ ...p, [a.id]: { loading: false, rows: json.destinations || [] } }));
    } catch {
      setDrill((p) => ({ ...p, [a.id]: { loading: false, error: true } }));
    }
  }, []);

  // toggleRow expands/collapses the per-destination drill-down for one attack,
  // lazily fetching the destinations the first time the row is opened.
  const toggleRow = useCallback(
    (a: Attack) => {
      if (expanded === a.id) {
        setExpanded(null);
        return;
      }
      setExpanded(a.id);
      if (!drill[a.id]?.rows) {
        loadDestinations(a);
      }
    },
    [expanded, drill, loadDestinations],
  );

  const resolve = async (id: string) => {
    setResolvingIds((prev) => new Set(prev).add(id));
    try {
      await authFetch(`/api/threatintel/anomalies?id=${encodeURIComponent(id)}`, { method: "DELETE" });
      setAttacks((prev) => (prev || []).filter((a) => a.id !== id));
    } finally {
      setResolvingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const list = attacks || [];
  const critical = list.filter((a) => a.severity === "critical").length;
  const high = list.filter((a) => a.severity === "high").length;
  const uniqUsers = new Set(list.map((a) => a.user_email)).size;
  const uniqScans = list.filter((a) => a.type === "port_scan").length;
  const uniqFloods = list.filter((a) => a.type === "abuse_port_flood").length;

  if (loading && attacks === null) {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-[400px] rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <StatCardGrid columns={4}>
        <StatCard
          icon={<Swords className="h-4 w-4" />}
          label="Active attacks"
          value={list.length}
          subValue={`${since} window`}
          variant={list.length > 0 ? "danger" : "muted"}
          highlight={list.length > 0}
        />
        <StatCard
          icon={<Target className="h-4 w-4" />}
          label="Critical + High"
          value={critical + high}
          subValue={`${critical} crit · ${high} high`}
          variant="warning"
        />
        <StatCard
          icon={<Crosshair className="h-4 w-4" />}
          label="Port scans"
          value={uniqScans}
          subValue={`${uniqFloods} brute-force floods`}
          variant="info"
        />
        <StatCard
          icon={<Swords className="h-4 w-4" />}
          label="Distinct attackers"
          value={uniqUsers}
          subValue="Unique users"
          variant="info"
        />
      </StatCardGrid>

      <Card className="border shadow-sm">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Swords className="h-4 w-4 text-muted-foreground" />
                Attacks originating from VPN clients
              </CardTitle>
              <CardDescription className="text-xs">
                Only hostile patterns (port scan / brute-force). CDN / normal browsing is filtered out.
                Click a row to see exactly where the user knocked, from which node and when.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Select value={since} onValueChange={setSince}>
                <SelectTrigger className="w-[120px] h-8">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SINCE_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={fetchAttacks} className="gap-1">
                <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {list.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-[240px] text-muted-foreground">
              <div className="w-16 h-16 rounded-full bg-emerald-100 dark:bg-emerald-900/30 flex items-center justify-center mb-3">
                <Swords className="h-8 w-8 text-emerald-500" />
              </div>
              <p className="text-sm font-medium">No attacks in the last {since}</p>
              <p className="text-xs">Scanning / brute-force detectors haven't fired</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[120px]">When</TableHead>
                    <TableHead className="w-[170px]">Type</TableHead>
                    <TableHead className="w-[200px]">User</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead className="w-[110px]">Severity</TableHead>
                    <TableHead className="w-[90px] text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((a) => {
                    const t = typeLabel[a.type] ?? { label: a.type, icon: null };
                    const details = (a.details ?? {}) as AttackDetails;
                    const target =
                      details.target_subnet && details.port
                        ? `${details.target_subnet} : ${details.port}  (${details.unique_ips ?? "?"} IPs)`
                        : details.port
                          ? `port ${details.port} (${details.unique_destinations ?? "?"} dests)`
                          : a.description;
                    const shownUser = a.username && a.username !== a.user_email
                      ? `${a.username}  ·  #${a.user_email}`
                      : `#${a.user_email}`;
                    const isOpen = expanded === a.id;
                    const d = drill[a.id];
                    return (
                      <Fragment key={a.id}>
                        <TableRow
                          className="cursor-pointer"
                          onClick={() => toggleRow(a)}
                          data-state={isOpen ? "selected" : undefined}
                        >
                          <TableCell className="text-xs text-muted-foreground">
                            {formatDistanceToNow(new Date(a.detected_at), { addSuffix: true })}
                          </TableCell>
                          <TableCell>
                            <span className="inline-flex items-center gap-1.5 text-xs">
                              {t.icon}
                              {t.label}
                            </span>
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            <Link
                              href={`/users/${encodeURIComponent(a.user_email)}`}
                              className="hover:underline text-primary"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {shownUser}
                            </Link>
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            <span className="inline-flex items-center gap-1">
                              {isOpen ? (
                                <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                              ) : (
                                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                              )}
                              {target}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={severityBadge[a.severity] ?? ""}>
                              {a.severity}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={resolvingIds.has(a.id)}
                              onClick={(e) => {
                                e.stopPropagation();
                                resolve(a.id);
                              }}
                              className="h-7 px-2"
                            >
                              <Check className="h-3.5 w-3.5" />
                            </Button>
                          </TableCell>
                        </TableRow>

                        {isOpen && (
                          <TableRow className="hover:bg-transparent">
                            <TableCell colSpan={6} className="bg-muted/30 p-0">
                              <DestinationsDrill state={d} onRetry={() => loadDestinations(a)} />
                              <div className="border-t">
                                <EnforcementDrill userEmail={a.user_email} />
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </Fragment>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// DestinationsDrill renders the per-destination breakdown for one attack:
// node, exact destination, hit count and first/last-seen times, with copy.
function DestinationsDrill({ state, onRetry }: { state?: DrillState; onRetry: () => void }) {
  if (!state || state.loading) {
    return (
      <div className="p-4 space-y-2">
        <Skeleton className="h-5 w-40" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }
  if (state.error) {
    return (
      <div className="p-4 text-xs text-muted-foreground flex items-center gap-3">
        Failed to load destinations.
        <Button variant="outline" size="sm" className="h-7" onClick={onRetry}>
          Retry
        </Button>
      </div>
    );
  }
  const rows = state.rows ?? [];
  if (rows.length === 0) {
    return (
      <div className="p-4 text-xs text-muted-foreground">
        No matching destinations are retained for this attack&apos;s window (raw log lines aren&apos;t stored;
        aggregated destinations may have expired).
      </div>
    );
  }

  // Plain-text dump for "Copy all" — tab-separated so it pastes cleanly.
  const allText = rows
    .map((r) => `${r.destination}\t${r.node_id}\t×${r.request_count}\t${fmtTs(r.first_seen)} → ${fmtTs(r.last_seen)}`)
    .join("\n");

  return (
    <div className="p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-muted-foreground">
          {rows.length} destination{rows.length === 1 ? "" : "s"} hit during the detection window
        </span>
        <CopyButton text={allText} label="Copy all" className="border" />
      </div>
      <div className="max-h-72 overflow-auto rounded-md border bg-background">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-muted/60 backdrop-blur">
            <tr className="text-left text-muted-foreground">
              <th className="px-2 py-1.5 font-medium">Destination</th>
              <th className="px-2 py-1.5 font-medium w-[140px]">Node</th>
              <th className="px-2 py-1.5 font-medium w-[70px] text-right">Hits</th>
              <th className="px-2 py-1.5 font-medium w-[150px]">First seen</th>
              <th className="px-2 py-1.5 font-medium w-[150px]">Last seen</th>
              <th className="px-2 py-1.5 w-[40px]"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={`${r.node_id}-${r.destination}-${i}`} className="border-t hover:bg-muted/40">
                <td className="px-2 py-1.5 font-mono">{r.destination}</td>
                <td className="px-2 py-1.5">
                  <span className="inline-flex items-center gap-1 text-muted-foreground">
                    <Server className="h-3 w-3" />
                    {r.node_id}
                  </span>
                </td>
                <td className="px-2 py-1.5 text-right tabular-nums">{r.request_count}</td>
                <td className="px-2 py-1.5 font-mono text-muted-foreground">{fmtTs(r.first_seen)}</td>
                <td className="px-2 py-1.5 font-mono text-muted-foreground">{fmtTs(r.last_seen)}</td>
                <td className="px-2 py-1.5 text-right">
                  <CopyButton text={r.destination} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
