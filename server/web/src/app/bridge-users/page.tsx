"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslations } from "next-intl";
import { authFetch } from "@/contexts/auth-context";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AnimatedNumber } from "@/components/ui/animated-number";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { RefreshCw, Route, Smartphone, Globe } from "lucide-react";

type BridgeUser = {
  user_uuid: string;
  username: string;
  short_uuid: string;
  telegram_id: number;
  status: string;
  online_at: string;
  bridge_node: string;
  last_seen: string;
  flows_count: number;
  last_real_ip: string;
  unique_destinations: number;
  top_destinations: string[] | null;
  hwid_count: number;
  used_traffic_bytes: number;
  traffic_limit_bytes: number;
};

const WINDOWS = [
  { label: "5m", value: "5m" },
  { label: "15m", value: "15m" },
  { label: "1h", value: "1h" },
  { label: "6h", value: "6h" },
  { label: "24h", value: "24h" },
];

function formatBytes(n: number): string {
  if (!n) return "0";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

function formatRelative(ts: string): string {
  if (!ts) return "—";
  const d = new Date(ts).getTime();
  if (!d || d < 1e10) return "—";
  const diff = Math.floor((Date.now() - d) / 1000);
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function statusVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status?.toUpperCase()) {
    case "ACTIVE":
      return "default";
    case "EXPIRED":
    case "DISABLED":
      return "destructive";
    case "LIMITED":
      return "secondary";
    default:
      return "outline";
  }
}

export default function BridgeUsersPage() {
  const t = useTranslations("bridgeUsersPage");
  const [users, setUsers] = useState<BridgeUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [since, setSince] = useState("1h");
  const [node, setNode] = useState("ru-white");

  const load = useCallback(async () => {
    try {
      const res = await authFetch(`/api/bridge-users?node=${encodeURIComponent(node)}&since=${encodeURIComponent(since)}&limit=200`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setUsers(json.users ?? []);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [node, since]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  // Auto-refresh every 30s.
  useEffect(() => {
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, [load]);

  const stats = useMemo(() => {
    const totalFlows = users.reduce((a, u) => a + (u.flows_count || 0), 0);
    const uniqueIPs = new Set(users.map(u => u.last_real_ip).filter(Boolean)).size;
    const uniqueDsts = users.reduce((a, u) => a + (u.unique_destinations || 0), 0);
    return { users: users.length, flows: totalFlows, uniqueIPs, uniqueDsts };
  }, [users]);

  return (
    <div className="p-4 md:p-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold tracking-tight flex items-center gap-2">
            <Route className="h-6 w-6" />
            {t("title")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("description")}</p>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => { setRefreshing(true); load(); }}
          disabled={refreshing}
        >
          <RefreshCw className={`h-4 w-4 mr-1 ${refreshing ? "animate-spin" : ""}`} />
          {t("refresh")}
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6 flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">{t("bridge")}:</span>
            {["ru-white", "ru-bride"].map(n => (
              <Button
                key={n}
                size="sm"
                variant={node === n ? "default" : "outline"}
                onClick={() => setNode(n)}
              >
                {n}
              </Button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">{t("window")}:</span>
            {WINDOWS.map(w => (
              <Button
                key={w.value}
                size="sm"
                variant={since === w.value ? "default" : "outline"}
                onClick={() => setSince(w.value)}
              >
                {w.label}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Stats */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">{t("totalUsers")}</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold"><AnimatedNumber value={stats.users} /></div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">{t("totalFlows")}</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold"><AnimatedNumber value={stats.flows} /></div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">{t("uniqueIPs")}</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold"><AnimatedNumber value={stats.uniqueIPs} /></div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">{t("uniqueDests")}</CardTitle></CardHeader>
          <CardContent><div className="text-2xl font-bold"><AnimatedNumber value={stats.uniqueDsts} /></div></CardContent>
        </Card>
      </div>

      {/* Table */}
      <Card>
        <CardHeader>
          <CardTitle>{t("usersOnBridge", { node })}</CardTitle>
          <CardDescription>{t("usersDesc", { window: since })}</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <Skeleton className="h-[400px]" />
          ) : error ? (
            <div className="text-sm text-destructive">{t("loadError")}: {error}</div>
          ) : users.length === 0 ? (
            <div className="text-sm text-muted-foreground py-8 text-center">{t("empty")}</div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("user")}</TableHead>
                    <TableHead>{t("status")}</TableHead>
                    <TableHead>{t("lastSeen")}</TableHead>
                    <TableHead className="text-right">{t("flows")}</TableHead>
                    <TableHead>{t("realIP")}</TableHead>
                    <TableHead>{t("topDestinations")}</TableHead>
                    <TableHead className="text-right">{t("devices")}</TableHead>
                    <TableHead className="text-right">{t("traffic")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map(u => (
                    <TableRow key={`${u.user_uuid}-${u.bridge_node}`}>
                      <TableCell>
                        <div className="font-medium">{u.username || u.user_uuid.slice(0, 8)}</div>
                        {u.telegram_id ? (
                          <div className="text-xs text-muted-foreground">tg:{u.telegram_id}</div>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(u.status)} className="text-xs">
                          {u.status || "—"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                        {formatRelative(u.last_seen)}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{u.flows_count}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {u.last_real_ip || "—"}
                      </TableCell>
                      <TableCell className="max-w-[280px]">
                        {u.top_destinations && u.top_destinations.length > 0 ? (
                          <div className="flex flex-wrap gap-1">
                            {u.top_destinations.slice(0, 3).map((d, i) => (
                              <span key={i} className="text-xs bg-muted px-1.5 py-0.5 rounded truncate max-w-[140px] inline-flex items-center gap-1" title={d}>
                                <Globe className="h-3 w-3" />
                                {d}
                              </span>
                            ))}
                            {u.top_destinations.length > 3 && (
                              <span className="text-xs text-muted-foreground">
                                +{u.top_destinations.length - 3}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <span className="inline-flex items-center gap-1 text-sm">
                          <Smartphone className="h-3 w-3 text-muted-foreground" />
                          {u.hwid_count}
                        </span>
                      </TableCell>
                      <TableCell className="text-right text-xs tabular-nums whitespace-nowrap">
                        {formatBytes(u.used_traffic_bytes)}
                        {u.traffic_limit_bytes > 0 && (
                          <div className="text-muted-foreground">
                            / {formatBytes(u.traffic_limit_bytes)}
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
