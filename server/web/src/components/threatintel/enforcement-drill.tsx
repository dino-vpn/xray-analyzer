"use client";

import { useCallback, useEffect, useState } from "react";
import { authFetch } from "@/contexts/auth-context";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { format, formatDistanceToNow } from "date-fns";
import { ShieldBan, UserX, Trash2, History, Loader2, Globe } from "lucide-react";

// ── Types mirroring /api/threatintel/detections ──────────────────────────────
type Anomaly = {
  id: string;
  type: string;
  severity: string;
  description: string;
  detected_at: string;
  resolved: boolean;
};
type ThreatMatch = {
  id: number;
  source_ip: string;
  destination: string;
  threat_type: string;
  source: string;
  description?: string;
  matched_at: string;
};
type IPRow = {
  ip_address: string;
  node_id?: string;
  country_code?: string;
  country_name?: string;
  city?: string;
  last_seen: string;
  request_count: number;
};
type ActionRow = {
  id: number;
  action_type: string;
  target_ip?: string;
  duration?: string;
  reason?: string;
  status: string;
  error?: string;
  created_at: string;
};
type Detections = {
  user_email: string;
  username?: string;
  anomalies: Anomaly[] | null;
  threat_matches: ThreatMatch[] | null;
  ips: IPRow[] | null;
  actions: ActionRow[] | null;
  active_bans: ActionRow[] | null;
  remnawave_enabled: boolean;
  crowdsec_enabled: boolean;
};

type Flash = { kind: "ok" | "err"; text: string } | null;

const BAN_DURATIONS = [
  { value: "30m", label: "30 минут" },
  { value: "1h", label: "1 час" },
  { value: "3h", label: "3 часа" },
  { value: "6h", label: "6 часов" },
  { value: "12h", label: "12 часов" },
  { value: "24h", label: "24 часа" },
];

const severityBadge: Record<string, string> = {
  low: "bg-blue-500/15 text-blue-700 dark:text-blue-300 border-blue-500/30",
  medium: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
  high: "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30",
  critical: "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30",
};

const actionLabel: Record<string, string> = {
  remna_disable: "Отключение юзера",
  remna_delete: "Удаление юзера",
  ip_ban: "Бан IP",
  ip_unban: "Снятие бана",
};

function fmtTs(iso: string): string {
  try {
    return format(new Date(iso), "yyyy-MM-dd HH:mm:ss");
  } catch {
    return iso;
  }
}

// EnforcementDrill is the per-user history + actions panel rendered under an
// expanded attack row. It loads the full detection history for the user and
// exposes Remnawave disable/delete and CrowdSec IP-ban controls.
export function EnforcementDrill({ userEmail }: { userEmail: string }) {
  const [data, setData] = useState<Detections | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [banOpen, setBanOpen] = useState(false);
  const [confirm, setConfirm] = useState<null | "disable" | "delete">(null);
  const [busy, setBusy] = useState(false);
  const [flash, setFlash] = useState<Flash>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(false);
    try {
      const res = await authFetch(
        `/api/threatintel/detections?user_email=${encodeURIComponent(userEmail)}&since=720h`,
      );
      if (!res.ok) {
        setError(true);
        setData(null);
        return;
      }
      setData(await res.json());
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [userEmail]);

  useEffect(() => {
    load();
  }, [load]);

  const runRemna = useCallback(
    async (kind: "disable" | "delete") => {
      setBusy(true);
      try {
        const res = await authFetch(`/api/enforcement/remnawave/${kind}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_email: userEmail }),
        });
        if (res.ok) {
          setFlash({ kind: "ok", text: kind === "delete" ? "Юзер удалён в Remnawave" : "Юзер отключён в Remnawave" });
        } else {
          const j = await res.json().catch(() => ({}));
          setFlash({ kind: "err", text: `Не удалось: ${j.error || res.status}` });
        }
      } catch (e) {
        setFlash({ kind: "err", text: `Ошибка запроса: ${String(e)}` });
      } finally {
        setBusy(false);
        setConfirm(null);
        load();
      }
    },
    [userEmail, load],
  );

  const unban = useCallback(
    async (ip: string) => {
      setBusy(true);
      try {
        const res = await authFetch(`/api/enforcement/ip-unban`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_email: userEmail, ips: [ip] }),
        });
        if (res.ok) setFlash({ kind: "ok", text: `Бан снят: ${ip}` });
        else setFlash({ kind: "err", text: `Не удалось снять бан: ${res.status}` });
      } finally {
        setBusy(false);
        load();
      }
    },
    [userEmail, load],
  );

  if (loading) {
    return (
      <div className="p-4 space-y-2">
        <Skeleton className="h-5 w-48" />
        <Skeleton className="h-28 w-full" />
      </div>
    );
  }
  if (error || !data) {
    return (
      <div className="p-4 text-xs text-muted-foreground flex items-center gap-3">
        Не удалось загрузить историю.
        <Button variant="outline" size="sm" className="h-7" onClick={load}>
          Повторить
        </Button>
      </div>
    );
  }

  const anomalies = data.anomalies ?? [];
  const matches = data.threat_matches ?? [];
  const ips = data.ips ?? [];
  const actions = data.actions ?? [];
  const activeBans = data.active_bans ?? [];

  // Merge anomalies + threat_matches into one chronological timeline.
  type TimelineItem = { ts: string; kind: "anomaly" | "threat"; title: string; tag: string; severity: string };
  const timeline: TimelineItem[] = [
    ...anomalies.map(
      (a): TimelineItem => ({
        ts: a.detected_at,
        kind: "anomaly",
        title: a.description,
        tag: a.type,
        severity: a.severity,
      }),
    ),
    ...matches.map(
      (m): TimelineItem => ({
        ts: m.matched_at,
        kind: "threat",
        title: `${m.threat_type} → ${m.destination}`,
        tag: m.source,
        severity: "medium",
      }),
    ),
  ].sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

  return (
    <div className="p-4 space-y-5">
      {/* ── Actions ─────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-muted-foreground mr-1">Действия:</span>
        <Button
          size="sm"
          variant="outline"
          className="h-7 gap-1"
          disabled={!data.remnawave_enabled || busy}
          title={data.remnawave_enabled ? "" : "Remnawave не настроен"}
          onClick={() => setConfirm("disable")}
        >
          <UserX className="h-3.5 w-3.5" /> Отключить юзера
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="h-7 gap-1 text-red-600 dark:text-red-400"
          disabled={!data.remnawave_enabled || busy}
          title={data.remnawave_enabled ? "" : "Remnawave не настроен"}
          onClick={() => setConfirm("delete")}
        >
          <Trash2 className="h-3.5 w-3.5" /> Удалить юзера
        </Button>
        <Button
          size="sm"
          variant="outline"
          className="h-7 gap-1"
          disabled={!data.crowdsec_enabled || busy || ips.length === 0}
          title={data.crowdsec_enabled ? "" : "CrowdSec не настроен"}
          onClick={() => setBanOpen(true)}
        >
          <ShieldBan className="h-3.5 w-3.5" /> Забанить IP
        </Button>
        {flash ? (
          <span className={`text-xs ${flash.kind === "ok" ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}>
            {flash.text}
          </span>
        ) : null}
      </div>

      {/* ── Active bans ─────────────────────────────────────────── */}
      {activeBans.length > 0 && (
        <div className="rounded-md border bg-red-500/5 p-2">
          <div className="text-xs font-medium text-muted-foreground mb-1">Активные баны</div>
          <div className="flex flex-wrap gap-2">
            {activeBans.map((b) => (
              <span
                key={b.id}
                className="inline-flex items-center gap-2 rounded border bg-background px-2 py-1 text-xs font-mono"
              >
                {b.target_ip}
                {b.duration ? <span className="text-muted-foreground">· {b.duration}</span> : null}
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-5 px-1 text-xs"
                  disabled={busy}
                  onClick={() => b.target_ip && unban(b.target_ip)}
                >
                  снять
                </Button>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Detection timeline ──────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground mb-2">
          <History className="h-3.5 w-3.5" /> История обнаружений ({timeline.length})
        </div>
        {timeline.length === 0 ? (
          <div className="text-xs text-muted-foreground">Обнаружений за период нет.</div>
        ) : (
          <div className="max-h-64 overflow-auto rounded-md border bg-background divide-y">
            {timeline.map((t, i) => (
              <div key={i} className="flex items-start gap-3 px-3 py-1.5 text-xs">
                <span className="font-mono text-muted-foreground whitespace-nowrap">{fmtTs(t.ts)}</span>
                <Badge variant="outline" className={severityBadge[t.severity] ?? ""}>
                  {t.tag}
                </Badge>
                <span className="flex-1">{t.title}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Action log ──────────────────────────────────────────── */}
      {actions.length > 0 && (
        <div>
          <div className="text-xs font-medium text-muted-foreground mb-2">Журнал действий</div>
          <div className="max-h-48 overflow-auto rounded-md border bg-background divide-y">
            {actions.map((a) => (
              <div key={a.id} className="flex items-center gap-3 px-3 py-1.5 text-xs">
                <span className="font-mono text-muted-foreground whitespace-nowrap">
                  {formatDistanceToNow(new Date(a.created_at), { addSuffix: true })}
                </span>
                <span className="font-medium">{actionLabel[a.action_type] ?? a.action_type}</span>
                {a.target_ip ? <span className="font-mono">{a.target_ip}</span> : null}
                {a.duration ? <span className="text-muted-foreground">{a.duration}</span> : null}
                <Badge
                  variant="outline"
                  className={
                    a.status === "success"
                      ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30"
                      : "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30"
                  }
                >
                  {a.status}
                </Badge>
                {a.error ? <span className="text-red-500 truncate">{a.error}</span> : null}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Remnawave confirm dialog ────────────────────────────── */}
      <AlertDialog open={confirm !== null} onOpenChange={(o) => !o && setConfirm(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirm === "delete" ? "Удалить юзера в Remnawave?" : "Отключить юзера в Remnawave?"}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {confirm === "delete"
                ? "Юзер будет безвозвратно удалён из панели Remnawave. Это действие необратимо."
                : "Юзер будет переведён в статус DISABLED в панели Remnawave."}
              <br />
              <span className="font-mono text-xs">{data.username || userEmail}</span>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Отмена</AlertDialogCancel>
            <AlertDialogAction
              disabled={busy}
              onClick={(e) => {
                e.preventDefault();
                if (confirm) runRemna(confirm);
              }}
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : confirm === "delete" ? "Удалить" : "Отключить"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── IP ban dialog ───────────────────────────────────────── */}
      <BanDialog
        open={banOpen}
        onOpenChange={setBanOpen}
        userEmail={userEmail}
        ips={ips}
        onResult={(f) => setFlash(f)}
        onDone={load}
      />
    </div>
  );
}

// BanDialog lets the operator pick which of the user's IPs to ban, for how long.
// Built on AlertDialog (the repo has no plain Dialog component) with controlled
// open state and plain footer buttons so an invalid submit doesn't auto-close.
// Uses a native checkbox input (no Checkbox UI primitive in this repo).
function BanDialog({
  open,
  onOpenChange,
  userEmail,
  ips,
  onResult,
  onDone,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  userEmail: string;
  ips: IPRow[];
  onResult: (f: Flash) => void;
  onDone: () => void;
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [duration, setDuration] = useState("30m");
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Reset selection whenever the dialog reopens.
  useEffect(() => {
    if (open) {
      setSelected(new Set());
      setDuration("30m");
      setReason("");
    }
  }, [open]);

  const toggle = (ip: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });

  const submit = async () => {
    if (selected.size === 0) return;
    setSubmitting(true);
    try {
      const res = await authFetch(`/api/enforcement/ip-ban`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_email: userEmail,
          ips: Array.from(selected),
          duration,
          reason,
        }),
      });
      if (res.ok) {
        const j = await res.json().catch(() => ({ results: [] }));
        const ok = (j.results || []).filter((r: { status: string }) => r.status === "success").length;
        const fail = (j.results || []).length - ok;
        onResult(
          fail === 0
            ? { kind: "ok", text: `Забанено IP: ${ok}` }
            : { kind: "err", text: `Забанено ${ok}, ошибок ${fail}` },
        );
        onOpenChange(false);
        onDone();
      } else {
        const j = await res.json().catch(() => ({}));
        onResult({ kind: "err", text: `Не удалось: ${j.error || res.status}` });
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="max-w-lg">
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            <ShieldBan className="h-4 w-4" /> Забанить IP через CrowdSec
          </AlertDialogTitle>
          <AlertDialogDescription>
            Выберите IP-адреса пользователя и срок бана. Бан применится централизованно через CrowdSec на
            всех нодах.
          </AlertDialogDescription>
        </AlertDialogHeader>

        <div className="space-y-3">
          <div className="max-h-56 overflow-auto rounded-md border divide-y">
            {ips.length === 0 ? (
              <div className="p-3 text-xs text-muted-foreground">У пользователя нет известных IP.</div>
            ) : (
              ips.map((ip) => (
                <label
                  key={ip.ip_address}
                  className="flex items-center gap-3 px-3 py-2 text-xs cursor-pointer hover:bg-muted/40"
                >
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-input accent-primary"
                    checked={selected.has(ip.ip_address)}
                    onChange={() => toggle(ip.ip_address)}
                  />
                  <span className="font-mono">{ip.ip_address}</span>
                  <span className="inline-flex items-center gap-1 text-muted-foreground">
                    <Globe className="h-3 w-3" />
                    {[ip.country_code, ip.city].filter(Boolean).join(" · ") || "—"}
                  </span>
                  <span className="ml-auto text-muted-foreground tabular-nums">×{ip.request_count}</span>
                  <span className="text-muted-foreground whitespace-nowrap">
                    {formatDistanceToNow(new Date(ip.last_seen), { addSuffix: true })}
                  </span>
                </label>
              ))
            )}
          </div>

          <div>
            <Label className="text-xs">Срок бана</Label>
            <Select value={duration} onValueChange={setDuration}>
              <SelectTrigger className="h-8 mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {BAN_DURATIONS.map((d) => (
                  <SelectItem key={d.value} value={d.value}>
                    {d.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label className="text-xs">Причина (необязательно)</Label>
            <Textarea
              className="mt-1 text-xs"
              rows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="port scan / brute-force …"
            />
          </div>
        </div>

        <AlertDialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            Отмена
          </Button>
          <Button onClick={submit} disabled={submitting || selected.size === 0}>
            {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : `Забанить (${selected.size})`}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
