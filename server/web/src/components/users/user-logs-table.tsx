"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsUpDown,
  ArrowUp,
  ArrowDown,
  Download,
  Search,
  Loader2,
} from "lucide-react";
import { format } from "date-fns";
import { authFetch } from "@/contexts/auth-context";
import { UserLogEvent, UserLogsResponse } from "@/lib/types";

type Period = "1h" | "6h" | "24h" | "7d" | "30d" | "all";
type Kind = "all" | "threat" | "blacklist" | "anomaly";
type SortKey = "ts" | "category" | "ip" | "destination" | "node";
type Order = "asc" | "desc";

const PERIODS: { value: Period; label: string }[] = [
  { value: "1h", label: "1 час" },
  { value: "6h", label: "6 часов" },
  { value: "24h", label: "24 часа" },
  { value: "7d", label: "7 дней" },
  { value: "30d", label: "30 дней" },
  { value: "all", label: "Всё время" },
];

const KINDS: { value: Kind; label: string }[] = [
  { value: "all", label: "Все события" },
  { value: "threat", label: "Угрозы" },
  { value: "blacklist", label: "Блок-лист" },
  { value: "anomaly", label: "Аномалии" },
];

const kindBadge: Record<string, string> = {
  threat: "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30",
  blacklist: "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30",
  anomaly: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
};

const kindLabel: Record<string, string> = {
  threat: "угроза",
  blacklist: "блок-лист",
  anomaly: "аномалия",
};

const PAGE_SIZE = 50;

function fmtTs(iso: string): string {
  try {
    return format(new Date(iso), "yyyy-MM-dd HH:mm:ss");
  } catch {
    return iso;
  }
}

// Builds the shared query string for both the data fetch and the CSV export so
// what you see is exactly what you download.
function buildParams(opts: {
  period: Period;
  kind: Kind;
  q: string;
  sort: SortKey;
  order: Order;
}): URLSearchParams {
  const p = new URLSearchParams();
  p.set("period", opts.period);
  if (opts.kind !== "all") p.set("kind", opts.kind);
  if (opts.q.trim()) p.set("q", opts.q.trim());
  p.set("sort", opts.sort);
  p.set("order", opts.order);
  return p;
}

export function UserLogsTable({ email }: { email: string }) {
  const [data, setData] = useState<UserLogsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [page, setPage] = useState(1);
  const [period, setPeriod] = useState<Period>("24h");
  const [kind, setKind] = useState<Kind>("all");
  const [sort, setSort] = useState<SortKey>("ts");
  const [order, setOrder] = useState<Order>("desc");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");

  // Debounce the search box.
  useEffect(() => {
    const t = setTimeout(() => setQ(qInput), 350);
    return () => clearTimeout(t);
  }, [qInput]);

  // Reset to page 1 whenever a filter/sort changes.
  useEffect(() => {
    setPage(1);
  }, [period, kind, q, sort, order]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = buildParams({ period, kind, q, sort, order });
      params.set("page", String(page));
      params.set("page_size", String(PAGE_SIZE));
      const res = await authFetch(`/api/users/${encodeURIComponent(email)}/logs?${params.toString()}`);
      if (res.ok) setData(await res.json());
    } catch (err) {
      console.error("Failed to fetch user logs:", err);
    } finally {
      setLoading(false);
    }
  }, [email, period, kind, q, sort, order, page]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const exportCsv = useCallback(async () => {
    setExporting(true);
    try {
      const params = buildParams({ period, kind, q, sort, order });
      const res = await authFetch(`/api/users/${encodeURIComponent(email)}/logs/export?${params.toString()}`);
      if (!res.ok) return;
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `user-${email.slice(0, 8)}-logs.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to export logs:", err);
    } finally {
      setExporting(false);
    }
  }, [email, period, kind, q, sort, order]);

  const onSort = useCallback(
    (key: SortKey) => {
      if (sort === key) {
        setOrder((o) => (o === "asc" ? "desc" : "asc"));
      } else {
        setSort(key);
        setOrder(key === "ts" ? "desc" : "asc");
      }
    },
    [sort],
  );

  const events = useMemo(() => data?.events ?? [], [data]);

  return (
    <div className="space-y-4">
      {/* ── Controls ─────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder="Поиск по IP или домену…"
            className="pl-8 h-9"
          />
        </div>
        <Select value={kind} onValueChange={(v) => setKind(v as Kind)}>
          <SelectTrigger className="h-9 w-[150px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {KINDS.map((k) => (
              <SelectItem key={k.value} value={k.value}>
                {k.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={period} onValueChange={(v) => setPeriod(v as Period)}>
          <SelectTrigger className="h-9 w-[130px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PERIODS.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="sm"
          className="h-9 gap-1.5"
          onClick={exportCsv}
          disabled={exporting || events.length === 0}
        >
          {exporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
          Экспорт CSV
        </Button>
      </div>

      <div className="text-xs text-muted-foreground">{data ? `${data.total} событий` : ""}</div>

      {/* ── Table ────────────────────────────────────────────────── */}
      {loading && !data ? (
        <div className="space-y-2">
          {[...Array(6)].map((_, i) => (
            <Skeleton key={i} className="h-10" />
          ))}
        </div>
      ) : events.length === 0 ? (
        <p className="text-sm text-muted-foreground py-8 text-center">Нет событий за выбранный период.</p>
      ) : (
        <div className="max-h-[480px] overflow-y-auto overflow-x-auto scrollbar-thin rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <SortHeader label="Время" col="ts" sort={sort} order={order} onSort={onSort} />
                <TableHead className="whitespace-nowrap">Тип</TableHead>
                <SortHeader label="Категория" col="category" sort={sort} order={order} onSort={onSort} />
                <SortHeader label="IP" col="ip" sort={sort} order={order} onSort={onSort} className="hidden sm:table-cell" />
                <SortHeader label="Домен / назначение" col="destination" sort={sort} order={order} onSort={onSort} />
                <SortHeader label="Нода" col="node" sort={sort} order={order} onSort={onSort} className="hidden lg:table-cell" />
                <TableHead className="text-right whitespace-nowrap hidden md:table-cell">Уровень</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((e, i) => (
                <LogRow key={i} e={e} />
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* ── Pagination ───────────────────────────────────────────── */}
      {data && data.total_pages > 1 && (
        <div className="flex items-center justify-between pt-1">
          <span className="text-sm text-muted-foreground">
            Стр. {data.page} из {data.total_pages}
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1 || loading}
            >
              <ChevronLeft className="h-4 w-4" />
              Назад
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage((p) => Math.min(data.total_pages, p + 1))}
              disabled={page >= data.total_pages || loading}
            >
              Вперёд
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function SortHeader({
  label,
  col,
  sort,
  order,
  onSort,
  className = "",
}: {
  label: string;
  col: SortKey;
  sort: SortKey;
  order: Order;
  onSort: (k: SortKey) => void;
  className?: string;
}) {
  const active = sort === col;
  return (
    <TableHead className={`whitespace-nowrap ${className}`}>
      <button
        type="button"
        onClick={() => onSort(col)}
        className="inline-flex items-center gap-1 hover:text-foreground"
      >
        {label}
        {!active ? (
          <ChevronsUpDown className="h-3 w-3 opacity-40" />
        ) : order === "asc" ? (
          <ArrowUp className="h-3 w-3" />
        ) : (
          <ArrowDown className="h-3 w-3" />
        )}
      </button>
    </TableHead>
  );
}

function LogRow({ e }: { e: UserLogEvent }) {
  return (
    <TableRow>
      <TableCell className="text-xs text-muted-foreground whitespace-nowrap font-mono">{fmtTs(e.ts)}</TableCell>
      <TableCell>
        <Badge variant="outline" className={kindBadge[e.kind] ?? ""}>
          {kindLabel[e.kind] ?? e.kind}
        </Badge>
      </TableCell>
      <TableCell className="text-xs font-mono whitespace-nowrap">{e.category}</TableCell>
      <TableCell className="text-xs font-mono hidden sm:table-cell">{e.source_ip || "—"}</TableCell>
      <TableCell className="font-mono text-xs max-w-[280px] truncate" title={e.destination}>
        {e.destination || (e.description ? e.description : "—")}
      </TableCell>
      <TableCell className="hidden lg:table-cell">
        {e.node_id ? (
          <Badge variant="outline" className="text-xs whitespace-nowrap">
            {e.node_name || e.node_id}
          </Badge>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </TableCell>
      <TableCell className="text-right hidden md:table-cell">
        {e.kind === "threat" ? (
          <span className={e.confidence >= 90 ? "text-destructive" : e.confidence >= 75 ? "text-orange-500" : ""}>
            {e.confidence}
          </span>
        ) : e.kind === "anomaly" && e.severity ? (
          <span className="text-xs uppercase text-muted-foreground">{e.severity}</span>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </TableCell>
    </TableRow>
  );
}
