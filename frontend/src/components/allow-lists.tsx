import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { createPortal } from "react-dom";
import { RefreshCw, Search, ShieldCheck, Trash2 } from "lucide-react";
import { Card, CardContent } from "./ui/card.tsx";
import { Button } from "./ui/button.tsx";
import { client } from "./api.tsx";

type TrafficMap = "allow-v4" | "allow-v6" | "packets-v4" | "packets-v6";
type MapEntry = {
  key: Record<string, unknown>;
  value: Record<string, unknown>;
  last_seen_at?: number | null;
  last_update_at?: number | null;
};
type AllowAction = "Allow" | "Deny";

function numberField(value: unknown): number {
  return typeof value === "number" ? value : 0;
}

function keyPayloadV4(key: Record<string, unknown>) {
  return {
    source_addr: numberField(key.source_addr),
    destination_addr: numberField(key.destination_addr),
    source_port: numberField(key.source_port),
    destination_port: numberField(key.destination_port),
    protocol: numberField(key.protocol),
  };
}

function keyPayloadV6(key: Record<string, unknown>) {
  return {
    source_addr: Array.isArray(key.source_addr)
      ? key.source_addr.map(numberField)
      : [0, 0, 0, 0],
    destination_addr: Array.isArray(key.destination_addr)
      ? key.destination_addr.map(numberField)
      : [0, 0, 0, 0],
    source_port: numberField(key.source_port),
    destination_port: numberField(key.destination_port),
    protocol: numberField(key.protocol),
  };
}

function readEntries(value: unknown): MapEntry[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is MapEntry =>
    Boolean(entry) &&
    typeof entry === "object" &&
    "key" in entry &&
    "value" in entry
  );
}

function ipv4(value: unknown): string {
  if (typeof value !== "number") return "unknown";
  const address = value >>> 0;
  return [24, 16, 8, 0].map((shift) => (address >>> shift) & 255).join(".");
}

function ipv6(value: unknown): string {
  if (!Array.isArray(value) || value.length !== 4) return "unknown";
  const groups = value.flatMap((word) => {
    const number = typeof word === "number" ? word >>> 0 : 0;
    return [(number >>> 16) & 0xffff, number & 0xffff];
  }).map((group) => group.toString(16));
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length;) {
    if (groups[start] !== "0") {
      start++;
      continue;
    }
    let end = start;
    while (end < groups.length && groups[end] === "0") end++;
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  if (bestLength < 2) return groups.join(":");
  return `${groups.slice(0, bestStart).join(":")}::${
    groups.slice(bestStart + bestLength).join(":")
  }`;
}

function protocol(value: unknown): string {
  const names: Record<number, string> = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
  };
  return typeof value === "number"
    ? names[value] ?? `Protocol ${value}`
    : "Unknown";
}

function formatValue(value: unknown): string {
  return typeof value === "number"
    ? new Intl.NumberFormat().format(value)
    : String(value ?? "—");
}

function localTime(value: unknown): string {
  if (typeof value !== "number") return "unknown";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function formatEntry(entry: MapEntry, isIpv6: boolean, isPacketMap: boolean) {
  const key = entry.key;
  const source = isIpv6 ? ipv6(key.source_addr) : ipv4(key.source_addr);
  const destination = isIpv6
    ? ipv6(key.destination_addr)
    : ipv4(key.destination_addr);
  const port = `${formatValue(key.source_port)} → ${
    formatValue(key.destination_port)
  }`;
  const details = isPacketMap
    ? `tokens ${formatValue(entry.value.tokens)} · updated ${
      localTime(entry.last_update_at)
    }`
    : `action ${String(entry.value.action ?? "Unknown")} · last seen ${
      localTime(entry.last_seen_at)
    }`;
  return {
    raw: entry,
    source,
    destination,
    port,
    protocol: protocol(key.protocol),
    details,
    search: `${source} ${destination} ${port} ${
      protocol(key.protocol)
    } ${details}`
      .toLowerCase(),
  };
}

export function AllowLists() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialMap = searchParams.get("map");
  const [trafficMap, setTrafficMap] = useState<TrafficMap>(
    initialMap === "allow-v6" ||
      initialMap === "packets-v4" ||
      initialMap === "packets-v6"
      ? initialMap
      : "allow-v4",
  );
  const [entries, setEntries] = useState<MapEntry[]>([]);
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [refreshToken, setRefreshToken] = useState(0);
  const [isMutating, setIsMutating] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [isClearDialogOpen, setIsClearDialogOpen] = useState(false);
  const [modifyEntry, setModifyEntry] = useState<MapEntry | null>(null);

  useEffect(() => {
    if (!isClearDialogOpen) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [isClearDialogOpen]);

  useEffect(() => {
    let active = true;
    setIsLoading(true);
    const load = async () => {
      try {
        const result = trafficMap === "allow-v4"
          ? await client.GET("/api/v1/config/allow_list/v4")
          : trafficMap === "allow-v6"
          ? await client.GET("/api/v1/config/allow_list/v6")
          : trafficMap === "packets-v4"
          ? await client.GET("/api/v1/config/packet_counts/v4")
          : await client.GET("/api/v1/config/packet_counts/v6");
        if (active) {
          setEntries(result.response.ok ? readEntries(result.data) : []);
        }
      } catch (error) {
        console.error("Failed to load firewall map:", error);
        if (active) setEntries([]);
      } finally {
        if (active) setIsLoading(false);
      }
    };
    void load();
    return () => {
      active = false;
    };
  }, [trafficMap, refreshToken]);

  const clearMap = async () => {
    if (entries.length === 0) return;
    setIsMutating(true);
    setNotice(null);
    setIsClearDialogOpen(false);
    try {
      const response = trafficMap === "allow-v4"
        ? await client.DELETE("/api/v1/config/allow_list/v4", {
          body: undefined as never,
        })
        : trafficMap === "allow-v6"
        ? await client.DELETE("/api/v1/config/allow_list/v6", {
          body: undefined as never,
        })
        : trafficMap === "packets-v4"
        ? await client.DELETE("/api/v1/config/packet_counts/v4", {
          body: undefined as never,
        })
        : await client.DELETE("/api/v1/config/packet_counts/v6", {
          body: undefined as never,
        });
      if (!response.response.ok) {
        setNotice("You do not have permission to clear this map.");
        return;
      }
      setEntries([]);
      setNotice("All entries cleared.");
    } catch (error) {
      console.error("Failed to clear firewall map:", error);
      setNotice("Failed to clear the map.");
    } finally {
      setIsMutating(false);
    }
  };

  const modifyAllowEntry = async (entry: MapEntry, action: AllowAction) => {
    if (isPacketMap) return;
    const state = {
      action,
      last_seen: numberField(entry.value.last_seen),
    };

    setIsMutating(true);
    setNotice(null);
    try {
      const response = isIpv6
        ? await client.POST("/api/v1/config/allow_list/v6", {
          body: { key: keyPayloadV6(entry.key), state },
        })
        : await client.POST("/api/v1/config/allow_list/v4", {
          body: { key: keyPayloadV4(entry.key), state },
        });
      if (!response.response.ok) {
        setNotice("You do not have permission to modify this entry.");
        return;
      }
      setEntries((current) =>
        current.map((item) => item === entry ? { ...item, value: state } : item)
      );
      setModifyEntry(null);
      setNotice("Entry updated.");
    } catch (error) {
      console.error("Failed to modify firewall entry:", error);
      setNotice("Failed to modify the entry.");
    } finally {
      setIsMutating(false);
    }
  };

  const deleteEntry = async (entry: MapEntry) => {
    setIsMutating(true);
    setNotice(null);
    try {
      const response = trafficMap === "allow-v4"
        ? await client.DELETE("/api/v1/config/allow_list/v4", {
          body: keyPayloadV4(entry.key),
        })
        : trafficMap === "allow-v6"
        ? await client.DELETE("/api/v1/config/allow_list/v6", {
          body: keyPayloadV6(entry.key),
        })
        : trafficMap === "packets-v4"
        ? await client.DELETE("/api/v1/config/packet_counts/v4", {
          body: keyPayloadV4(entry.key),
        })
        : await client.DELETE("/api/v1/config/packet_counts/v6", {
          body: keyPayloadV6(entry.key),
        });
      if (!response.response.ok) {
        setNotice("You do not have permission to delete this entry.");
        return;
      }
      setEntries((current) => current.filter((item) => item !== entry));
      setNotice("Entry deleted.");
    } catch (error) {
      console.error("Failed to delete firewall entry:", error);
      setNotice("Failed to delete the entry.");
    } finally {
      setIsMutating(false);
    }
  };

  const isPacketMap = trafficMap.startsWith("packets");
  const isIpv6 = trafficMap.endsWith("v6");
  const rows = useMemo(
    () =>
      entries
        .map((entry) => formatEntry(entry, isIpv6, isPacketMap))
        .filter((entry) => entry.search.includes(search.trim().toLowerCase())),
    [entries, isIpv6, isPacketMap, search],
  );
  const mapLabel = isPacketMap ? "Packet counts" : "Allow lists";

  return (
    <div className="space-y-8 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">
            Traffic policy
          </p>
          <h1 className="text-3xl font-bold tracking-tight">{mapLabel}</h1>
          <p className="mt-2 text-muted-foreground">
            Search tracked {isIpv6 ? "IPv6" : "IPv4"}{" "}
            flows by address, protocol, port, or action.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => setRefreshToken((token) => token + 1)}
            disabled={isMutating}
          >
            <RefreshCw className="size-4" /> Refresh
          </Button>
          <Button
            variant="destructive"
            onClick={() => setIsClearDialogOpen(true)}
            disabled={isMutating || entries.length === 0}
          >
            <Trash2 className="size-4" /> Clear all
          </Button>
        </div>
      </div>
      <div className="max-w-full overflow-x-auto rounded-xl border bg-background p-1 shadow-sm">
        <div className="flex w-max gap-2">
          {([
            ["allow-v4", "Allow list IPv4"],
            ["allow-v6", "Allow list IPv6"],
            ["packets-v4", "Packet counts IPv4"],
            ["packets-v6", "Packet counts IPv6"],
          ] as const).map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={`shrink-0 rounded-lg px-4 py-2 text-sm font-medium ${
                trafficMap === value
                  ? "bg-primary text-primary-foreground shadow-sm"
                  : "text-muted-foreground hover:bg-muted"
              }`}
              onClick={() => {
                setTrafficMap(value);
                setSearch("");
                setSearchParams({ map: value });
              }}
            >
              {label}
              {trafficMap === value && (
                <span className="ml-1 text-xs opacity-70">
                  ({entries.length})
                </span>
              )}
            </button>
          ))}
        </div>
      </div>
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <input
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search address, protocol, port, or action..."
          aria-label="Search firewall entries"
          className="h-11 w-full rounded-lg border bg-background pl-10 pr-4 text-sm outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring"
        />
      </div>
      {notice && (
        <p className="text-sm text-muted-foreground" role="status">{notice}</p>
      )}
      {isClearDialogOpen && createPortal(
        <div
          className="fixed inset-0 z-50 grid h-dvh w-full place-items-center overflow-hidden bg-slate-950/45 p-4 backdrop-blur-sm"
          onClick={() => !isMutating && setIsClearDialogOpen(false)}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="clear-map-title"
            className="w-full max-w-md animate-in zoom-in-95 overflow-hidden rounded-2xl border bg-background p-6 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start gap-4">
              <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-destructive/15 text-destructive">
                <Trash2 className="size-5" />
              </div>
              <div>
                <h2 id="clear-map-title" className="text-lg font-semibold">
                  Clear {mapLabel.toLowerCase()}?
                </h2>
                <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                  This permanently removes all{" "}
                  <span className="font-medium text-foreground">
                    {entries.length} {isIpv6 ? "IPv6" : "IPv4"} entries
                  </span>{" "}
                  from the current map. This cannot be undone.
                </p>
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <Button
                variant="outline"
                onClick={() => setIsClearDialogOpen(false)}
                disabled={isMutating}
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={() => void clearMap()}
                disabled={isMutating}
              >
                {isMutating ? "Clearing…" : "Clear all"}
              </Button>
            </div>
          </section>
        </div>,
        document.body,
      )}
      {modifyEntry && createPortal(
        <div
          className="fixed inset-0 z-50 grid h-dvh w-full place-items-center overflow-hidden bg-slate-950/45 p-4 backdrop-blur-sm"
          onClick={() => !isMutating && setModifyEntry(null)}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="modify-entry-title"
            className="w-full max-w-md animate-in zoom-in-95 overflow-hidden rounded-2xl border bg-background p-6 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <h2 id="modify-entry-title" className="text-lg font-semibold">
              Modify action
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Choose the action for this flow.
            </p>
            <div className="mt-6 grid grid-cols-2 gap-3">
              {(["Allow", "Deny"] as const).map((action) => (
                <Button
                  key={action}
                  variant={modifyEntry.value.action === action
                    ? "default"
                    : "outline"}
                  className="h-10"
                  disabled={isMutating}
                  onClick={() => void modifyAllowEntry(modifyEntry, action)}
                >
                  {action}
                </Button>
              ))}
            </div>
            <div className="mt-6 flex justify-end">
              <Button
                variant="outline"
                onClick={() => setModifyEntry(null)}
                disabled={isMutating}
              >
                Cancel
              </Button>
            </div>
          </section>
        </div>,
        document.body,
      )}
      <Card className="border-0 shadow-sm">
        <CardContent className="p-0">
          {isLoading
            ? (
              <div className="p-8 text-center text-sm text-muted-foreground">
                Reading eBPF map…
              </div>
            )
            : rows.length === 0
            ? (
              <div className="flex flex-col items-center p-12 text-center">
                <ShieldCheck className="size-10 text-primary/60" />
                <h2 className="mt-4 font-semibold">
                  {entries.length === 0
                    ? `No ${isIpv6 ? "IPv6" : "IPv4"} entries`
                    : "No matching entries"}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  {entries.length === 0
                    ? `The ${
                      isPacketMap ? "packet-count map" : "allow list"
                    } is currently empty.`
                    : "Try a different address, protocol, port, or action."}
                </p>
              </div>
            )
            : (
              <div className="divide-y">
                {rows.map((entry, index) => (
                  <div
                    key={`${entry.source}-${entry.destination}-${index}`}
                    className="px-8 py-6"
                  >
                    <div className="flex flex-wrap items-center gap-3">
                      <code className="font-mono text-sm font-semibold">
                        {entry.source}
                      </code>
                      <span className="text-muted-foreground">→</span>
                      <code className="font-mono text-sm font-semibold">
                        {entry.destination}
                      </code>
                      <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
                        {entry.protocol}
                      </span>
                    </div>
                    <div className="mt-2 pl-6 text-xs text-muted-foreground">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <span>
                          ports {entry.port} <span className="mx-2">·</span>
                          {" "}
                          {entry.details}
                        </span>
                        <div className="flex items-center gap-2">
                          {!isPacketMap && (
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={isMutating}
                              onClick={() => setModifyEntry(entry.raw)}
                            >
                              Modify
                            </Button>
                          )}
                          <Button
                            variant="destructive"
                            size="sm"
                            disabled={isMutating}
                            onClick={() => void deleteEntry(entry.raw)}
                          >
                            <Trash2 className="size-3.5" /> Delete
                          </Button>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
        </CardContent>
      </Card>
    </div>
  );
}
