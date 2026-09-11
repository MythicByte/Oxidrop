import { useEffect, useState } from "react";
import { ScrollText, ShieldCheck } from "lucide-react";
import { Card, CardContent } from "./ui/card.tsx";

type LogEntry = {
  id: number;
  timestamp: number;
  level: string;
  message: string;
  actor?: string | null;
};

export function Logs() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [level, setLevel] = useState("ALL");

  useEffect(() => {
    let socket: WebSocket | undefined;
    let active = true;
    void fetch("/api/v1/logs", { credentials: "include" }).then(
      async (response) => {
        if (!response.ok) {
          throw new Error(`Log request failed (${response.status})`);
        }
        const initial = await response.json() as LogEntry[];
        if (active) setEntries(initial);
        const protocol = globalThis.location.protocol === "https:"
          ? "wss:"
          : "ws:";
        socket = new WebSocket(
          `${protocol}//${globalThis.location.host}/api/v1/logs/ws`,
        );
        socket.onmessage = (event) => {
          const entry = JSON.parse(event.data) as LogEntry;
          if (active) {
            setEntries((current) => [entry, ...current].slice(0, 500));
          }
        };
      },
    ).catch((error: unknown) => {
      console.error("Failed to load firewall logs:", error);
      if (active) {
        setError(
          error instanceof Error ? error.message : "Unable to load logs",
        );
      }
    });
    return () => {
      active = false;
      socket?.close();
    };
  }, []);

  const visibleEntries = level === "ALL"
    ? entries
    : entries.filter((entry) => entry.level === level);
  const levelStyle: Record<string, string> = {
    TRACE:
      "border-slate-500/30 bg-slate-500/5 text-slate-700 dark:text-slate-300",
    INFO: "border-sky-500/30 bg-sky-500/5 text-sky-700 dark:text-sky-300",
    WARN:
      "border-amber-500/30 bg-amber-500/5 text-amber-700 dark:text-amber-300",
    ERROR: "border-red-500/30 bg-red-500/5 text-red-700 dark:text-red-300",
    DEBUG:
      "border-violet-500/30 bg-violet-500/5 text-violet-700 dark:text-violet-300",
  };
  const levels = ["ALL", "TRACE", "DEBUG", "INFO", "WARN", "ERROR"];

  return (
    <div className="space-y-8 p-4 sm:p-6 lg:p-8">
      <div>
        <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">
          Administrator tools
        </p>
        <h1 className="text-3xl font-bold tracking-tight">Logs</h1>
        <p className="mt-2 text-muted-foreground">
          Review security and policy events for this firewall.
        </p>
      </div>
      <Card className="border shadow-sm">
        <CardContent className="p-0">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b p-5">
            <div className="flex items-center gap-3">
              <div className="grid size-10 place-items-center rounded-md bg-primary/10 text-primary">
                <ScrollText className="size-5" />
              </div>
              <div>
                <h2 className="font-semibold">Firewall events</h2>
                <p className="text-xs text-muted-foreground">
                  {error ??
                    `${visibleEntries.length} visible of ${entries.length} events`}
                </p>
              </div>
            </div>
            <div className="max-w-full scroll-smooth overflow-x-auto rounded-md border bg-muted/40 p-1 scrollbar-thin">
              <div className="flex w-max gap-1">
                {levels.map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setLevel(value)}
                    className={`shrink-0 rounded px-3 py-1.5 text-xs font-semibold transition-[background-color,color,transform,box-shadow] duration-300 ease-out ${
                      level === value
                        ? "scale-[1.03] bg-background text-foreground shadow-sm"
                        : "text-muted-foreground hover:bg-background/60 hover:text-foreground"
                    }`}
                  >
                    {value}
                  </button>
                ))}
              </div>
            </div>
          </div>
          {visibleEntries.length === 0
            ? (
              <div className="flex flex-col items-center p-12 text-center">
                <ShieldCheck className="size-10 text-primary/60" />
                <h2 className="mt-4 font-semibold">
                  {error ?? "No events at this level"}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Events emitted by the firewall and HTTP control plane appear
                  here.
                </p>
              </div>
            )
            : (
              <div className="divide-y">
                {visibleEntries.map((entry) => (
                  <div
                    key={`${entry.id}-${entry.timestamp}`}
                    className="flex flex-wrap items-start gap-3 px-5 py-4 text-sm"
                  >
                    <span
                      className={`mt-0.5 min-w-16 rounded border px-2 py-1 text-center text-[10px] font-bold tracking-wider ${
                        levelStyle[entry.level] ??
                          "border-border bg-muted text-muted-foreground"
                      }`}
                    >
                      {entry.level}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="font-medium">{entry.message}</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {entry.actor ? `Source: ${entry.actor} · ` : ""}
                        {new Date(entry.timestamp * 1000).toLocaleString()}
                      </p>
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
