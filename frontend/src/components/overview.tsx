import { useEffect, useState } from "react";
import { Activity, ArrowUpRight, Network, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { client } from "./api";

type Metric = { label: string; value: string; detail: string; icon: typeof Activity; tone: string };

async function readJson(response: Response): Promise<unknown> {
  if (!response.ok) return null;
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function countEntries(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === "object") return Object.keys(value).length;
  return 0;
}

function formatCount(value: number | null): string {
  return value === null ? "—" : new Intl.NumberFormat().format(value);
}

export function DashboardOverview() {
  const [metrics, setMetrics] = useState({ ipv4: null as number | null, ipv6: null as number | null, allow4: null as number | null, allow6: null as number | null });
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function loadMetrics() {
      try {
        const [v4Count, v6Count, v4Allow, v6Allow] = await Promise.all([
          client.GET("/api/v1/config/packet_counts/v4"),
          client.GET("/api/v1/config/packet_counts/v6"),
          client.GET("/api/v1/config/allow_list/v4"),
          client.GET("/api/v1/config/allow_list/v6"),
        ]);
        const values = await Promise.all([v4Count.response, v6Count.response, v4Allow.response, v6Allow.response].map(readJson));
        if (active) setMetrics({ ipv4: countEntries(values[0]), ipv6: countEntries(values[1]), allow4: countEntries(values[2]), allow6: countEntries(values[3]) });
      } catch (error) {
        console.error("Failed to load firewall metrics:", error);
      } finally {
        if (active) setIsLoading(false);
      }
    }
    void loadMetrics();
    return () => { active = false; };
  }, []);

  const cards: Metric[] = [
    { label: "IPv4 packet entries", value: isLoading ? "…" : formatCount(metrics.ipv4), detail: "Tracked by eBPF", icon: Activity, tone: "text-sky-600 bg-sky-500/10" },
    { label: "IPv6 packet entries", value: isLoading ? "…" : formatCount(metrics.ipv6), detail: "Tracked by eBPF", icon: Activity, tone: "text-violet-600 bg-violet-500/10" },
    { label: "IPv4 allow list", value: isLoading ? "…" : formatCount(metrics.allow4), detail: "Active policy entries", icon: ShieldCheck, tone: "text-emerald-600 bg-emerald-500/10" },
    { label: "IPv6 allow list", value: isLoading ? "…" : formatCount(metrics.allow6), detail: "Active policy entries", icon: ShieldCheck, tone: "text-amber-600 bg-amber-500/10" },
  ];

  return (
    <div className="space-y-8 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">Security operations</p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Firewall overview</h1>
          <p className="mt-2 max-w-xl text-muted-foreground">Monitor policy enforcement and eBPF state from one focused control plane.</p>
        </div>
        <div className="flex items-center gap-2 rounded-full border bg-background px-3 py-2 text-xs font-medium shadow-sm">
          <span className="size-2 rounded-full bg-emerald-500" /> Enforcement active
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map(({ label, value, detail, icon: Icon, tone }) => (
          <Card key={label} className="border-0 shadow-sm">
            <CardContent className="p-5">
              <div className="flex items-start justify-between">
                <div className={`grid size-10 place-items-center rounded-xl ${tone}`}><Icon className="size-5" /></div>
                <ArrowUpRight className="size-4 text-muted-foreground" />
              </div>
              <p className="mt-5 text-sm text-muted-foreground">{label}</p>
              <p className="mt-1 text-3xl font-bold tracking-tight">{value}</p>
              <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
        <Card className="border-0 shadow-sm">
          <CardContent className="p-6">
            <div className="flex items-start justify-between">
              <div><h2 className="font-semibold">Protection status</h2><p className="mt-1 text-sm text-muted-foreground">Your firewall is ready to enforce traffic policy.</p></div>
              <ShieldAlert className="size-5 text-primary" />
            </div>
            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              {[["eBPF programs", "Attached"], ["Policy engine", "Healthy"], ["Telemetry", "Available"]].map(([label, status]) => (
                <div key={label} className="rounded-xl border bg-muted/30 p-4"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-2 flex items-center gap-2 text-sm font-semibold"><span className="size-2 rounded-full bg-emerald-500" />{status}</p></div>
              ))}
            </div>
          </CardContent>
        </Card>
        <Card className="border-0 bg-primary text-primary-foreground shadow-sm">
          <CardContent className="flex h-full flex-col justify-between p-6">
            <div><Zap className="size-6" /><h2 className="mt-5 text-xl font-bold">Tune your policy</h2><p className="mt-2 text-sm text-primary-foreground/75">Review allow lists and interface bindings before putting a new rule into production.</p></div>
            <Button variant="secondary" className="mt-6 w-fit" onClick={() => window.location.assign("/dashboard/allow-lists")}>Manage allow lists <Network /></Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
