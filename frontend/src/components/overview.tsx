import { useEffect, useId, useState } from "react";
import { useNavigate } from "react-router";
import { Activity, ArrowUpRight, ShieldAlert, ShieldCheck } from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  YAxis,
} from "recharts";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card.tsx";
import { client } from "./api.tsx";

type Metrics = { ipv4: number; ipv6: number; allow4: number; allow6: number };
type Series = {
  key: string;
  label: string;
  color: string;
  values: number[];
};
type HistoryPoint = Metrics & { timestamp: number };

function countEntries(value: unknown): number {
  return Array.isArray(value)
    ? value.length
    : value && typeof value === "object"
    ? Object.keys(value).length
    : 0;
}

function formatCount(value: number | null): string {
  return value === null ? "—" : new Intl.NumberFormat().format(value);
}

function FirewallAreaChart({
  series,
  timestamps,
  title,
  description,
}: {
  series: Series[];
  timestamps: number[];
  title: string;
  description: string;
}) {
  const chartId = `chart-${useId().replaceAll(":", "")}`;
  const data = timestamps.map((timestamp, index) =>
    Object.fromEntries([
      ["timestamp", timestamp],
      ...series.map(({ key, values }) => [key, values[index] ?? 0]),
    ])
  );
  const hasData = data.length > 1;
  const formatTimestamp = (value: number) =>
    new Intl.DateTimeFormat(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value));

  return (
    <Card className="border shadow-sm">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="pt-0">
        {hasData
          ? (
            <div
              data-slot="chart"
              data-chart={chartId}
              className="flex aspect-video justify-center text-xs [&_.recharts-cartesian-axis-tick_text]:fill-muted-foreground [&_.recharts-cartesian-grid_line[stroke='#ccc']]:stroke-border/50 [&_.recharts-curve.recharts-tooltip-cursor]:stroke-border [&_.recharts-layer]:outline-hidden [&_.recharts-surface]:outline-hidden"
            >
              <style>
                {`
          [data-chart="${chartId}"] {
            ${
                  series.map(({ key, color }) => `--color-${key}: ${color};`)
                    .join(
                      "\n",
                    )
                }
          }
          .dark [data-chart="${chartId}"] {
            ${
                  series.map(({ key, color }) => `--color-${key}: ${color};`)
                    .join(
                      "\n",
                    )
                }
          }
        `}
              </style>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  accessibilityLayer
                  data={data}
                  margin={{ left: 12, right: 12 }}
                >
                  <CartesianGrid vertical={false} />
                  <YAxis
                    hide
                    domain={[0, (dataMax: number) =>
                      Math.ceil(Math.max(dataMax, 1) * 1.15)]}
                    allowDecimals={false}
                  />
                  <Tooltip
                    cursor={false}
                    contentStyle={{
                      borderRadius: "0.75rem",
                      border: "1px solid var(--border)",
                      background: "var(--popover)",
                      color: "var(--popover-foreground)",
                    }}
                    formatter={(value, name) => [
                      formatCount(typeof value === "number" ? value : 0),
                      series.find((item) =>
                        item.key === name
                      )?.label ?? name,
                    ]}
                    labelFormatter={(value) => formatTimestamp(Number(value))}
                  />
                  {series.map(({ key }) => (
                    <Area
                      key={key}
                      dataKey={key}
                      type="monotone"
                      fill={`var(--color-${key})`}
                      fillOpacity={0.4}
                      stroke={`var(--color-${key})`}
                      strokeWidth={2}
                    />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )
          : (
            <div className="flex aspect-video items-center justify-center text-sm text-muted-foreground">
              {data.length === 0 ? "No data available" : "Collecting data…"}
            </div>
          )}
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-2 text-xs text-muted-foreground">
          {series.map(({ label, color, values }) => (
            <div key={label} className="flex items-center gap-2">
              <span
                className="size-2 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span>{label}</span>
              <strong className="text-foreground">
                {formatCount(values.at(-1) ?? 0)}
              </strong>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export function DashboardOverview() {
  const [metrics, setMetrics] = useState<Metrics>({
    ipv4: 0,
    ipv6: 0,
    allow4: 0,
    allow6: 0,
  });
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [ddosEnabled, setDdosEnabled] = useState<boolean | null>(null);
  const [enforcementActive, setEnforcementActive] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    let active = true;
    async function loadMetrics() {
      try {
        const [
          v4Count,
          v6Count,
          v4Allow,
          v6Allow,
          configResponse,
          adapterResponse,
        ] = await Promise.all([
          client.GET("/api/v1/config/packet_counts/v4"),
          client.GET("/api/v1/config/packet_counts/v6"),
          client.GET("/api/v1/config/allow_list/v4"),
          client.GET("/api/v1/config/allow_list/v6"),
          fetch("/api/v1/config", { credentials: "include" }),
          client.GET("/api/v1/config/adapters"),
        ]);
        const config = configResponse.ok
          ? await configResponse.json() as {
            ddos_activated?: boolean;
          }
          : null;
        if (active) {
          const next = {
            ipv4: v4Count.response.ok ? countEntries(v4Count.data) : 0,
            ipv6: v6Count.response.ok ? countEntries(v6Count.data) : 0,
            allow4: v4Allow.response.ok ? countEntries(v4Allow.data) : 0,
            allow6: v6Allow.response.ok ? countEntries(v6Allow.data) : 0,
          };
          setMetrics(next);
          setHistory((current) => [...current, {
            ...next,
            timestamp: Date.now(),
          }]);
          setDdosEnabled(config?.ddos_activated ?? null);
          setEnforcementActive(
            adapterResponse.response.ok &&
              adapterResponse.data?.enforcement_active === true,
          );
        }
      } catch (error) {
        console.error("Failed to load firewall metrics:", error);
      } finally {
        if (active) setIsLoading(false);
      }
    }
    void loadMetrics();
    const interval = globalThis.setInterval(() => void loadMetrics(), 2_000);
    return () => {
      active = false;
      globalThis.clearInterval(interval);
    };
  }, []);

  const cards = [
    [
      "IPv4 packet entries",
      metrics.ipv4,
      "Tracked by eBPF",
      Activity,
      "text-sky-600 bg-sky-500/10",
    ],
    [
      "IPv6 packet entries",
      metrics.ipv6,
      "Tracked by eBPF",
      Activity,
      "text-violet-600 bg-violet-500/10",
    ],
    [
      "IPv4 allow list",
      metrics.allow4,
      "Active policy entries",
      ShieldCheck,
      "text-emerald-600 bg-emerald-500/10",
    ],
    [
      "IPv6 allow list",
      metrics.allow6,
      "Active policy entries",
      ShieldCheck,
      "text-amber-600 bg-amber-500/10",
    ],
  ] as const;
  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);
  const todayHistory = history.filter((point) =>
    point.timestamp >= startOfToday.getTime()
  );
  const toSeries = (
    points: HistoryPoint[],
    key: keyof Metrics,
    label: string,
    color: string,
  ): Series => ({
    key,
    label,
    color,
    values: points.map((point) => point[key]),
  });

  return (
    <div className="mx-auto max-w-375 space-y-7 p-4 sm:p-6 lg:p-8">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary">
            Security operations
          </p>
          <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">
            Firewall overview
          </h1>
          <p className="mt-2 max-w-xl text-muted-foreground">
            Monitor policy enforcement and eBPF state from one focused control
            plane.
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-xs font-medium shadow-sm">
          <span
            className={`size-2 rounded-full ${
              enforcementActive ? "bg-emerald-500" : "bg-amber-500"
            }`}
          />
          {enforcementActive ? "Enforcement active" : "Enforcement inactive"}
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map(([label, value, detail, Icon, tone], index) => (
          <Card
            key={label}
            className="border shadow-sm transition-colors hover:border-primary/50"
            role="link"
            tabIndex={0}
            onClick={() =>
              navigate(
                index === 0
                  ? "/dashboard/allow-lists?map=packets-v4"
                  : index === 1
                  ? "/dashboard/allow-lists?map=packets-v6"
                  : index === 2
                  ? "/dashboard/allow-lists?map=allow-v4"
                  : "/dashboard/allow-lists?map=allow-v6",
              )}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                navigate(
                  index === 0
                    ? "/dashboard/allow-lists?map=packets-v4"
                    : index === 1
                    ? "/dashboard/allow-lists?map=packets-v6"
                    : index === 2
                    ? "/dashboard/allow-lists?map=allow-v4"
                    : "/dashboard/allow-lists?map=allow-v6",
                );
              }
            }}
          >
            <CardContent className="p-5">
              <div className="flex items-start justify-between">
                <div
                  className={`grid size-10 place-items-center rounded-md ${tone}`}
                >
                  <Icon className="size-5" />
                </div>
                <ArrowUpRight className="size-4 text-muted-foreground" />
              </div>
              <p className="mt-5 text-sm text-muted-foreground">{label}</p>
              <p className="mt-1 text-3xl font-bold tracking-tight">
                {isLoading ? "…" : formatCount(value)}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <FirewallAreaChart
          title="Packets transmitted — all time"
          description={`All observations captured during this dashboard session. DDoS ${
            ddosEnabled === null
              ? "status unknown"
              : ddosEnabled
              ? "enabled"
              : "disabled"
          }.`}
          series={[{
            key: "transmitted",
            label: "Transmitted packets",
            color: "#0ea5e9",
            values: history.map(({ ipv4, ipv6 }) => ipv4 + ipv6),
          }]}
          timestamps={history.map(({ timestamp }) => timestamp)}
        />
        <FirewallAreaChart
          title="Packets transmitted — today"
          description="Observations since local midnight."
          series={[
            {
              key: "transmitted",
              label: "Transmitted packets",
              color: "#0ea5e9",
              values: todayHistory.map(({ ipv4, ipv6 }) => ipv4 + ipv6),
            },
          ]}
          timestamps={todayHistory.map(({ timestamp }) => timestamp)}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <FirewallAreaChart
          title="Packet count — all time"
          description="IPv4 and IPv6 tracked flow entries for this session."
          series={[
            {
              key: "ipv4",
              label: "IPv4 flows",
              color: "#38bdf8",
              values: history.map(({ ipv4 }) => ipv4),
            },
            {
              key: "ipv6",
              label: "IPv6 flows",
              color: "#8b5cf6",
              values: history.map(({ ipv6 }) => ipv6),
            },
          ]}
          timestamps={history.map(({ timestamp }) => timestamp)}
        />
        <FirewallAreaChart
          title="Packet count — today"
          description="IPv4 and IPv6 tracked flow entries since local midnight."
          series={[
            toSeries(todayHistory, "ipv4", "IPv4 flows", "#38bdf8"),
            toSeries(todayHistory, "ipv6", "IPv6 flows", "#8b5cf6"),
          ]}
          timestamps={todayHistory.map(({ timestamp }) => timestamp)}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <FirewallAreaChart
          title="Allow-list activity — all time"
          description="IPv4 and IPv6 policy entries for this session."
          series={[
            {
              key: "allow4",
              label: "IPv4 allow list",
              color: "#10b981",
              values: history.map(({ allow4 }) => allow4),
            },
            {
              key: "allow6",
              label: "IPv6 allow list",
              color: "#f59e0b",
              values: history.map(({ allow6 }) => allow6),
            },
          ]}
          timestamps={history.map(({ timestamp }) => timestamp)}
        />
        <FirewallAreaChart
          title="Allow-list activity — today"
          description="IPv4 and IPv6 policy entries since local midnight."
          series={[
            toSeries(todayHistory, "allow4", "IPv4 allow list", "#10b981"),
            toSeries(todayHistory, "allow6", "IPv6 allow list", "#f59e0b"),
          ]}
          timestamps={todayHistory.map(({ timestamp }) => timestamp)}
        />
      </div>

      <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
        <Card className="border shadow-sm lg:col-span-2">
          <CardContent className="p-6">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="font-semibold">Protection status</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Your firewall is ready to enforce traffic policy.
                </p>
              </div>
              <ShieldAlert className="size-5 text-primary" />
            </div>
            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              {[
                [
                  "eBPF programs",
                  enforcementActive ? "Attached" : "Not attached",
                ],
                ["Policy engine", enforcementActive ? "Healthy" : "Inactive"],
                [
                  "Telemetry",
                  enforcementActive ? "Available" : "Waiting for eBPF",
                ],
              ].map(([label, status]) => (
                <div key={label} className="rounded-md border bg-muted/30 p-4">
                  <p className="text-xs text-muted-foreground">{label}</p>
                  <p className="mt-2 flex items-center gap-2 text-sm font-semibold">
                    <span
                      className={`size-2 rounded-full ${
                        enforcementActive ? "bg-emerald-500" : "bg-amber-500"
                      }`}
                    />
                    {status}
                  </p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
