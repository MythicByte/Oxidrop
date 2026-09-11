import { useEffect, useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card.tsx";
import { Button } from "./ui/button.tsx";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select.tsx";
import { Switch } from "./ui/switch.tsx";
import { Label } from "./ui/label.tsx";
import { Network, Power, RotateCw, ShieldAlert } from "lucide-react";
import { client } from "./api.tsx";
import type { components } from "../api/schema.d.ts";

type Config = components["schemas"]["ConfigPatch"];
type AdapterResponse = components["schemas"]["AdaptersResponse"];
type TrafficStats = components["schemas"]["TrafficStatsResponse"];

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(2)} GiB`;
}

export function FirewallConfiguration() {
  const [config, setConfig] = useState<Config>({ ddos_activated: true });
  const [adapters, setAdapters] = useState<AdapterResponse>({
    available: [],
    enforcement_active: false,
  });
  const [permissions, setPermissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [attachmentNotice, setAttachmentNotice] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);
  const [noticeFading, setNoticeFading] = useState(false);
  const [confirmAction, setConfirmAction] = useState<
    "shutdown" | "restart" | null
  >(null);

  const hasModify = permissions.includes("Modify");
  const [traffic, setTraffic] = useState<TrafficStats>({
    incoming: { packets: 0, bytes: 0 },
    outgoing: { packets: 0, bytes: 0 },
  });

  useEffect(() => {
    if (!attachmentNotice) {
      setNoticeFading(false);
      return;
    }

    setNoticeFading(false);
    const fadeTimer = globalThis.setTimeout(() => setNoticeFading(true), 9_500);
    const removeTimer = globalThis.setTimeout(
      () => setAttachmentNotice(null),
      10_000,
    );
    return () => {
      globalThis.clearTimeout(fadeTimer);
      globalThis.clearTimeout(removeTimer);
    };
  }, [attachmentNotice]);

  useEffect(() => {
    async function fetchState() {
      try {
        // Fetch RBAC, Config, and Adapters in parallel
        const [rbacRes, configRes, adapterRes] = await Promise.all([
          client.GET("/api/v1/role_and_permissions"),
          client.GET("/api/v1/config"),
          client.GET("/api/v1/config/adapters"),
        ]);

        if (rbacRes.response.ok && rbacRes.data) {
          setPermissions(rbacRes.data.permissions);
        }
        if (configRes.response.ok && configRes.data) {
          setConfig({
            ddos_activated: true,
            ...(configRes.data as unknown as Config),
          });
        }
        if (adapterRes.response.ok && adapterRes.data) {
          setAdapters(adapterRes.data as AdapterResponse);
        }
      } catch (error) {
        console.error("Failed to load firewall state:", error);
      } finally {
        setIsLoading(false);
      }
    }
    fetchState();
  }, []);

  useEffect(() => {
    let active = true;
    const sample = async () => {
      const response = await fetch("/api/v1/config/traffic", {
        credentials: "include",
      });
      if (active && response.ok) {
        setTraffic(await response.json() as TrafficStats);
      }
    };
    void sample();
    const interval = globalThis.setInterval(() => void sample(), 30_000);
    return () => {
      active = false;
      globalThis.clearInterval(interval);
    };
  }, []);

  const handleSave = async () => {
    try {
      const payload = {
        ddos_activated: config.ddos_activated,
        incoming_ethernet_adapter: config.incoming_ethernet_adapter,
        output_ethernet_adapter: config.output_ethernet_adapter,
      };

      const { response } = await client.POST("/api/v1/config", {
        body: payload,
      });
      if (response.ok) {
        const adapterResponse = await client.GET("/api/v1/config/adapters");
        if (adapterResponse.response.ok && adapterResponse.data) {
          setAdapters(adapterResponse.data);
        }
        setAttachmentNotice({
          kind: "success",
          message: "eBPF interface attachment succeeded.",
        });
      } else {
        const message = await response.text();
        setConfig((current) => ({
          ...current,
          incoming_ethernet_adapter: null,
          output_ethernet_adapter: null,
        }));
        const adapterResponse = await client.GET("/api/v1/config/adapters");
        if (adapterResponse.response.ok && adapterResponse.data) {
          setAdapters(adapterResponse.data);
        }
        setAttachmentNotice({
          kind: "error",
          message: message ||
            "The eBPF program could not attach to the selected interface.",
        });
      }
    } catch (error) {
      console.error("Failed to update config:", error);
      setAttachmentNotice({
        kind: "error",
        message: "The firewall could not apply this configuration.",
      });
    }
  };

  const handleEbpfAction = async (action: "shutdown" | "restart") => {
    try {
      const response = await fetch(`/api/v1/config/ebpf/${action}`, {
        method: "POST",
        credentials: "include",
      });
      if (!response.ok) {
        setAttachmentNotice({
          kind: "error",
          message: await response.text() ||
            `Failed to ${action} the eBPF program.`,
        });
        return;
      }
      const adapterResponse = await client.GET("/api/v1/config/adapters");
      if (adapterResponse.response.ok && adapterResponse.data) {
        setAdapters(adapterResponse.data);
      }
      setAttachmentNotice({
        kind: "success",
        message: action === "shutdown"
          ? "eBPF program shut down."
          : "eBPF program restarted.",
      });
    } catch (error) {
      console.error(`Failed to ${action} eBPF program:`, error);
      setAttachmentNotice({
        kind: "error",
        message: `Failed to ${action} the eBPF program.`,
      });
    }
  };

  if (isLoading) return <div className="p-6">Loading eBPF state...</div>;

  return (
    <div className="p-6 space-y-6">
      <div>
        {attachmentNotice && (
          <div
            role="alert"
            className={`mb-5 flex items-center gap-3 border px-4 py-3 text-sm font-medium transition-opacity duration-500 ease-out ${
              noticeFading ? "opacity-0" : "opacity-100"
            } ${
              attachmentNotice.kind === "success"
                ? "animate-pulse border-emerald-500/40 bg-emerald-500/10 text-emerald-700"
                : "border-destructive/40 bg-destructive/10 text-destructive"
            }`}
          >
            <span
              className={`size-2 shrink-0 rounded-full ${
                attachmentNotice.kind === "success"
                  ? "animate-ping bg-emerald-500"
                  : "bg-destructive"
              }`}
            />
            {attachmentNotice.message}
          </div>
        )}
        <h2 className="text-3xl font-bold tracking-tight">
          Firewall Configuration
        </h2>
        <p className="text-muted-foreground">
          Manage core eBPF parameters and hardware adapters.
        </p>
        {!hasModify && (
          <div className="mt-2 text-sm text-amber-600 font-medium">
            Read-only mode: You do not have permission to modify these settings.
          </div>
        )}
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Hardware Adapters Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Network className="h-5 w-5" /> Network Adapters
            </CardTitle>
            <CardDescription>
              Bind the eBPF programs to specific interfaces.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Incoming Adapter (Ingress)</Label>
              <Select
                disabled={!hasModify}
                value={config.incoming_ethernet_adapter?.toString() ?? "none"}
                onValueChange={(v) =>
                  setConfig({
                    ...config,
                    incoming_ethernet_adapter: v === "none" ? null : Number(v),
                  })}
              >
                <SelectTrigger className="rounded-md">
                  <SelectValue placeholder="Select incoming adapter" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  {(adapters.available ?? []).map((adapter) => (
                    <SelectItem
                      key={adapter.index}
                      value={adapter.index.toString()}
                    >
                      {adapter.index} — {adapter.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Outgoing Adapter (Egress)</Label>
              <Select
                disabled={!hasModify}
                value={config.output_ethernet_adapter?.toString() ?? "none"}
                onValueChange={(v) =>
                  setConfig({
                    ...config,
                    output_ethernet_adapter: v === "none" ? null : Number(v),
                  })}
              >
                <SelectTrigger className="rounded-md">
                  <SelectValue placeholder="Select outgoing adapter" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  {(adapters.available ?? []).map((adapter) => (
                    <SelectItem
                      key={adapter.index}
                      value={adapter.index.toString()}
                    >
                      {adapter.index} — {adapter.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Network</CardTitle>
                <CardDescription>
                  Live traffic transmitted between the selected eBPF adapters.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <svg
                  viewBox="0 0 760 270"
                  className="h-80 w-full"
                  role="img"
                  aria-label="Traffic flowing from the incoming adapter through the eBPF firewall to the outgoing adapter"
                >
                  <path
                    d="M180 132H300"
                    fill="none"
                    className="stroke-border"
                    strokeWidth="3"
                  />
                  <path
                    d="M460 132H580"
                    fill="none"
                    className="stroke-border"
                    strokeWidth="3"
                  />
                  <path id="traffic-in" d="M180 132H300" fill="none" />
                  <path id="traffic-out" d="M460 132H580" fill="none" />
                  <circle r="5" fill="#38bdf8">
                    <animateMotion dur="1.8s" repeatCount="indefinite">
                      <mpath href="#traffic-in" />
                    </animateMotion>
                  </circle>
                  <circle r="5" fill="#38bdf8">
                    <animateMotion
                      begin="0.9s"
                      dur="1.8s"
                      repeatCount="indefinite"
                    >
                      <mpath href="#traffic-in" />
                    </animateMotion>
                  </circle>
                  <circle r="5" fill="#34d399">
                    <animateMotion dur="1.8s" repeatCount="indefinite">
                      <mpath href="#traffic-out" />
                    </animateMotion>
                  </circle>
                  <circle r="5" fill="#34d399">
                    <animateMotion
                      begin="0.9s"
                      dur="1.8s"
                      repeatCount="indefinite"
                    >
                      <mpath href="#traffic-out" />
                    </animateMotion>
                  </circle>
                  <rect
                    x="20"
                    y="80"
                    width="160"
                    height="104"
                    rx="12"
                    className="fill-background stroke-border"
                    strokeWidth="2"
                  />
                  <text
                    x="100"
                    y="124"
                    textAnchor="middle"
                    fontSize="17"
                    fontWeight="600"
                    className="fill-foreground"
                  >
                    {adapters.incoming?.name ?? "Incoming"}
                  </text>
                  <text
                    x="100"
                    y="148"
                    textAnchor="middle"
                    fontSize="14"
                    className="fill-muted-foreground"
                  >
                    {formatBytes(traffic.incoming.bytes)}
                  </text>
                  <rect
                    x="300"
                    y="72"
                    width="160"
                    height="120"
                    rx="12"
                    className="fill-background stroke-border"
                    strokeWidth="2"
                  />
                  <text
                    x="380"
                    y="120"
                    textAnchor="middle"
                    fontSize="17"
                    fontWeight="600"
                    className="fill-foreground"
                  >
                    eBPF firewall
                  </text>
                  <text
                    x="380"
                    y="146"
                    textAnchor="middle"
                    fontSize="14"
                    className="fill-muted-foreground"
                  >
                    {traffic.outgoing.packets.toLocaleString()} packets
                  </text>
                  <circle cx="432" cy="88" r="5" fill="#22c55e" />
                  <rect
                    x="580"
                    y="80"
                    width="160"
                    height="104"
                    rx="12"
                    className="fill-background stroke-border"
                    strokeWidth="2"
                  />
                  <text
                    x="660"
                    y="124"
                    textAnchor="middle"
                    fontSize="17"
                    fontWeight="600"
                    className="fill-foreground"
                  >
                    {adapters.output?.name ?? "Outgoing"}
                  </text>
                  <text
                    x="660"
                    y="148"
                    textAnchor="middle"
                    fontSize="14"
                    className="fill-muted-foreground"
                  >
                    {formatBytes(traffic.outgoing.bytes)}
                  </text>
                  <text
                    x="240"
                    y="116"
                    textAnchor="middle"
                    fontSize="14"
                    className="fill-muted-foreground"
                  >
                    {formatBytes(traffic.incoming.bytes)}
                  </text>
                  <text
                    x="520"
                    y="116"
                    textAnchor="middle"
                    fontSize="14"
                    className="fill-muted-foreground"
                  >
                    {formatBytes(traffic.outgoing.bytes)}
                  </text>
                </svg>
                <div className="mt-3 flex justify-between text-xs text-muted-foreground">
                  <span>
                    <i className="mr-2 inline-block size-2 rounded-full bg-sky-500" />Incoming
                  </span>
                  <span>
                    <i className="mr-2 inline-block size-2 rounded-full bg-emerald-500" />Outgoing
                  </span>
                </div>
              </CardContent>
            </Card>
            <div className="flex flex-wrap gap-2 border-t pt-4">
              <Button
                type="button"
                variant="outline"
                disabled={!hasModify}
                onClick={() => setConfirmAction("shutdown")}
              >
                <Power className="size-4" /> Shut down eBPF
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={!hasModify}
                onClick={() => setConfirmAction("restart")}
              >
                <RotateCw className="size-4" /> Restart eBPF
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Threat Mitigation Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" /> Threat Mitigation
            </CardTitle>
            <CardDescription>Global security policies.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <Label className="text-base">DDoS Protection</Label>
                <p className="text-sm text-muted-foreground">
                  Activate global rate limiting profiles.
                </p>
              </div>
              <Switch
                disabled={!hasModify}
                checked={config.ddos_activated ?? true}
                onCheckedChange={(c) =>
                  setConfig({ ...config, ddos_activated: c })}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {hasModify && (
        <Button onClick={handleSave} className="w-full md:w-auto">
          Commit Configuration
        </Button>
      )}
      {confirmAction && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm"
          onClick={() => setConfirmAction(null)}
        >
          <section
            className="w-full max-w-md animate-in zoom-in-95 rounded-2xl border bg-background p-6 shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start gap-4">
              <div
                className={`grid size-11 shrink-0 place-items-center rounded-xl ${
                  confirmAction === "shutdown"
                    ? "bg-amber-500/15 text-amber-600"
                    : "bg-primary/15 text-primary"
                }`}
              >
                {confirmAction === "shutdown"
                  ? <Power className="size-5" />
                  : <RotateCw className="size-5" />}
              </div>
              <div>
                <h2 className="text-lg font-semibold">
                  {confirmAction === "shutdown"
                    ? "Shut down eBPF?"
                    : "Restart eBPF?"}
                </h2>
                <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
                  {confirmAction === "shutdown"
                    ? "Traffic enforcement will stop on all attached interfaces."
                    : "The current adapter configuration will be detached and attached again."}
                </p>
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <Button variant="outline" onClick={() => setConfirmAction(null)}>
                Cancel
              </Button>
              <Button
                variant={confirmAction === "shutdown"
                  ? "destructive"
                  : "default"}
                onClick={() => {
                  const action = confirmAction;
                  setConfirmAction(null);
                  void handleEbpfAction(action);
                }}
              >
                {confirmAction === "shutdown" ? "Shut down" : "Restart"}
              </Button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
