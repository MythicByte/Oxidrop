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
import { Input } from "./ui/input.tsx";
import {
  Check,
  Network,
  Plus,
  Power,
  RotateCw,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import { client } from "./api.tsx";
import type { components } from "../api/schema.d.ts";

type Config = Partial<components["schemas"]["FirewallConfig"]>;
type ConfigPatch = components["schemas"]["ConfigPatch"];
type AdapterResponse = components["schemas"]["AdaptersResponse"];
type TrafficStats = components["schemas"]["TrafficStatsResponse"];
type SubnetAction = components["schemas"]["Action"];

const DEFAULT_PROTOCOL_MASK = (1 << 1) | (1 << 4);

const PROTOCOL_OPTIONS = [
  {
    bit: 1 << 0,
    label: "Loopback",
    description: "Local host traffic",
    shortLabel: "LOOP",
  },
  {
    bit: 1 << 1,
    label: "IPv4",
    description: "Internet Protocol v4",
    shortLabel: "IPv4",
  },
  {
    bit: 1 << 2,
    label: "ARP",
    description: "Address resolution",
    shortLabel: "ARP",
  },
  {
    bit: 1 << 3,
    label: "802.1Q",
    description: "VLAN-tagged traffic",
    shortLabel: "VLAN",
  },
  {
    bit: 1 << 4,
    label: "IPv6",
    description: "Internet Protocol v6",
    shortLabel: "IPv6",
  },
  {
    bit: 1 << 5,
    label: "802.1AD",
    description: "Q-in-Q VLAN traffic",
    shortLabel: "QinQ",
  },
] as const;

interface SubnetV4Rule {
  network: number;
  prefix_len: number;
  action: SubnetAction;
  address: string;
}

interface SubnetV6Rule {
  network: number[];
  prefix_len: number;
  action: SubnetAction;
  address: string;
}

function parseIpv4(value: string): number | null {
  const octets = value.split(".");
  if (octets.length !== 4) return null;
  const parsed = octets.map(Number);
  if (
    parsed.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) return null;
  return parsed.reduce((network, octet) => network * 256 + octet, 0);
}

function parseIpv6(value: string): number[] | null {
  const parts = value.split("::");
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts[1] ? parts[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((parts.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  const values = groups.map((group) => Number.parseInt(group, 16));
  if (
    values.length !== 8 ||
    values.some((group) =>
      !Number.isInteger(group) || group < 0 || group > 0xffff
    )
  ) return null;
  return [0, 2, 4, 6].map((offset) =>
    values[offset] * 0x10000 + values[offset + 1]
  );
}

function formatIpv4(network: number): string {
  return [
    network >>> 24,
    (network >>> 16) & 255,
    (network >>> 8) & 255,
    network & 255,
  ].join(".");
}

function formatIpv6(network: number[]): string {
  const groups = network.flatMap((word) => [
    Math.floor(word / 0x10000).toString(16),
    (word % 0x10000).toString(16),
  ]);
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length;) {
    if (groups[start] !== "0") {
      start += 1;
      continue;
    }
    let end = start;
    while (end < groups.length && groups[end] === "0") end += 1;
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  if (bestLength < 2) return groups.join(":");
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");
  return `${left}::${right}`;
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(2)} GiB`;
}

export function FirewallConfiguration() {
  const [config, setConfig] = useState<Config>({
    ddos_activated: true,
    protocol_allowed: DEFAULT_PROTOCOL_MASK,
  });
  const [adapters, setAdapters] = useState<AdapterResponse>({
    available: [],
    enforcement_active: false,
  });
  const [permissions, setPermissions] = useState<string[]>([]);
  const [subnetV4Rules, setSubnetV4Rules] = useState<SubnetV4Rule[]>([]);
  const [subnetV6Rules, setSubnetV6Rules] = useState<SubnetV6Rule[]>([]);
  const [subnetV4Address, setSubnetV4Address] = useState("");
  const [subnetV6Address, setSubnetV6Address] = useState("");
  const [subnetV4Prefix, setSubnetV4Prefix] = useState("24");
  const [subnetV6Prefix, setSubnetV6Prefix] = useState("64");
  const [subnetV4Action, setSubnetV4Action] = useState<SubnetAction>("Allow");
  const [subnetV6Action, setSubnetV6Action] = useState<SubnetAction>("Allow");
  const [isLoading, setIsLoading] = useState(true);
  const [attachmentNotice, setAttachmentNotice] = useState<
    { kind: "success" | "error"; message: string } | null
  >(null);
  const [noticeFading, setNoticeFading] = useState(false);
  const [protocolUpdate, setProtocolUpdate] = useState<
    "idle" | "saving" | "success" | "error"
  >("idle");
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
        const [rbacRes, configRes, adapterRes, subnetV4Res, subnetV6Res] =
          await Promise.all([
            client.GET("/api/v1/role_and_permissions"),
            client.GET("/api/v1/config"),
            client.GET("/api/v1/config/adapters"),
            fetch("/api/v1/config/subnet/v4", { credentials: "include" }),
            fetch("/api/v1/config/subnet/v6", { credentials: "include" }),
          ]);

        if (rbacRes.response.ok && rbacRes.data) {
          setPermissions(rbacRes.data.permissions);
        }
        if (configRes.response.ok && configRes.data) {
          setConfig({
            ...(configRes.data as unknown as Config),
            ddos_activated: configRes.data.ddos_activated ?? true,
            protocol_allowed: configRes.data.protocol_allowed ??
              DEFAULT_PROTOCOL_MASK,
          });
        }
        if (adapterRes.response.ok && adapterRes.data) {
          setAdapters(adapterRes.data as AdapterResponse);
        }
        if (subnetV4Res.ok) {
          const rules = await subnetV4Res.json() as Array<{
            network: number;
            prefix_len: number;
            action: SubnetAction;
          }>;
          setSubnetV4Rules(
            rules.map((rule) => ({
              ...rule,
              address: formatIpv4(rule.network),
            })),
          );
        }
        if (subnetV6Res.ok) {
          const rules = await subnetV6Res.json() as Array<{
            network: number[];
            prefix_len: number;
            action: SubnetAction;
          }>;
          setSubnetV6Rules(
            rules.map((rule) => ({
              ...rule,
              address: formatIpv6(rule.network),
            })),
          );
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

  const addSubnetV4 = async () => {
    const network = parseIpv4(subnetV4Address);
    const prefix_len = Number(subnetV4Prefix);
    if (
      network === null || !Number.isInteger(prefix_len) || prefix_len < 0 ||
      prefix_len > 32
    ) {
      setAttachmentNotice({
        kind: "error",
        message: "Enter a valid IPv4 network and prefix length.",
      });
      return;
    }
    const rule = { network, prefix_len, action: subnetV4Action };
    const { response } = await client.POST("/api/v1/config/subnet/v4", {
      body: rule,
    });
    if (!response.ok) {
      setAttachmentNotice({
        kind: "error",
        message: "Failed to add the IPv4 subnet rule.",
      });
      return;
    }
    setSubnetV4Rules((current) => [
      ...current.filter((item) =>
        !(item.network === network && item.prefix_len === prefix_len)
      ),
      { ...rule, address: subnetV4Address },
    ]);
    setSubnetV4Address("");
  };

  const addSubnetV6 = async () => {
    const network = parseIpv6(subnetV6Address);
    const prefix_len = Number(subnetV6Prefix);
    if (
      network === null || !Number.isInteger(prefix_len) || prefix_len < 0 ||
      prefix_len > 128
    ) {
      setAttachmentNotice({
        kind: "error",
        message: "Enter a valid IPv6 network and prefix length.",
      });
      return;
    }
    const rule = { network, prefix_len, action: subnetV6Action };
    const { response } = await client.POST("/api/v1/config/subnet/v6", {
      body: rule,
    });
    if (!response.ok) {
      setAttachmentNotice({
        kind: "error",
        message: "Failed to add the IPv6 subnet rule.",
      });
      return;
    }
    setSubnetV6Rules((current) => [
      ...current.filter((item) =>
        !(item.network.every((word, index) => word === network[index]) &&
          item.prefix_len === prefix_len)
      ),
      { ...rule, address: subnetV6Address },
    ]);
    setSubnetV6Address("");
  };

  const removeSubnetV4 = async (rule: SubnetV4Rule) => {
    const { response } = await client.DELETE("/api/v1/config/subnet/v4", {
      body: {
        network: rule.network,
        prefix_len: rule.prefix_len,
        action: rule.action,
      },
    });
    if (response.ok) {
      setSubnetV4Rules((current) => current.filter((item) => item !== rule));
    }
  };

  const removeSubnetV6 = async (rule: SubnetV6Rule) => {
    const { response } = await client.DELETE("/api/v1/config/subnet/v6", {
      body: {
        network: rule.network,
        prefix_len: rule.prefix_len,
        action: rule.action,
      },
    });
    if (response.ok) {
      setSubnetV6Rules((current) => current.filter((item) => item !== rule));
    }
  };

  const updatePolicy = async (
    field: "ddos_activated" | "subnet_activated",
    enabled: boolean,
  ) => {
    const previous = config[field];
    setConfig((current) => ({ ...current, [field]: enabled }));
    try {
      const { response } = await client.POST("/api/v1/config", {
        body: { [field]: enabled },
      });
      if (!response.ok) {
        const message = await response.text();
        setConfig((current) => ({ ...current, [field]: previous }));
        setAttachmentNotice({
          kind: "error",
          message: message ||
            `Failed to ${enabled ? "enable" : "disable"} ${
              field === "ddos_activated" ? "DDoS protection" : "subnet matching"
            }.`,
        });
        return;
      }
      setConfig((current) => ({ ...current, [field]: enabled }));
      setAttachmentNotice({
        kind: "success",
        message: `${
          field === "ddos_activated" ? "DDoS protection" : "Subnet matching"
        } ${enabled ? "enabled" : "disabled"}.`,
      });
    } catch (error) {
      console.error(`Failed to update ${field}:`, error);
      setConfig((current) => ({ ...current, [field]: previous }));
      setAttachmentNotice({
        kind: "error",
        message: "The firewall policy could not be updated.",
      });
    }
  };

  const updateProtocols = async (protocolAllowed: number) => {
    const previous = config.protocol_allowed ?? 0;
    setProtocolUpdate("saving");
    setConfig((current) => ({
      ...current,
      protocol_allowed: protocolAllowed,
    }));
    try {
      const { response } = await client.POST("/api/v1/config", {
        body: { protocol_allowed: protocolAllowed },
      });
      if (!response.ok) {
        const message = await response.text();
        setConfig((current) => ({
          ...current,
          protocol_allowed: previous,
        }));
        setProtocolUpdate("error");
        setAttachmentNotice({
          kind: "error",
          message: message ||
            "The allowed protocol policy could not be updated.",
        });
        return;
      }
      setProtocolUpdate("success");
      setAttachmentNotice({
        kind: "success",
        message: "Allowed protocols updated successfully.",
      });
    } catch (error) {
      console.error("Failed to update allowed protocols:", error);
      setConfig((current) => ({
        ...current,
        protocol_allowed: previous,
      }));
      setProtocolUpdate("error");
      setAttachmentNotice({
        kind: "error",
        message: "The allowed protocol policy could not be updated.",
      });
    }
  };

  const toggleProtocol = (bit: number, enabled: boolean) => {
    const current = config.protocol_allowed ?? 0;
    void updateProtocols(enabled ? current | bit : current & ~bit);
  };

  const handleSave = async () => {
    try {
      const payload: ConfigPatch = {
        ddos_activated: config.ddos_activated,
        subnet_activated: config.subnet_activated,
        protocol_allowed: config.protocol_allowed,
        incoming_ethernet_adapter: config.incoming_ethernet_adapter,
        output_ethernet_adapter: config.output_ethernet_adapter,
      };

      const { response } = await client.POST("/api/v1/config", {
        body: payload,
      });
      if (response.ok) {
        try {
          const adapterResponse = await client.GET("/api/v1/config/adapters");
          if (adapterResponse.response.ok && adapterResponse.data) {
            setAdapters(adapterResponse.data);
          }
        } catch (error) {
          console.error("Failed to refresh adapter state:", error);
        }
        setAttachmentNotice({
          kind: "success",
          message: "Configuration applied successfully.",
        });
      } else {
        const message = await response.text();
        setConfig((current) => ({
          ...current,
          incoming_ethernet_adapter: null,
          output_ethernet_adapter: null,
        }));
        try {
          const adapterResponse = await client.GET("/api/v1/config/adapters");
          if (adapterResponse.response.ok && adapterResponse.data) {
            setAdapters(adapterResponse.data);
          }
        } catch (error) {
          console.error("Failed to refresh adapter state:", error);
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
      if (action === "shutdown") {
        setConfig((current) => ({
          ...current,
          incoming_ethernet_adapter: null,
          output_ethernet_adapter: null,
        }));
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

  const selectedIncoming = adapters.available?.find(
    (a) => a.index === config.incoming_ethernet_adapter,
  );
  const selectedOutgoing = adapters.available?.find(
    (a) => a.index === config.output_ethernet_adapter,
  );

  return (
    <div className="p-6 space-y-6">
      <div>
        {attachmentNotice && (
          <div
            role="alert"
            className={`relative mb-5 flex items-center gap-3 border px-4 py-3 pr-10 text-sm font-medium transition-opacity duration-500 ease-out ${
              noticeFading ? "opacity-0" : "opacity-100"
            } ${
              attachmentNotice.kind === "success"
                ? "animate-pulse border-emerald-500/40 bg-emerald-500/10 text-emerald-700"
                : "animate-in slide-in-from-right-2 border-destructive/40 bg-destructive/10 text-destructive"
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
            <button
              type="button"
              aria-label="Dismiss notification"
              onClick={() => setAttachmentNotice(null)}
              className="absolute right-2 top-2 rounded-md p-1 opacity-70 transition-opacity hover:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-current"
            >
              <X className="size-4" />
            </button>
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

      <div className="grid w-full min-w-0 grid-cols-1 gap-6 2xl:grid-cols-2">
        {/* Hardware Adapters Card */}
        <Card className="w-full min-w-0">
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
              <Label>Incoming Adapter</Label>
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
                  {selectedIncoming
                    ? (
                      <span>
                        {selectedIncoming.index} {selectedIncoming.name}
                      </span>
                    )
                    : <SelectValue placeholder="Select incoming adapter" />}
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  {(adapters.available ?? []).map((adapter) => (
                    <SelectItem
                      key={adapter.index}
                      value={adapter.index.toString()}
                    >
                      {adapter.index} {adapter.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Outgoing Adapter</Label>
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
                  {selectedOutgoing
                    ? (
                      <span>
                        {selectedOutgoing.index} {selectedOutgoing.name}
                      </span>
                    )
                    : <SelectValue placeholder="Select outgoing adapter" />}
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  {(adapters.available ?? []).map((adapter) => (
                    <SelectItem
                      key={adapter.index}
                      value={adapter.index.toString()}
                    >
                      {adapter.index} {adapter.name}
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
            {hasModify && (
              <div className="flex justify-end border-t pt-4">
                <Button type="button" onClick={() => void handleSave()}>
                  Apply Configuration
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="w-full min-w-0">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" /> Allowed protocols
            </CardTitle>
            <CardDescription>
              Choose which Ethernet traffic the firewall processes. Disabled
              protocol types are rejected before higher-level rules run.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/30 p-3">
              <div>
                <p className="font-medium">
                  {PROTOCOL_OPTIONS.filter(({ bit }) =>
                    (config.protocol_allowed ?? 0) & bit
                  ).length} of {PROTOCOL_OPTIONS.length} protocols enabled
                </p>
                <p className="text-sm text-muted-foreground">
                  Changes apply immediately to the eBPF policy.
                </p>
              </div>
              <div className="flex gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={!hasModify || protocolUpdate === "saving" ||
                    (config.protocol_allowed ?? 0) ===
                      PROTOCOL_OPTIONS.reduce((mask, { bit }) => mask | bit, 0)}
                  onClick={() =>
                    void updateProtocols(
                      PROTOCOL_OPTIONS.reduce((mask, { bit }) => mask | bit, 0),
                    )}
                >
                  Enable all
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={!hasModify || protocolUpdate === "saving" ||
                    (config.protocol_allowed ?? 0) === 0}
                  onClick={() => void updateProtocols(0)}
                >
                  Clear
                </Button>
              </div>
            </div>
            {protocolUpdate !== "idle" && (
              <p
                className={`text-sm font-medium ${
                  protocolUpdate === "error"
                    ? "text-destructive"
                    : protocolUpdate === "success"
                    ? "text-emerald-600"
                    : "text-muted-foreground"
                }`}
                role={protocolUpdate === "error" ? "alert" : undefined}
              >
                {protocolUpdate === "saving"
                  ? "Applying protocol policy..."
                  : protocolUpdate === "success"
                  ? "Protocol policy applied successfully."
                  : "The protocol policy could not be applied."}
              </p>
            )}
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {PROTOCOL_OPTIONS.map(
                ({ bit, label, description, shortLabel }) => {
                  const enabled = Boolean((config.protocol_allowed ?? 0) & bit);
                  return (
                    <div
                      key={label}
                      role="button"
                      tabIndex={hasModify ? 0 : -1}
                      aria-pressed={enabled}
                      onClick={() => {
                        if (hasModify && protocolUpdate !== "saving") {
                          toggleProtocol(bit, !enabled);
                        }
                      }}
                      onKeyDown={(event) => {
                        if (
                          hasModify &&
                          protocolUpdate !== "saving" &&
                          (event.key === "Enter" || event.key === " ")
                        ) {
                          event.preventDefault();
                          toggleProtocol(bit, !enabled);
                        }
                      }}
                      className={`group flex items-center justify-between gap-3 rounded-lg border p-3 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                        enabled
                          ? "border-primary/40 bg-primary/5"
                          : "bg-background hover:bg-muted/40"
                      }`}
                    >
                      <div className="flex min-w-0 items-center gap-3">
                        <span
                          className={`flex size-9 shrink-0 items-center justify-center rounded-md text-xs font-bold ${
                            enabled
                              ? "bg-primary text-primary-foreground"
                              : "bg-muted text-muted-foreground"
                          }`}
                        >
                          {enabled ? <Check className="size-4" /> : shortLabel}
                        </span>
                        <div className="min-w-0">
                          <Label className="text-sm font-medium">{label}</Label>
                          <p className="truncate text-xs text-muted-foreground">
                            {description}
                          </p>
                        </div>
                      </div>
                      <Switch
                        size="sm"
                        disabled={!hasModify || protocolUpdate === "saving"}
                        checked={enabled}
                        aria-label={`Allow ${label}`}
                        onClick={(event) => event.stopPropagation()}
                        onCheckedChange={(checked) =>
                          toggleProtocol(bit, checked)}
                      />
                    </div>
                  );
                },
              )}
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
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between rounded-lg border p-2.5">
              <div className="space-y-0.5">
                <Label className="text-base">DDoS Protection</Label>
                <p className="text-sm text-muted-foreground">
                  Activate global rate limiting profiles.
                </p>
              </div>
              <Switch
                disabled={!hasModify}
                checked={config.ddos_activated ?? true}
                onCheckedChange={(checked) =>
                  updatePolicy("ddos_activated", checked)}
              />
            </div>
            <div className="flex items-center justify-between rounded-lg border p-2.5">
              <div className="space-y-0.5">
                <Label className="text-base">Subnet Matching</Label>
                <p className="text-sm text-muted-foreground">
                  Enforce IPv4 and IPv6 subnet rules.
                </p>
              </div>
              <Switch
                disabled={!hasModify}
                checked={config.subnet_activated ?? true}
                onCheckedChange={(checked) =>
                  updatePolicy("subnet_activated", checked)}
              />
            </div>
            <div className="space-y-4 rounded-lg border p-3">
              <div>
                <Label className="text-base">IPv4 subnets</Label>
                <p className="text-sm text-muted-foreground">
                  Add a CIDR network. Adding an existing network modifies it.
                </p>
              </div>
              <div className="grid gap-2 sm:grid-cols-[1fr_90px_110px_auto]">
                <Input
                  value={subnetV4Address}
                  disabled={!hasModify}
                  onChange={(event) => setSubnetV4Address(event.target.value)}
                  placeholder="192.168.1.0"
                  aria-label="IPv4 network"
                />
                <Input
                  value={subnetV4Prefix}
                  disabled={!hasModify}
                  onChange={(event) => setSubnetV4Prefix(event.target.value)}
                  placeholder="24"
                  aria-label="IPv4 prefix length"
                  type="number"
                  min={0}
                  max={32}
                />
                <Select
                  disabled={!hasModify}
                  value={subnetV4Action}
                  onValueChange={(value) =>
                    setSubnetV4Action(value as SubnetAction)}
                >
                  <SelectTrigger aria-label="IPv4 subnet action">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Allow">Allow</SelectItem>
                    <SelectItem value="Deny">Deny</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  disabled={!hasModify}
                  onClick={() => void addSubnetV4()}
                >
                  <Plus className="size-4" /> Add
                </Button>
              </div>
              {subnetV4Rules.map((rule) => (
                <div
                  key={`${rule.network}/${rule.prefix_len}`}
                  className="flex items-center justify-between rounded border px-3 py-2 text-sm"
                >
                  <span>{rule.address}/{rule.prefix_len} · {rule.action}</span>
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={!hasModify}
                    onClick={() => void removeSubnetV4(rule)}
                    aria-label={`Delete IPv4 subnet ${rule.address}`}
                  >
                    <Trash2 className="size-4" />
                  </Button>
                </div>
              ))}
            </div>
            <div className="space-y-4 rounded-lg border p-3">
              <div>
                <Label className="text-base">IPv6 subnets</Label>
                <p className="text-sm text-muted-foreground">
                  Add a CIDR network. Adding an existing network modifies it.
                </p>
              </div>
              <div className="grid gap-2 sm:grid-cols-[1fr_90px_110px_auto]">
                <Input
                  value={subnetV6Address}
                  disabled={!hasModify}
                  onChange={(event) => setSubnetV6Address(event.target.value)}
                  placeholder="2001:db8::"
                  aria-label="IPv6 network"
                />
                <Input
                  value={subnetV6Prefix}
                  disabled={!hasModify}
                  onChange={(event) => setSubnetV6Prefix(event.target.value)}
                  placeholder="64"
                  aria-label="IPv6 prefix length"
                  type="number"
                  min={0}
                  max={128}
                />
                <Select
                  disabled={!hasModify}
                  value={subnetV6Action}
                  onValueChange={(value) =>
                    setSubnetV6Action(value as SubnetAction)}
                >
                  <SelectTrigger aria-label="IPv6 subnet action">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Allow">Allow</SelectItem>
                    <SelectItem value="Deny">Deny</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  disabled={!hasModify}
                  onClick={() => void addSubnetV6()}
                >
                  <Plus className="size-4" /> Add
                </Button>
              </div>
              {subnetV6Rules.map((rule) => (
                <div
                  key={`${rule.address}/${rule.prefix_len}`}
                  className="flex items-center justify-between rounded border px-3 py-2 text-sm"
                >
                  <span>{rule.address}/{rule.prefix_len} · {rule.action}</span>
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={!hasModify}
                    onClick={() => void removeSubnetV6(rule)}
                    aria-label={`Delete IPv6 subnet ${rule.address}`}
                  >
                    <Trash2 className="size-4" />
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

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
