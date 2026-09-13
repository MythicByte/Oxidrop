#![cfg(target_os = "linux")]

use std::{
    process::Command,
    sync::atomic::{
        AtomicUsize,
        Ordering,
    },
};

use aya::maps::lpm_trie::Key;
use oxidrop::{
    Opt,
    ebpf::EbpfProgramm,
};
use oxidrop_common::{
    Action,
    ActivaterEtherTypes,
    AllowListState,
    FirewallConfig,
    Ipv4Packet,
};

struct NamespaceTopology {
    client: String,
    server: String,
    client_host: String,
    server_host: String,
    client_ifindex: u32,
    firewalld_trusted: bool,
}

impl NamespaceTopology {
    fn create() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let process_id = std::process::id() % 10_000;
        let client = format!("o{process_id:04}{id:02}c");
        let server = format!("o{process_id:04}{id:02}s");
        let client_host = format!("o{process_id:04}{id:02}ci");
        let server_host = format!("o{process_id:04}{id:02}si");
        let client_peer = format!("o{process_id:04}{id:02}cp");
        let server_peer = format!("o{process_id:04}{id:02}sp");

        run("ip", &["netns", "add", &client]);
        run("ip", &["netns", "add", &server]);
        run(
            "ip",
            &[
                "link",
                "add",
                &client_host,
                "type",
                "veth",
                "peer",
                "name",
                &client_peer,
            ],
        );
        run("ip", &["link", "set", &client_peer, "netns", &client]);
        run(
            "ip",
            &[
                "link",
                "add",
                &server_host,
                "type",
                "veth",
                "peer",
                "name",
                &server_peer,
            ],
        );
        run("ip", &["link", "set", &server_peer, "netns", &server]);

        run(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &client_host,
                "address",
                "02:00:00:00:10:01",
            ],
        );
        run(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &server_host,
                "address",
                "02:00:00:00:20:01",
            ],
        );
        netns(
            &client,
            &[
                "link",
                "set",
                "dev",
                &client_peer,
                "address",
                "02:00:00:00:01:01",
            ],
        );
        netns(
            &server,
            &[
                "link",
                "set",
                "dev",
                &server_peer,
                "address",
                "02:00:00:00:02:01",
            ],
        );

        run("ip", &["addr", "add", "10.0.1.1/24", "dev", &client_host]);
        run("ip", &["addr", "add", "10.0.2.1/24", "dev", &server_host]);
        run("ip", &["-6", "addr", "flush", "dev", &client_host]);
        run("ip", &["-6", "addr", "flush", "dev", &server_host]);
        run(
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv6.conf.{client_host}.disable_ipv6=1"),
            ],
        );
        run(
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv6.conf.{server_host}.disable_ipv6=1"),
            ],
        );
        run(
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv4.conf.{client_host}.rp_filter=0"),
            ],
        );
        run(
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv4.conf.{server_host}.rp_filter=0"),
            ],
        );
        run("ip", &["link", "set", &client_host, "up"]);
        run("ip", &["link", "set", &server_host, "up"]);
        run("ip", &["link", "set", "dev", &client_host, "promisc", "on"]);
        run("ip", &["link", "set", "dev", &server_host, "promisc", "on"]);
        let firewalld_trusted =
            trust_firewall_interfaces(&client_host) | trust_firewall_interfaces(&server_host);
        firewall_rule(
            &client_host,
            &server_host,
            "10.0.1.0/24",
            "10.0.2.0/24",
            true,
        );
        firewall_rule(
            &server_host,
            &client_host,
            "10.0.2.0/24",
            "10.0.1.0/24",
            true,
        );
        netns(&client, &["link", "set", "lo", "up"]);
        netns(&server, &["link", "set", "lo", "up"]);
        netns(
            &client,
            &["addr", "add", "10.0.1.2/24", "dev", &client_peer],
        );
        netns(
            &server,
            &["addr", "add", "10.0.2.2/24", "dev", &server_peer],
        );
        netns(&client, &["-6", "addr", "flush", "dev", &client_peer]);
        netns(&server, &["-6", "addr", "flush", "dev", &server_peer]);
        netns(
            &client,
            &[
                "-6",
                "link",
                "set",
                "dev",
                &client_peer,
                "addrgenmode",
                "none",
            ],
        );
        netns_run(
            &client,
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv6.conf.{client_peer}.disable_ipv6=1"),
            ],
        );
        netns(
            &server,
            &[
                "-6",
                "link",
                "set",
                "dev",
                &server_peer,
                "addrgenmode",
                "none",
            ],
        );
        netns_run(
            &server,
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv6.conf.{server_peer}.disable_ipv6=1"),
            ],
        );
        netns_run(
            &client,
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv4.conf.{client_peer}.rp_filter=0"),
            ],
        );
        netns_run(
            &server,
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv4.conf.{server_peer}.rp_filter=0"),
            ],
        );
        netns(&client, &["link", "set", &client_peer, "up"]);
        netns(&server, &["link", "set", &server_peer, "up"]);
        netns(&client, &["link", "set", &client_peer, "promisc", "on"]);
        netns(&server, &["link", "set", &server_peer, "promisc", "on"]);
        netns(
            &client,
            &[
                "neigh",
                "replace",
                "10.0.1.1",
                "lladdr",
                "02:00:00:00:10:01",
                "nud",
                "permanent",
                "dev",
                &client_peer,
            ],
        );
        netns(
            &server,
            &[
                "neigh",
                "replace",
                "10.0.2.1",
                "lladdr",
                "02:00:00:00:20:01",
                "nud",
                "permanent",
                "dev",
                &server_peer,
            ],
        );
        netns(&client, &["route", "add", "10.0.2.0/24", "via", "10.0.1.1"]);
        netns(&server, &["route", "add", "10.0.1.0/24", "via", "10.0.2.1"]);
        run("sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"]);

        let client_ifindex = interface_index(&client_host);
        Self {
            client,
            server,
            client_host,
            server_host,
            client_ifindex,
            firewalld_trusted,
        }
    }
}

impl Drop for NamespaceTopology {
    fn drop(&mut self) {
        if self.firewalld_trusted {
            untrust_firewall_interface(&self.client_host);
            untrust_firewall_interface(&self.server_host);
        }
        firewall_rule(
            &self.client_host,
            &self.server_host,
            "10.0.1.0/24",
            "10.0.2.0/24",
            false,
        );
        firewall_rule(
            &self.server_host,
            &self.client_host,
            "10.0.2.0/24",
            "10.0.1.0/24",
            false,
        );
        let _ = Command::new("ip")
            .args(["link", "del", &self.client_host])
            .output();
        let _ = Command::new("ip")
            .args(["link", "del", &self.server_host])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.client])
            .output();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.server])
            .output();
    }
}

fn trust_firewall_interfaces(interface: &str) -> bool {
    let active = Command::new("systemctl")
        .args(["is-active", "--quiet", "firewalld"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    active
        && Command::new("firewall-cmd")
            .args(["--zone=trusted", "--change-interface", interface])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
}

fn untrust_firewall_interface(interface: &str) {
    let _ = Command::new("firewall-cmd")
        .args(["--zone=trusted", "--remove-interface", interface])
        .status();
}

fn firewall_rule(input: &str, output: &str, source: &str, destination: &str, add: bool) {
    let action = if add { "-I" } else { "-D" };
    let mut args = vec![action, "FORWARD"];
    if add {
        args.push("1");
    }
    args.extend([
        "-s",
        source,
        "-d",
        destination,
        "-i",
        input,
        "-o",
        output,
        "-j",
        "ACCEPT",
    ]);
    let status = Command::new("iptables")
        .args(&args)
        .status()
        .unwrap_or_else(|error| panic!("failed to execute iptables: {error}"));
    if add {
        assert!(
            status.success(),
            "iptables {action} FORWARD rule failed for {input}->{output}"
        );
    } else if !status.success() {
        eprintln!("warning: iptables cleanup failed for {input}->{output}");
    }
}

fn run(program: &str, args: &[&str]) {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to execute {program}: {error}"));
    assert!(
        output.status.success(),
        "{program} {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn netns(namespace: &str, args: &[&str]) {
    let mut command = vec!["netns", "exec", namespace, "ip"];
    command.extend_from_slice(args);
    run("ip", &command);
}

fn netns_run(namespace: &str, program: &str, args: &[&str]) {
    let mut command = vec!["netns", "exec", namespace, program];
    command.extend_from_slice(args);
    run("ip", &command);
}

fn interface_index(name: &str) -> u32 {
    let output = Command::new("ip")
        .args(["-o", "link", "show", "dev", name])
        .output()
        .expect("interface index command must execute");
    assert!(
        output.status.success(),
        "interface index lookup must succeed for {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .split_once(':')
        .and_then(|(index, _)| index.trim().parse().ok())
        .unwrap_or_else(|| panic!("interface index must be present for {name}"))
}

fn ping(namespace: &str) -> std::process::Output {
    Command::new("ip")
        .args([
            "netns", "exec", namespace, "ping", "-c", "1", "-W", "2", "10.0.2.2",
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to execute ping in {namespace}: {error}"))
}

fn namespace_command(namespace: &str, args: &[&str]) -> String {
    let mut command = vec!["netns", "exec", namespace];
    command.extend_from_slice(args);
    let output = Command::new("ip")
        .args(command)
        .output()
        .unwrap_or_else(|error| panic!("failed to inspect namespace {namespace}: {error}"));
    format!(
        "status={}; stdout={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn real_veth_namespaces_forward_and_deny_stateful_icmp() {
    let topology = NamespaceTopology::create();
    let mut ebpf = EbpfProgramm::new().expect("eBPF object must load");
    let (
        mut config,
        mut allow_list_v4,
        _allow_list_v6,
        _packet_counts_v4,
        _packet_counts_v6,
        mut subnet_v4,
        _subnet_v6,
    ) = ebpf
        .get_maps()
        .expect("all production maps must be available");

    let firewall_config = FirewallConfig {
        protocol_allowed: ActivaterEtherTypes::IPV4,
        ddos_activated: false,
        subnet_activated: true,
        incoming_ethernet_adapter: Some(topology.client_ifindex),
        output_ethernet_adapter: None,
        ..FirewallConfig::default()
    };
    config
        .set(0, firewall_config, 0)
        .expect("CONFIG map must accept namespace configuration");

    let client = u32::from_be_bytes([10, 0, 1, 2]);
    let server = u32::from_be_bytes([10, 0, 2, 2]);
    subnet_v4
        .insert(&Key::new(32, client.to_be_bytes()), Action::Allow, 0)
        .expect("client subnet must be allowed");
    subnet_v4
        .insert(&Key::new(32, server.to_be_bytes()), Action::Allow, 0)
        .expect("server subnet must be allowed");
    allow_list_v4
        .insert(
            Ipv4Packet::new(server, client, 0, 0, 1),
            AllowListState {
                action: Action::Allow,
                last_seen: 0,
            },
            0,
        )
        .expect("ICMP flow must be allowed");
    allow_list_v4
        .insert(
            Ipv4Packet::new(client, server, 0, 0, 1),
            AllowListState {
                action: Action::Allow,
                last_seen: 0,
            },
            0,
        )
        .expect("reverse ICMP flow must be allowed");

    ebpf.reboot(
        &firewall_config,
        &Opt {
            http_port: 0,
            incoming_adapter: Some(topology.client_ifindex),
            output_adapter: None,
        },
    )
    .expect("eBPF must attach to both namespace-facing interfaces");

    let ping_output = ping(&topology.client);
    assert!(
        ping_output.status.success(),
        "allowed ICMP must cross the routed namespace topology after XDP policy approval; stdout={}; stderr={}; client_addr={}; client_route={}; server_addr={}; server_route={}; client_host_link={}; server_host_link={}; client_link={}; server_link={}",
        String::from_utf8_lossy(&ping_output.stdout),
        String::from_utf8_lossy(&ping_output.stderr),
        namespace_command(&topology.client, &["ip", "addr"]),
        namespace_command(&topology.client, &["ip", "route"]),
        namespace_command(&topology.server, &["ip", "addr"]),
        namespace_command(&topology.server, &["ip", "route"]),
        host_interface_stats(&topology.client_host),
        host_interface_stats(&topology.server_host),
        namespace_command(&topology.client, &["ip", "-s", "link"]),
        namespace_command(&topology.server, &["ip", "-s", "link"])
    );

    allow_list_v4
        .remove(&Ipv4Packet::new(server, client, 0, 0, 1))
        .expect("ICMP flow state must be removable");
    allow_list_v4
        .remove(&Ipv4Packet::new(client, server, 0, 0, 1))
        .expect("reverse ICMP flow state must be removable");
    let denied_ping = ping(&topology.client);
    assert!(
        !denied_ping.status.success(),
        "ICMP must fail after its stateful allow-list entry is removed; stdout={}; stderr={}",
        String::from_utf8_lossy(&denied_ping.stdout),
        String::from_utf8_lossy(&denied_ping.stderr)
    );
}

fn host_interface_stats(name: &str) -> String {
    let output = Command::new("ip")
        .args(["-s", "link", "show", "dev", name])
        .output()
        .unwrap_or_else(|error| panic!("failed to inspect host interface {name}: {error}"));
    format!(
        "status={}; stdout={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
