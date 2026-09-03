use aya::{
    Ebpf,
    TestRun,
    maps::{
        Array,
        HashMap,
        lpm_trie::{
            Key,
            LpmTrie,
        },
    },
    programs::{
        TestRunOptions,
        Xdp,
    },
};
use etherparse::PacketBuilder;
use oxidrop_common::{
    Action,
    FirewallConfig,
    Ipv4Packet,
    Ipv6Packet,
};

const XDP_ABORTED: u32 = 0;
const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;

struct XdpTestHarness {
    ebpf: Ebpf,
}

impl XdpTestHarness {
    fn new() -> Self {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/oxidrop"
        )))
        .expect("Failed to load eBPF bytecode");

        let program: &mut Xdp = ebpf
            .program_mut("oxidrop")
            .expect("Program 'oxidrop' not found")
            .try_into()
            .unwrap();

        program.load().expect("Failed to load XDP program");

        let mut config_map: Array<_, FirewallConfig> =
            Array::try_from(ebpf.map_mut("CONFIG").expect("CONFIG map not found"))
                .expect("Failed to cast CONFIG to Array");

        config_map
            .set(0, FirewallConfig::default(), 0)
            .expect("Failed to set default CONFIG");

        Self { ebpf }
    }

    fn run_packet(&mut self, packet_bytes: &[u8]) -> u32 {
        let program: &mut Xdp = self
            .ebpf
            .program_mut("oxidrop")
            .unwrap()
            .try_into()
            .unwrap();

        let result = program
            .test_run(TestRunOptions {
                data_in: Some(packet_bytes),
                ..Default::default()
            })
            .expect("BPF_PROG_TEST_RUN failed");

        result.return_value
    }

    fn allow_ipv4_flow(&mut self, flow: Ipv4Packet) {
        let mut subnet_map: LpmTrie<_, u32, Action> =
            LpmTrie::try_from(self.ebpf.map_mut("SUBNET_MATCHING_V4").unwrap()).unwrap();

        let subnet_key = Key::new(32, flow.source_addr);
        subnet_map.insert(&subnet_key, Action::Allow, 0).unwrap();

        let mut allow_list: HashMap<_, Ipv4Packet, Action> =
            HashMap::try_from(self.ebpf.map_mut("ALLOW_LIST_V4").unwrap()).unwrap();

        // Insert the flow directly without any byte-swapping
        allow_list.insert(flow, Action::Allow, 0).unwrap();
    }
    fn allow_ipv6_flow(&mut self, flow: Ipv6Packet) {
        let mut subnet_map: LpmTrie<_, [u32; 4], Action> =
            LpmTrie::try_from(self.ebpf.map_mut("SUBNET_MATCHING_V6").unwrap()).unwrap();

        let subnet_key = Key::new(128, flow.source_addr);
        subnet_map.insert(&subnet_key, Action::Allow, 0).unwrap();

        let mut allow_list: HashMap<_, Ipv6Packet, Action> =
            HashMap::try_from(self.ebpf.map_mut("ALLOW_LIST_V6").unwrap()).unwrap();

        allow_list.insert(flow, Action::Allow, 0).unwrap();
    }
    fn print_allow_list(&mut self) {
        let allow_list: HashMap<_, Ipv4Packet, Action> =
            HashMap::try_from(self.ebpf.map_mut("ALLOW_LIST_V4").unwrap()).unwrap();

        println!("--- ALLOW_LIST_V4 Contents ---");
        for entry in allow_list.iter() {
            match entry {
                Ok((key, value)) => {
                    let src_ip = std::net::Ipv4Addr::from(key.source_addr);
                    let dst_ip = std::net::Ipv4Addr::from(key.destination_addr);
                    println!(
                        "Src IP: {}, Dst IP: {}, Src Port: {}, Dst Port: {}, Proto: {}, Action: {:?}",
                        src_ip, dst_ip, key.source_port, key.destination_port, key.protocol, value
                    );
                }
                Err(e) => eprintln!("Error iterating map: {:?}", e),
            }
        }
        println!("------------------------------");
    }
}
fn build_ipv6_udp(src_ip: [u8; 16], dst_ip: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv6(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let mut payload = Vec::new();
    builder.write(&mut payload, &[0u8; 64]).unwrap();
    payload
}
fn build_ipv4_udp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let mut payload = Vec::new();
    builder.write(&mut payload, &[0u8; 64]).unwrap();
    payload
}

#[test]
fn test_malformed_packet_aborts() {
    let mut harness = XdpTestHarness::new();
    let mut truncated_data = vec![0u8; 14];
    truncated_data[12] = 0x08;
    truncated_data[13] = 0x00;
    truncated_data.extend_from_slice(&[0x45, 0x00]);
    assert_eq!(harness.run_packet(&truncated_data), XDP_ABORTED);
}

#[test]
fn test_arp_bypasses_firewall() {
    let mut harness = XdpTestHarness::new();
    let eth = etherparse::Ethernet2Header {
        source: [1; 6],
        destination: [2; 6],
        ether_type: etherparse::EtherType::ARP,
    };
    let mut arp_bytes = Vec::new();
    eth.write(&mut arp_bytes).unwrap();
    arp_bytes.extend_from_slice(&[
        0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01, 1, 1, 1, 1, 1, 1, 192, 168, 1, 1, 0, 0, 0, 0, 0,
        0, 192, 168, 1, 2,
    ]);
    arp_bytes.extend_from_slice(&[0u8; 18]);
    assert_eq!(harness.run_packet(&arp_bytes), XDP_PASS);
}

#[test]
fn test_ipv4_denied_by_default() {
    let mut harness = XdpTestHarness::new();
    let pkt = build_ipv4_udp([192, 168, 1, 50], [10, 0, 0, 1], 12345, 3000);
    assert_eq!(harness.run_packet(&pkt), XDP_DROP);
}

#[test]
fn test_ipv4_allowed_by_list() {
    let mut harness = XdpTestHarness::new();
    let src_ip = [192, 168, 1, 50];
    let dst_ip = [10, 0, 0, 1];
    let src_port = 12345;
    let dst_port = 3000;
    let protocol_udp = 17;

    let flow = Ipv4Packet::new(
        u32::from_ne_bytes(src_ip),
        u32::from_ne_bytes(dst_ip),
        src_port,
        dst_port,
        protocol_udp,
    );

    harness.allow_ipv4_flow(flow);

    // Print map contents to verify insertion
    harness.print_allow_list();

    let pkt = build_ipv4_udp(src_ip, dst_ip, src_port, dst_port);
    assert_eq!(harness.run_packet(&pkt), XDP_PASS);
}

#[test]
fn test_ipv4_udp_rate_limiting() {
    let mut harness = XdpTestHarness::new();
    let src_ip = [10, 0, 0, 2];
    let dst_ip = [10, 0, 0, 3];
    let src_port = 5555;
    let dst_port = 80;
    let protocol_udp = 17;

    let flow = Ipv4Packet::new(
        u32::from_be_bytes(src_ip),
        u32::from_be_bytes(dst_ip),
        src_port,
        dst_port,
        protocol_udp,
    );
    harness.allow_ipv4_flow(flow);
    let pkt = build_ipv4_udp(src_ip, dst_ip, src_port, dst_port);

    let mut dropped = false;
    for _ in 0..2050 {
        if harness.run_packet(&pkt) == XDP_DROP {
            dropped = true;
            break;
        }
    }
    assert!(dropped, "Rate limiter failed to drop");
}
#[test]
fn test_ipv6_denied_by_default() {
    let mut harness = XdpTestHarness::new();
    let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    let pkt = build_ipv6_udp(src_ip, dst_ip, 12345, 80);
    assert_eq!(harness.run_packet(&pkt), XDP_DROP);
}

#[test]
fn test_ipv6_allowed_by_list() {
    let mut harness = XdpTestHarness::new();
    let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let src_port = 12345;
    let dst_port = 80;
    let protocol_udp = 17;

    // Chunk the 16-byte IPv6 addresses into four big-endian u32 words,
    // exactly matching the chunking logic used inside the eBPF program.
    let src_array = [
        u32::from_be_bytes(src_ip[0..4].try_into().unwrap()),
        u32::from_be_bytes(src_ip[4..8].try_into().unwrap()),
        u32::from_be_bytes(src_ip[8..12].try_into().unwrap()),
        u32::from_be_bytes(src_ip[12..16].try_into().unwrap()),
    ];
    let dst_array = [
        u32::from_be_bytes(dst_ip[0..4].try_into().unwrap()),
        u32::from_be_bytes(dst_ip[4..8].try_into().unwrap()),
        u32::from_be_bytes(dst_ip[8..12].try_into().unwrap()),
        u32::from_be_bytes(dst_ip[12..16].try_into().unwrap()),
    ];

    let flow = Ipv6Packet::new(src_array, dst_array, src_port, dst_port, protocol_udp);

    harness.allow_ipv6_flow(flow);

    let pkt = build_ipv6_udp(src_ip, dst_ip, src_port, dst_port);
    assert_eq!(harness.run_packet(&pkt), XDP_PASS);
}
