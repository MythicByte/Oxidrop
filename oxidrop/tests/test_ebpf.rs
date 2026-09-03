use aya::{
    Ebpf,
    TestRun,
    programs::{
        TestRunOptions,
        Xdp,
    },
};
use etherparse::PacketBuilder;

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

        Self { ebpf }
    }

    fn test_packet(&mut self, packet_bytes: &[u8]) -> u32 {
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
            .expect("BPF_PROG_TEST_RUN execution failed");

        result.return_value
    }
}

#[test]
fn test_oxidrop_suite() {
    let mut harness = XdpTestHarness::new();

    // Scenario: Malformed packet
    let mut truncated_data = vec![0u8; 14];
    truncated_data[12] = 0x08;
    truncated_data[13] = 0x00; // EtherType = IPv4
    truncated_data.extend_from_slice(&[0x45, 0x00]);
    assert_eq!(harness.test_packet(&truncated_data), XDP_ABORTED);
    // Scenario: ARP Packet (Passed)
    let eth = etherparse::Ethernet2Header {
        source: [1, 1, 1, 1, 1, 1],
        destination: [2, 2, 2, 2, 2, 2],
        ether_type: etherparse::EtherType::ARP,
    };
    let mut arp_bytes = Vec::new();
    eth.write(&mut arp_bytes).unwrap();
    arp_bytes.extend_from_slice(&[
        0x00, 0x01, // Hardware type: Ethernet
        0x08, 0x00, // Protocol type: IPv4
        6,    // Hardware size
        4,    // Protocol size
        0x00, 0x01, // Opcode: Request
    ]);
    arp_bytes.extend_from_slice(&[1, 1, 1, 1, 1, 1]); // Sender MAC
    arp_bytes.extend_from_slice(&[192, 168, 1, 1]); // Sender IP
    arp_bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // Target MAC
    arp_bytes.extend_from_slice(&[192, 168, 1, 2]); // Target IP
    assert_eq!(harness.test_packet(&arp_bytes), XDP_PASS);

    // Scenario: Unallowed IPv4 Packet (Dropped)
    let ipv4_builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
        .ipv4([192, 168, 1, 50], [10, 0, 0, 1], 64)
        .udp(12345, 3000);
    let mut ipv4_bytes = Vec::new();
    ipv4_builder.write(&mut ipv4_bytes, &[]).unwrap();
    assert_eq!(harness.test_packet(&ipv4_bytes), XDP_DROP);
}
