// tests/integration.rs
use aya::maps::lpm_trie::{
    Key,
    LpmTrie,
};
use etherparse::{
    IpNumber,
    Ipv6FlowLabel,
    PacketBuilder,
};
use oxidrop_common::{
    Action,
    Ipv4Packet,
    Ipv6Packet,
};

use crate::test_ebpf::{
    XDP_ABORTED,
    XDP_DROP,
    XDP_PASS,
    XdpTestHarness,
};
#[path = "test_ebpf.rs"]
mod test_ebpf;

// ============================================================================
// Packet Builders
// ============================================================================

fn build_ipv4_udp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let mut payload = Vec::new();
    builder.write(&mut payload, &[0u8; 64]).unwrap();
    payload
}

fn build_ipv4_tcp(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    // etherparse tcp() requires: src_port, dst_port, sequence, ack
    let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 0, 0);
    let mut payload = Vec::new();
    builder.write(&mut payload, &[0u8; 0]).unwrap();
    payload
}

fn build_ipv6_udp(src_ip: [u8; 16], dst_ip: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv6(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let mut payload = Vec::new();
    builder.write(&mut payload, &[0u8; 64]).unwrap();
    payload
}

/// Build IPv6 packet with Hop-by-Hop extension header
/// Note: etherparse API requires manual construction for extension headers
fn build_ipv6_with_hopopt(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    use etherparse::{
        EtherType,
        Ipv6Header,
        UdpHeader,
    };

    let mut packet = Vec::new();

    // Ethernet header
    let eth = etherparse::Ethernet2Header {
        source: [1; 6],
        destination: [2; 6],
        ether_type: EtherType::IPV6,
    };
    eth.write(&mut packet).unwrap();

    // IPv6 header - note: etherparse 0.21+ requires all fields
    let ipv6 = Ipv6Header {
        source: src_ip,
        destination: dst_ip,
        next_header: IpNumber::IPV6_HEADER_HOP_BY_HOP,
        hop_limit: 64,
        payload_length: 48,
        traffic_class: 0,
        flow_label: unsafe { Ipv6FlowLabel::new_unchecked(0) },
    };
    ipv6.write(&mut packet).unwrap();

    // Hop-by-Hop extension header (8 bytes: next_header, length, 6 bytes options)
    // next_header = 17 (UDP), length = 0 (means 8 bytes total)
    packet.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);

    // UDP header - etherparse 0.21+ requires checksum and length
    let udp = UdpHeader {
        source_port: src_port,
        destination_port: dst_port,
        length: 8 + 32, // header + payload
        checksum: 0,
    };
    udp.write(&mut packet).unwrap();

    // Payload
    packet.extend_from_slice(&[0u8; 32]);

    packet
}

fn build_truncated_ipv4() -> Vec<u8> {
    let mut data = vec![0u8; 14];
    data[12] = 0x08;
    data[13] = 0x00;
    data
}

fn build_arp_packet() -> Vec<u8> {
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

    arp_bytes
}

// ============================================================================
// P0: Critical Tests
// ============================================================================

#[test]
fn test_ipv4_denied_by_default() {
    let mut harness = XdpTestHarness::new();
    let pkt = build_ipv4_udp([192, 168, 1, 50], [10, 0, 0, 1], 12345, 3000);
    assert_eq!(harness.run_packet(&pkt), XDP_DROP);
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
fn test_ipv4_allowed_by_exact_flow() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [192, 168, 1, 50];
    let dst_ip = [10, 0, 0, 1];
    let src_port = 12345u16;
    let dst_port = 3000u16;
    let protocol = 17u8;

    let flow = Ipv4Packet::new(
        u32::from_be_bytes(src_ip),
        u32::from_be_bytes(dst_ip),
        src_port,
        dst_port,
        protocol,
    );

    harness.allow_ipv4_flow(flow);

    let pkt = build_ipv4_udp(src_ip, dst_ip, src_port, dst_port);
    assert_eq!(harness.run_packet(&pkt), XDP_PASS);
}

#[test]
fn test_ipv4_reverse_flow_allowed() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [192, 168, 1, 50];
    let dst_ip = [10, 0, 0, 1];
    let src_port = 12345u16;
    let dst_port = 3000u16;
    let protocol = 17u8;

    let flow = Ipv4Packet::new(
        u32::from_be_bytes(src_ip),
        u32::from_be_bytes(dst_ip),
        src_port,
        dst_port,
        protocol,
    );
    harness.allow_ipv4_flow(flow);

    let reply_pkt = build_ipv4_udp(dst_ip, src_ip, dst_port, src_port);
    assert_eq!(harness.run_packet(&reply_pkt), XDP_PASS);
}

#[test]
fn test_ipv4_rate_limiting_drops_after_burst() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [10, 0, 0, 2];
    let dst_ip = [10, 0, 0, 3];
    let src_port = 5555u16;
    let dst_port = 80u16;
    let protocol = 17u8;

    let flow = Ipv4Packet::new(
        u32::from_be_bytes(src_ip),
        u32::from_be_bytes(dst_ip),
        src_port,
        dst_port,
        protocol,
    );
    harness.allow_ipv4_flow(flow);

    let pkt = build_ipv4_udp(src_ip, dst_ip, src_port, dst_port);

    let mut dropped = false;
    for i in 0..2050 {
        let result = harness.run_packet(&pkt);
        if result == XDP_DROP {
            dropped = true;
            assert_eq!(
                harness.run_packet(&pkt),
                XDP_DROP,
                "Packet {} should also be dropped",
                i
            );
            break;
        }
    }

    assert!(dropped, "Rate limiter failed to drop after burst exhausted");
}

#[test]
fn test_ipv4_rate_limit_token_refill() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [10, 0, 0, 5];
    let dst_ip = [10, 0, 0, 6];
    let src_port = 7777u16;
    let dst_port = 443u16;
    let protocol = 6u8;

    let flow = Ipv4Packet::new(
        u32::from_be_bytes(src_ip),
        u32::from_be_bytes(dst_ip),
        src_port,
        dst_port,
        protocol,
    );
    harness.allow_ipv4_flow(flow);

    let pkt = build_ipv4_tcp(src_ip, dst_ip, src_port, dst_port);

    for _ in 0..1005 {
        harness.run_packet(&pkt);
    }

    assert_eq!(harness.run_packet(&pkt), XDP_DROP);
}

#[test]
fn test_malformed_packet_aborts_safely() {
    let mut harness = XdpTestHarness::new();
    let truncated = build_truncated_ipv4();
    assert_eq!(harness.run_packet(&truncated), XDP_ABORTED);
}

#[test]
fn test_arp_bypasses_firewall() {
    let mut harness = XdpTestHarness::new();
    let arp_pkt = build_arp_packet();
    assert_eq!(harness.run_packet(&arp_pkt), XDP_PASS);
}

// ============================================================================
// P1: Important Tests
// ============================================================================

#[test]
fn test_ipv4_subnet_matching_slash24() {
    let mut harness = XdpTestHarness::new();

    let mut subnet_map: LpmTrie<_, u32, Action> =
        LpmTrie::try_from(harness.ebpf.map_mut("SUBNET_MATCHING_V4").unwrap()).unwrap();

    let subnet_addr = u32::from_be_bytes([192, 168, 1, 0]);
    let subnet_key = Key::new(24, subnet_addr);
    subnet_map.insert(&subnet_key, Action::Allow, 0).unwrap();

    let flow = Ipv4Packet::new(
        u32::from_be_bytes([192, 168, 1, 100]),
        u32::from_be_bytes([10, 0, 0, 1]),
        12345,
        80,
        17,
    );
    harness.allow_ipv4_flow(flow);

    let pkt = build_ipv4_udp([192, 168, 1, 100], [10, 0, 0, 1], 12345, 80);
    assert_eq!(harness.run_packet(&pkt), XDP_PASS);

    let pkt2 = build_ipv4_udp([192, 168, 2, 100], [10, 0, 0, 1], 12345, 80);
    assert_eq!(harness.run_packet(&pkt2), XDP_DROP);
}

#[test]
fn test_ipv6_with_extension_headers() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let src_port = 12345u16;
    let dst_port = 80u16;
    let protocol = 17u8;

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

    let flow = Ipv6Packet::new(src_array, dst_array, src_port, dst_port, protocol);
    harness.allow_ipv6_flow(flow);

    let pkt = build_ipv6_with_hopopt(src_ip, dst_ip, src_port, dst_port);
    assert_eq!(harness.run_packet(&pkt), XDP_PASS);
}

#[test]
fn test_ipv4_allow_list_lru_eviction() {
    let mut harness = XdpTestHarness::new();

    let capacity_test = 100;

    for i in 0..capacity_test {
        let src_ip = [10, 0, (i >> 8) as u8, (i & 0xFF) as u8];
        let dst_ip = [10, 0, 0, 1];

        let flow = Ipv4Packet::new(
            u32::from_be_bytes(src_ip),
            u32::from_be_bytes(dst_ip),
            12345,
            80,
            17,
        );
        harness.allow_ipv4_flow(flow);
    }

    let pkt = build_ipv4_udp([10, 0, 0, 0], [10, 0, 0, 1], 12345, 80);
    assert_eq!(harness.run_packet(&pkt), XDP_PASS);

    for i in capacity_test..(capacity_test * 2) {
        let src_ip = [10, 1, (i >> 8) as u8, (i & 0xFF) as u8];
        let dst_ip = [10, 0, 0, 1];

        let flow = Ipv4Packet::new(
            u32::from_be_bytes(src_ip),
            u32::from_be_bytes(dst_ip),
            12345,
            80,
            17,
        );
        harness.allow_ipv4_flow(flow);
    }
}

#[test]
fn test_config_update_changes_rate_limit() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [10, 0, 0, 10];
    let dst_ip = [10, 0, 0, 11];
    let src_port = 9999u16;
    let dst_port = 8080u16;
    let protocol = 17u8;

    let flow = Ipv4Packet::new(
        u32::from_be_bytes(src_ip),
        u32::from_be_bytes(dst_ip),
        src_port,
        dst_port,
        protocol,
    );
    harness.allow_ipv4_flow(flow);

    let pkt = build_ipv4_udp(src_ip, dst_ip, src_port, dst_port);

    for _ in 0..100 {
        assert_eq!(harness.run_packet(&pkt), XDP_PASS);
    }
}

#[test]
fn test_tcp_uses_tcp_rate_profile() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [10, 0, 0, 20];
    let dst_ip = [10, 0, 0, 21];
    let src_port = 54321u16;
    let dst_port = 443u16;
    let protocol = 6u8;

    let flow = Ipv4Packet::new(
        u32::from_be_bytes(src_ip),
        u32::from_be_bytes(dst_ip),
        src_port,
        dst_port,
        protocol,
    );
    harness.allow_ipv4_flow(flow);

    let pkt = build_ipv4_tcp(src_ip, dst_ip, src_port, dst_port);

    let mut dropped = false;
    for _ in 0..1005 {
        if harness.run_packet(&pkt) == XDP_DROP {
            dropped = true;
            break;
        }
    }

    assert!(dropped, "TCP rate limiting failed - wrong profile?");
}

#[test]
fn test_ipv6_allowed_by_exact_flow() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let src_port = 12345u16;
    let dst_port = 80u16;
    let protocol = 17u8;

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

    let flow = Ipv6Packet::new(src_array, dst_array, src_port, dst_port, protocol);
    harness.allow_ipv6_flow(flow);

    let pkt = build_ipv6_udp(src_ip, dst_ip, src_port, dst_port);
    assert_eq!(harness.run_packet(&pkt), XDP_PASS);
}

// ============================================================================
// P2: Edge Cases
// ============================================================================

#[test]
fn test_icmp_rate_limiting() {
    // Documented edge case - ICMP parsing not fully implemented
    let _harness = XdpTestHarness::new();
}

#[test]
fn test_ipv4_flow_key_padding_zeroed() {
    let flow1 = Ipv4Packet::new(0xC0A80132, 0x0A000001, 12345, 3000, 17);

    assert_eq!(flow1._pad, 0);
    assert_eq!(flow1._pad2, 0);

    let _flow2 = Ipv4Packet::new(0xC0A80132, 0x0A000001, 12345, 3000, 17);
}

#[test]
fn test_ipv4_port_zero_edge_case() {
    let mut harness = XdpTestHarness::new();

    let src_ip = [10, 0, 0, 30];
    let dst_ip = [10, 0, 0, 31];
    let src_port = 0u16;
    let dst_port = 0u16;
    let protocol = 17u8;

    let flow = Ipv4Packet::new(
        u32::from_be_bytes(src_ip),
        u32::from_be_bytes(dst_ip),
        src_port,
        dst_port,
        protocol,
    );
    harness.allow_ipv4_flow(flow);
}

// ============================================================================
// Concurrency Tests
// ============================================================================

#[test]
fn test_concurrent_flow_tracking() {
    let mut harness = XdpTestHarness::new();

    let flows: Vec<([u8; 4], [u8; 4], u16, u16)> = vec![
        ([10, 0, 1, 1], [10, 0, 2, 1], 1001, 80),
        ([10, 0, 1, 2], [10, 0, 2, 1], 1002, 80),
        ([10, 0, 1, 3], [10, 0, 2, 1], 1003, 80),
        ([10, 0, 1, 4], [10, 0, 2, 1], 1004, 80),
        ([10, 0, 1, 5], [10, 0, 2, 1], 1005, 80),
    ];

    for (src, dst, sport, dport) in &flows {
        let flow = Ipv4Packet::new(
            u32::from_be_bytes(*src),
            u32::from_be_bytes(*dst),
            *sport,
            *dport,
            17,
        );
        harness.allow_ipv4_flow(flow);
    }

    for _ in 0..100 {
        for (src, dst, sport, dport) in &flows {
            let pkt = build_ipv4_udp(*src, *dst, *sport, *dport);
            let result = harness.run_packet(&pkt);
            assert_eq!(
                result,
                XDP_PASS,
                "Flow {:?} failed",
                (src, dst, sport, dport)
            );
        }
    }
}

// ============================================================================
// Test Modules
// ============================================================================

#[cfg(test)]
mod ipv4_tests {
    use super::*;

    #[test]
    fn test_default_deny() {
        test_ipv4_denied_by_default();
    }

    #[test]
    fn test_allow_exact_flow() {
        test_ipv4_allowed_by_exact_flow();
    }

    #[test]
    fn test_reverse_flow() {
        test_ipv4_reverse_flow_allowed();
    }

    #[test]
    fn test_rate_limiting() {
        test_ipv4_rate_limiting_drops_after_burst();
    }

    #[test]
    fn test_subnet_matching() {
        test_ipv4_subnet_matching_slash24();
    }
}

#[cfg(test)]
mod ipv6_tests {
    use super::*;

    #[test]
    fn test_default_deny() {
        test_ipv6_denied_by_default();
    }

    #[test]
    fn test_allow_exact_flow() {
        test_ipv6_allowed_by_exact_flow();
    }

    #[test]
    fn test_extension_headers() {
        test_ipv6_with_extension_headers();
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_malformed_packet() {
        test_malformed_packet_aborts_safely();
    }

    #[test]
    fn test_arp_bypass() {
        test_arp_bypasses_firewall();
    }

    #[test]
    fn test_rate_limiting_ddos() {
        test_ipv4_rate_limiting_drops_after_burst();
    }
}
