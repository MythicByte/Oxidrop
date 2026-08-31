#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{
        map,
        xdp,
    },
    maps::{
        Array,
        LpmTrie,
        LruHashMap,
        LruPerCpuHashMap,
        RingBuf,
        lpm_trie::Key,
    },
    programs::XdpContext,
};
use network_types::{
    eth::{
        EthHdr,
        EtherType,
    },
    ip::{
        Ipv4Hdr,
        Ipv6Hdr,
    },
    udp::UdpHdr,
};
use oxidrop_common::{
    Action,
    ActivaterEtherTypes,
    FirewallConfig,
    FirewallError,
    Ipv4Packet,
    Ipv6Packet,
    TokenBucketState,
};

const DEFAULT_CONFIG: FirewallConfig = FirewallConfig {
    rate_ns: 1_000_000,
    burst: 1000,
    protcol_allowed: ActivaterEtherTypes::union(
        ActivaterEtherTypes::IPV4,
        ActivaterEtherTypes::IPV6,
    ),
    ddos_activated: true,
};

/// Usersapce config
#[map]
static CONFIG: Array<FirewallConfig> = Array::with_max_entries(1, 0);
/// Allow List, on this block bool is ignored
/// first ip and port, and then the packet counter
#[map]
static ALLOW_LIST_V4: LruHashMap<Ipv4Packet, Action> = LruHashMap::with_max_entries(4096, 0);

#[map]
static ALLOW_LIST_V6: LruHashMap<Ipv6Packet, Action> = LruHashMap::with_max_entries(4096, 0);
/// Track Ip Packets
/// first ip and port, and then the packet counter
#[map]
static PACKET_COUNTS_V4: LruPerCpuHashMap<Ipv4Packet, TokenBucketState> =
    LruPerCpuHashMap::with_max_entries(4096, 0);
/// Track Ip Packets
/// first ip and port, and then the packet counter
#[map]
static PACKET_COUNTS_V6: LruPerCpuHashMap<Ipv6Packet, TokenBucketState> =
    LruPerCpuHashMap::with_max_entries(4096, 0);

/// Events: pushed to userspace whenever we drop a source for the first time.
#[map]
static BLOCKED_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// IPv4 Subnet Matching (Key is a 32-bit integer)
#[map]
static SUBNET_MATCHING_V4: LpmTrie<u32, Action> = LpmTrie::with_max_entries(2048, 0);

/// IPv6 Subnet Matching (Key is a 128-bit )
#[map]
static SUBNET_MATCHING_V6: LpmTrie<[u32; 4], Action> = LpmTrie::with_max_entries(2048, 0);
#[xdp]
pub fn oxidrop(ctx: XdpContext) -> u32 {
    match xdp_firewall(ctx) {
        Ok(ret) => ret,
        // if error packet is thrown out
        Err(FirewallError::OutOfBounds) => xdp_action::XDP_ABORTED,
        Err(FirewallError::InvalidChecksum) => xdp_action::XDP_DROP,
        Err(FirewallError::RateLimited) => xdp_action::XDP_DROP,
        Err(FirewallError::DeniedByPolicy) => xdp_action::XDP_DROP,
        // errors we ignore
        // # FIX check later if should be dropped by default or not
        Err(FirewallError::NotIpTraffic) => xdp_action::XDP_PASS,
        Err(FirewallError::UnsupportedProtocol) => xdp_action::XDP_PASS,
    }
}
/// checks pointer length
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn xdp_firewall(ctx: XdpContext) -> Result<u32, FirewallError> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0).map_err(|_| FirewallError::OutOfBounds)? };
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4)
            if CONFIG
                .get(0)
                .unwrap_or(&DEFAULT_CONFIG)
                .protcol_allowed
                .contains(ActivaterEtherTypes::IPV4) =>
        {
            let ipv4hdr: *const Ipv4Hdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN).map_err(|_| FirewallError::OutOfBounds)? };

            let source_addr = unsafe { *ipv4hdr }.src_addr();
            let dest_addr = unsafe { *ipv4hdr }.dst_addr();

            let (source_port, dest_port) = {
                let udphdr: *const UdpHdr = unsafe {
                    ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| FirewallError::OutOfBounds)
                }?;
                (unsafe { *udphdr }.src_port(), unsafe { *udphdr }.dst_port())
            };

            let protocol = unsafe { *ipv4hdr }
                .proto()
                .map_err(|_| FirewallError::OutOfBounds)?;

            let flow_key = Ipv4Packet::new(
                u32::from_be(source_addr.into()),
                u32::from_be(dest_addr.into()),
                source_port,
                dest_port,
                protocol.into(), // Safely converts to u8
            );
            // for reverse lookup
            let reverse_flow_key = Ipv4Packet::new(
                u32::from_be(dest_addr.into()),
                u32::from_be(source_addr.into()),
                dest_port,
                source_port,
                protocol.into(), // Safely converts to u8
            );
            let subnet_key_v4 = Key::new(32, flow_key.source_addr);
            match SUBNET_MATCHING_V4.get(&subnet_key_v4) {
                Some(Action::Allow) => (),
                _ => return Err(FirewallError::DeniedByPolicy),
            }
            match unsafe {
                ALLOW_LIST_V4
                    .get(&flow_key)
                    .or_else(|| ALLOW_LIST_V4.get(&reverse_flow_key))
            } {
                Some(Action::Allow) => (),
                _ => return Err(FirewallError::DeniedByPolicy),
            }

            //  Packet Tracking
            let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

            let config = CONFIG.get(0).unwrap_or(&DEFAULT_CONFIG);

            // Fetch or initialize token bucket state for IPv4
            let mut bucket = unsafe {
                PACKET_COUNTS_V4
                    .get(&flow_key)
                    .copied()
                    .unwrap_or(TokenBucketState {
                        tokens: config.burst,
                        last_update: now,
                    })
            };

            // Calculate token refill based on elapsed time
            let elapsed = now.saturating_sub(bucket.last_update);
            let generated_tokens = elapsed / config.rate_ns;

            if generated_tokens > 0 {
                bucket.tokens = (bucket.tokens + generated_tokens).min(config.burst);
                bucket.last_update = now;
            }

            // Consume a token or drop the packet
            if bucket.tokens > 0 {
                bucket.tokens -= 1;
                let _ = PACKET_COUNTS_V4.insert(&flow_key, bucket, 0);
                Ok(xdp_action::XDP_PASS)
            } else {
                // Keep the last update timestamp even when rate-limited
                let _ = PACKET_COUNTS_V4.insert(&flow_key, bucket, 0);
                Err(FirewallError::RateLimited)
            }
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN).map_err(|_| FirewallError::OutOfBounds)? };

            let segs_src = unsafe { (*ipv6hdr).src_addr().segments() };
            let segs_dst = unsafe { (*ipv6hdr).dst_addr().segments() };

            let mut src_array = [0u32; 4];
            let mut dst_array = [0u32; 4];
            for i in 0..4 {
                src_array[i] = ((segs_src[i * 2] as u32) << 16) | (segs_src[i * 2 + 1] as u32);
                dst_array[i] = ((segs_dst[i * 2] as u32) << 16) | (segs_dst[i * 2 + 1] as u32);
            }

            let (source_port, dest_port) = {
                let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }
                    .map_err(|_| FirewallError::OutOfBounds)?;
                unsafe { ((*udphdr).src_port(), (*udphdr).dst_port()) }
            };

            let protocol =
                unsafe { (*ipv6hdr).next_hdr() }.map_err(|_| FirewallError::OutOfBounds)?;

            let flow_key = Ipv6Packet::new(
                src_array,
                dst_array,
                source_port,
                dest_port,
                protocol.into(),
            );
            let reverse_flow_key = Ipv6Packet::new(
                dst_array,
                src_array,
                dest_port,
                source_port,
                protocol.into(),
            );
            let subnet_key_v6 = Key::new(128, ipv6_be_words(segs_src));
            match SUBNET_MATCHING_V6.get(&subnet_key_v6) {
                Some(Action::Allow) => (),
                _ => return Err(FirewallError::DeniedByPolicy),
            }
            match unsafe {
                ALLOW_LIST_V6
                    .get(&flow_key)
                    .or_else(|| ALLOW_LIST_V6.get(&reverse_flow_key))
            } {
                Some(Action::Allow) => (),
                _ => return Err(FirewallError::DeniedByPolicy),
            }

            //  Packet Tracking
            let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

            let config = CONFIG.get(0).unwrap_or(&DEFAULT_CONFIG);

            // Fetch or initialize token bucket state for IPv4
            let mut bucket = unsafe {
                PACKET_COUNTS_V6
                    .get(&flow_key)
                    .copied()
                    .unwrap_or(TokenBucketState {
                        tokens: config.burst,
                        last_update: now,
                    })
            };

            // Calculate token refill based on elapsed time
            let elapsed = now.saturating_sub(bucket.last_update);
            let generated_tokens = elapsed / config.rate_ns;

            if generated_tokens > 0 {
                bucket.tokens = (bucket.tokens + generated_tokens).min(config.burst);
                bucket.last_update = now;
            }

            // Consume a token or drop the packet
            if bucket.tokens > 0 {
                bucket.tokens -= 1;
                let _ = PACKET_COUNTS_V6.insert(&flow_key, bucket, 0);
                Ok(xdp_action::XDP_PASS)
            } else {
                // Keep the last update timestamp even when rate-limited
                let _ = PACKET_COUNTS_V6.insert(&flow_key, bucket, 0);
                Err(FirewallError::RateLimited)
            }
        }
        // check if other typ is allowed and get through
        Ok(x)
            if CONFIG
                .get(0)
                .unwrap_or(&DEFAULT_CONFIG)
                .protcol_allowed
                .contains(x.into()) =>
        {
            Ok(xdp_action::XDP_PASS)
        }
        _ => {
            // protocol not supported
            return Err(FirewallError::UnsupportedProtocol);
        }
    }
}
#[inline(always)]
fn ipv6_be_words(segments: [u16; 8]) -> [u32; 4] {
    let mut words = [0u32; 4];
    for i in 0..4 {
        let combined = ((segments[i * 2] as u32) << 16) | (segments[i * 2 + 1] as u32);
        words[i] = u32::from_be(combined);
    }
    words
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
