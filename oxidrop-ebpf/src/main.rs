#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::{
        BPF_F_NO_PREALLOC,
        xdp_action,
    },
    macros::{
        map,
        xdp,
    },
    maps::{
        Array,
        LpmTrie,
        LruHashMap,
        lpm_trie::Key,
    },
    programs::XdpContext,
};
use aya_log_ebpf::error;
use network_types::{
    eth::{
        EthHdr,
        EtherType,
    },
    ip::{
        IpProto,
        Ipv4Hdr,
        Ipv6Hdr,
    },
    tcp::TcpHdr,
    udp::UdpHdr,
};
use num_traits::FromPrimitive;
use oxidrop_common::{
    Action,
    ActivaterEtherTypes,
    AllowListState,
    FirewallConfig,
    FirewallError,
    Ipv4Packet,
    Ipv6Packet,
    RateProfile,
    TokenBucketState,
    TraficDirection,
};

const DEFAULT_CONFIG: FirewallConfig = FirewallConfig {
    protocol_allowed: ActivaterEtherTypes::union(
        ActivaterEtherTypes::IPV4,
        ActivaterEtherTypes::IPV6,
    ),
    ddos_activated: true,
    tcp_profile: RateProfile {
        rate_shift: 20,
        burst: 1000,
    },

    // UDP: Games, QUIC, DNS. Generous burst and faster ~2000 pps refill.
    udp_profile: RateProfile {
        rate_shift: 19,
        burst: 2000,
    },

    // ICMP: Pings. Strictly clamped to ~15 pps with a tiny burst.
    icmp_profile: RateProfile {
        rate_shift: 26,
        burst: 10,
    },

    // Fallback: Conservative limits for unsupported/weird protocols.
    default_profile: RateProfile {
        rate_shift: 23,
        burst: 100,
    },
    incoming_ethernet_adapter: None,
    output_ethernet_adapter: None,
    subnet_activated: true,
};

/// Userspace configuration.
#[map]
static CONFIG: Array<FirewallConfig> = Array::with_max_entries(1, 0);
/// Allowed flows keyed by source/destination addresses and ports.
#[map]
static ALLOW_LIST_V4: LruHashMap<Ipv4Packet, AllowListState> =
    LruHashMap::with_max_entries(1000000, 0);

#[map]
static ALLOW_LIST_V6: LruHashMap<Ipv6Packet, AllowListState> =
    LruHashMap::with_max_entries(1000000, 0);
/// Token buckets for IPv4 flows.
#[map]
static PACKET_COUNTS_V4: LruHashMap<Ipv4Packet, TokenBucketState> =
    LruHashMap::with_max_entries(1000000, 0);
/// Token buckets for IPv6 flows.
#[map]
static PACKET_COUNTS_V6: LruHashMap<Ipv6Packet, TokenBucketState> =
    LruHashMap::with_max_entries(1000000, 0);

/// IPv4 subnet matching keyed by four network-order address bytes.
#[map]
static SUBNET_MATCHING_V4: LpmTrie<[u8; 4], Action> =
    LpmTrie::with_max_entries(2048, BPF_F_NO_PREALLOC);

/// IPv6 subnet matching keyed by sixteen network-order address bytes.
#[map]
static SUBNET_MATCHING_V6: LpmTrie<[u8; 16], Action> =
    LpmTrie::with_max_entries(2048, BPF_F_NO_PREALLOC);
#[xdp]
pub fn oxidrop(ctx: XdpContext) -> u32 {
    match xdp_firewall(ctx) {
        Ok(ret) => ret,
        // if error packet is thrown out
        Err(FirewallError::OutOfBounds) => {
            error!(ctx, "Out of bounds read happend");
            xdp_action::XDP_ABORTED
        }
        Err(FirewallError::RateLimited) => xdp_action::XDP_DROP,
        Err(FirewallError::DeniedByPolicy) => xdp_action::XDP_DROP,
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

#[inline(always)]
fn traffic_direction(config: &FirewallConfig, ingress_ifindex: u32) -> TraficDirection {
    if config.incoming_ethernet_adapter == Some(ingress_ifindex) {
        TraficDirection::Incoming
    } else if config.output_ethernet_adapter == Some(ingress_ifindex) {
        TraficDirection::Outgoing
    } else {
        TraficDirection::Incoming
    }
}

#[inline(always)]
fn active_profile(config: &FirewallConfig, protocol: IpProto) -> &RateProfile {
    if protocol == IpProto::Tcp {
        &config.tcp_profile
    } else if protocol == IpProto::Udp {
        &config.udp_profile
    } else if protocol == IpProto::Icmp {
        &config.icmp_profile
    } else {
        &config.default_profile
    }
}

#[inline(always)]
fn redirect_target(config: &FirewallConfig, direction: TraficDirection) -> Option<u32> {
    match direction {
        TraficDirection::Incoming => config.output_ethernet_adapter,
        TraficDirection::Outgoing => config.incoming_ethernet_adapter,
    }
}

#[inline(always)]
fn redirect_or_pass(config: &FirewallConfig, direction: TraficDirection) -> u32 {
    redirect_target(config, direction).map_or(xdp_action::XDP_PASS, |ifindex| unsafe {
        aya_ebpf::helpers::bpf_redirect(ifindex, 0) as u32
    })
}

#[inline(always)]
fn ipv6_words(octets: [u8; 16]) -> Result<[u32; 4], FirewallError> {
    let (chunks, remainder) = octets.as_chunks::<4>();
    let [first, second, third, fourth] = chunks else {
        return Err(FirewallError::OutOfBounds);
    };
    if !remainder.is_empty() {
        return Err(FirewallError::OutOfBounds);
    }
    Ok([
        u32::from_be_bytes(*first),
        u32::from_be_bytes(*second),
        u32::from_be_bytes(*third),
        u32::from_be_bytes(*fourth),
    ])
}

fn xdp_firewall(ctx: XdpContext) -> Result<u32, FirewallError> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0).map_err(|_| FirewallError::OutOfBounds)? };
    let config = CONFIG.get(0).unwrap_or(&DEFAULT_CONFIG);
    let direction = traffic_direction(config, ctx.ingress_ifindex() as u32);
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) if config.protocol_allowed.contains(ActivaterEtherTypes::IPV4) => {
            let ipv4hdr: *const Ipv4Hdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN).map_err(|_| FirewallError::OutOfBounds)? };

            let source_addr = unsafe { *ipv4hdr }.src_addr();
            let dest_addr = unsafe { *ipv4hdr }.dst_addr();
            let protocol = unsafe { *ipv4hdr }
                .proto()
                .map_err(|_| FirewallError::OutOfBounds)?;
            let ip_header_len_ipv4_ihl = unsafe { (*ipv4hdr).ihl() } as usize;
            let (source_port, dest_port, remove_from_hashmap) = if protocol == IpProto::Tcp {
                let tcphdr: *const TcpHdr =
                    unsafe { ptr_at(&ctx, EthHdr::LEN + ip_header_len_ipv4_ihl) }
                        .map_err(|_| FirewallError::OutOfBounds)?;
                let remove_from_hashmap = {
                    let is_fin = unsafe { (*tcphdr).fin() } != 0;
                    let is_rst = unsafe { (*tcphdr).rst() } != 0;
                    is_rst || is_fin
                };
                (
                    u16::from_be_bytes(unsafe { (*tcphdr).source }),
                    u16::from_be_bytes(unsafe { (*tcphdr).dest }),
                    remove_from_hashmap,
                )
            } else if protocol == IpProto::Udp {
                let udphdr: *const UdpHdr =
                    unsafe { ptr_at(&ctx, EthHdr::LEN + ip_header_len_ipv4_ihl) }
                        .map_err(|_| FirewallError::OutOfBounds)?;
                unsafe { ((*udphdr).src_port(), (*udphdr).dst_port(), false) }
            } else {
                (0, 0, false)
            };
            let flow_key_direction = match direction {
                TraficDirection::Incoming => {
                    Ipv4Packet::new(
                        u32::from_be_bytes(dest_addr.octets()),
                        u32::from_be_bytes(source_addr.octets()),
                        dest_port,
                        source_port,
                        protocol.into(), // Safely converts to u8
                    )
                }
                TraficDirection::Outgoing => {
                    Ipv4Packet::new(
                        u32::from_be_bytes(source_addr.octets()),
                        u32::from_be_bytes(dest_addr.octets()),
                        source_port,
                        dest_port,
                        protocol.into(), // Safely converts to u8
                    )
                }
            };
            let external_addr_v4 = match direction {
                TraficDirection::Incoming => source_addr,
                TraficDirection::Outgoing => dest_addr,
            };

            let subnet_key_v4 = Key::new(32, external_addr_v4.octets());
            if config.subnet_activated
                && !matches!(SUBNET_MATCHING_V4.get(&subnet_key_v4), Some(Action::Allow))
            {
                return Err(FirewallError::DeniedByPolicy);
            }
            // normal operation
            if !remove_from_hashmap {
                match direction {
                    TraficDirection::Incoming => {
                        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                        if let Some(state_ptr) = ALLOW_LIST_V4.get_ptr_mut(flow_key_direction) {
                            unsafe {
                                if (*state_ptr).action == Action::Allow {
                                    (*state_ptr).last_seen = now; // Refresh the timer on every active packet
                                } else {
                                    return Err(FirewallError::DeniedByPolicy);
                                }
                            }
                        } else {
                            return Err(FirewallError::DeniedByPolicy);
                        }
                    }
                    TraficDirection::Outgoing => {
                        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                        if let Some(state_ptr) = ALLOW_LIST_V4.get_ptr_mut(flow_key_direction) {
                            // Entry already exists: refresh the timestamp
                            unsafe {
                                (*state_ptr).last_seen = now;
                            }
                        } else {
                            // Entry doesn't exist yet: insert a new allowed flow state
                            let _ = ALLOW_LIST_V4.insert(
                                flow_key_direction,
                                AllowListState {
                                    action: Action::Allow,
                                    last_seen: now,
                                },
                                0,
                            );
                        }
                    }
                }
            } else {
                // remove tcp reset or find
                let _ = ALLOW_LIST_V4.remove(flow_key_direction);
                let _ = PACKET_COUNTS_V4.remove(flow_key_direction);
                return Ok(redirect_or_pass(config, direction));
            }

            let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
            let active_profile = active_profile(config, protocol);

            // Fetch or initialize token bucket state for IPv4
            let bucket = unsafe {
                PACKET_COUNTS_V4
                    .get(flow_key_direction)
                    .copied()
                    .unwrap_or(TokenBucketState {
                        tokens: active_profile.burst,
                        last_update: now,
                    })
            };

            ddos_and_bucket_ending_v4(
                config,
                bucket,
                now,
                active_profile,
                flow_key_direction,
                direction,
            )
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN).map_err(|_| FirewallError::OutOfBounds)? };

            let src_octets = unsafe { (*ipv6hdr).src_addr().octets() };
            let dst_octets = unsafe { (*ipv6hdr).dst_addr().octets() };

            let src_array = ipv6_words(src_octets)?;
            let dst_array = ipv6_words(dst_octets)?;
            let protocol_first =
                unsafe { (*ipv6hdr).next_hdr() }.map_err(|_| FirewallError::OutOfBounds)?;

            let mut current_offset = EthHdr::LEN + Ipv6Hdr::LEN;
            let mut next_proto: IpProto = protocol_first;
            let mut found_l4 = false;
            // Bounded loop to safely walk extension headers
            #[allow(clippy::wildcard_enum_match_arm)]
            for _ in 0..6 {
                match next_proto {
                    IpProto::Tcp | IpProto::Udp | IpProto::Ipv6Icmp => {
                        found_l4 = true;
                        break;
                    }
                    IpProto::HopOpt | IpProto::Ipv6Route | IpProto::Ipv6Opts => {
                        let ext_hdr: *const [u8; 2] = unsafe {
                            ptr_at(&ctx, current_offset).map_err(|_| FirewallError::OutOfBounds)?
                        };
                        let [value, ext_len] = unsafe { *ext_hdr };
                        let Some(parsed) = IpProto::from_u8(value) else {
                            break;
                        };
                        next_proto = parsed;
                        current_offset += (ext_len as usize + 1) * 8;
                    }
                    IpProto::Ipv6Frag => {
                        let ext_hdr: *const [u8; 2] = unsafe {
                            ptr_at(&ctx, current_offset).map_err(|_| FirewallError::OutOfBounds)?
                        };
                        let [value, _] = unsafe { *ext_hdr };
                        let Some(parsed) = IpProto::from_u8(value) else {
                            break;
                        };
                        next_proto = parsed;
                        current_offset += 8;
                    }
                    IpProto::Ah => {
                        let ext_hdr: *const [u8; 2] = unsafe {
                            ptr_at(&ctx, current_offset).map_err(|_| FirewallError::OutOfBounds)?
                        };
                        let [value, ext_len] = unsafe { *ext_hdr };
                        let Some(parsed) = IpProto::from_u8(value) else {
                            break;
                        };
                        next_proto = parsed;
                        current_offset += (ext_len as usize + 2) * 4;
                    }
                    _ => break,
                }
            }
            let (source_port, dest_port, remove_from_hashmap) =
                if found_l4 && next_proto == IpProto::Tcp {
                    let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, current_offset) }
                        .map_err(|_| FirewallError::OutOfBounds)?;
                    let remove_from_hashmap = {
                        let is_fin = unsafe { (*tcphdr).fin() } != 0;
                        let is_rst = unsafe { (*tcphdr).rst() } != 0;
                        is_rst || is_fin
                    };
                    (
                        u16::from_be_bytes(unsafe { (*tcphdr).source }),
                        u16::from_be_bytes(unsafe { (*tcphdr).dest }),
                        remove_from_hashmap,
                    )
                } else if found_l4 && next_proto == IpProto::Udp {
                    let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, current_offset) }
                        .map_err(|_| FirewallError::OutOfBounds)?;
                    unsafe { ((*udphdr).src_port(), (*udphdr).dst_port(), false) }
                } else {
                    (0, 0, false)
                };
            let _flow_key = Ipv6Packet::new(
                src_array,
                dst_array,
                source_port,
                dest_port,
                next_proto.into(),
            );
            let flow_key_direction = match direction {
                TraficDirection::Incoming => Ipv6Packet::new(
                    dst_array,
                    src_array,
                    dest_port,
                    source_port,
                    next_proto.into(),
                ),
                TraficDirection::Outgoing => Ipv6Packet::new(
                    src_array,
                    dst_array,
                    source_port,
                    dest_port,
                    next_proto.into(),
                ),
            };
            let external_octets_v6 = match direction {
                TraficDirection::Incoming => src_octets,
                TraficDirection::Outgoing => dst_octets,
            };

            let subnet_key_v6 = Key::new(128, external_octets_v6);
            if config.subnet_activated
                && !matches!(SUBNET_MATCHING_V6.get(&subnet_key_v6), Some(Action::Allow))
            {
                return Err(FirewallError::DeniedByPolicy);
            }
            if !remove_from_hashmap {
                match direction {
                    TraficDirection::Incoming => {
                        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                        if let Some(state_ptr) = ALLOW_LIST_V6.get_ptr_mut(flow_key_direction) {
                            unsafe {
                                if (*state_ptr).action == Action::Allow {
                                    (*state_ptr).last_seen = now; // Refresh the timer on every active packet
                                } else {
                                    return Err(FirewallError::DeniedByPolicy);
                                }
                            }
                        } else {
                            return Err(FirewallError::DeniedByPolicy);
                        }
                    }
                    TraficDirection::Outgoing => {
                        let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
                        if let Some(state_ptr) = ALLOW_LIST_V6.get_ptr_mut(flow_key_direction) {
                            // Entry already exists: refresh the timestamp
                            unsafe {
                                (*state_ptr).last_seen = now;
                            }
                        } else {
                            // Entry doesn't exist yet: insert a new allowed flow state
                            let _ = ALLOW_LIST_V6.insert(
                                flow_key_direction,
                                AllowListState {
                                    action: Action::Allow,
                                    last_seen: now,
                                },
                                0,
                            );
                        }
                    }
                }
            } else {
                let _ = ALLOW_LIST_V6.remove(flow_key_direction);
                let _ = PACKET_COUNTS_V6.remove(flow_key_direction);
                return Ok(redirect_or_pass(config, direction));
            }

            //  Packet Tracking
            let now = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

            let active_profile = active_profile(config, next_proto);

            // Fetch or initialize token bucket state for Ipv4
            let bucket = unsafe {
                PACKET_COUNTS_V6
                    .get(flow_key_direction)
                    .copied()
                    .unwrap_or(TokenBucketState {
                        tokens: active_profile.burst,
                        last_update: now,
                    })
            };

            ddos_and_bucket_ending_v6(
                config,
                bucket,
                now,
                active_profile,
                flow_key_direction,
                direction,
            )
        }
        // check if other typ is allowed and get through
        Ok(x) if config.protocol_allowed.contains(x.into()) => Ok(xdp_action::XDP_PASS),
        #[allow(clippy::wildcard_enum_match_arm)]
        _ => {
            // protocol not supported
            Err(FirewallError::UnsupportedProtocol)
        }
    }
}
#[inline(always)]
fn evaluate_bucket(
    bucket: &mut TokenBucketState,
    active_rateprofil: &RateProfile,
    now: u64,
) -> Result<u32, FirewallError> {
    let elapsed = now.saturating_sub(bucket.last_update);

    let generated_tokens = elapsed >> active_rateprofil.rate_shift;

    if generated_tokens > 0 {
        bucket.tokens = (bucket.tokens + generated_tokens).min(active_rateprofil.burst);
        bucket.last_update = now;
    }

    if bucket.tokens > 0 {
        bucket.tokens -= 1;
        Ok(xdp_action::XDP_PASS)
    } else {
        Err(FirewallError::RateLimited)
    }
}
#[inline(always)]
fn ddos_and_bucket_ending_v4(
    config: &FirewallConfig,
    mut bucket: TokenBucketState,
    now: u64,
    active_profile: &RateProfile,
    flow_key_direction: Ipv4Packet,
    direction: TraficDirection,
) -> Result<u32, FirewallError> {
    if config.ddos_activated {
        let result = evaluate_bucket(&mut bucket, active_profile, now);
        let _ = PACKET_COUNTS_V4.insert(flow_key_direction, bucket, 0);
        if result.is_ok() {
            Ok(redirect_or_pass(config, direction))
        } else {
            Err(FirewallError::RateLimited)
        }
    } else {
        Ok(redirect_or_pass(config, direction))
    }
}
#[inline(always)]
fn ddos_and_bucket_ending_v6(
    config: &FirewallConfig,
    mut bucket: TokenBucketState,
    now: u64,
    active_profile: &RateProfile,
    flow_key_direction: Ipv6Packet,
    direction: TraficDirection,
) -> Result<u32, FirewallError> {
    if config.ddos_activated {
        let result = evaluate_bucket(&mut bucket, active_profile, now);
        let _ = PACKET_COUNTS_V6.insert(flow_key_direction, bucket, 0);
        if result.is_ok() {
            Ok(redirect_or_pass(config, direction))
        } else {
            Err(FirewallError::RateLimited)
        }
    } else {
        Ok(redirect_or_pass(config, direction))
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
