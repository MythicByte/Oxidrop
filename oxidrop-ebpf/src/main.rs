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
    },
    programs::XdpContext,
};
use aya_log_ebpf::info;
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
    FirewallConfig,
    FirewallError,
    Ipv4Packet,
    Ipv6Packet,
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
static PACKET_COUNTS_V4: LruPerCpuHashMap<Ipv4Packet, u64> =
    LruPerCpuHashMap::with_max_entries(4096, 0);
/// Track Ip Packets
/// first ip and port, and then the packet counter
#[map]
static PACKET_COUNTS_V6: LruPerCpuHashMap<Ipv6Packet, u64> =
    LruPerCpuHashMap::with_max_entries(4096, 0);

/// Events: pushed to userspace whenever we drop a source for the first time.
#[map]
static BLOCKED_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// for checking if a subnet is allowed
///
/// # Fix bool placeholder
#[map]
static SUBNET_MATCHING: LpmTrie<bool, Action> = LpmTrie::with_max_entries(2048, 0);

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
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN).map_err(|_| FirewallError::OutOfBounds)? };
            let source_addr = unsafe { (*ipv4hdr).src_addr() };

            let source_port = {
                let udphdr: *const UdpHdr = unsafe {
                    ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| FirewallError::OutOfBounds)
                }?;
                unsafe { (*udphdr).src_port() }
            };
            let protocol = unsafe { (*ipv4hdr).proto().map_err(|_| FirewallError::OutOfBounds) }?;
            let flow_key = Ipv4Packet::new(
                u32::from_be(source_addr.into()),
                source_port,
                protocol.into(),
            );
            info!(
                &ctx,
                "SRC IP: {:i}, SRC PORT: {}",
                flow_key.ip(),
                flow_key.port()
            );
            match unsafe { ALLOW_LIST_V4.get(&flow_key) } {
                Some(Action::Allow) => (),
                _ => return Err(FirewallError::DeniedByPolicy),
            }

            //  Packet Tracking
            let count = unsafe { PACKET_COUNTS_V4.get(&flow_key).unwrap_or(&0) };
            let _ = PACKET_COUNTS_V4.insert(&flow_key, count + 1, 0);

            Ok(xdp_action::XDP_PASS)
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN).map_err(|_| FirewallError::OutOfBounds)? };
            // let source_addr = unsafe { (*ipv6hdr).src_addr() };

            let source_port = {
                let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }
                    .map_err(|_| FirewallError::OutOfBounds)?;
                unsafe { (*udphdr).src_port() }
            };
            let protocol =
                unsafe { (*ipv6hdr).next_hdr() }.map_err(|_| FirewallError::OutOfBounds)?;
            //  Get the 16-bit segments from the IPv6 address
            let segs = unsafe { (*ipv6hdr).src_addr().segments() };

            //  Pack the eight u16 segments into four u32 integers for our map key
            let mut ip_array = [0u32; 4];
            for i in 0..4 {
                ip_array[i] = ((segs[i * 2] as u32) << 16) | (segs[i * 2 + 1] as u32);
            }
            let flow_key = Ipv6Packet::new(ip_array, source_port, protocol.into());
            // # FIX add src later
            info!(&ctx, "SRC IP: , SRC PORT: {}", flow_key.port());
            match unsafe { ALLOW_LIST_V6.get(&flow_key) } {
                Some(Action::Allow) => (),
                _ => return Err(FirewallError::DeniedByPolicy),
            }

            //  Packet Tracking
            let count = unsafe { PACKET_COUNTS_V6.get(&flow_key).unwrap_or(&0) };
            let _ = PACKET_COUNTS_V6.insert(&flow_key, count + 1, 0);

            Ok(xdp_action::XDP_PASS)
        }
        _ => {
            // protocol not supported
            return Err(FirewallError::UnsupportedProtocol);
        }
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
