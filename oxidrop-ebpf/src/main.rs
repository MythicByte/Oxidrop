#![no_std]
#![no_main]

use core::{
    mem,
    net::{IpAddr, SocketAddr},
};

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LpmTrie, LruPerCpuHashMap, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use ipnet::IpNet;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};
use oxidrop_common::Action;

/// Allow List, on this block bool is ignored
/// first ip and port, and then the packet counter
#[map]
static ALLOW_LIST: LruPerCpuHashMap<SocketAddr, Action> =
    LruPerCpuHashMap::with_max_entries(4096, 0);
/// Track Ip Packets
/// first ip and port, and then the packet counter
#[map]
static PACKET_COUNTS: LruPerCpuHashMap<SocketAddr, u64> =
    LruPerCpuHashMap::with_max_entries(4096, 0);

/// Events: pushed to userspace whenever we drop a source for the first time.
#[map]
static BLOCKED_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// for checking if a subnet is allowed
#[map]
static SUBNET_MATCHING: LpmTrie<IpNet, Action> = LpmTrie::with_max_entries(2048, 0);

#[xdp]
pub fn oxidrop(ctx: XdpContext) -> u32 {
    match xdp_firewall(ctx) {
        Ok(ret) => ret,
        // if error packet is thrown out
        Err(_) => xdp_action::XDP_ABORTED,
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

fn xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let socket = match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv4hdr).src_addr() };

            let source_port = {
                let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                unsafe { (*udphdr).src_port() }
            };

            SocketAddr::new(IpAddr::V4(source_addr), source_port)
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv6hdr).src_addr() };

            let source_port = {
                let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                unsafe { (*udphdr).src_port() }
            };
            SocketAddr::new(IpAddr::V6(source_addr), source_port)
        }
        _ => {
            // protocol not supported
            return Err(());
        }
    };
    info!(
        &ctx,
        "SRC IP: {:i}, SRC PORT: {}",
        socket.ip(),
        socket.port()
    );
    // only allow if in allowed list
    match unsafe { ALLOW_LIST.get(socket) } {
        Some(is_it_allowed) => match is_it_allowed {
            Action::Allow => (),
            Action::Deny => return Ok(xdp_action::XDP_DROP),
        },
        None => return Err(()),
    }

    // SAFETY: we have a per cpu hasmap can ignore that values are overriden from other
    let count = unsafe { PACKET_COUNTS.get(&socket).unwrap_or(&0) };
    let _ = PACKET_COUNTS.insert(&socket, count + 1, 0);
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
