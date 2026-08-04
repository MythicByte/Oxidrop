#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpError, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn oxidrop(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
// #[xdp]
// pub fn oxidrop(ctx: XdpContext) -> u32 {
//     match try_oxidrop(ctx) {
//         Ok(ret) => ret,
//         Err(_) => xdp_action::XDP_ABORTED,
//     }
// }

// fn try_oxidrop(ctx: XdpContext) -> Result<u32, u32> {
//     info!(&ctx, "received a packet");
//     Ok(xdp_action::XDP_PASS)
// }
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

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv4hdr).src_addr() };

            let source_port = match unsafe { (*ipv4hdr).proto().map_err(|_: IpError| ())? } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    u16::from_be_bytes(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    unsafe { (*udphdr).src_port() }
                }
                _ => return Ok(xdp_action::XDP_PASS),
            };

            info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let source_addr = unsafe { (*ipv6hdr).src_addr() };

            let source_port = match unsafe { (*ipv6hdr).next_hdr().map_err(|_: IpError| ())? } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                    u16::from_be_bytes(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                    unsafe { (*udphdr).src_port() }
                }
                _ => return Ok(xdp_action::XDP_PASS),
            };

            info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);
        }
        _ => {}
    }

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
