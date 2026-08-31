#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

/// What to do with a list
#[repr(C)]
#[derive(Clone, Copy)]
pub enum Action {
    Allow,
    Deny,
}
/// Erros for the firewall
#[repr(C)]
#[derive(Clone, Copy)]
pub enum FirewallError {
    /// The packet is too short, and reading the header would go out of bounds.
    OutOfBounds,
    /// The packet is not IPv4 or IPv6 (e.g., ARP).
    NotIpTraffic,
    /// The IP protocol is not supported (e.g., not TCP or UDP).
    UnsupportedProtocol,
    /// Checkusm mismatched
    InvalidChecksum,
    /// Rate Limit
    RateLimited,
    /// Denied with policy
    DeniedByPolicy,
}
// Configuration provided by Userspace
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FirewallConfig {
    pub rate_ns: u64, // Nanoseconds per token
    pub burst: u64,   // Max tokens (bucket size)
}

/// Tightly packed 5-Tuple for IPv4 state tracking
/// Total size: 16 bytes (Strictly aligned)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Packet {
    pub source_addr: u32,      // 4 bytes (Source IP)
    pub source_port: u16,      // 2 bytes (Source Port)
    pub destination_addr: u32, // 4 bytes (Destination IP)
    pub destination_port: u16, // 2 bytes (Destination Port)
    pub protocol: u8,          // 1 byte  (Protocol - TCP/UDP)
    pub _pad: u8,              // 1 byte  - ZERO THIS OUT
    pub _pad2: u16,            // 2 bytes - ZERO THIS OUT (Ensures 4-byte alignment)
}

impl Ipv4Packet {
    #[inline(always)]
    pub fn new(
        source_addr: u32,
        destination_addr: u32,
        source_port: u16,
        destination_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            source_addr,
            destination_addr,
            source_port,
            destination_port,
            protocol,
            _pad: 0,
            _pad2: 0,
        }
    }
}

/// Tightly packed 5-Tuple for IPv6 state tracking
/// Total size: 40 bytes (Strictly aligned)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6Packet {
    pub source_addr: [u32; 4],      // 16 bytes
    pub source_port: u16,           // 2 bytes
    pub destination_addr: [u32; 4], // 16 bytes
    pub destination_port: u16,      // 2 bytes
    pub protocol: u8,               // 1 byte
    pub _pad: [u8; 3],              // 3 bytes - ZERO THIS OUT (Ensures 4-byte alignment)
}

impl Ipv6Packet {
    #[inline(always)]
    pub fn new(
        source_addr: [u32; 4],
        destination_addr: [u32; 4],
        source_port: u16,
        destination_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            source_addr,
            destination_addr,
            source_port,
            destination_port,
            protocol,
            _pad: [0; 3], // Explicitly zeroed padding
        }
    }
}
#[cfg(feature = "user")]
unsafe impl Pod for Action {}
#[cfg(feature = "user")]
unsafe impl Pod for FirewallError {}
#[cfg(feature = "user")]
unsafe impl Pod for FirewallConfig {}
#[cfg(feature = "user")]
unsafe impl Pod for Ipv4Packet {}
#[cfg(feature = "user")]
unsafe impl Pod for Ipv6Packet {}
