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

/// Tightly packed struct for IPv4
/// Total size: 8 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Packet {
    pub ip_addr: u32, // 4 bytes
    pub port: u16,    // 2 bytes
    pub protocol: u8, // 1 byte
    pub _pad: u8,     // 1 byte - ZERO THIS OUT
}

impl Ipv4Packet {
    /// Create a new IPv4
    #[inline(always)]
    pub fn new(ip: u32, port: u16, protocol: u8) -> Self {
        Self {
            ip_addr: ip,
            port,
            protocol,
            _pad: 0,
        }
    }

    /// get ip
    #[inline(always)]
    pub fn ip(&self) -> u32 {
        self.ip_addr
    }

    /// get protocol
    #[inline(always)]
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// get port
    #[inline(always)]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Tightly packed struct for IPv6
/// Total size: 20 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6Packet {
    pub ip_addr: [u32; 4], // 16 bytes
    pub port: u16,         // 2 bytes
    pub protocol: u8,      // 1 byte
    pub _pad: u8,          // 1 byte - ZERO THIS OUT
}

impl Ipv6Packet {
    /// Create a new IPv6 key
    #[inline(always)]
    pub fn new(ip: [u32; 4], port: u16, protocol: u8) -> Self {
        Self {
            ip_addr: ip,
            port,
            protocol,
            _pad: 0, // Explicitly zeroed padding
        }
    }

    /// get ip
    #[inline(always)]
    pub fn ip(&self) -> [u32; 4] {
        self.ip_addr
    }

    /// get protocol
    #[inline(always)]
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// get port
    #[inline(always)]
    pub fn port(&self) -> u16 {
        self.port
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
