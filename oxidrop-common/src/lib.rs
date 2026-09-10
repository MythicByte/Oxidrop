// not_std active normal disable with feature
#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
use aya::Pod;
use network_types::eth::EtherType;
#[cfg(feature = "user")]
use serde::Deserialize;
#[cfg(feature = "user")]
use serde::Serialize;
#[cfg(feature = "user")]
use utoipa::ToSchema;
/// What to do with a list
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub enum Action {
    Allow = 0,
    Deny = 1,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub struct AllowListState {
    pub action: Action,
    pub last_seen: u64,
}

/// which directions of ethenet adapter i need to check
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub enum TraficDirection {
    Incoming = 0,
    Outgoing = 1,
}
/// The ddos protection bucket
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub struct TokenBucketState {
    pub tokens: u64,
    pub last_update: u64,
}
/// Erros for the firewall
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub enum FirewallError {
    /// The packet is too short, and reading the header would go out of bounds.
    OutOfBounds = 0,
    /// The packet is not IPv4 or IPv6 (e.g., ARP).
    NotIpTraffic = 1,
    /// The IP protocol is not supported (e.g., not TCP or UDP).
    UnsupportedProtocol = 2,
    /// Rate Limit
    RateLimited = 3,
    /// Denied with policy
    DeniedByPolicy = 4,
}
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
    pub struct ActivaterEtherTypes: u16 {
        const LOOP       = 1 << 0;
        const IPV4       = 1 << 1;
        const ARP        = 1 << 2;
        const IEEE8021Q  = 1 << 3;
        const IPV6       = 1 << 4;
        const IEEE8021AD  = 1 << 5;
    }
}
/// Bucket State for Rate Limiting
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub struct RateProfile {
    pub rate_shift: u64,
    pub burst: u64,
}
// Configuration provided by Userspace
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub struct FirewallConfig {
    pub tcp_profile: RateProfile,
    pub udp_profile: RateProfile,
    pub icmp_profile: RateProfile,
    pub default_profile: RateProfile,
    #[cfg_attr(feature = "user", schema(value_type = u8))]
    pub protocol_allowed: ActivaterEtherTypes,
    /// if ddos protection is on
    pub ddos_activated: bool,
    /// The ethernet address for incoming traffic
    pub incoming_ethernet_adapter: Option<u32>,
    /// The ethernet address for outcoming traffic
    pub output_ethernet_adapter: Option<u32>,
}

/// Tightly packed 5-Tuple for IPv4 state tracking
/// Total size: 16 bytes (Strictly aligned)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub struct Ipv4Packet {
    pub source_addr: u32,      // 4 bytes (Source IP)
    pub destination_addr: u32, // 4 bytes (Destination IP)
    pub source_port: u16,      // 2 bytes (Source Port)
    pub destination_port: u16, // 2 bytes (Destination Port)
    pub protocol: u8,          // 1 byte  (Protocol - TCP/UDP)
    #[cfg_attr(feature = "user", serde(default))]
    pub _pad: u8, // 1 byte  - ZERO THIS OUT
    #[cfg_attr(feature = "user", serde(default))]
    pub _pad2: u16, // 2 bytes - ZERO THIS OUT (Ensures 4-byte alignment)
}

impl Ipv4Packet {
    #[must_use]
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
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize, ToSchema))]
pub struct Ipv6Packet {
    pub source_addr: [u32; 4],      // 16 bytes
    pub destination_addr: [u32; 4], // 16 bytes
    pub source_port: u16,           // 2 bytes
    pub destination_port: u16,      // 2 bytes
    pub protocol: u8,               // 1 byte
    #[cfg_attr(feature = "user", serde(default))]
    pub _pad: [u8; 3], // 3 bytes - ZERO THIS OUT (Ensures 4-byte alignment)
}

impl Ipv6Packet {
    #[inline(always)]
    #[must_use]
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
impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            protocol_allowed: ActivaterEtherTypes::IPV4 | ActivaterEtherTypes::IPV6,
            ddos_activated: true,
            // TCP: Standard web traffic. ~1000 pps refill.
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
#[cfg(feature = "user")]
unsafe impl Pod for TokenBucketState {}
#[cfg(feature = "user")]
unsafe impl Pod for TraficDirection {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for AllowListState {}

impl From<EtherType> for ActivaterEtherTypes {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::Loop => Self::LOOP,
            EtherType::Ipv4 => Self::IPV4,
            EtherType::Arp => Self::ARP,
            EtherType::Ieee8021q => Self::IEEE8021Q,
            EtherType::Ipv6 => Self::IPV6,
            EtherType::Ieee8021ad => Self::IEEE8021AD,
            _ => Self::empty(),
        }
    }
}
