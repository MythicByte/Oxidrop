#![no_std]

/// What to do with a list
pub enum Action {
    Allow,
    Deny,
}
/// Erros for the firewall
pub enum FirewallError {
    /// The packet is too short, and reading the header would go out of bounds.
    OutOfBounds,
    /// The packet is not IPv4 or IPv6 (e.g., ARP).
    NotIpTraffic,
    /// The IP protocol is not supported (e.g., not TCP or UDP).
    UnsupportedProtocol,
    /// Checkusm mismatched
    InvalidChecksum,
}
