//! gvproxy-switch primitives: subnet arithmetic, MAC derivation, the vsock wire
//! constants, and gvproxy `-config` rendering.
//!
//! Shared by `minimald` (the in-guest / native switch client + IP allocator) and
//! `minvmd` (the host switch supervisor). A standalone crate — these are network
//! primitives, not part of the `minimald-rpc` wire contract — so both sides have
//! one definition rather than drifting copies.

use std::fmt;
use std::net::Ipv4Addr;

/// MTU advertised to the switch and the tap devices. gvproxy's own default.
pub const DEFAULT_MTU: u16 = 1500;

/// Stable, locally-administered MAC for the switch gateway.
pub const GATEWAY_MAC: MacAddr = MacAddr([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd]);

/// AF_VSOCK CID of the host as seen from inside a libkrun guest. Well-known:
/// `VMADDR_CID_HOST == 2`. The per-PTask shuttle dials this CID to reach the
/// host gvproxy switch (DM1/3/4).
pub const VSOCK_HOST_CID: u32 = 2;

/// vsock port the per-PTask shuttle connects to on the host to reach the host
/// gvproxy switch. libkrun bridges this guest-initiated connection to the host
/// gvproxy `-listen` socket.
pub const VSOCK_GVPROXY_SHUTTLE_PORT: u32 = 1024;

/// Default gvproxy switch subnet: the RFC 6598 (CGNAT) `100.64.0.0/16` block.
///
/// Chosen so PTask switch addresses never collide with the common RFC 1918
/// ranges a host or its containers already use.
pub const DEFAULT_SUBNET: SwitchSubnet = SwitchSubnet {
    base: Ipv4Addr::new(100, 64, 0, 0),
    prefix: 16,
};

/// A subnet was constructed with a prefix outside the supported `8..=29` range —
/// a configuration error, distinct from runtime address exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPrefix(pub u8);

impl fmt::Display for InvalidPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gvproxy subnet prefix /{} is invalid; must be in 8..=29 (narrower \
             has no room for a PTask address; wider lets the high octet vary, \
             which the derived MAC cannot keep collision-free)",
            self.0
        )
    }
}

impl std::error::Error for InvalidPrefix {}

/// An IPv4 subnet (`base`/`prefix`) the switch hands addresses out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchSubnet {
    base: Ipv4Addr,
    prefix: u8,
}

impl Default for SwitchSubnet {
    fn default() -> Self {
        DEFAULT_SUBNET
    }
}

impl fmt::Display for SwitchSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

impl SwitchSubnet {
    /// Builds a subnet from a base address and prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPrefix`] for a prefix outside `8..=29`. A prefix narrower
    /// than /29 has no room for the reserved network/gateway/host-alias/broadcast
    /// addresses plus a PTask address. A prefix wider than /8 lets the high octet
    /// vary, which [`MacAddr::for_switch_ip`] does not fold into the derived MAC,
    /// so two addresses differing only in that octet would collide.
    pub fn new(base: Ipv4Addr, prefix: u8) -> Result<Self, InvalidPrefix> {
        if !(8..=29).contains(&prefix) {
            return Err(InvalidPrefix(prefix));
        }
        // Canonicalize: zero the host bits so two subnets with the same network
        // compare equal regardless of host bits in `base` (Display and all
        // address math already normalize through `network()`). `prefix` is in
        // 8..=29, so the shift never overflows.
        let mask = u32::MAX << (32 - prefix);
        let base = Ipv4Addr::from(u32::from(base) & mask);
        Ok(Self { base, prefix })
    }

    fn mask(self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    /// The prefix length (the `/N` of the subnet), used to render a PTask's
    /// address as CIDR when configuring its tap.
    #[must_use]
    pub fn prefix(self) -> u8 {
        self.prefix
    }

    /// The network address (host bits zeroed).
    #[must_use]
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.base) & self.mask())
    }

    /// The broadcast address (host bits set).
    #[must_use]
    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network()) | !self.mask())
    }

    /// The gateway address: the first usable host (`network + 1`).
    #[must_use]
    pub fn gateway(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network()) + 1)
    }

    /// The DNS server for the switch. gvproxy answers DNS on the gateway
    /// (`render_gvproxy_config` sets `gatewayIP`), so an own-IP PTask — whose
    /// fresh netns cannot reach the host's `127.0.0.53` stub resolver — resolves
    /// via the gateway. The single source of truth for "own-IP DNS lives at the
    /// gateway", consumed by both the sandbox resolv.conf and the in-VM guest.
    #[must_use]
    pub fn dns_server(self) -> Ipv4Addr {
        self.gateway()
    }

    /// The host alias address (`broadcast - 1`): a virtual IP that gvproxy NATs
    /// to the host loopback so a PTask can reach host services. Reserved, never
    /// handed to a PTask.
    #[must_use]
    pub fn host_alias(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.broadcast()) - 1)
    }

    /// The daemon address (`broadcast - 2`): the guest root netns' primary tap,
    /// which gives `minimald` itself egress through the host gvproxy (so it can
    /// fetch upstream packages). Reserved from the top so the PTask range still
    /// starts at `network + 2` and never collides with it.
    #[must_use]
    pub fn daemon_ip(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.broadcast()) - 2)
    }

    /// The first address that may be allocated to a PTask (`network + 2`,
    /// i.e. the first host after the gateway).
    #[must_use]
    pub fn first_ptask(self) -> u32 {
        u32::from(self.network()) + 2
    }

    /// The last address that may be allocated to a PTask (`broadcast - 3`),
    /// leaving the daemon address at `broadcast - 2` and the host alias at
    /// `broadcast - 1` reserved.
    #[must_use]
    pub fn last_ptask(self) -> u32 {
        u32::from(self.broadcast()) - 3
    }
}

/// A 48-bit Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl MacAddr {
    /// Derives a stable, locally-administered unicast MAC for a switch IP.
    ///
    /// Uses the QEMU OUI `52:54:00` (locally administered) followed by the low
    /// three octets of the address. Within a single `/16` (or narrower) switch
    /// subnet the low three octets are unique, so the derived MAC is
    /// collision-free and deterministic — the switch's static-lease table can be
    /// pre-seeded without round-tripping through DHCP.
    #[must_use]
    pub fn for_switch_ip(ip: Ipv4Addr) -> Self {
        let o = ip.octets();
        Self([0x52, 0x54, 0x00, o[1], o[2], o[3]])
    }
}

/// Renders the gvproxy `-config` YAML for the given subnet and static leases.
///
/// gvproxy v0.8.9 has no `-subnet` CLI flag: the subnet, gateway, NAT alias, and
/// DHCP static leases are all expressed through a `-config` YAML file (see the
/// 2026-06-21 spike). gvproxy reads this file only at spawn time; an `OwnIp`
/// PTask configures its switch address statically rather than via DHCP, so
/// `dhcpStaticLeases` is a startup-time seed, not a live source.
#[must_use]
pub fn render_gvproxy_config(subnet: SwitchSubnet, leases: &[(Ipv4Addr, MacAddr)]) -> String {
    let mut s = String::with_capacity(256 + leases.len() * 48);
    s.push_str("stack:\n");
    s.push_str(&format!("  mtu: {DEFAULT_MTU}\n"));
    s.push_str(&format!("  subnet: \"{subnet}\"\n"));
    s.push_str(&format!("  gatewayIP: \"{}\"\n", subnet.gateway()));
    s.push_str(&format!("  gatewayMacAddress: \"{GATEWAY_MAC}\"\n"));
    s.push_str("  nat:\n");
    s.push_str(&format!("    \"{}\": \"127.0.0.1\"\n", subnet.host_alias()));
    s.push_str("  gatewayVirtualIPs:\n");
    s.push_str(&format!("    - \"{}\"\n", subnet.host_alias()));
    s.push_str("  dhcpStaticLeases:\n");
    if leases.is_empty() {
        // gvproxy accepts an empty map; keep the key present for clarity.
        s.push_str("    {}\n");
    } else {
        for (ip, mac) in leases {
            s.push_str(&format!("    \"{ip}\": \"{mac}\"\n"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_cgnat_slash16() {
        let net = SwitchSubnet::default();
        assert_eq!(net.to_string(), "100.64.0.0/16");
        assert_eq!(net.gateway(), Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(net.host_alias(), Ipv4Addr::new(100, 64, 255, 254));
        assert_eq!(net.daemon_ip(), Ipv4Addr::new(100, 64, 255, 253));
    }

    #[test]
    fn new_rejects_out_of_range_prefixes() {
        assert_eq!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 7),
            Err(InvalidPrefix(7))
        );
        assert_eq!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 30),
            Err(InvalidPrefix(30))
        );
        assert!(SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 29).is_ok());
    }

    #[test]
    fn new_canonicalizes_host_bits_in_base() {
        // Equal networks compare equal regardless of host bits in `base`.
        let a = SwitchSubnet::new(Ipv4Addr::new(10, 1, 2, 3), 16).unwrap();
        let b = SwitchSubnet::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.network(), Ipv4Addr::new(10, 1, 0, 0));
    }

    #[test]
    fn mac_is_derived_from_low_octets() {
        let mac = MacAddr::for_switch_ip(Ipv4Addr::new(100, 64, 1, 2));
        assert_eq!(mac.to_string(), "52:54:00:40:01:02");
    }

    #[test]
    fn render_emits_empty_lease_map() {
        let yaml = render_gvproxy_config(SwitchSubnet::default(), &[]);
        assert!(yaml.contains("dhcpStaticLeases:\n    {}\n"));
        assert!(yaml.contains("subnet: \"100.64.0.0/16\""));
    }
}
