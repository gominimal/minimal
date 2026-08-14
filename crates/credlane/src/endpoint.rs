//! Where a box reaches the broker, per deployment model and network mode.
//!
//! The switch host alias is a virtual IP gvproxy NATs to the loopback of
//! whichever machine runs gvproxy, so it resolves only from a netns that is a
//! switch client. A native-Linux `HostNet` box is not one: it shares the host
//! netns outright, where the broker is simply on `127.0.0.1`.
//!
//! The alias is never written as a literal here — it is derived from the
//! subnet the switch was configured with, so a non-default subnet moves the
//! endpoint with it.

use std::fmt;
use std::net::Ipv4Addr;

use sessions::NetworkMode;
use switch::SwitchSubnet;

/// Where the box runs relative to the machine hosting the broker.
///
/// The distinction is not the deployment model but the netns: a guest root
/// netns is itself a switch client, so every mode inside a microVM reaches the
/// host alias, while on a native host only an `OwnIp` box is wired to the
/// switch at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxLocation {
    /// Inside a libkrun microVM (DM1/3/4); the broker runs on the host outside.
    MicroVm,
    /// On the machine that runs the broker (native Linux, DM2).
    NativeHost,
}

/// The broker address a box is handed, and the port it listens on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerEndpoint {
    addr: Ipv4Addr,
    port: u16,
}

impl BrokerEndpoint {
    /// Derives the endpoint a box in `location` with network `mode` uses, or
    /// `None` when the broker is unreachable from it and the box gets no lane.
    #[must_use]
    pub fn derive(
        location: BoxLocation,
        mode: NetworkMode,
        subnet: SwitchSubnet,
        port: u16,
    ) -> Option<Self> {
        let addr = match (location, mode) {
            // No IP reaches anything from an empty netns.
            (_, NetworkMode::NoNet) => return None,
            (BoxLocation::MicroVm, _) | (BoxLocation::NativeHost, NetworkMode::OwnIp) => {
                subnet.host_alias()
            }
            // The box's loopback *is* the host's, so the broker is on it.
            (BoxLocation::NativeHost, NetworkMode::HostNet) => Ipv4Addr::LOCALHOST,
            // `NetworkMode` is `#[non_exhaustive]`: a mode whose wiring this
            // crate has not been taught gets no lane rather than a guess.
            _ => return None,
        };
        Some(Self { addr, port })
    }

    /// The address the box dials.
    #[must_use]
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// The port the box dials.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The full URL for one lane: the value of that lane's endpoint variable.
    /// The leading path segment is the selector the broker resolves.
    #[must_use]
    pub fn lane_url(&self, lane: &str) -> String {
        format!("{self}/{lane}")
    }
}

impl fmt::Display for BrokerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http://{}:{}", self.addr, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 7656;

    fn derive(location: BoxLocation, mode: NetworkMode) -> Option<BrokerEndpoint> {
        BrokerEndpoint::derive(location, mode, SwitchSubnet::default(), PORT)
    }

    #[test]
    fn a_microvm_box_reaches_the_host_alias_in_every_mode_that_has_a_network() {
        let alias = SwitchSubnet::default().host_alias();
        for mode in [NetworkMode::HostNet, NetworkMode::OwnIp] {
            assert_eq!(derive(BoxLocation::MicroVm, mode).unwrap().addr(), alias);
        }
    }

    #[test]
    fn a_native_own_ip_box_reaches_the_host_alias() {
        assert_eq!(
            derive(BoxLocation::NativeHost, NetworkMode::OwnIp)
                .unwrap()
                .addr(),
            SwitchSubnet::default().host_alias()
        );
    }

    #[test]
    fn a_native_host_net_box_reaches_loopback() {
        assert_eq!(
            derive(BoxLocation::NativeHost, NetworkMode::HostNet)
                .unwrap()
                .addr(),
            Ipv4Addr::LOCALHOST
        );
    }

    #[test]
    fn a_no_net_box_gets_no_endpoint() {
        assert!(derive(BoxLocation::MicroVm, NetworkMode::NoNet).is_none());
        assert!(derive(BoxLocation::NativeHost, NetworkMode::NoNet).is_none());
    }

    #[test]
    fn the_endpoint_moves_with_a_non_default_subnet() {
        let subnet = SwitchSubnet::new(Ipv4Addr::new(10, 42, 0, 0), 16).unwrap();
        let endpoint =
            BrokerEndpoint::derive(BoxLocation::MicroVm, NetworkMode::HostNet, subnet, PORT)
                .unwrap();
        assert_eq!(endpoint.addr(), subnet.host_alias());
        assert_ne!(endpoint.addr(), SwitchSubnet::default().host_alias());
    }

    #[test]
    fn a_lane_url_names_the_lane_as_the_leading_path_segment() {
        let endpoint = derive(BoxLocation::MicroVm, NetworkMode::HostNet).unwrap();
        assert_eq!(
            endpoint.lane_url("anthropic"),
            "http://100.64.255.254:7656/anthropic"
        );
    }
}
