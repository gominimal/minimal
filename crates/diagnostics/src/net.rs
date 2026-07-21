//! Network-state capture for diagnostic bundles: listening sockets, host
//! interfaces (MACs masked to their vendor OUI), and routes.
//!
//! Mechanics only — verbatim tool output written at fixed relative paths under
//! a caller-supplied `dest` group (the CLI passes `"host"`). Each capture tries
//! the platform's tools in order and, on Linux, falls back to the raw
//! `/proc/net` tables so a bundle from a stripped host still carries the socket
//! picture. Commands run through [`crate::capture::command_stdout`].

use std::time::Duration;

use crate::bundle::{BundleSink, BundleWriter};
use crate::capture::{CaptureError, command_stdout};
use crate::manifest::Redaction;

/// Per-command deadline: a wedged `ss`/`ifconfig` must not eat the collector
/// budget on its own.
const NET_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs the first of `attempts` that yields usable output, returning its
/// echoed command banner and stdout. The last error survives for the caller's
/// fallback message. `attempts` is never empty at any call site.
async fn first_available(attempts: &[(&str, &[&str])]) -> Result<(String, String), CaptureError> {
    let mut last_err = None;
    for (cmd, args) in attempts {
        match command_stdout(cmd, args, NET_TIMEOUT).await {
            Ok(text) => return Ok((format!("$ {cmd} {}", args.join(" ")), text)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("attempts is never empty"))
}

/// `<dest>/net/listening.txt`: listening TCP/UDP sockets with owning pids.
pub async fn listening_sockets<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
) -> Result<(), anyhow::Error> {
    let attempts: &[(&str, &[&str])] = if cfg!(target_os = "linux") {
        &[("ss", &["-ltnup"]), ("netstat", &["-ltnp"])]
    } else {
        &[("netstat", &["-anv", "-p", "tcp"])]
    };
    let text = match first_available(attempts).await {
        Ok((banner, out)) => format!("{banner}\n{out}"),
        #[cfg(target_os = "linux")]
        Err(cmd_err) => format!(
            "(commands unavailable: {cmd_err})\n{}",
            proc_net_listeners().await
        ),
        #[cfg(not(target_os = "linux"))]
        Err(cmd_err) => return Err(cmd_err.into()),
    };
    w.add_bytes(
        &format!("{dest}/net/listening.txt"),
        text.as_bytes(),
        Redaction::None,
    )
    .await
}

/// `<dest>/net/interfaces.txt`: interface addresses, MACs masked to OUI. The
/// IPs and subnets are the diagnostic payload (own-IP rides the 100.64/16
/// CGNAT block VPNs also use, so collisions must be visible); MACs carry no
/// such signal and are masked.
pub async fn interfaces<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
) -> Result<(), anyhow::Error> {
    let attempts: &[(&str, &[&str])] = if cfg!(target_os = "linux") {
        &[("ip", &["addr"]), ("ifconfig", &["-a"])]
    } else {
        &[("ifconfig", &["-a"])]
    };
    let (banner, out) = first_available(attempts).await?;
    let text = format!("{banner}\n{}", mask_macs(&out));
    w.add_bytes(
        &format!("{dest}/net/interfaces.txt"),
        text.as_bytes(),
        Redaction::Keys,
    )
    .await
}

/// `<dest>/net/routes.txt`: the host routing table — which gateway/tunnel the
/// default route rides, and whether anything overlaps the own-IP or gvproxy
/// switch subnets.
pub async fn routes<W: BundleSink>(
    w: &mut BundleWriter<W>,
    dest: &str,
) -> Result<(), anyhow::Error> {
    let attempts: &[(&str, &[&str])] = if cfg!(target_os = "linux") {
        &[("ip", &["route", "show"]), ("netstat", &["-rn"])]
    } else {
        &[("netstat", &["-rn"])]
    };
    let (banner, out) = first_available(attempts).await?;
    w.add_bytes(
        &format!("{dest}/net/routes.txt"),
        format!("{banner}\n{out}").as_bytes(),
        Redaction::None,
    )
    .await
}

/// True when `tok` is exactly a six-group MAC address.
fn is_mac(tok: &str) -> bool {
    tok.len() == 17
        && tok.bytes().enumerate().all(|(i, b)| match i % 3 {
            2 => b == b':',
            _ => b.is_ascii_hexdigit(),
        })
}

/// Masks the device-unique half of every MAC address, keeping the vendor OUI:
/// `f0:18:98:aa:bb:cc` → `f0:18:98:<redacted>`.
///
/// Tokens are maximal runs of non-whitespace and every original separator is
/// preserved byte-for-byte — `ifconfig` indents with tabs while `ip` uses
/// spaces, and splitting on `' '` alone would leave a tab-adjacent MAC
/// (`ether\tf0:18:98:aa:bb:cc`) inside a larger token and emit it unmasked.
/// Whole-token matching is what keeps IPv6 shorthand like
/// `fe80::aa:bb:cc:dd:ee:ff` — colon-adjacent, never a standalone six-group
/// token — untouched.
fn mask_macs(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        // Copy the run of separators verbatim (spaces, tabs, newlines).
        let sep = rest
            .find(|c: char| !c.is_whitespace())
            .unwrap_or(rest.len());
        out.push_str(&rest[..sep]);
        rest = &rest[sep..];
        if rest.is_empty() {
            break;
        }
        // Then the token itself.
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let tok = &rest[..end];
        if is_mac(tok) {
            out.push_str(&tok[..8]);
            out.push_str(":<redacted>");
        } else {
            out.push_str(tok);
        }
        rest = &rest[end..];
    }
    out
}

/// Raw `/proc/net` tables — not parsed; the dev team decodes hex
/// address:port pairs, and fidelity beats prettiness in a fallback.
#[cfg(target_os = "linux")]
async fn proc_net_listeners() -> String {
    let mut text = String::new();
    for table in ["tcp", "tcp6", "udp", "udp6", "unix"] {
        let path = format!("/proc/net/{table}");
        text.push_str(&format!("=== {path} ===\n"));
        match tokio::fs::read_to_string(&path).await {
            Ok(t) => text.push_str(&t),
            Err(e) => text.push_str(&format!("<unreadable: {e}>\n")),
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_macs_keeps_oui_and_leaves_ipv6_alone() {
        let input = "\tether f0:18:98:aa:bb:cc\n\
                     \tinet6 fe80::aa:bb:cc:dd:ee:ff%en0 prefixlen 64\n\
                     2: eth0: link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\n\
                     \tinet 192.168.1.10 netmask 0xffffff00";
        let out = mask_macs(input);
        assert!(out.contains("ether f0:18:98:<redacted>"), "{out}");
        assert!(out.contains("link/ether 02:42:ac:<redacted>"), "{out}");
        assert!(
            out.contains("ff:ff:ff:<redacted>"),
            "broadcast is MAC-shaped too: {out}"
        );
        assert!(
            out.contains("fe80::aa:bb:cc:dd:ee:ff%en0"),
            "IPv6 survives: {out}"
        );
        assert!(out.contains("192.168.1.10"), "IPv4 survives: {out}");
    }

    /// A MAC separated by a tab must mask too — `ifconfig` indents with tabs,
    /// and splitting on `' '` alone would emit it verbatim.
    #[test]
    fn mask_macs_is_whitespace_delimited_not_space_delimited() {
        let out = mask_macs("\tether\tf0:18:98:aa:bb:cc\n  ether  02:42:ac:11:00:02  \n");
        assert!(
            !out.contains("f0:18:98:aa:bb:cc"),
            "tab-adjacent MAC: {out}"
        );
        assert!(out.contains("f0:18:98:<redacted>"), "{out}");
        assert!(out.contains("02:42:ac:<redacted>"), "{out}");
        // Separators survive byte-for-byte, so the capture still reads as the
        // tool printed it.
        assert_eq!(
            out, "\tether\tf0:18:98:<redacted>\n  ether  02:42:ac:<redacted>  \n",
            "original whitespace preserved"
        );
    }
}
