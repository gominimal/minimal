//! `min box spec`: what a project's box gets from the local Box Egress
//! Proxy (BEP-038). It prints the proxy's root CA fingerprint, each broker
//! grant with its upstream hosts and the `full` marker, each store
//! reference, the resolved steering mode, and the `quic443` stance when it
//! lets HTTP/3 past the proxy.
//!
//! The rows come from [`render`], which is pure. [`cmd_box_spec`] gathers
//! its inputs: the project's `minimal.toml`, the proxy's published identity
//! and the client configuration's full-breadth acknowledgement (BEP-057).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use boxes::core::bep::{
    ActivationRefused, ActivationSpec, BepRefusal, BepSettings, BepWarning, HostFacts, Quic443,
    SecretGrant, SecretGrants, Steering, refusals,
};

use crate::{BoxSpecArgs, GlobalArgs};

/// What [`render`] reads.
pub(crate) struct SpecInputs<'a> {
    /// The SHA-256 fingerprint of the proxy's root certificate, as colon
    /// separated hex pairs, or `None` when the proxy has not published it.
    pub root_fingerprint: Option<&'a str>,
    /// `[session.network.bep]`.
    pub bep: &'a BepSettings,
    /// `[session.network] quic443`, `None` when not declared.
    pub quic443: Option<Quic443>,
    /// `[session.secrets]`.
    pub secrets: &'a SecretGrants,
    /// Whether the client configuration sets the full-breadth
    /// acknowledgement.
    pub acknowledged: bool,
    /// The GitHub module's upstream hosts.
    pub github_hosts: &'a [&'a str],
}

/// Writes the `min box spec` rows for `inputs`.
///
/// # Errors
///
/// [`ActivationRefused`] (exit 3) when a GitHub grant declares scopes
/// narrower than `full` and the client configuration does not acknowledge
/// full breadth (BEP-057), and the writer's error.
pub(crate) fn render(inputs: &SpecInputs<'_>, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    let credentialed = inputs.secrets.values().any(SecretGrant::is_credentialed);
    if !credentialed {
        writeln!(
            out,
            "This project declares no broker secret, so its box does not use the proxy."
        )?;
        return Ok(());
    }

    // BEP-057: every host is un-enrolled today.
    // Interim: only BEP-057 is previewed here; the full exit-3 set is gominimal/minimal#2445.
    let host = HostFacts {
        full_breadth_acknowledged: inputs.acknowledged,
        ..HostFacts::LOCAL
    };
    let egress = None;
    let spec = ActivationSpec {
        network: boxes::NetworkMode::OwnIp,
        egress,
        bep: inputs.bep,
        secrets: inputs.secrets,
    };
    let narrow: Vec<BepRefusal> = refusals(&spec, host, inputs.github_hosts)
        .into_iter()
        .filter(|refusal| matches!(refusal, BepRefusal::NarrowScopesUnenrolled { .. }))
        .collect();
    if !narrow.is_empty() {
        return Err(ActivationRefused { refusals: narrow }.into());
    }

    match inputs.root_fingerprint {
        // #2446: the fingerprint of the published root certificate, in the
        // form `openssl x509 -noout -fingerprint -sha256` prints for it.
        Some(fingerprint) => writeln!(out, "root CA  certificate SHA256:{fingerprint}")?,
        None => writeln!(
            out,
            "root CA  not published yet. The proxy publishes it when it starts."
        )?,
    }

    for (name, grant) in inputs.secrets {
        if !grant.is_credentialed() {
            continue;
        }
        if grant.is_github() {
            let scopes: Vec<&str> = grant
                .scopes
                .iter()
                .map(String::as_str)
                .filter(|scope| scope.starts_with("github:"))
                .collect();
            // An un-enrolled host mints every GitHub member `full` (BEP-005).
            writeln!(
                out,
                "grant  {}  full  {name}  hosts {}",
                scopes.join(", "),
                inputs.github_hosts.join(", ")
            )?;
            if grant.is_narrower_than_full() {
                writeln!(
                    out,
                    "  acknowledge_full_breadth_unenrolled is set in config.toml: \
                     for the life of this box, {name} reaches every repository your \
                     GitHub sign-in reaches, through the hosts above only."
                )?;
            }
        }
        for scope in grant.scopes.iter().filter(|s| !s.starts_with("github:")) {
            // No store has registered hosts yet (the `[secret-store-rules]`
            // slice adds them).
            writeln!(out, "store  {scope}  {name}  no hosts registered")?;
        }
    }

    let steering = inputs.bep.resolved_steering();
    writeln!(out, "steering  {}", steering.word())?;
    // Networking §5.4: steering `off` with a GitHub grant is a warning, not
    // a refusal, so the exit stays 0.
    if steering == Steering::Off {
        let grants: Vec<String> = inputs
            .secrets
            .iter()
            .filter(|(_, grant)| grant.is_github())
            .map(|(name, _)| name.clone())
            .collect();
        if !grants.is_empty() {
            writeln!(
                out,
                "warning  {}",
                BepWarning::SteeringOffWithGrant { grants }
            )?;
        }
    }
    if !inputs.quic443.unwrap_or_default().blocks(true, steering) {
        writeln!(out, "quic443  allowed (HTTP/3 bypasses the proxy)")?;
    }
    Ok(())
}

/// `~/.minimal/bep/identity.json`, where the proxy publishes its keys.
fn identity_path() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/identity.json"))
}

/// The published root certificate's fingerprint, or `None` with a debug
/// line saying why.
pub(crate) fn root_fingerprint(path: Option<&Path>) -> Option<String> {
    let path = path?;
    match bep::publish::Identity::read(path)
        .and_then(|identity| identity.root_certificate_fingerprint())
    {
        Ok(fingerprint) => Some(fingerprint),
        Err(error) => {
            tracing::debug!(path = %path.display(), %error, "no published root CA");
            None
        }
    }
}

/// `min box spec [PATH]`.
pub(crate) fn cmd_box_spec(global: &GlobalArgs, args: BoxSpecArgs) -> anyhow::Result<()> {
    let project = args
        .path
        .or_else(|| global.repo_dir.clone())
        .unwrap_or_else(|| PathBuf::from("."));
    let session = match mfile::File::from_dir_recursive(&project) {
        Ok(file) => file.session,
        Err(mfile::Error::NotFound) => anyhow::bail!(
            "No {} found in {} or its parent directories.",
            mfile::MFILE_NAME,
            project.display()
        ),
        Err(error) => {
            return Err(crate::ProjectFileInvalid { error }.into());
        }
    };
    let (bep, quic443, secrets) = session.map_or_else(Default::default, |session| {
        let network = session.network.unwrap_or_default();
        (
            network.bep.unwrap_or_default(),
            network.quic443,
            session.secrets,
        )
    });
    let acknowledged = crate::config::full_breadth_acknowledged(global)?;
    let root = root_fingerprint(identity_path().as_deref());
    tracing::debug!(
        project = %project.display(),
        root_found = root.is_some(),
        "rendering min box spec"
    );
    let github_hosts: Vec<&str> = bep::module::GITHUB
        .hosts
        .iter()
        .map(|authority| authority.host)
        .collect();
    let mut stdout = std::io::stdout().lock();
    render(
        &SpecInputs {
            root_fingerprint: root.as_deref(),
            bep: &bep,
            quic443,
            secrets: &secrets,
            acknowledged,
            github_hosts: &github_hosts,
        },
        &mut stdout,
    )?;
    stdout.flush().context("failed to write to stdout")
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::core::bep::GrantSource;

    const HOSTS: &[&str] = &[
        "github.com",
        "api.github.com",
        "uploads.github.com",
        "codeload.github.com",
    ];

    fn grant(scopes: &[&str]) -> SecretGrant {
        SecretGrant {
            source: GrantSource::Broker,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            mode: None,
        }
    }

    fn proxy_env() -> BepSettings {
        BepSettings {
            steering: Some(Steering::ProxyEnv),
            ..BepSettings::default()
        }
    }

    fn rendered(
        secrets: &SecretGrants,
        bep: &BepSettings,
        quic443: Option<Quic443>,
        acknowledged: bool,
    ) -> anyhow::Result<String> {
        let mut out = Vec::new();
        render(
            &SpecInputs {
                root_fingerprint: Some("abc123"),
                bep,
                quic443,
                secrets,
                acknowledged,
                github_hosts: HOSTS,
            },
            &mut out,
        )?;
        Ok(String::from_utf8(out).expect("utf-8"))
    }

    /// BEP-038: the root fingerprint, the upstream hosts per grant, the
    /// steering mode and each store reference.
    #[test]
    fn box_spec_renders_ca_upstreams_steering_and_references() {
        let secrets = SecretGrants::from([
            ("GH_TOKEN".to_string(), grant(&["github:user-token"])),
            ("NPM_TOKEN".to_string(), grant(&["keychain:npm"])),
        ]);
        let text = rendered(&secrets, &proxy_env(), None, false).expect("renders");
        assert_eq!(
            text,
            "root CA  certificate SHA256:abc123\n\
             grant  github:user-token  full  GH_TOKEN  hosts github.com, api.github.com, \
             uploads.github.com, codeload.github.com\n\
             store  keychain:npm  NPM_TOKEN  no hosts registered\n\
             steering  proxy_env\n\
             quic443  allowed (HTTP/3 bypasses the proxy)\n"
        );

        // No published root says so, and a project with no broker secret
        // prints one line.
        let mut out = Vec::new();
        let bep = proxy_env();
        render(
            &SpecInputs {
                root_fingerprint: None,
                bep: &bep,
                quic443: None,
                secrets: &secrets,
                acknowledged: false,
                github_hosts: HOSTS,
            },
            &mut out,
        )
        .expect("renders");
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("root CA  not published yet.")
        );
        let none = rendered(&SecretGrants::new(), &proxy_env(), None, false).unwrap();
        assert_eq!(
            none,
            "This project declares no broker secret, so its box does not use the proxy.\n"
        );

        // Networking §5.4: steering `off` with a GitHub grant writes one
        // warning row after the `steering` row, and still renders.
        let off = BepSettings {
            steering: Some(Steering::Off),
            ..BepSettings::default()
        };
        let text = rendered(&secrets, &off, None, false).expect("renders with a warning");
        let warning = BepWarning::SteeringOffWithGrant {
            grants: vec!["GH_TOKEN".into()],
        };
        assert!(
            text.contains(&format!("steering  off\nwarning  {warning}\n")),
            "{text}"
        );
        assert_eq!(text.matches("warning  ").count(), 1, "{text}");
        // `proxy_env` writes no warning.
        let text = rendered(&secrets, &proxy_env(), None, false).expect("renders");
        assert!(!text.contains("warning  "), "{text}");
    }

    /// #2446, BEP-072: the root row is the fingerprint of the root
    /// certificate the proxy published, read from its identity file. An
    /// identity with no certificate reads as not published.
    #[test]
    fn box_spec_shows_the_root_certificate_fingerprint() {
        let der = b"0\x82\x01\x0a a root certificate's DER".to_vec();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        let identity = bep::publish::Identity::default();
        identity
            .clone()
            .with_root_certificate(&der)
            .publish(&path)
            .expect("publishes");

        let fingerprint = root_fingerprint(Some(&path)).expect("a published root");
        assert_eq!(fingerprint, bep::publish::certificate_fingerprint(&der));
        let secrets = SecretGrants::from([("GH_TOKEN".to_string(), grant(&["github:user-token"]))]);
        let bep = proxy_env();
        let mut out = Vec::new();
        render(
            &SpecInputs {
                root_fingerprint: Some(&fingerprint),
                bep: &bep,
                quic443: None,
                secrets: &secrets,
                acknowledged: false,
                github_hosts: HOSTS,
            },
            &mut out,
        )
        .expect("renders");
        let text = String::from_utf8(out).unwrap();
        let first = text.lines().next().unwrap();
        assert_eq!(first, format!("root CA  certificate SHA256:{fingerprint}"));
        assert!(!text.contains("thumbprint"), "{text}");
        // 32 bytes as uppercase hex pairs joined by colons.
        let hex = first.trim_start_matches("root CA  certificate SHA256:");
        assert_eq!(hex.split(':').count(), 32, "{hex}");
        assert!(
            hex.split(':').all(|pair| pair.len() == 2
                && pair
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())),
            "{hex}"
        );

        // An identity with no certificate gives no fingerprint.
        identity.publish(&path).expect("publishes");
        assert_eq!(root_fingerprint(Some(&path)), None);
        assert_eq!(root_fingerprint(None), None);
    }

    /// BEP-038: a `full` member is marked `full` beside its declared scope.
    #[test]
    fn box_spec_marks_full_breadth_member() {
        for scope in ["github:user-token", "github:repo:full"] {
            let secrets = SecretGrants::from([("GH_TOKEN".to_string(), grant(&[scope]))]);
            let text = rendered(&secrets, &proxy_env(), None, false).expect("renders");
            assert!(
                text.contains(&format!("grant  {scope}  full  GH_TOKEN")),
                "{text}"
            );
            assert!(
                !text.contains("acknowledge_full_breadth_unenrolled"),
                "{text}"
            );
        }
    }

    /// BEP-038: the allowed stance is flagged whether `allow` was declared
    /// or `auto` resolved to it, and a blocked stance prints no row.
    #[test]
    fn box_spec_flags_allowed_quic_stance_on_grant_box() {
        let secrets = SecretGrants::from([("GH_TOKEN".to_string(), grant(&["github:user-token"]))]);
        let flag = "quic443  allowed (HTTP/3 bypasses the proxy)";
        let dns = BepSettings {
            steering: Some(Steering::Dns),
            ..BepSettings::default()
        };
        let cases = [
            (proxy_env(), None, true),
            (proxy_env(), Some(Quic443::Auto), true),
            (dns.clone(), Some(Quic443::Allow), true),
            (dns.clone(), None, false),
            (dns, Some(Quic443::Auto), false),
            (proxy_env(), Some(Quic443::Block), false),
        ];
        for (bep, quic443, flagged) in cases {
            let text = rendered(&secrets, &bep, quic443, false).expect("renders");
            assert_eq!(text.contains(flag), flagged, "{bep:?} {quic443:?}\n{text}");
        }
    }

    /// BEP-057: with the acknowledgement in the client configuration, a
    /// narrower grant renders `full` with the acknowledgement beside it.
    /// Without it, `min box spec` refuses with exit 3.
    #[test]
    fn acknowledged_narrow_grant_renders_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let user = dir.path().join("config.toml");
        std::fs::write(
            &user,
            "[loadouts]\ndefault_loadouts = []\n\n[secrets]\nacknowledge_full_breadth_unenrolled = true\n",
        )
        .unwrap();
        let organization = dir.path().join("missing.toml");
        let acknowledged =
            crate::config::acknowledged_in(&[user, organization.clone()]).expect("reads");
        assert!(acknowledged);
        assert!(!crate::config::acknowledged_in(&[organization]).expect("reads"));

        let secrets = SecretGrants::from([("GH_TOKEN".to_string(), grant(&["github:repo:read"]))]);
        let text = rendered(&secrets, &proxy_env(), None, acknowledged).expect("renders");
        assert!(
            text.contains("grant  github:repo:read  full  GH_TOKEN  hosts github.com"),
            "{text}"
        );
        assert!(
            text.contains(
                "  acknowledge_full_breadth_unenrolled is set in config.toml: for the life \
                 of this box, GH_TOKEN reaches every repository your GitHub sign-in reaches"
            ),
            "{text}"
        );

        let err = rendered(&secrets, &proxy_env(), None, false).expect_err("refused");
        let refused = err
            .downcast_ref::<ActivationRefused>()
            .expect("an activation refusal");
        assert_eq!(refused.exit_code(), 3);
        assert!(refused.to_string().contains("GH_TOKEN"), "{refused}");
        assert!(
            refused
                .to_string()
                .contains("acknowledge_full_breadth_unenrolled"),
            "{refused}"
        );
    }
}
