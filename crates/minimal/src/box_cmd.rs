//! `min box spec`: what a box's spec asks for and what the box is given.
//!
//! The review surface for a box's credentials (BEP-038): the fingerprint of
//! the host's interception root, each grant with the upstream hosts its
//! member is bound to and the breadth it is minted at, the resolved steering
//! mode, and each store reference with the authorities registered for it.
//! Interception is declared here rather than discovered in a box.
//!
//! The rendering runs the same validation activation runs, so a spec this
//! host cannot honour is refused with exit 3 naming every cause — including a
//! grant declaring scopes narrower than the `full` member an un-enrolled host
//! mints, until the operator acknowledges the widening (BEP-057).

use std::io::Write;

use anyhow::Context as _;

use crate::{BoxSpecArgs, GlobalArgs};

/// One store reference of a box spec: the identifier the box declares, its
/// store, and the upstream authorities the client's `[secret-store-rules]`
/// rule registers for it (BEP-038). The box spec grammar that declares a
/// reference and the rules that register its authorities arrive with the
/// Keychain slice; the rendering is here so the review surface is one
/// surface, not one retrofitted per credential kind.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferenceView {
    store: String,
    id: String,
    authorities: Vec<String>,
}

/// One grant of a box spec: what it declares, and the upstream hosts the
/// member it receives is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantView {
    grant: sessions::Grant,
    upstreams: Vec<String>,
}

impl GrantView {
    /// The scopes the grant declares, as the spec spells them, or a note
    /// that it declares none and takes the member as minted.
    fn declared(&self) -> String {
        if self.grant.scopes.is_empty() {
            "nothing (takes the member as minted)".to_owned()
        } else {
            self.grant.scopes.join(", ")
        }
    }
}

/// What `min box spec` renders.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpecView {
    /// The project the spec was read from.
    project: String,
    /// The fingerprint of this host's interception root CA key, or `None`
    /// when the host holds none.
    root: Option<String>,
    /// The steering the spec resolves to (BEP-016).
    steering: sessions::Steering,
    /// Whether the interception root is injected into the box trust store.
    inject_ca: bool,
    /// The proxy environment the box is created with, empty when none is.
    proxy_env: Vec<(String, String)>,
    /// Whether the client configuration acknowledges full-breadth minting on
    /// this un-enrolled host (BEP-057).
    acknowledged: bool,
    grants: Vec<GrantView>,
    references: Vec<ReferenceView>,
}

impl SpecView {
    /// The view of a spec. `expansion` is the admitted expansion, or `None`
    /// when the validation refused it: a refused spec still shows the
    /// reviewer the root, the grants and the steering the spec resolves to,
    /// with nothing claimed about what the box would be given.
    fn of(
        project: &camino::Utf8Path,
        root: Option<String>,
        network: &sessions::BoxNetwork,
        grants: &[sessions::Grant],
        expansion: Option<&sessions::GrantExpansion>,
        acknowledged: bool,
        references: Vec<ReferenceView>,
    ) -> Self {
        Self {
            project: project.to_string(),
            root,
            steering: expansion.map_or_else(|| network.bep.resolved_steering(), |e| e.steering),
            inject_ca: expansion.is_some_and(|e| e.inject_ca),
            proxy_env: expansion
                .map(sessions::GrantExpansion::proxy_env_vars)
                .unwrap_or_default(),
            acknowledged,
            grants: grants
                .iter()
                .map(|grant| GrantView {
                    upstreams: upstreams(grant.module),
                    grant: grant.clone(),
                })
                .collect(),
            references,
        }
    }
}

/// The upstream hosts a grant's member is bound to: its module's host set,
/// which is what the member is sealed against and what the proxy admits it
/// for (BEP-021).
fn upstreams(module: sessions::GrantModule) -> Vec<String> {
    match module {
        sessions::GrantModule::Github => sessions::GITHUB_HOST_SET
            .iter()
            .map(|host| (*host).to_owned())
            .collect(),
        // A module a later version adds has a host set this build cannot
        // derive; the grant is still named, with no upstreams claimed.
        _ => Vec::new(),
    }
}

/// Writes the spec review. Every grant carries its declared scopes, the
/// breadth the member is minted at — `full` while the host is not enrolled —
/// and its upstream set; every reference carries its registered authorities.
fn render(view: &SpecView, out: &mut impl Write) -> Result<(), anyhow::Error> {
    writeln!(out, "box spec: {}", view.project)?;
    match &view.root {
        Some(fingerprint) => writeln!(out, "  interception root: {fingerprint}")?,
        None => writeln!(
            out,
            "  interception root: none held on this host (the proxy generates it on first use)"
        )?,
    }
    writeln!(
        out,
        "  steering: {} ({})",
        view.steering,
        if view.inject_ca {
            "interception root in the box trust store"
        } else {
            "no interception root injected"
        }
    )?;
    if view.proxy_env.is_empty() {
        writeln!(out, "  proxy environment: not set")?;
    } else {
        writeln!(out, "  proxy environment:")?;
        for (name, value) in &view.proxy_env {
            writeln!(out, "    {name}={value}")?;
        }
    }
    if view.grants.is_empty() {
        writeln!(out, "  grants: none declared")?;
    } else {
        writeln!(out, "  grants:")?;
        for grant in &view.grants {
            writeln!(
                out,
                "    - {}: mode {}, declared {}, minted full{}",
                grant.grant,
                grant.grant.mode,
                grant.declared(),
                acknowledgement_note(&grant.grant, view.acknowledged),
            )?;
            writeln!(out, "      upstreams: {}", grant.upstreams.join(", "))?;
        }
    }
    if view.references.is_empty() {
        writeln!(out, "  references: none declared")?;
    } else {
        writeln!(out, "  references:")?;
        for reference in &view.references {
            writeln!(
                out,
                "    - {} reference `{}`: authorities {}",
                reference.store,
                reference.id,
                reference.authorities.join(", ")
            )?;
        }
    }
    Ok(())
}

/// What follows the `full` marker for a grant whose declared scopes are
/// narrower than the member minted for it: the acknowledgement that admitted
/// the widening, so the operator sees it beside the marker (BEP-057). A grant
/// that declares `full`, or declares nothing, needs no note.
fn acknowledgement_note(grant: &sessions::Grant, acknowledged: bool) -> String {
    if acknowledged && !grant.narrower_than_full().is_empty() {
        " (wider than declared, acknowledged by `[secrets] \
         acknowledge_full_breadth_unenrolled = true`)"
            .to_owned()
    } else {
        String::new()
    }
}

/// This host's interception root as the spec reports it: the fingerprint of
/// the root CA key the proxy holds, read without generating one, or `None`
/// when the host holds no root yet.
#[cfg(target_os = "macos")]
fn root_fingerprint() -> Option<String> {
    let held = bep::keys::inspect(&bep::keychain::MacosKeychain).ok()?;
    held.into_iter()
        .find(|status| status.role == bep::KeyRole::Root)?
        .fingerprint
        .map(|fingerprint| fingerprint.to_string())
}

/// A host with no keychain backend holds no root CA key — as `min auth` says
/// of the sign-in — so there is no fingerprint to report.
#[cfg(not(target_os = "macos"))]
fn root_fingerprint() -> Option<String> {
    None
}

/// The project directory the spec is read from: the argument, else
/// `-C`/`--repo-dir`, else the working directory.
fn project_root(
    global: &GlobalArgs,
    path: Option<&str>,
) -> Result<camino::Utf8PathBuf, anyhow::Error> {
    let effective = match (path, &global.repo_dir) {
        (Some(p), _) => std::path::PathBuf::from(p),
        (None, Some(dir)) => dir.clone(),
        (None, None) => std::path::PathBuf::from("."),
    };
    let canonical = std::fs::canonicalize(&effective)
        .with_context(|| format!("Cannot resolve project path '{}'", effective.display()))?;
    camino::Utf8PathBuf::from_path_buf(canonical)
        .map_err(|_| anyhow::anyhow!("Project path is not valid UTF-8"))
}

/// The box spec of the project at `root`: its `[session.network]`,
/// `[[session.grants]]` and `[session.secrets]` tables. A project with no
/// `minimal.toml` declares no box spec and renders as such; a broken one is
/// an error, because a review that reads nothing must not read as a review
/// that found nothing.
fn read_box_spec(
    root: &camino::Utf8Path,
) -> Result<
    (
        sessions::BoxNetwork,
        Vec<sessions::Grant>,
        sessions::BoxSecrets,
    ),
    anyhow::Error,
> {
    let file = match mfile::File::from_dir(root.as_std_path()) {
        Ok(file) => file,
        Err(mfile::Error::NotFound) => return Ok(Default::default()),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "found a broken {name} while reading the box spec: {e}",
                name = mfile::MFILE_NAME,
            ));
        }
    };
    let Some(session) = file.session.as_ref() else {
        return Ok(Default::default());
    };
    Ok((
        session.network.clone().unwrap_or_default(),
        session.grants.clone(),
        session.secrets.clone().unwrap_or_default(),
    ))
}

/// Renders the project's box spec, and refuses with exit 3 a spec this host
/// cannot honour — the refusal activation would give, before a box exists.
///
/// # Errors
///
/// The project path, a broken `minimal.toml`, an unreadable client
/// configuration, or a [`sessions::GrantRefusal`] naming every cause.
pub fn cmd_box_spec(global: &GlobalArgs, args: BoxSpecArgs) -> Result<(), anyhow::Error> {
    let project = project_root(global, args.path.as_deref())?;
    let (network, grants, secrets) = read_box_spec(&project)?;
    let client = crate::config::read_client_config(global)?;
    let (acknowledged, ignored) = sessions::acknowledgement_in_force(
        client.secrets.acknowledge_full_breadth_unenrolled,
        &secrets,
    );
    if let Some(warning) = &ignored {
        eprintln!("warning: {warning}");
    }
    let box_name = project.file_name().unwrap_or("box");
    let ctx = sessions::GrantContext {
        box_name,
        host_set: &sessions::GITHUB_HOST_SET,
        sign_in_held: crate::auth::sign_in_held(),
        // No host runs the box-zone resolver yet, as at activation.
        resolver_present: false,
        full_breadth_acknowledged: acknowledged,
    };
    let expansion = sessions::validate_grants(&network, &grants, &ctx);
    if let Ok(admitted) = &expansion {
        for warning in &admitted.warnings {
            eprintln!("warning: {warning}");
        }
    }
    let view = SpecView::of(
        &project,
        root_fingerprint(),
        &network,
        &grants,
        expansion.as_ref().ok(),
        acknowledged,
        // The declared references, once the box spec grammar carries them.
        Vec::new(),
    );
    render(&view, &mut std::io::stdout().lock())?;
    tracing::info!(
        box_name,
        grants = view.grants.len(),
        references = view.references.len(),
        "rendered the box spec"
    );
    expansion.map(|_| ()).map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::core::primitives::StrictVarName;

    fn grant(scopes: &[&str]) -> sessions::Grant {
        sessions::Grant {
            module: sessions::GrantModule::Github,
            env: StrictVarName::try_new("GITHUB_TOKEN").unwrap(),
            source: sessions::GrantSource::Broker,
            mode: sessions::GrantMode::User,
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// A spec as the proxy-steered box of the first slice declares it, with
    /// `grants` and the acknowledgement varying per test.
    fn view(
        grants: &[sessions::Grant],
        acknowledged: bool,
        references: Vec<ReferenceView>,
    ) -> SpecView {
        let network = sessions::BoxNetwork {
            mode: Some(sessions::NetworkMode::OwnIp),
            egress: Some(sessions::EgressPolicy {
                allow_dns_hosts: Some(
                    sessions::GITHUB_HOST_SET
                        .iter()
                        .map(|h| (*h).to_owned())
                        .collect(),
                ),
                ..sessions::EgressPolicy::default()
            }),
            bep: sessions::BepPolicy {
                steering: Some(sessions::Steering::ProxyEnv),
                ..sessions::BepPolicy::default()
            },
        };
        let ctx = sessions::GrantContext {
            box_name: "web",
            host_set: &sessions::GITHUB_HOST_SET,
            sign_in_held: true,
            resolver_present: false,
            full_breadth_acknowledged: acknowledged,
        };
        let expansion = sessions::validate_grants(&network, grants, &ctx)
            .expect("the spec under test is admitted");
        SpecView::of(
            camino::Utf8Path::new("/repo/web"),
            Some("sha256:0f1e2d3c".to_owned()),
            &network,
            grants,
            Some(&expansion),
            acknowledged,
            references,
        )
    }

    fn rendered(view: &SpecView) -> String {
        let mut out = Vec::new();
        render(view, &mut out).expect("rendering a spec writes");
        String::from_utf8(out).expect("the rendering is UTF-8")
    }

    /// BEP-038: the spec renders the interception root's fingerprint, the
    /// derived upstream set of each grant, the resolved steering mode, and
    /// each store reference with its registered authorities.
    #[test]
    fn box_spec_renders_ca_upstreams_steering_and_references() {
        let text = rendered(&view(
            &[grant(&[sessions::GITHUB_SCOPE_FULL])],
            false,
            vec![ReferenceView {
                store: "keychain".to_owned(),
                id: "anthropic-api-key".to_owned(),
                authorities: vec!["api.anthropic.com:443".to_owned()],
            }],
        ));

        assert!(text.contains("sha256:0f1e2d3c"), "{text}");
        for host in sessions::GITHUB_HOST_SET {
            assert!(text.contains(host), "{host} missing from:\n{text}");
        }
        assert!(text.contains("steering: proxy_env"), "{text}");
        assert!(
            text.contains("interception root in the box trust store"),
            "{text}"
        );
        assert!(text.contains("HTTPS_PROXY=http://127.0.0.1:7655"), "{text}");
        assert!(
            text.contains(
                "keychain reference `anthropic-api-key`: authorities \
                           api.anthropic.com:443"
            ),
            "{text}"
        );
        // Never the value, and never a token: identifiers and authorities
        // only (BEP-038's enforcement note).
        assert!(!text.contains("ghu_"), "{text}");

        // A host holding no root says so rather than showing a blank.
        let mut no_root = view(&[grant(&[])], false, Vec::new());
        no_root.root = None;
        let text = rendered(&no_root);
        assert!(text.contains("none held on this host"), "{text}");
        assert!(text.contains("references: none declared"), "{text}");
    }

    /// BEP-038: a grant whose member is `full` breadth is marked `full`
    /// beside its declared scope, and nothing is said about an
    /// acknowledgement that did not admit it.
    #[test]
    fn box_spec_marks_full_breadth_member() {
        let text = rendered(&view(
            &[grant(&[sessions::GITHUB_SCOPE_FULL])],
            false,
            Vec::new(),
        ));
        let line = text
            .lines()
            .find(|line| line.contains("github grant `GITHUB_TOKEN`"))
            .expect("the grant is named");
        assert!(line.contains(sessions::GITHUB_SCOPE_FULL), "{line}");
        assert!(line.contains("minted full"), "{line}");
        assert!(!line.contains("acknowledged"), "{line}");

        // A grant declaring no scope at all still shows the breadth it is
        // minted at.
        let text = rendered(&view(&[grant(&[])], false, Vec::new()));
        assert!(text.contains("declared nothing"), "{text}");
        assert!(text.contains("minted full"), "{text}");
    }

    /// BEP-057: with the acknowledgement set, a grant declaring narrower
    /// scopes is minted `full` and renders as `full` with the
    /// acknowledgement visible; without it the same spec is refused with
    /// exit 3 naming the grant and the acknowledgement as the remedy.
    #[test]
    fn acknowledged_narrow_grant_renders_full() {
        let narrow = grant(&["github:repo:acme/web"]);
        let text = rendered(&view(std::slice::from_ref(&narrow), true, Vec::new()));
        let line = text
            .lines()
            .find(|line| line.contains("github grant `GITHUB_TOKEN`"))
            .expect("the grant is named");
        assert!(line.contains("github:repo:acme/web"), "{line}");
        assert!(line.contains("minted full"), "{line}");
        assert!(
            line.contains("acknowledged by `[secrets] acknowledge_full_breadth_unenrolled = true`"),
            "{line}"
        );

        let ctx = sessions::GrantContext {
            box_name: "web",
            host_set: &sessions::GITHUB_HOST_SET,
            sign_in_held: true,
            resolver_present: false,
            full_breadth_acknowledged: false,
        };
        let network = sessions::BoxNetwork {
            bep: sessions::BepPolicy {
                steering: Some(sessions::Steering::ProxyEnv),
                ..sessions::BepPolicy::default()
            },
            ..sessions::BoxNetwork::default()
        };
        let refusal = sessions::validate_grants(&network, &[narrow], &ctx)
            .expect_err("an unacknowledged narrow grant is refused");
        assert_eq!(sessions::GrantRefusal::EXIT_CODE, 3);
        let text = refusal.to_string();
        assert!(text.contains("github grant `GITHUB_TOKEN`"), "{text}");
        assert!(
            text.contains("acknowledge_full_breadth_unenrolled"),
            "{text}"
        );
    }

    /// The command tree carries `min box spec` with an optional project
    /// path, so the review runs against another checkout without a `cd`.
    #[test]
    fn box_spec_parses_with_an_optional_path() {
        use clap::Parser as _;

        let parsed = crate::Cli::try_parse_from(["min", "box", "spec"]).expect("bare form parses");
        match parsed.command {
            Some(crate::Command::Box(crate::BoxArgs {
                command: crate::BoxCommand::Spec(args),
            })) => assert_eq!(args.path, None),
            _ => panic!("expected `box spec`"),
        }
        let parsed =
            crate::Cli::try_parse_from(["min", "box", "spec", "/repo/web"]).expect("path parses");
        match parsed.command {
            Some(crate::Command::Box(crate::BoxArgs {
                command: crate::BoxCommand::Spec(args),
            })) => assert_eq!(args.path.as_deref(), Some("/repo/web")),
            _ => panic!("expected `box spec` with a path"),
        }
    }
}
