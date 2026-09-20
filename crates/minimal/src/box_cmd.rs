//! `min box spec` and `min box audit`: what a box's spec asks for and what the
//! box is given, and what the proxy has since done for it.
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
//!
//! `min box audit <box>` is the read side (BEP-042): the proxy's own records
//! for that box and no other's, from the log beside its control socket — every
//! retained segment of it, oldest first, so a trail that crossed a rotation
//! reads as one trail (BEP-068). `--parent` merges every box under one onto a
//! single stream, `--follow` tails what the proxy appends next, and `-o jsonl`
//! prints the log's own lines. `self` is refused while the host is not
//! enrolled — a box has no identity surface to read its trail through — naming
//! the host command that reads it.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use bep::audit::{Reader, Record, Subject};

use crate::{AuditFormat, BoxAuditArgs, BoxSpecArgs, GlobalArgs};

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

/// The box `self` names: the box this command runs in.
const SELF: &str = "self";

/// The defined error `min box audit self` is refused with while the host is
/// not enrolled (BEP-042).
const SELF_UNSUPPORTED: &str = "audit_self_unsupported_unenrolled";

/// The variable a session carries its own name in, seeded by the daemon
/// (`minimald`'s session baseline environment): what a box's own name is,
/// when this command runs inside one.
const SESSION_NAME_ENV: &str = "MINIMAL_SESSION_NAME";

/// How long a `--follow` read waits before polling the log again.
const FOLLOW_POLL: Duration = Duration::from_millis(250);

/// A tailing read: how long to wait between polls, and what tells the read it
/// has what it came for. `min box audit --follow` never has enough — an
/// interrupt ends it — so only the tests ever answer `true`.
#[derive(Debug, Clone, Copy)]
struct Tail {
    poll: Duration,
    enough: fn(records: usize, polls: u32) -> bool,
}

/// What `--follow` answers when asked whether it has enough.
fn never_enough(_records: usize, _polls: u32) -> bool {
    false
}

/// The proxy's audit log: `<minimal_dir>/bep/audit.log`, beside the control
/// socket ([`crate::auth::control_socket_path`]), named by the constant
/// `minvmd` starts the proxy with so the reader and the writer cannot drift.
/// The active segment; the rotated ones sit beside it as `audit.log.<n>`
/// ([`bep::audit::segments`]).
pub(crate) fn audit_log_path(minimal_dir: Option<&Path>) -> PathBuf {
    crate::auth::control_socket_path(minimal_dir).with_file_name(minvmd::net::BEP_AUDIT_LOG_FILE)
}

/// The defined error `self` is refused with: an un-enrolled host has no
/// `identity.sock` for a box to read its own trail through, so the trail is
/// read on the host by name. `in_box` names the box when this process runs in
/// one, so the refusal can print the command to run.
fn self_refusal(in_box: Option<&str>) -> String {
    let box_id = in_box.unwrap_or("<box>");
    format!(
        "{SELF_UNSUPPORTED}: `self` needs the box's own identity surface, which this host does \
         not have while it is not enrolled; run `min box audit {box_id}` on the host instead"
    )
}

/// The records `args` asks for: one box's, or every box under one.
/// `in_box` is the box this process runs in, when it runs in one.
fn subject_of(args: &BoxAuditArgs, in_box: Option<&str>) -> Result<Subject, anyhow::Error> {
    let (named, children) = match (args.box_id.as_deref(), args.parent.as_deref()) {
        (Some(box_id), None) => (box_id, false),
        (None, Some(parent)) => (parent, true),
        // The argument group admits exactly one of the two; a build that
        // loses it says so rather than guessing which was meant.
        _ => bail!("name one box to read, or one parent with `--parent <box>`"),
    };
    if named == SELF {
        bail!(self_refusal(in_box));
    }
    Ok(if children {
        Subject::Children(named.to_owned())
    } else {
        Subject::Box(named.to_owned())
    })
}

/// One record as a line of the default output: its own box first, so a merged
/// `--parent` read names the box of every record on the stream.
fn render_record(record: &Record) -> String {
    let marker = if record.marker.is_empty() {
        String::new()
    } else {
        format!(" ({})", record.marker)
    };
    format!(
        "{sub}  {kind} {decision}  {authority}  {credential}  {resource} {permission}{marker}",
        sub = record.sub,
        kind = record.kind,
        decision = record.decision,
        authority = record.authority,
        credential = record.credential,
        resource = record.resource,
        permission = record.permission,
    )
}

/// Writes every record `subject` wants and, with `tail` set, keeps polling for
/// the records appended after the replay (BEP-042). Returns how many records
/// were written.
fn stream(
    reader: &mut Reader,
    subject: &Subject,
    format: AuditFormat,
    out: &mut impl Write,
    tail: Option<Tail>,
) -> Result<usize, anyhow::Error> {
    let mut written = 0;
    let mut polls = 0;
    loop {
        for record in reader.read(subject)? {
            match format {
                AuditFormat::Text => writeln!(out, "{}", render_record(&record))?,
                AuditFormat::Jsonl => writeln!(out, "{}", record.line())?,
            }
            written += 1;
        }
        out.flush()?;
        let Some(tail) = tail else {
            return Ok(written);
        };
        polls += 1;
        if (tail.enough)(written, polls) {
            return Ok(written);
        }
        std::thread::sleep(tail.poll);
    }
}

/// Prints one box's audit trail, or every box's under one, from the proxy's
/// log (BEP-042). `--follow` tails the log until the command is interrupted.
///
/// # Errors
///
/// A `self` subject while the host is not enrolled, an unreadable log, or a
/// log line that is no record.
pub fn cmd_box_audit(global: &GlobalArgs, args: BoxAuditArgs) -> Result<(), anyhow::Error> {
    let in_box = std::env::var(SESSION_NAME_ENV).ok();
    let subject = subject_of(&args, in_box.as_deref())?;
    let log = audit_log_path(global.minimal_dir.as_deref());
    // Every retained segment, oldest first, then the active one (BEP-068).
    let mut reader = Reader::open(bep::audit::segments(&log)?);
    let segments = reader.segments();
    let tail = args.follow.then_some(Tail {
        poll: FOLLOW_POLL,
        enough: never_enough,
    });
    let records = stream(
        &mut reader,
        &subject,
        args.output,
        &mut std::io::stdout().lock(),
        tail,
    )?;
    tracing::info!(
        box_id = %subject,
        segments,
        records,
        "read the box audit trail"
    );
    Ok(())
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

    /// An event the proxy records for `box_id`, with the authority varying per
    /// record so one record is told from another in the output.
    fn audit_event(box_id: &str, authority: &str) -> bep::Event {
        bep::Event {
            kind: bep::Kind::Decision,
            box_id: box_id.to_owned(),
            authority: authority.to_owned(),
            credential: Some("github:user-token".to_owned()),
            mapping: bep::Mapping::mapped("repo:acme/web", "contents:write"),
            decision: bep::audit::Decision::Admit,
            marker: None,
        }
    }

    /// Appends `events` to the log at `path`, in order, as the proxy would.
    fn log_with(path: &Path, events: &[bep::Event]) {
        let mut log = bep::Log::open(path).expect("the log opens for append");
        for event in events {
            log.append(event).expect("the log takes an append");
        }
    }

    /// The arguments `argv` parses to, as the command receives them.
    fn audit_args(argv: &[&str]) -> BoxAuditArgs {
        use clap::Parser as _;

        match crate::Cli::try_parse_from(argv)
            .expect("the audit form parses")
            .command
        {
            Some(crate::Command::Box(crate::BoxArgs {
                command: crate::BoxCommand::Audit(args),
            })) => args,
            _ => panic!("expected `box audit`"),
        }
    }

    /// One read of the log at `path`, with no tailing: what it printed, and
    /// how many records it wrote. Over the same segment list the command reads,
    /// so a rotated log reads here as it does there.
    fn read(path: &Path, args: &BoxAuditArgs) -> (String, usize) {
        let subject = subject_of(args, None).expect("the subject is a box");
        let mut reader = Reader::open(bep::audit::segments(path).expect("the segments list"));
        let mut out = Vec::new();
        let written = stream(&mut reader, &subject, args.output, &mut out, None)
            .expect("the read prints the trail");
        (
            String::from_utf8(out).expect("the output is UTF-8"),
            written,
        )
    }

    /// BEP-042: the command prints the records whose subject is the named box
    /// and no other's — a box that no longer exists included, since the log is
    /// the proxy's — in either output form.
    #[test]
    fn box_audit_filters_to_one_box() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut off_module = audit_event("api", "packages.example");
        off_module.credential = None;
        off_module.mapping = bep::Mapping::Unmapped;
        off_module.marker = Some("off_module".to_owned());
        off_module.decision = bep::audit::Decision::Refuse;
        log_with(
            &path,
            &[
                audit_event("web", "api.github.com"),
                off_module,
                audit_event("web", "codeload.github.com"),
                // A box that has since been removed: its records stay.
                audit_event("gone-9f2c", "uploads.github.com"),
            ],
        );

        let (text, written) = read(&path, &audit_args(&["min", "box", "audit", "web"]));
        assert_eq!(written, 2, "{text}");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines.iter().all(|line| line.starts_with("web  ")), "{text}");
        assert!(lines[0].contains("api.github.com"), "{text}");
        assert!(lines[1].contains("codeload.github.com"), "{text}");
        // Nothing of another box reaches the output: not its name, not its
        // authority, not its marker.
        for absent in ["packages.example", "off_module", "gone-9f2c"] {
            assert!(!text.contains(absent), "{absent} reached:\n{text}");
        }
        // Each line carries what the proxy decided for that box.
        assert!(lines[0].contains("decision admit"), "{text}");
        assert!(lines[0].contains("github:user-token"), "{text}");
        assert!(lines[0].contains("repo:acme/web contents:write"), "{text}");

        // `-o jsonl` prints the log's own lines for that box and no other's.
        let (jsonl, written) = read(
            &path,
            &audit_args(&["min", "box", "audit", "web", "-o", "jsonl"]),
        );
        assert_eq!(written, 2);
        let held: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        for line in jsonl.lines() {
            let record: Record = serde_json_lenient::from_str(line).expect("a record per line");
            assert_eq!(record.sub, "web");
            assert!(
                held.iter().any(|line_of_log| line_of_log == line),
                "{line} is not a line of the log"
            );
        }

        // A removed box's trail reads the same: nothing consults the session
        // store, so `min box rm` never takes the records away.
        let (reaped, written) = read(&path, &audit_args(&["min", "box", "audit", "gone-9f2c"]));
        assert_eq!(written, 1, "{reaped}");
        assert!(reaped.starts_with("gone-9f2c  "), "{reaped}");

        // The grammar names a box or a parent; neither names a read.
        use clap::Parser as _;
        assert!(crate::Cli::try_parse_from(["min", "box", "audit"]).is_err());
    }

    /// BEP-068: a read covers every retained segment, oldest first — a box's
    /// trail that crossed a rotation reads as one trail, with the same filter
    /// applied across the segments.
    #[test]
    fn box_audit_reads_across_segments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // The proxy's own rotation, at a bound small enough that these records
        // span more than one segment.
        let mut log = bep::Log::open(&path)
            .expect("the log opens for append")
            .with_segment_bytes(500);
        let appended = [
            ("web", "api.github.com"),
            ("web", "github.com"),
            // Another box's records ride along, so the filter is still doing
            // its work on either side of the rotation.
            ("api", "codeload.github.com"),
            ("web", "uploads.github.com"),
            ("web", "api.github.com"),
            ("api", "github.com"),
        ];
        for (box_id, authority) in appended {
            log.append(&audit_event(box_id, authority))
                .expect("the log takes an append");
        }
        drop(log);

        let segments = bep::audit::segments(&path).expect("the segments list");
        assert!(segments.len() > 1, "the log rotated: {segments:?}");
        // The box's records are spread over the segments, so a read that covers
        // one of them cannot be complete.
        let spread: Vec<usize> = segments
            .iter()
            .map(|segment| {
                std::fs::read_to_string(segment)
                    .unwrap_or_default()
                    .lines()
                    .filter(|line| line.contains(r#""sub":"web""#))
                    .count()
            })
            .collect();
        assert_eq!(spread.iter().sum::<usize>(), 4, "{spread:?}");
        assert!(
            spread.iter().filter(|held| **held > 0).count() > 1,
            "one segment holds all of the box's records: {spread:?}"
        );

        let (text, written) = read(&path, &audit_args(&["min", "box", "audit", "web"]));
        assert_eq!(written, 4, "{text}");
        let authorities: Vec<&str> = text
            .lines()
            .map(|line| {
                line.split_whitespace()
                    .nth(3)
                    .expect("each line names the authority")
            })
            .collect();
        // Every record of the box, in the order the proxy appended them, the
        // rotated segments' first.
        assert_eq!(
            authorities,
            [
                "api.github.com",
                "github.com",
                "uploads.github.com",
                "api.github.com"
            ],
            "{text}"
        );
        assert!(text.lines().all(|line| line.starts_with("web  ")), "{text}");
        assert!(!text.contains("codeload.github.com"), "{text}");

        // `-o jsonl` prints the lines the segments hold, whichever segment each
        // came from.
        let (jsonl, written) = read(
            &path,
            &audit_args(&["min", "box", "audit", "web", "-o", "jsonl"]),
        );
        assert_eq!(written, 4);
        let held: Vec<String> = segments
            .iter()
            .flat_map(|segment| {
                std::fs::read_to_string(segment)
                    .unwrap_or_default()
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();
        for line in jsonl.lines() {
            assert!(
                held.iter().any(|line_of_log| line_of_log == line),
                "{line} is no line of any segment"
            );
        }
    }

    /// BEP-042: `--follow` replays the box's records and then prints the ones
    /// the proxy appends after the replay, in that order.
    #[test]
    fn box_audit_follow_replays_then_tails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        log_with(
            &path,
            &[
                audit_event("web", "api.github.com"),
                audit_event("other", "github.com"),
                audit_event("web", "codeload.github.com"),
            ],
        );

        // Appended while the read is already tailing.
        let appending = std::thread::spawn({
            let path = path.clone();
            move || {
                std::thread::sleep(Duration::from_millis(50));
                log_with(&path, &[audit_event("web", "uploads.github.com")]);
            }
        });

        let args = audit_args(&["min", "box", "audit", "web", "--follow"]);
        assert!(args.follow);
        let subject = subject_of(&args, None).expect("the subject is a box");
        let mut reader = Reader::open([path.clone()]);
        let mut out = Vec::new();
        let written = stream(
            &mut reader,
            &subject,
            args.output,
            &mut out,
            // Three of the box's records, or five seconds of polling: the
            // bound keeps a failure a failure instead of a hang.
            Some(Tail {
                poll: Duration::from_millis(10),
                enough: |records, polls| records >= 3 || polls >= 500,
            }),
        )
        .expect("the follow read prints the trail");
        appending.join().expect("the appending thread");

        let text = String::from_utf8(out).expect("the output is UTF-8");
        assert_eq!(written, 3, "{text}");
        let lines: Vec<&str> = text.lines().collect();
        // The replay first, in log order, then what was appended after it.
        assert!(lines[0].contains("api.github.com"), "{text}");
        assert!(lines[1].contains("codeload.github.com"), "{text}");
        assert!(lines[2].contains("uploads.github.com"), "{text}");
        assert!(lines.iter().all(|line| line.starts_with("web  ")), "{text}");
    }

    /// BEP-042: `--parent` merges the records of every box under the named one
    /// onto one stream, each record naming its own box.
    #[test]
    fn box_audit_parent_merges_children() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        log_with(
            &path,
            &[
                audit_event("web/agent-1", "api.github.com"),
                audit_event("other/agent-1", "github.com"),
                audit_event("web", "codeload.github.com"),
                audit_event("web/task-build", "uploads.github.com"),
                audit_event("web/agent-1", "github.com"),
            ],
        );

        let args = audit_args(&["min", "box", "audit", "--parent", "web"]);
        assert_eq!(args.box_id, None);
        let (text, written) = read(&path, &args);
        assert_eq!(written, 3, "{text}");
        let boxes: Vec<&str> = text
            .lines()
            .map(|line| {
                line.split_whitespace()
                    .next()
                    .expect("each line names a box")
            })
            .collect();
        // Both children, in log order, each naming itself — never the
        // parent's own records, and never another parent's child.
        assert_eq!(boxes, ["web/agent-1", "web/task-build", "web/agent-1"]);
        assert!(!text.contains("other/agent-1"), "{text}");
        assert!(!text.contains("codeload.github.com"), "{text}");
    }

    /// BEP-042: `self` is refused with the defined error
    /// `audit_self_unsupported_unenrolled`, naming the box the host reads by
    /// name instead — the box's own name when the command runs inside one.
    #[test]
    fn box_audit_self_unenrolled_refused_with_error() {
        let inside = subject_of(
            &audit_args(&["min", "box", "audit", "self"]),
            Some("web-4f21"),
        )
        .expect_err("`self` is refused while the host is not enrolled")
        .to_string();
        assert!(inside.starts_with(SELF_UNSUPPORTED), "{inside}");
        assert!(inside.contains("min box audit web-4f21"), "{inside}");
        assert!(inside.contains("not enrolled"), "{inside}");

        // Outside a box the command is still named, with the box left to the
        // reader to fill in.
        let outside = subject_of(&audit_args(&["min", "box", "audit", "self"]), None)
            .expect_err("`self` is refused off a box too")
            .to_string();
        assert!(outside.contains("min box audit <box>"), "{outside}");

        // `--parent self` is the same refusal: it names `self` too.
        let parent = subject_of(
            &audit_args(&["min", "box", "audit", "--parent", "self"]),
            Some("web-4f21"),
        )
        .expect_err("`--parent self` is refused as well")
        .to_string();
        assert!(parent.starts_with(SELF_UNSUPPORTED), "{parent}");

        // Any other name is read, not refused.
        let named = subject_of(&audit_args(&["min", "box", "audit", "myself"]), None)
            .expect("a box named otherwise is read");
        assert_eq!(named, Subject::Box("myself".to_owned()));
    }
}
