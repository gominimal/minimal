//! Command handlers for the `min` CLI, grouped by command family.

use anyhow::{Context as _, bail};
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::path::PathBuf;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;

// The version gate lives in `minimal-client`, next to the transport it guards,
// so the dashboard's activation path (`minimal-tui`, which cannot depend on
// this crate) gates on the same wording and the same override.
// `ensure_version_reported` asserts a build a reply already carried;
// `ensure_version_match` is the round-trip form, for paths with no first RPC
// of their own to carry it.
use minimal_client::{ensure_version_match, ensure_version_reported, version_assertion};

use crate::*;

mod admin;
mod list;
mod net;
mod project;
mod session;

// The Ctrl-C cleanup (`arm_activation_interrupt`) withdraws the row the
// activation registered with the VM host daemon; the withdrawal lives with
// the session commands, as does the provider-kind rule its gate keys on.
use session::{daemon_provider_kind, vm_host_control_sock, withdraw_box_row};

pub use admin::*;
pub use list::*;
pub use net::*;
pub use project::*;
pub use session::*;

pub async fn run(cli: Cli) -> Result<(), anyhow::Error> {
    use tracing::Instrument as _;
    let ctx = minimal_client::trace_context();
    let root = tracing::info_span!(
        "cmd",
        trace_id = %ctx.trace_id_hex(),
        span_id = %ctx.span_id_hex(),
    );
    // Boxed: inlined, this dispatch match's deepest arm overruns rustc's
    // query depth (128) when computing the future's layout.
    Box::pin(run_command(cli)).instrument(root).await
}

pub(crate) async fn run_command(cli: Cli) -> Result<(), anyhow::Error> {
    // Adopt any pre-split `providers/local-<N>` dirs into the kind-tagged scheme
    // once per invocation, before any command resolves a provider dir, so an
    // upgraded CLI finds an existing instance rather than orphaning it.
    client::migrate_legacy_provider_dirs(cli.global_args.minimal_dir.as_deref());

    match cli.command {
        // A bare `min` (no subcommand) resolves-or-creates a session in a
        // terminal, and prints a read-only state report otherwise — see
        // `cmd_bare`.
        None => cmd_bare(&cli.global_args).await,
        Some(Command::Ls(args)) => cmd_ls(&cli.global_args, args).await,
        Some(Command::Stop(args)) => cmd_stop(&cli.global_args, args).await,
        Some(Command::Session(SessionArgs { command })) => match command {
            SessionCommand::List(args) => cmd_ls(&cli.global_args, args).await,
            SessionCommand::Activate(args) => cmd_activate(&cli.global_args, args).await,
            SessionCommand::Attach(args) => cmd_attach(&cli.global_args, args).await,
            SessionCommand::Exec(args) => cmd_exec(&cli.global_args, args).await,
            SessionCommand::Run(args) => cmd_session_run(&cli.global_args, args).await,
            SessionCommand::Destroy(args) => cmd_destroy(&cli.global_args, args).await,
            SessionCommand::Rename(args) => cmd_rename(&cli.global_args, args).await,
            SessionCommand::Policy(args) => cmd_session_policy(&cli.global_args, args).await,
            SessionCommand::SetupZed(args) => cmd_session_setup_zed(&cli.global_args, args).await,
            SessionCommand::Hooks(args) => cmd_session_hooks(&cli.global_args, args).await,
        },
        Some(Command::Loadout(LoadoutArgs {
            command: LoadoutCommand::List(args),
        })) => loadouts::cmd_loadout_list(args, &cli.global_args),
        Some(Command::Task(TaskArgs { command })) => match command {
            TaskCommand::Run(args) => task::cmd_task_run(&cli.global_args, args).await,
        },
        Some(Command::Run(args)) => task::cmd_run(&args),
        Some(Command::Net(NetArgs {
            command: NetCommand::Forward(args),
        })) => cmd_net_forward(&cli.global_args, args).await,
        Some(Command::Net(NetArgs {
            command: NetCommand::Setup,
        })) => cmd_net_setup(&cli.global_args).await,
        Some(Command::Dirs) => dirs::cmd_dirs(&cli.global_args),
        Some(Command::Bug(args)) => diag::cmd_bug(&cli.global_args, args).await,
        Some(Command::Diag(diag::DiagArgs { command })) => match command {
            diag::DiagCommand::Collect(args) => diag::cmd_bug(&cli.global_args, args).await,
            diag::DiagCommand::Upload(args) => diag::cmd_diag_upload(args).await,
        },
        #[cfg(feature = "remote-access")]
        Some(Command::Mesh(MeshArgs { command })) => match command {
            MeshCommand::Status => cmd_mesh_status(&cli.global_args).await,
            MeshCommand::Join(args) => cmd_mesh_join(&cli.global_args, args),
            MeshCommand::Leave => cmd_mesh_leave(&cli.global_args),
        },
        Some(Command::Proxy(args)) => cmd_proxy(&cli.global_args, args).await,
        Some(Command::Login(args)) => {
            cmd_login(&cli.global_args, args, &mut std::io::stdout().lock()).await
        }
        // Unlocked handle: `Stdout` takes its lock per write, so the lock is
        // not held across the daemon handshake, where a spawned task's
        // logging may need stdout too.
        Some(Command::Version) => cmd_version(&cli.global_args, &mut std::io::stdout()).await,
        Some(Command::Spin(args)) => cmd_spin(&cli.global_args, args).await,
        #[cfg(debug_assertions)]
        Some(Command::DebugAnswererCommand) => {
            println!(
                "{}",
                crate::resolver::answerer_command_for_this_host().await?
            );
            Ok(())
        }
        Some(Command::Init(args)) => cmd_init(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Some(Command::Add(args)) => cmd_add(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Some(Command::Update(args)) => cmd_update(&cli.global_args, args)
            .await
            .map_err(|e| anyhow::anyhow!("{e}")),
        Some(Command::CompleteSessionStr(args)) => {
            completion::cmd_complete_session_str(&cli.global_args, args).await
        }
        Some(Command::Completions(CompletionsArgs { command })) => match command {
            CompletionsCommand::Print(args) => completions::cmd_print(args.shell),
            CompletionsCommand::Install(args) => completions::cmd_install(&args.shells),
        },
        Some(Command::Dash) => cmd_dash(&cli.global_args).await,
    }
}

/// Bounded retries when a freshly minted autogen name collides with an
/// existing session built from the same directory.
pub(crate) const AUTOGEN_NAME_RETRIES: u32 = 8;

/// Longest component [`sanitize_name_component`] returns, so a minted
/// `task-<component>-<hex>` (the longest wrapper) stays inside the 63-octet
/// DNS label `validate_session_name` requires.
const NAME_COMPONENT_MAX: usize = 48;

/// Reduce a directory basename to the characters a session name may carry —
/// ASCII alphanumerics, lowercased, with `-`, `_` and `.` each mapped to `-` —
/// dropping everything else (spaces, unicode) and capping the length, so the
/// minted handle is typable and is a single DNS label that clears
/// `validate_session_name`. Falls back to `session` when nothing survives.
pub(crate) fn sanitize_name_component(basename: &str) -> String {
    let filtered: String = basename
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() {
                Some(c.to_ascii_lowercase())
            } else if matches!(c, '-' | '_' | '.') {
                Some('-')
            } else {
                None
            }
        })
        .take(NAME_COMPONENT_MAX)
        .collect();
    let trimmed = filtered.trim_matches('-');
    if trimmed.is_empty() {
        "session".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Mint a typable session name `<dir-basename>-<hex>` from the project
/// directory. The caller supplies the hex so the format is unit-testable and
/// so a collision retry can re-mint with fresh entropy.
pub(crate) fn autogen_session_name(project_dir: &camino::Utf8Path, hex: &str) -> String {
    let base = sanitize_name_component(project_dir.file_name().unwrap_or("session"));
    format!("{base}-{hex}")
}

/// Four lowercase hex digits of per-call entropy, drawn from the stdlib
/// hasher's randomized seed — enough to disambiguate sessions from one
/// directory without pulling in an RNG dependency. Each call reseeds, so a
/// retry gets a fresh suffix.
pub(crate) fn random_hex4() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::BuildHasher;
    let seed = RandomState::new().hash_one("minimal-session-name");
    format!("{:04x}", seed & 0xffff)
}

/// The daemon collapses the session-store `AlreadyExists` into a plain message
/// (see `serve_create_session` in `crates/minimald/src/rpc.rs`); match it so an
/// autogen name clash can be told apart from any other `CreateSession` failure.
pub(crate) fn is_name_collision(error: &str) -> bool {
    error.contains("already exists")
}

/// Whether a failed `CreateSession` should retry under a freshly minted name:
/// only autogen names (`autogen`), only on a name collision, and only within
/// the bounded budget. A user-supplied name never retries, so its collision
/// surfaces verbatim.
pub(crate) fn should_retry_autogen(autogen: bool, attempts: u32, error: &str) -> bool {
    autogen && attempts < AUTOGEN_NAME_RETRIES && is_name_collision(error)
}

/// Connect to the daemon, resolving the socket path from global args, and
/// refuse to proceed against a daemon of a different build
/// ([`ensure_version_match`]).
///
/// Costs a `GetVersion` round trip, which is why the paths that care — the
/// activation, and the attach/exec hand-offs — do not come through here: they
/// fold the assertion into the RPC they were already sending. This stays the
/// safe default for the rest, whose first call differs from one command to the
/// next and none of which is hot.
pub async fn connect_daemon(global: &GlobalArgs) -> Result<client::Client, anyhow::Error> {
    let mut client = connect_daemon_unchecked(global).await?;
    ensure_version_match(&mut client).await?;
    Ok(client)
}

/// [`connect_daemon`] without the `GetVersion` gate.
///
/// Two kinds of caller. The commands that must keep working *because* the pair
/// is skewed — `min stop` is the recovery the gate's own message prescribes, so
/// gating it would leave the operator with no way out. And the activation path,
/// which *is* gated, just not from here: its `CreateSession` carries the
/// assertion itself, so routing it through [`connect_daemon`] would only add
/// the round trip this connector exists to skip.
pub(crate) async fn connect_daemon_unchecked(
    global: &GlobalArgs,
) -> Result<client::Client, anyhow::Error> {
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;

    client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")
}

/// A session reference parsed from a CLI string: either a UUID or a name.
/// A name lookup that misses falls back to a unique id prefix in
/// [`get_session_record`]. Used to build the typed request enums both `GetSessionRecord` and
/// `GetSessionPolicy` expect.
pub(crate) enum SessionLookup {
    Id(sessions::SessionId),
    Name(String),
}

impl SessionLookup {
    /// Parse a user-supplied session string. If it parses as a UUID,
    /// the lookup is by ID; otherwise by name.
    pub(crate) fn parse(s: &str) -> Self {
        match sessions::SessionId::parse_str(s) {
            Ok(id) => Self::Id(id),
            Err(_) => Self::Name(s.to_string()),
        }
    }
}

impl From<SessionLookup> for minimald_rpc::GetSessionRecordRequest {
    fn from(l: SessionLookup) -> Self {
        match l {
            SessionLookup::Id(id) => Self::Id(id),
            SessionLookup::Name(n) => Self::Name(n),
        }
    }
}

impl From<SessionLookup> for minimald_rpc::GetSessionPolicyRequest {
    fn from(l: SessionLookup) -> Self {
        match l {
            SessionLookup::Id(id) => Self::Id(id),
            SessionLookup::Name(n) => Self::Name(n),
        }
    }
}

impl From<SessionLookup> for minimald_rpc::GetSessionHooksRequest {
    fn from(l: SessionLookup) -> Self {
        match l {
            SessionLookup::Id(id) => Self::Id(id),
            SessionLookup::Name(n) => Self::Name(n),
        }
    }
}

/// Resolve a session by UUID, unique id prefix, or session name, returning
/// its record.
///
/// Used by commands that need the full record before proceeding (destroy,
/// rename). If the string parses as a UUID, the session
/// is looked up by ID; otherwise by name, then by unique id prefix (see
/// [`get_session_record`]). Bails if no session matches.
pub(crate) async fn resolve_session(
    client: &mut client::Client,
    session: &str,
) -> Result<sessions::Record, anyhow::Error> {
    let resp = get_session_record(client, session).await?;
    named_record(resp.record, session)
}

/// [`resolve_session`] for the paths that must refuse a version-skewed daemon:
/// the same lookup, with the build it reports asserted before the record is
/// used for anything.
///
/// The lookup is the first RPC `min session attach`, `min session exec`, and
/// `min session setup-zed` make, so the gate rides on
/// its reply rather than on a `GetVersion` sent ahead of it — an activation
/// must not pay a round trip for a check the calls it already makes can carry
/// (#1251). Ordered so the skew is reported ahead of a "no session found":
/// against the wrong daemon, the name is the less useful of the two answers.
pub(crate) async fn resolve_session_version_gated(
    client: &mut client::Client,
    session: &str,
) -> Result<sessions::Record, anyhow::Error> {
    let resp = get_session_record(client, session).await?;
    ensure_version_reported(resp.daemon_version.as_deref())?;
    named_record(resp.record, session)
}

/// The `GetSessionRecord` round trip both resolvers share.
///
/// A name lookup that finds no record falls back to matching `session` as an
/// id prefix (see [`match_id_prefix`]), so the short id `min ls` prints
/// resolves. An exact name always wins, because the name is asked first. A
/// prefix that matches several sessions is an error naming them; one that
/// matches none returns the empty reply, for the caller's "no session found".
pub(crate) async fn get_session_record(
    client: &mut client::Client,
    session: &str,
) -> Result<minimald_rpc::GetSessionRecordResponse, anyhow::Error> {
    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest, ListSessions};
    let lookup = SessionLookup::parse(session);
    let by_name = matches!(lookup, SessionLookup::Name(_));
    let resp = client
        .oneshot_rpc::<GetSessionRecord>(GetSessionRecordRequest::from(lookup))
        .await
        .context("GetSessionRecord RPC failed")?;
    if resp.record.is_some() || !by_name || !is_id_prefix(session) {
        return Ok(resp);
    }
    let listing = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?;
    match match_id_prefix(&listing.sessions, session)? {
        Some(id) => client
            .oneshot_rpc::<GetSessionRecord>(GetSessionRecordRequest::Id(id))
            .await
            .context("GetSessionRecord RPC failed"),
        None => Ok(resp),
    }
}

/// Whether `s` is shaped like a session id prefix: 4 to 32 hex digits, with
/// dashes allowed between them.
pub(crate) fn is_id_prefix(s: &str) -> bool {
    let digits = s.chars().filter(|c| *c != '-').count();
    (4..=32).contains(&digits) && s.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
}

/// Match `session` against the listed sessions: an exact name first, then a
/// name that matches ignoring ASCII case (the fold names are made unique
/// under), then a unique id prefix (compared without dashes, ignoring case).
/// A case-folded name that matches several sessions (written before names
/// were made unique that way) resolves to none of them, not to an id prefix
/// either. `None` when nothing matches or `session` is not prefix-shaped; an
/// error naming the candidates when the prefix matches more than one session.
pub(crate) fn match_id_prefix(
    entries: &[minimald_rpc::ListSessionsEntry],
    session: &str,
) -> Result<Option<sessions::SessionId>, anyhow::Error> {
    if let Some(entry) = entries.iter().find(|e| e.name.as_deref() == Some(session)) {
        return Ok(Some(entry.id));
    }
    let mut folded = entries.iter().filter(|e| {
        e.name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case(session))
    });
    match (folded.next(), folded.next()) {
        (Some(entry), None) => return Ok(Some(entry.id)),
        (Some(_), Some(_)) => return Ok(None),
        _ => {}
    }
    if !is_id_prefix(session) {
        return Ok(None);
    }
    let prefix = session.replace('-', "").to_ascii_lowercase();
    let matches: Vec<&minimald_rpc::ListSessionsEntry> = entries
        .iter()
        .filter(|e| e.id.as_ref().simple().to_string().starts_with(&prefix))
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [entry] => Ok(Some(entry.id)),
        several => {
            // `min ls` shows sessions cut to eight digits, but sessions made
            // close together share a long UUIDv7 prefix, so the refusal names
            // each candidate at the shortest length that keeps them distinct.
            let simples: Vec<String> = several
                .iter()
                .map(|e| e.id.as_ref().simple().to_string())
                .collect();
            let cut = (8..=32)
                .find(|&n| {
                    let prefixes: Vec<&str> = simples.iter().map(|s| &s[..n]).collect();
                    let mut seen = std::collections::HashSet::new();
                    prefixes.iter().all(|p| seen.insert(*p))
                })
                .unwrap_or(32);
            // Only a shortened id gets an ellipsis; a full id is not cut.
            let ellipsis = if cut < 32 { "…" } else { "" };
            let candidates: Vec<String> = several
                .iter()
                .zip(&simples)
                .map(|(entry, simple)| {
                    let mut candidate = format!("{}{ellipsis}", &simple[..cut]);
                    if let Some(name) = entry.name.as_deref() {
                        candidate.push_str(&format!(" ({name})"));
                    }
                    candidate
                })
                .collect();
            Err(AmbiguousIdPrefix(format!(
                "'{session}' matches sessions {}; use more characters",
                candidates.join(", ")
            ))
            .into())
        }
    }
}

/// An id prefix that matches more than one session; the message names them.
/// Typed so a caller can tell it from a failed RPC.
#[derive(Debug)]
pub(crate) struct AmbiguousIdPrefix(String);

impl std::fmt::Display for AmbiguousIdPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AmbiguousIdPrefix {}

/// Unwrap a looked-up record, naming what was asked for when nothing matched.
pub(crate) fn named_record(
    record: Option<sessions::Record>,
    session: &str,
) -> Result<sessions::Record, anyhow::Error> {
    record.ok_or_else(|| anyhow::anyhow!("No session found matching '{session}'"))
}

/// `ListSessions` with the daemon's build asserted off the same reply, for the
/// paths that go on to attach or activate. See
/// [`resolve_session_version_gated`] for why the gate rides here rather than on
/// a `GetVersion` of its own.
pub(crate) async fn list_sessions_version_gated(
    client: &mut client::Client,
) -> Result<minimald_rpc::ListSessionsResponse, anyhow::Error> {
    use minimald_rpc::ListSessions;
    let resp = client
        .oneshot_rpc::<ListSessions>(())
        .await
        .context("ListSessions RPC failed")?;
    ensure_version_reported(resp.daemon_version.as_deref())?;
    Ok(resp)
}

/// Ensure the minimald daemon is running, autospawning it if necessary.
pub(crate) fn ensure_daemon(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    autospawn::ensure_daemon_running(global.use_minvmd(), global.minimal_dir.as_deref())
        .context("Failed to ensure the minimald daemon is running")
}

/// Prompt the user with a yes/no question on stderr.
pub(crate) fn confirm(question: &str, default: bool) -> Result<bool, anyhow::Error> {
    let prompt = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{question} {prompt} ");
    std::io::stderr().flush().ok();

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("reading stdin")?;
    let trimmed = input.trim();
    Ok(if trimmed.is_empty() {
        default
    } else {
        trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes")
    })
}

/// The environment variable a shell sets to ask `min` for completions.
///
/// clap_complete's default, named here because both ends have to agree: the
/// shim rendered by [`completions::cmd_print`] sets it, and the `CompleteEnv`
/// call in `main.rs` reads it.
pub const COMPLETE_VAR: &str = "COMPLETE";

/// Whether the operator can be prompted interactively. The prompt
/// renders on stderr (so stderr must be a terminal) and reads
/// keypresses from stdin (so stdin must be a terminal too). If
/// either side is redirected we take the `--no-prompt` path — going
/// interactive when stdin is a pipe just hangs the prompt and then
/// aborts with a much less helpful error than the `--no-prompt`
/// snippet the operator actually wants to paste.
pub(crate) fn can_prompt_interactively() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// Phase 3 gate: run the user policy + hooks over the daemon's
/// pending items and produce the wire verdict (plus the final
/// policy after any hook mutations). Does NOT talk to the daemon —
/// the caller decides whether to actually submit or abort.
///
/// `policy` is the user's own [`UserPolicy`](sessions::core::policy::UserPolicy)
/// loaded from `user_policy.toml`; daemon-side pending items
/// (packages, projects) are gated against it here on the client.
/// `hooks` decides what happens when the policy can't auto-decide an
/// item — see [`crate::prompt`] for the two implementations
/// (interactive prompt vs. `--no-prompt` collect-and-abort).
///
/// Split from [`submit_verdict_and_wait`] so `NoPromptHook` — which
/// fake-approves every item to keep both var and patch hooks firing
/// — can be intercepted between "verdict computed" and "verdict
/// submitted"; otherwise a `--no-prompt` run would submit a bogus
/// approval on the wire.
pub(crate) fn compute_verdict(
    response: sessions::wire::request::ContributionResponse,
    policy: sessions::core::policy::UserPolicy,
    options: sessions::core::compose::ComposeOptions,
    hooks: &dyn sessions::core::hooks::PolicyHooks,
) -> Result<
    (
        sessions::wire::request::ContributionVerdict,
        sessions::core::policy::UserPolicy,
    ),
    sessions::core::compose::ComposeError,
> {
    sessions::client::handler::handle_response(response, &[], policy, hooks, options, &|name| {
        std::env::var(name)
    })
}

/// Ship the verdict to the daemon and wait for `Active`. Every
/// failure path in here has to `send_abort` first — the daemon is
/// parked in `Draft{pending}` and leaks the session slot otherwise.
pub(crate) async fn submit_verdict_and_wait(
    client: &mut client::Client,
    session_id: sessions::SessionId,
    verdict: sessions::wire::request::ContributionVerdict,
) -> Result<sessions::SessionId, anyhow::Error> {
    use minimald_rpc::SubmitVerdict;
    use sessions::wire::request::SessionStep;

    let resp = match client.oneshot_rpc::<SubmitVerdict>(verdict).await {
        Ok(r) => r,
        Err(e) => {
            send_abort(client, session_id).await;
            return Err(e).context("SubmitVerdict RPC failed");
        }
    };
    let step = match resp {
        minimald_rpc::Errorable::Ok(s) => s,
        minimald_rpc::Errorable::Err { error } => {
            send_abort(client, session_id).await;
            bail!("SubmitVerdict failed: {error}");
        }
    };
    match step {
        SessionStep::Materialized { id } => Ok(id),
        SessionStep::Fault { error } => {
            send_abort(client, session_id).await;
            bail!("SubmitVerdict faulted: {error}");
        }
    }
}

/// The interactive-prompt caller's happy path: gate, then submit,
/// then return the finalized id + policy + the verdict that was
/// submitted. The verdict is returned so the caller can pick the
/// approved daemon-side patches out for upload — those files were
/// only surfaced during Phase 3 and won't otherwise be available
/// to the client-side upload step. Any gating failure aborts the
/// daemon-side session before propagating.
pub(crate) async fn drive_pending_to_active(
    client: &mut client::Client,
    response: sessions::wire::request::ContributionResponse,
    policy: sessions::core::policy::UserPolicy,
    options: sessions::core::compose::ComposeOptions,
    hooks: &dyn sessions::core::hooks::PolicyHooks,
    project_dir: &camino::Utf8Path,
) -> Result<
    (
        sessions::SessionId,
        sessions::core::policy::UserPolicy,
        Vec<(std::path::PathBuf, paths::SandboxRelPath)>,
    ),
    anyhow::Error,
> {
    let session_id = response.session_id;
    let (verdict, final_policy) = match compute_verdict(response, policy, options, hooks) {
        Ok(v) => v,
        Err(e) => {
            send_abort(client, session_id).await;
            // Declining at the prompt is not a broken project: only a
            // genuine compose failure gets the directory-led message.
            use sessions::core::compose::ComposeError;
            match e {
                ComposeError::Aborted | ComposeError::Denied { .. } => bail!("{e}"),
                _ => bail!(composition_failure_message(project_dir, &e.to_string())),
            }
        }
    };
    // Extract the approved-patch destinations before submit consumes
    // the verdict — avoids cloning the whole wire type (both vars
    // and patches Vecs plus their owned strings) just so the caller
    // can walk one field of it after the fact.
    let approved_patches: Vec<_> = approved_patches_from_verdict(&verdict).collect();
    let id = submit_verdict_and_wait(client, session_id, verdict).await?;
    Ok((id, final_policy, approved_patches))
}

/// Collect the sandbox destinations of every `Approved` patch
/// verdict — the daemon-side patches the client just approved and
/// now needs to upload. `Ignored`/`Denied` verdicts contribute
/// nothing to the composition, so they're not uploaded.
pub(crate) fn approved_patches_from_verdict(
    verdict: &sessions::wire::request::ContributionVerdict,
) -> impl Iterator<Item = (std::path::PathBuf, paths::SandboxRelPath)> + '_ {
    verdict.patches.iter().filter_map(|v| match v {
        sessions::wire::policy::WirePatchVerdict::Approved {
            host_path,
            destination,
            ..
        } => Some((
            host_path.as_utf8_path().as_std_path().to_path_buf(),
            destination.clone(),
        )),
        sessions::wire::policy::WirePatchVerdict::Ignored { .. }
        | sessions::wire::policy::WirePatchVerdict::Denied { .. } => None,
    })
}

/// Fire an `AbortSession` at the daemon for a `Pending` session the
/// client has decided not to finalize. A best-effort teardown.
pub(crate) async fn send_abort(client: &mut client::Client, session_id: sessions::SessionId) {
    use minimald_rpc::AbortSession;
    match client
        .oneshot_rpc::<AbortSession>(minimald_rpc::AbortSessionRequest { id: session_id })
        .await
    {
        Ok(minimald_rpc::Errorable::Ok(_)) => {}
        Ok(minimald_rpc::Errorable::Err { error }) => {
            eprintln!("AbortSession failed: {error}");
        }
        Err(e) => {
            eprintln!("AbortSession RPC failed: {e}");
        }
    }
}

/// Best-effort destroy for a `Materializing` session the client
/// couldn't finalize (patch upload failed, network blip, etc.).
/// Unlike `AbortSession`, `DestroySession` works on any status
/// past `Pending`. Errors are logged, not propagated — the caller
/// is already reporting a primary error.
///
/// Bounded by a hard timeout: the same network conditions that
/// caused the primary error (wedged daemon, half-open SSH channel,
/// a VM whose bridge accepted but whose guest never answered) can
/// make the RPC hang indefinitely, which would swallow the
/// operator-visible primary error we're supposed to be racing
/// back to `cmd_activate`.
pub(crate) async fn best_effort_destroy(
    client: &mut client::Client,
    session_id: sessions::SessionId,
) {
    /// Ceiling on how long we let a cleanup RPC run. Chosen well
    /// above a healthy `DestroySession` (single-digit milliseconds
    /// on a UDS) so the timeout only fires against pathologies.
    const DESTROY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    use minimald_rpc::DestroySession;
    let call = client
        .oneshot_rpc::<DestroySession>(minimald_rpc::DestroySessionRequest { id: session_id });
    match tokio::time::timeout(DESTROY_TIMEOUT, call).await {
        Ok(Ok(minimald_rpc::Errorable::Ok(_))) => {}
        Ok(Ok(minimald_rpc::Errorable::Err { error })) => {
            eprintln!("DestroySession failed while cleaning up: {error}");
        }
        Ok(Err(e)) => {
            eprintln!("DestroySession RPC failed while cleaning up: {e}");
        }
        Err(_) => {
            eprintln!(
                "DestroySession timed out after {DESTROY_TIMEOUT:?} while cleaning up \
                 session {session_id}; the session may still be present on the daemon \
                 (run `min session destroy {session_id}` to clean up manually)",
            );
        }
    }
}

/// Upload the composition's patches and external hook scripts (if
/// any) and finalize the session. The session is `Materializing` at
/// entry; `Active` on success. On upload/finalize failure the session
/// is left in `Materializing` — the caller is responsible for
/// destroying it.
///
/// Both uploads precede `FinalizeSession`, which gates on each
/// upload's ready-marker: a session must not become attachable while
/// either its patches or its hook scripts are still missing from the
/// daemon.
///
/// `hook_budget` is the summed declared timeout of the composition's
/// `on_activate` hooks, which the daemon runs inside `FinalizeSession`;
/// the call's deadline is extended by it so a hook declaring more than the
/// base RPC timeout is not cut short.
pub(crate) async fn upload_and_finalize(
    client: &mut client::Client,
    session_id: sessions::SessionId,
    patches: &[(std::path::PathBuf, paths::SandboxRelPath)],
    hook_scripts: &[sessions::client::hookscripts::StagedScript],
    hook_budget: std::time::Duration,
) -> Result<(), anyhow::Error> {
    client
        .upload_patches(session_id, patches)
        .await
        .context("Failed to upload composition patches")?;

    client
        .upload_hook_scripts(session_id, hook_scripts)
        .await
        .context("Failed to upload lifecycle hook scripts")?;

    use minimald_rpc::{FinalizeSession, FinalizeSessionRequest};
    let resp = client
        .oneshot_rpc_with_hook_budget::<FinalizeSession>(
            FinalizeSessionRequest { session_id },
            hook_budget,
        )
        .await
        .context("FinalizeSession RPC failed")?;
    match resp {
        minimald_rpc::Errorable::Ok(ok) => {
            // An activate hook runs headlessly, so without this the only
            // trace of it is the daemon log. Say what ran — the user
            // agreed to let this code execute, and is owed the receipt.
            for hook in &ok.activate_hooks {
                match hook.description.as_deref() {
                    Some(d) => eprintln!("Ran activation hook from {}: {d}", hook.declared_by),
                    None => eprintln!("Ran activation hook from {}", hook.declared_by),
                }
                // The description is an author-supplied label; what the
                // hook actually said is its captured output. Echo it to
                // stderr — stdout is reserved for the bare session id.
                if !hook.output.is_empty() {
                    eprint!("{}", hook.output);
                    if !hook.output.ends_with('\n') {
                        eprintln!();
                    }
                }
            }
            if ok.package_check_skipped {
                eprintln!(
                    "warning: the session package check was skipped (the package graph \
                     did not resolve in time or could not be evaluated; see the daemon \
                     log); unknown package names will surface at first exec"
                );
            }
            Ok(())
        }
        minimald_rpc::Errorable::Err { error } => {
            bail!("FinalizeSession failed: {error}");
        }
    }
}

/// Guard that tears down a half-built session if the user interrupts the
/// activation with Ctrl-C.
///
/// inquire (crossterm raw mode) captures a Ctrl-C at the
/// composition-gating prompt as an error return, so the abort-cleanup
/// that [`drive_pending_to_active`] runs gets to execute. During the
/// non-prompt phases (waiting on the daemon) a Ctrl-C is a plain
/// SIGINT, which would kill `min` before that cleanup, leaving the
/// daemon holding a `Pending` session that blocks its name.
/// [`arm_activation_interrupt`] installs a SIGINT handler that best-effort
/// `AbortSession`s the in-flight session over a fresh connection — the
/// activation borrows the primary one — then exits. The daemon's
/// connection-close reap is the backstop if the abort can't be
/// delivered.
///
/// Dropping the guard cancels the handler, so a Ctrl-C after the session
/// is safely `Active` (e.g. during the `--attach` hand-off) no longer
/// tears it down.
pub(crate) struct ActivationInterrupt {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ActivationInterrupt {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn arm_activation_interrupt(
    global: &GlobalArgs,
    session_id: sessions::SessionId,
) -> ActivationInterrupt {
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd());
    // Resolved here, not inside the task: the withdrawal's socket is the
    // same provider dir's, and the borrow must not cross the spawn. Keyed
    // on the provider kind — the rule the socket resolution itself and the
    // fabric display turn on — not on `use_minvmd()`, which is true only
    // under an explicit `--provider local-minvmd`: on macOS every invocation
    // is minvmd-backed with no flag at all, and a Ctrl-C that keyed on the
    // flag would leave exactly that host's box row published.
    let control_sock =
        vm_host_control_sock(daemon_provider_kind(global), global.minimal_dir.as_deref());
    let task = tokio::spawn(async move {
        // Only the first Ctrl-C is intercepted; a second falls through to
        // the default disposition so a wedged cleanup can still be killed.
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        eprintln!("\nAborting activation; cleaning up session {session_id}…");
        // Deliberately not version-gated: this is the cleanup half of an
        // activation the gate already cleared, and a cleanup that refuses to
        // run is the orphaned session #1251 is about.
        if let Ok(sock) = sock
            && let Ok(mut client) = client::Client::connect(&sock).await
        {
            use minimald_rpc::{AbortSession, AbortSessionRequest};
            // The record is fetched **before** the abort, which may take it
            // with the session: it carries the pair the box's registration
            // handed back (T66), whose row is withdrawn after the abort —
            // the creator's withdrawal, best-effort. A session that
            // registered no box (a task session, a native host) holds no
            // pair, and the withdrawal stays silent for it.
            let row = get_session_record(&mut client, &session_id.to_string())
                .await
                .ok()
                .and_then(|resp| resp.record);
            let _ = client
                .oneshot_rpc::<AbortSession>(AbortSessionRequest { id: session_id })
                .await;
            if let Some(record) = row {
                withdraw_box_row(control_sock, record.name.as_deref(), record.box_addresses).await;
            }
        }
        std::process::exit(130);
    });
    ActivationInterrupt { task }
}

/// The user-facing text for a session that could not be composed, by
/// either route: a refused `ConfigureLoadout` or failed gating of what it
/// sent back. The underlying error often names an internal step the caller
/// never asked for (a package server, a git lock), so the directory leads
/// and that text follows as the only diagnostic there is. The cause may or
/// may not implicate the project configuration, so the remedy is phrased
/// conditionally rather than assuming the config is at fault. Shared with
/// `min task run` (`crate::task`), which creates a session through the same
/// two steps.
pub(crate) fn composition_failure_message(project_dir: &camino::Utf8Path, error: &str) -> String {
    format!(
        "Cannot start a session for {project_dir}: composing a session environment from \
         that directory's project configuration failed, so no session was activated. If \
         the cause below names the project configuration, fix it there; otherwise re-run.\
         \n\ncause: {error}"
    )
}
