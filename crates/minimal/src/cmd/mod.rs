//! Command handlers for the `min` CLI, grouped by command family.

use anyhow::{Context as _, bail};
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

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
mod project;
mod session;

pub use admin::*;
pub use list::*;
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
        Some(Command::Auth(AuthArgs { command })) => {
            auth::cmd_auth(&cli.global_args, command).await
        }
        Some(Command::Box(BoxArgs { command })) => match command {
            BoxCommand::Spec(args) => box_cmd::cmd_box_spec(&cli.global_args, args),
            BoxCommand::Audit(args) => box_cmd::cmd_box_audit(&cli.global_args, args),
        },
        Some(Command::Net(NetArgs { command })) => match command {
            NetCommand::Forward(args) => net::cmd_net_forward(&cli.global_args, args).await,
            NetCommand::Setup(args) => net::cmd_net_setup(args),
            NetCommand::Expose(args) => net::cmd_net_expose(&cli.global_args, args).await,
        },
        Some(Command::Secret(SecretArgs { command })) => {
            secret::cmd_secret(&cli.global_args, command)
        }
        Some(Command::Task(TaskArgs { command })) => match command {
            TaskCommand::Run(args) => task::cmd_task_run(&cli.global_args, args).await,
        },
        Some(Command::Run(args)) => task::cmd_run(&args),
        Some(Command::Dirs) => dirs::cmd_dirs(&cli.global_args),
        Some(Command::Doctor) => doctor::cmd_doctor(&cli.global_args),
        Some(Command::Bug(args)) => diag::cmd_bug(&cli.global_args, args).await,
        #[cfg(feature = "remote-access")]
        Some(Command::Mesh(MeshArgs { command })) => match command {
            MeshCommand::Status => cmd_mesh_status(&cli.global_args).await,
            MeshCommand::Join(args) => cmd_mesh_join(&cli.global_args, args),
            MeshCommand::Leave => cmd_mesh_leave(&cli.global_args),
        },
        Some(Command::Proxy(args)) => cmd_proxy(&cli.global_args, args).await,
        Some(Command::Version) => cmd_version(&cli.global_args).await,
        Some(Command::Spin(args)) => cmd_spin(&cli.global_args, args).await,
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

/// Reduce a directory basename to the characters a session name should carry —
/// ASCII alphanumerics plus `-`, `_`, `.`, lowercased — dropping everything
/// else (spaces, unicode) so the minted handle is typable and clears
/// `validate_session_name`. Falls back to `session` when nothing survives.
pub(crate) fn sanitize_name_component(basename: &str) -> String {
    let filtered: String = basename
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() {
                Some(c.to_ascii_lowercase())
            } else if matches!(c, '-' | '_' | '.') {
                Some(c)
            } else {
                None
            }
        })
        .collect();
    let trimmed = filtered.trim_matches(|c| matches!(c, '-' | '_' | '.'));
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
/// Used to build the typed request enums both `GetSessionRecord` and
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

/// Resolve a session by UUID or name, returning its record.
///
/// Used by commands that need the full record before proceeding (destroy,
/// rename, attach). If the string parses as a UUID, the session is looked up
/// by ID; otherwise by name. Bails if no session matches.
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
pub(crate) async fn get_session_record(
    client: &mut client::Client,
    session: &str,
) -> Result<minimald_rpc::GetSessionRecordResponse, anyhow::Error> {
    use minimald_rpc::{GetSessionRecord, GetSessionRecordRequest};
    let lookup: GetSessionRecordRequest = SessionLookup::parse(session).into();
    client
        .oneshot_rpc::<GetSessionRecord>(lookup)
        .await
        .context("GetSessionRecord RPC failed")
}

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

/// Whether this invocation may put a question to the operator at all: a
/// terminal on both sides *and* no flag forbidding the prompt. A decision
/// taken before a prompt is reached — whether a `[secret-store-rules]` rule
/// with `action = "ask"` is admitted, say — reads this rather than the
/// terminal alone, so `--no-prompt` and `--no-input` cannot admit a question
/// that would then be asked anyway.
pub(crate) fn can_ask_operator(no_prompt: bool, no_input: bool, at_a_terminal: bool) -> bool {
    !no_prompt && !no_input && at_a_terminal
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
            let _ = client
                .oneshot_rpc::<AbortSession>(AbortSessionRequest { id: session_id })
                .await;
        }
        std::process::exit(130);
    });
    ActivationInterrupt { task }
}

/// The user-facing text for a session that could not be composed, by
/// either route: a refused `ConfigureLoadout` or failed gating of what it
/// sent back. The underlying error names an internal step the caller never
/// asked for, so the directory leads and that text follows as the only
/// diagnostic there is. Shared with `min task run` (`crate::task`), which
/// creates a session through the same two steps.
pub(crate) fn composition_failure_message(project_dir: &camino::Utf8Path, error: &str) -> String {
    format!(
        "Cannot start a session for {project_dir}: composing a session environment from \
         that directory's project configuration failed, so no session was activated. Fix \
         the configuration there, then re-run.\n\ncause: {error}"
    )
}

// ---------------------------------------------------------------------------
// Store references: the handle a box receives for a value it never holds, and
// the client key the proxy verifies handles under (BEP-063).
// ---------------------------------------------------------------------------

/// The injection form a handle carries for a rule: the rule's own form, in the
/// wire shape the proxy compares against the rule it holds (BEP-064).
///
/// # Errors
///
/// When the rule declares a form this client cannot mint a handle for, rather
/// than minting one that claims a form the proxy would not honour.
fn handle_injection(injection: &sessions::Injection) -> Result<bep::mint::Inject, anyhow::Error> {
    match injection {
        sessions::Injection::Header { name, prefix } => {
            Ok(bep::mint::Inject::header(name.clone(), prefix))
        }
        sessions::Injection::BasicAuth { field } => {
            Ok(bep::mint::Inject::basic_auth(field.to_string()))
        }
        other => bail!(
            "a `[secret-store-rules]` rule registers the injection form {other}, which this \
             client cannot mint a store handle for"
        ),
    }
}

/// Mints one short-lived handle per admitted store reference, sealed to this
/// host's keys and bound to `box_name`, and registers the client's own
/// handle-signing key with the proxy first (BEP-063).
///
/// The registration goes over the proxy's control socket before any handle is
/// minted: a handle the proxy cannot verify is no use to the box, so a proxy
/// that will not hold the key fails the mint rather than letting a box receive
/// handles that are refused on first use. It is idempotent, so the next run
/// registers the same key and the proxy still holds the one.
///
/// What comes back is the value per reference, for the variable the reference
/// names: the envelope carrying the handle, never the stored value, which
/// stays in the host store and reaches the upstream from the proxy alone.
///
/// # Errors
///
/// When the client's handle-signing key cannot be opened or described, the
/// proxy does not register it, a rule registers a form no handle can carry, or
/// a handle cannot be minted or sealed.
pub async fn mint_store_handles<S: bep::KeyStore>(
    key_store: &S,
    identity: &bep::PublicIdentity,
    control: &std::path::Path,
    box_name: &str,
    host: &str,
    admitted: &[sessions::AdmittedReference<'_>],
    now: u64,
) -> Result<Vec<(sessions::core::primitives::StrictVarName, bep::SealedValue)>, anyhow::Error> {
    if admitted.is_empty() {
        return Ok(Vec::new());
    }
    let client = bep::mint::client_key(key_store)
        .context("opening the client's handle-signing key in the host store")?;
    let public = bep::keychain::PrivateKey::public_key(&client)
        .context("reading the client's handle-signing key")?;
    register_client_key(control, &bep::control::ClientKey::of(&public))
        .await
        .context("registering the client's handle-signing key with the proxy")?;

    let mut minted = Vec::with_capacity(admitted.len());
    for candidate in admitted {
        let reference = &candidate.reference;
        let inject = handle_injection(&candidate.rule.inject)?;
        let store = reference.store.to_string();
        let handle = bep::mint::mint_store_handle(
            identity,
            &client,
            &bep::mint::StoreMintRequest {
                box_id: box_name,
                host,
                store: &store,
                id: &reference.id,
                upstream: &candidate.rule.upstream,
                inject: &inject,
                now,
            },
        )
        .with_context(|| format!("minting a handle for the {reference}"))?;
        minted.push((reference.env.clone(), handle.value));
    }
    Ok(minted)
}

/// Registers the client's handle-signing key with the proxy over its control
/// socket: one JSON line out, the proxy's acknowledgement back (BEP-063).
///
/// # Errors
///
/// When the socket cannot be reached, the exchange fails, or the proxy answers
/// anything but an acknowledgement.
async fn register_client_key(
    control: &std::path::Path,
    key: &bep::control::ClientKey,
) -> Result<bep::control::Registered, anyhow::Error> {
    let stream = tokio::net::UnixStream::connect(control)
        .await
        .with_context(|| {
            format!(
                "connecting to the proxy's control socket {}",
                control.display()
            )
        })?;
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json_lenient::to_string(&bep::Submission::RegisterKey(key.clone()))?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    let mut reply = String::new();
    tokio::io::BufReader::new(reader)
        .read_line(&mut reply)
        .await?;
    let registered: bep::control::Registered = serde_json_lenient::from_str(reply.trim())
        .with_context(|| format!("the proxy refused the registration: {}", reply.trim()))?;
    tracing::info!(
        key = %registered.key,
        keys = registered.keys,
        "the proxy registered the client's handle-signing key"
    );
    Ok(registered)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bep::keychain::PrivateKey as _;
    use sessions::core::primitives::StrictVarName;
    use sessions::{
        AdmittedReference, BasicAuthField, Injection, ReferenceSource, RuleAction, SecretStore,
        StoreReference, StoreRule,
    };
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const HOST: &str = "mac-1";
    const BOX: &str = "box-a1";

    fn reference(id: &str, env: &str) -> StoreReference {
        StoreReference {
            store: SecretStore::Keychain,
            id: id.to_owned(),
            env: StrictVarName::try_new(env).unwrap(),
            source: ReferenceSource::Store,
        }
    }

    fn rule(id: &str, upstream: &[&str], inject: Injection) -> StoreRule {
        StoreRule {
            store: SecretStore::Keychain,
            id: id.to_owned(),
            upstream: upstream.iter().map(|host| (*host).to_owned()).collect(),
            inject,
            action: RuleAction::Allow,
        }
    }

    /// A proxy's control socket, for the client to register a key over: it
    /// records every submission it is sent and answers a registration the way
    /// the proxy does, refusing anything else.
    fn control_socket(path: &std::path::Path) -> Arc<Mutex<Vec<bep::Submission>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            let keys = Arc::new(Mutex::new(bep::control::ClientKeys::new()));
            while let Ok((stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                let keys = Arc::clone(&keys);
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut line = String::new();
                    tokio::io::BufReader::new(reader)
                        .read_line(&mut line)
                        .await
                        .unwrap();
                    let submission: bep::Submission = serde_json_lenient::from_str(&line).unwrap();
                    recorded.lock().unwrap().push(submission.clone());
                    let reply = match &submission {
                        bep::Submission::RegisterKey(key) => keys
                            .lock()
                            .unwrap()
                            .register(key)
                            .map(|registered| serde_json_lenient::to_string(&registered).unwrap())
                            .unwrap_or_else(|error| format!(r#"{{"error":"{error}"}}"#)),
                        _ => r#"{"error":"the control socket took no such submission"}"#.to_owned(),
                    };
                    writer
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                });
            }
        });
        seen
    }

    /// A question is admitted only where it could be put: a terminal on both
    /// sides is not enough on its own, because `--no-prompt` and `--no-input`
    /// say the operator is not there to answer one. A rule with
    /// `action = "ask"` is admitted on this answer before the box exists, so a
    /// flag that forbids the prompt has to deny the rule rather than let the
    /// activation reach a question nobody can answer.
    #[test]
    fn a_flag_that_forbids_a_prompt_leaves_nothing_to_ask() {
        assert!(can_ask_operator(false, false, true));
        assert!(!can_ask_operator(true, false, true), "--no-prompt");
        assert!(!can_ask_operator(false, true, true), "--no-input");
        assert!(!can_ask_operator(false, false, false), "no terminal");
    }

    /// BEP-063: each store reference of a box yields one handle signed under
    /// the client's own key, carrying the store, the identifier, the rule's
    /// registered upstream authorities and injection form, and an expiry five
    /// minutes on; the box receives it sealed to this host and bound to the
    /// box, and the client registers the key the proxy verifies it under
    /// exactly once, over the control socket, before any handle is minted.
    #[tokio::test]
    async fn store_handle_signed_and_key_registered() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let seen = control_socket(&socket);
        let store = bep::MemoryStore::new();
        let keys = bep::Keys::open(store.clone()).unwrap();

        let rules = [
            rule(
                "anthropic-api-key",
                &["api.anthropic.com:443"],
                Injection::Header {
                    name: "x-api-key".to_owned(),
                    prefix: String::new(),
                },
            ),
            rule(
                "registry-password",
                &["registry.example.com:443", "cdn.example.com:443"],
                Injection::BasicAuth {
                    field: BasicAuthField::Password,
                },
            ),
        ];
        let references = [
            reference("anthropic-api-key", "ANTHROPIC_API_KEY"),
            reference("registry-password", "REGISTRY_PASSWORD"),
        ];
        let admitted: Vec<AdmittedReference<'_>> = references
            .iter()
            .zip(&rules)
            .map(|(reference, rule)| AdmittedReference {
                reference: reference.clone(),
                rule,
                prompt: false,
            })
            .collect();

        let minted = mint_store_handles(
            &store,
            &keys.public_identity(),
            &socket,
            BOX,
            HOST,
            &admitted,
            NOW,
        )
        .await
        .unwrap();

        // The key the proxy verifies handles under reached it over the control
        // socket, once, and it is the client's own key — nothing else was
        // submitted, and no value of any kind was.
        let client = bep::mint::client_key(&store).unwrap();
        let public = client.public_key().unwrap();
        let submissions = seen.lock().unwrap().clone();
        assert_eq!(submissions.len(), 1, "{submissions:?}");
        match &submissions[0] {
            bep::Submission::RegisterKey(key) => {
                assert_eq!(key, &bep::control::ClientKey::of(&public));
                assert_eq!(
                    bep::Fingerprint::of(&key.public_key().unwrap()),
                    bep::Fingerprint::of(&public)
                );
            }
            other => panic!("expected a key registration, got {other:?}"),
        }

        // One handle per reference, in the variable the reference names.
        assert_eq!(minted.len(), 2);
        let other = bep::KeyStore::generate(&store, "someone-else")
            .unwrap()
            .public_key()
            .unwrap();
        let mut handles = Vec::new();
        for ((env, value), (reference, rule)) in minted.iter().zip(references.iter().zip(&rules)) {
            assert_eq!(env, &reference.env);
            // What the box carries is the envelope, not the handle in the
            // clear: the handle is the member inside it, bound to this box.
            assert!(value.as_str().starts_with(bep::seal::PREFIX), "{value}");
            let unsealed = bep::unseal(&keys, value.as_str()).unwrap();
            assert_eq!(unsealed.context.box_id, BOX);
            assert_eq!(unsealed.context.host, HOST);
            assert_eq!(unsealed.context.module, "keychain");
            assert_eq!(unsealed.context.mode, bep::mint::STORE_MODE);
            assert_eq!(unsealed.context.breadth, bep::mint::STORE_BREADTH);
            assert_eq!(
                unsealed.context.expires_at,
                NOW + bep::mint::HANDLE_LIFETIME_SECS
            );

            let handle = unsealed.member.expose().to_owned();
            assert!(handle.starts_with(bep::mint::HANDLE_PREFIX), "{handle}");
            assert!(!value.as_str().contains(&handle), "{value}");
            let parsed = bep::mint::parse_store_handle(&handle).unwrap();
            assert_eq!(parsed.claims.store, "keychain");
            assert_eq!(parsed.claims.id, reference.id);
            assert_eq!(parsed.claims.upstream, rule.upstream);
            assert_eq!(
                parsed.claims.inject,
                handle_injection(&rule.inject).unwrap()
            );
            assert_eq!(parsed.claims.exp, NOW + bep::mint::HANDLE_LIFETIME_SECS);
            assert_eq!(parsed.claims.key, bep::Fingerprint::of(&public).to_string());
            // Signed under the client's key, and under no other.
            assert!(parsed.verifies_under(&public));
            assert!(!parsed.verifies_under(&other));
            handles.push(handle);
        }

        // The signature covers the claims it was minted with: one handle's
        // claims under the other's signature verify under neither key.
        let crossed = format!(
            "{}.{}",
            handles[0].rsplit_once('.').unwrap().0,
            handles[1].rsplit_once('.').unwrap().1
        );
        assert!(
            !bep::mint::parse_store_handle(&crossed)
                .unwrap()
                .verifies_under(&public)
        );

        // The next run signs under the same key the proxy already holds: the
        // key is found in the store, not generated again, and the proxy still
        // holds one.
        let again = mint_store_handles(
            &store,
            &keys.public_identity(),
            &socket,
            BOX,
            HOST,
            &admitted[..1],
            NOW + 60,
        )
        .await
        .unwrap();
        let unsealed = bep::unseal(&keys, again[0].1.as_str()).unwrap();
        let handle = bep::mint::parse_store_handle(unsealed.member.expose()).unwrap();
        assert_eq!(handle.claims.key, bep::Fingerprint::of(&public).to_string());
        assert_eq!(
            handle.claims.exp,
            NOW + 60 + bep::mint::HANDLE_LIFETIME_SECS
        );
        assert!(handle.verifies_under(&public));
        let submissions = seen.lock().unwrap().clone();
        assert_eq!(submissions.len(), 2, "{submissions:?}");
        assert_eq!(submissions[0], submissions[1]);

        // A box that refers to nothing registers nothing and mints nothing.
        assert!(
            mint_store_handles(
                &store,
                &keys.public_identity(),
                &socket,
                BOX,
                HOST,
                &[],
                NOW
            )
            .await
            .unwrap()
            .is_empty()
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
    }
}
