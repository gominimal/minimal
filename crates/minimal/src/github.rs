//! `min github login|status|logout` — the CLI surface for the daemon-held
//! GitHub App device-flow auth (spec 10, R1.4/R7.2).
//!
//! All three commands are thin RPC callers: `minimald` owns the device flow,
//! the token store, and the App-installation/scope bookkeeping (see
//! `crates/github` and `crates/minimald/src/github/`). This module never
//! sees a token — the wire types it talks to (`GithubBeginLogin`,
//! `GithubPollLogin`, `GithubStatus`, `GithubListAuths`, `GithubLogout`) carry
//! login/grant-id metadata only.

use std::io::IsTerminal as _;
use std::time::Duration;

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand};

use crate::{GlobalArgs, client, confirm, connect_daemon, ensure_daemon, resolve_session};

/// `min github` — sign in and inspect GitHub auth/session status.
#[derive(Debug, Args)]
pub struct GithubArgs {
    #[command(subcommand)]
    pub command: GithubCommand,
}

#[derive(Debug, Subcommand)]
pub enum GithubCommand {
    /// Sign in to GitHub via the device flow (R1.1)
    Login(LoginArgs),
    /// Show GitHub identity, token validity, App installation, and session
    /// repo status (R1.4/R8.2)
    Status(StatusArgs),
    /// Forget a stored GitHub authentication grant
    Logout(LogoutArgs),
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Request an explicit permission scope (`scope:permission`, e.g.
    /// `contents:rw`). Repeatable. When omitted, the daemon applies its
    /// least-privilege defaults (R5.1); `workflows` is never requested
    /// (NG6) and is rejected by the daemon if named here.
    #[arg(long = "scope", value_name = "SCOPE:PERMISSION")]
    pub scope: Vec<String>,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Also report the repo/branch/scope table for this session (UUID or name)
    #[arg(long)]
    pub session: Option<String>,
    /// Additional `owner/repo` to report GitHub App installation state for,
    /// beyond any the session declares. Repeatable.
    #[arg(long = "repo", value_name = "OWNER/REPO")]
    pub repo: Vec<String>,
}

#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// The grant to forget (see `min github status`). May be omitted when
    /// exactly one GitHub authentication grant is stored.
    pub grant_id: Option<String>,
    /// Skip the confirmation prompt
    #[arg(long, short)]
    pub force: bool,
}

/// Dispatch a `min github <subcommand>` invocation.
pub async fn cmd_github(global: &GlobalArgs, args: GithubArgs) -> Result<(), anyhow::Error> {
    match args.command {
        GithubCommand::Login(args) => cmd_github_login(global, args).await,
        GithubCommand::Status(args) => cmd_github_status(global, args).await,
        GithubCommand::Logout(args) => cmd_github_logout(global, args).await,
    }
}

/// `min github login`: start the device flow, show the verification URL and
/// code, then poll until the user approves (or the code expires) (R1.1).
pub async fn cmd_github_login(global: &GlobalArgs, args: LoginArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let mut client = connect_daemon(global).await?;

    let begin_resp = client
        .oneshot_rpc::<minimald_rpc::GithubBeginLogin>(minimald_rpc::GithubBeginLoginRequest::new(
            args.scope,
        ))
        .await
        .context("GithubBeginLogin RPC failed")?;

    let begin = match begin_resp {
        minimald_rpc::Errorable::Ok(begin) => begin,
        minimald_rpc::Errorable::Err { error } => bail!("{error}"),
    };

    println!(
        "Open {} and enter code {}",
        begin.verification_uri, begin.user_code
    );

    let outcome = poll_login_until_done(
        &mut client,
        &begin.login_id,
        Duration::from_secs(begin.poll_interval_secs.max(1)),
        Duration::from_secs(begin.expires_in_secs.max(1)),
    )
    .await?;

    match outcome {
        minimald_rpc::GithubPollLoginResponse::Complete { login, grant_id } => {
            println!("Logged in to GitHub as {login} (grant {grant_id}).");
            Ok(())
        }
        minimald_rpc::GithubPollLoginResponse::Failed { message } => {
            bail!("GitHub login failed: {message}")
        }
        minimald_rpc::GithubPollLoginResponse::Expired => {
            bail!("GitHub login code expired; run `min github login` again")
        }
        minimald_rpc::GithubPollLoginResponse::Pending => {
            // poll_login_until_done never returns Pending; kept exhaustive
            // against the wire enum's #[non_exhaustive] growth.
            bail!("unexpected pending state from the daemon")
        }
        _ => bail!("unrecognized login state from the daemon"),
    }
}

/// Poll `GithubPollLogin` at `interval` until a terminal state, the code
/// expires, or the user hits Ctrl-C. Drives a stderr spinner while waiting
/// when stderr is a terminal.
async fn poll_login_until_done(
    client: &mut client::Client,
    login_id: &str,
    interval: Duration,
    expires_in: Duration,
) -> Result<minimald_rpc::GithubPollLoginResponse, anyhow::Error> {
    let spinner = std::io::stderr().is_terminal().then(|| {
        let bar = indicatif::ProgressBar::new_spinner();
        bar.enable_steady_tick(Duration::from_millis(120));
        bar.set_message("waiting for approval in the browser (Ctrl-C to cancel)...");
        bar
    });

    let deadline = tokio::time::Instant::now() + expires_in;

    let result = loop {
        if tokio::time::Instant::now() >= deadline {
            break Ok(minimald_rpc::GithubPollLoginResponse::Expired);
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break Err(anyhow::anyhow!("login cancelled"));
            }
            () = tokio::time::sleep(interval) => {}
        }

        let poll_resp = client
            .oneshot_rpc::<minimald_rpc::GithubPollLogin>(
                minimald_rpc::GithubPollLoginRequest::new(login_id.to_string()),
            )
            .await
            .context("GithubPollLogin RPC failed");

        match poll_resp {
            Err(e) => break Err(e),
            Ok(minimald_rpc::Errorable::Err { error }) => break Err(anyhow::anyhow!("{error}")),
            Ok(minimald_rpc::Errorable::Ok(minimald_rpc::GithubPollLoginResponse::Pending)) => {
                continue;
            }
            Ok(minimald_rpc::Errorable::Ok(state)) => break Ok(state),
        }
    };

    if let Some(spinner) = spinner {
        spinner.finish_and_clear();
    }

    result
}

/// `min github status`: identity, token validity/expiry, per-repo App
/// installation + guidance URL, and (when `--session` is given) the
/// session's repo/branch/scope table (R1.4/R1.5/R8.2).
pub async fn cmd_github_status(global: &GlobalArgs, args: StatusArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let mut client = connect_daemon(global).await?;

    let repos = args
        .repo
        .iter()
        .map(|raw| {
            raw.parse::<github::RepoSpec>()
                .map(|spec| format!("{}/{}", spec.owner(), spec.repo()))
                .map_err(|e| anyhow::anyhow!("invalid --repo '{raw}': {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let session_id = match &args.session {
        Some(s) => Some(resolve_session(&mut client, s).await?.id),
        None => None,
    };

    let resp = client
        .oneshot_rpc::<minimald_rpc::GithubStatus>(minimald_rpc::GithubStatusRequest::new(
            session_id, repos,
        ))
        .await
        .context("GithubStatus RPC failed")?;

    let status = match resp {
        minimald_rpc::Errorable::Ok(status) => status,
        minimald_rpc::Errorable::Err { error } => bail!("{error}"),
    };

    print!("{}", render_status(&status));
    Ok(())
}

/// Render a [`minimald_rpc::GithubStatusResponse`] as the `min github status`
/// human-readable report. Split out from [`cmd_github_status`] so canned
/// responses can be rendered in tests without an RPC round-trip.
///
/// Every `writeln!` below targets a plain `String`, whose `Write` impl never
/// returns `Err`; `.expect(...)` documents that invariant instead of silently
/// discarding a `Result` (never a `let _ = ...` swallow).
fn render_status(status: &minimald_rpc::GithubStatusResponse) -> String {
    use std::fmt::Write as _;

    const INFALLIBLE: &str = "writing to a String cannot fail";

    let mut out = String::new();

    match &status.identity {
        Some(identity) => {
            writeln!(
                out,
                "Logged in as {} (grant {})",
                identity.login, identity.grant_id
            )
            .expect(INFALLIBLE);
        }
        None => {
            writeln!(out, "Not logged in. Run `min github login`.").expect(INFALLIBLE);
        }
    }

    match (status.token_valid, &status.token_expires_at) {
        (true, Some(expires_at)) => {
            writeln!(out, "Token valid until {expires_at}").expect(INFALLIBLE);
        }
        (true, None) => {
            writeln!(out, "Token valid").expect(INFALLIBLE);
        }
        (false, _) => {
            writeln!(out, "Token invalid or expired; run `min github login`.").expect(INFALLIBLE);
        }
    }

    if !status.installations.is_empty() {
        writeln!(out, "\nRepository App installation:").expect(INFALLIBLE);
        for install in &status.installations {
            if install.installed {
                writeln!(out, "  {} - installed", install.repo).expect(INFALLIBLE);
            } else {
                match &install.install_url {
                    Some(url) => {
                        writeln!(out, "  {} - NOT installed; install at {url}", install.repo)
                            .expect(INFALLIBLE);
                    }
                    None => {
                        writeln!(out, "  {} - NOT installed", install.repo).expect(INFALLIBLE);
                    }
                }
            }
        }
    }

    if !status.session_repos.is_empty() {
        writeln!(out, "\nSession repos:").expect(INFALLIBLE);
        for row in &status.session_repos {
            let base = row.base.as_deref().unwrap_or("-");
            writeln!(
                out,
                "  {} @ {} (base {base}) - scopes: {}",
                row.repo,
                row.branch,
                render_scopes(&row.scopes)
            )
            .expect(INFALLIBLE);
        }
    }

    out
}

/// Render a row's plain-label scopes (e.g. `["contents:rw", "metadata:read"]`)
/// in the canonical consent order via [`github::ScopeSet`]. Falls back to a
/// raw join when the labels don't parse (defensive: never fail a status
/// render over an unexpected daemon-side value).
fn render_scopes(scopes: &[String]) -> String {
    if scopes.is_empty() {
        return "-".to_string();
    }
    match github::ScopeSet::from_attr_value(&scopes.join(",")) {
        Ok(set) if !set.is_empty() => set.render_for_consent(),
        _ => scopes.join(", "),
    }
}

/// `min github logout`: forget a stored auth grant, after confirmation
/// (R6.4's reuse-or-mint substrate; this is the "forget" side of it).
pub async fn cmd_github_logout(global: &GlobalArgs, args: LogoutArgs) -> Result<(), anyhow::Error> {
    ensure_daemon(global)?;
    let mut client = connect_daemon(global).await?;

    let grant_id = match args.grant_id {
        Some(id) => id,
        None => resolve_sole_grant(&mut client).await?,
    };

    if !args.force {
        if !std::io::stdin().is_terminal() {
            bail!("refusing to log out without confirmation; pass --force");
        }
        if !confirm(
            &format!("Forget GitHub authentication grant {grant_id}?"),
            false,
        )? {
            println!("Aborted.");
            return Ok(());
        }
    }

    let resp = client
        .oneshot_rpc::<minimald_rpc::GithubLogout>(minimald_rpc::GithubLogoutRequest::new(
            grant_id.clone(),
        ))
        .await
        .context("GithubLogout RPC failed")?;

    match resp {
        minimald_rpc::Errorable::Ok(r) if r.removed => {
            println!("Removed GitHub authentication grant {grant_id}.");
            Ok(())
        }
        minimald_rpc::Errorable::Ok(_) => {
            bail!("no GitHub authentication grant matched {grant_id}")
        }
        minimald_rpc::Errorable::Err { error } => bail!("{error}"),
    }
}

/// Resolve the sole stored grant when `min github logout` is called without a
/// `grant_id`. Fails closed (asks the user to disambiguate) when zero or more
/// than one grant is stored, rather than guessing.
async fn resolve_sole_grant(client: &mut client::Client) -> Result<String, anyhow::Error> {
    let resp = client
        .oneshot_rpc::<minimald_rpc::GithubListAuths>(minimald_rpc::GithubListAuthsRequest::new())
        .await
        .context("GithubListAuths RPC failed")?;

    let grants = match resp {
        minimald_rpc::Errorable::Ok(r) => r.grants,
        minimald_rpc::Errorable::Err { error } => bail!("{error}"),
    };

    match grants.as_slice() {
        [] => bail!("no GitHub authentication grants are stored"),
        [grant] => Ok(grant.grant_id.clone()),
        many => {
            let ids: Vec<_> = many
                .iter()
                .map(|g| format!("{} ({})", g.grant_id, g.login))
                .collect();
            bail!(
                "multiple GitHub authentication grants are stored; specify one: {}",
                ids.join(", ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser as _;

    fn parse(args: &[&str]) -> Cli {
        let mut full = vec!["min"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).expect("clap parse")
    }

    #[test]
    fn login_parses_with_no_flags() {
        let cli = parse(&["github", "login"]);
        let Some(Command::Github(GithubArgs {
            command: GithubCommand::Login(args),
        })) = cli.command
        else {
            panic!("expected Command::Github(Login)");
        };
        assert!(args.scope.is_empty());
    }

    #[test]
    fn login_collects_repeated_scope_flags() {
        let cli = parse(&[
            "github",
            "login",
            "--scope",
            "contents:rw",
            "--scope",
            "issues:rw",
        ]);
        let Some(Command::Github(GithubArgs {
            command: GithubCommand::Login(args),
        })) = cli.command
        else {
            panic!("expected Command::Github(Login)");
        };
        assert_eq!(args.scope, vec!["contents:rw", "issues:rw"]);
    }

    #[test]
    fn status_parses_session_and_repeated_repo_flags() {
        let cli = parse(&[
            "github",
            "status",
            "--session",
            "my-session",
            "--repo",
            "octocat/hello",
            "--repo",
            "octocat/world",
        ]);
        let Some(Command::Github(GithubArgs {
            command: GithubCommand::Status(args),
        })) = cli.command
        else {
            panic!("expected Command::Github(Status)");
        };
        assert_eq!(args.session.as_deref(), Some("my-session"));
        assert_eq!(args.repo, vec!["octocat/hello", "octocat/world"]);
    }

    #[test]
    fn status_parses_with_no_flags() {
        let cli = parse(&["github", "status"]);
        let Some(Command::Github(GithubArgs {
            command: GithubCommand::Status(args),
        })) = cli.command
        else {
            panic!("expected Command::Github(Status)");
        };
        assert!(args.session.is_none());
        assert!(args.repo.is_empty());
    }

    #[test]
    fn logout_parses_grant_id_and_force() {
        let cli = parse(&["github", "logout", "grant-123", "--force"]);
        let Some(Command::Github(GithubArgs {
            command: GithubCommand::Logout(args),
        })) = cli.command
        else {
            panic!("expected Command::Github(Logout)");
        };
        assert_eq!(args.grant_id.as_deref(), Some("grant-123"));
        assert!(args.force);
    }

    #[test]
    fn logout_parses_without_grant_id() {
        let cli = parse(&["github", "logout"]);
        let Some(Command::Github(GithubArgs {
            command: GithubCommand::Logout(args),
        })) = cli.command
        else {
            panic!("expected Command::Github(Logout)");
        };
        assert!(args.grant_id.is_none());
        assert!(!args.force);
    }

    fn sample_identity() -> minimald_rpc::GithubIdentity {
        minimald_rpc::GithubIdentity::new("octocat".to_string(), "grant-1".to_string())
    }

    #[test]
    fn render_status_reports_identity_and_token_validity() {
        let status = minimald_rpc::GithubStatusResponse::new(
            Some(sample_identity()),
            true,
            None,
            vec![],
            vec![],
        );
        let rendered = render_status(&status);
        assert!(rendered.contains("Logged in as octocat (grant grant-1)"));
        assert!(rendered.contains("Token valid"));
    }

    #[test]
    fn render_status_reports_no_identity() {
        let status = minimald_rpc::GithubStatusResponse::new(None, false, None, vec![], vec![]);
        let rendered = render_status(&status);
        assert!(rendered.contains("Not logged in"));
        assert!(rendered.contains("Token invalid or expired"));
    }

    #[test]
    fn render_status_reports_missing_app_installation_with_guidance_url() {
        let status = minimald_rpc::GithubStatusResponse::new(
            Some(sample_identity()),
            true,
            None,
            vec![minimald_rpc::RepoInstallationStatus::new(
                "octocat/hello".to_string(),
                false,
                Some("https://github.com/apps/minimal/installations/new".to_string()),
            )],
            vec![],
        );
        let rendered = render_status(&status);
        assert!(rendered.contains("octocat/hello - NOT installed"));
        assert!(rendered.contains("install at https://github.com/apps/minimal/installations/new"));
    }

    #[test]
    fn render_status_reports_installed_repo() {
        let status = minimald_rpc::GithubStatusResponse::new(
            Some(sample_identity()),
            true,
            None,
            vec![minimald_rpc::RepoInstallationStatus::new(
                "octocat/hello".to_string(),
                true,
                None,
            )],
            vec![],
        );
        let rendered = render_status(&status);
        assert!(rendered.contains("octocat/hello - installed"));
    }

    #[test]
    fn render_status_reports_session_repo_rows_with_ordered_scopes() {
        let status = minimald_rpc::GithubStatusResponse::new(
            Some(sample_identity()),
            true,
            None,
            vec![],
            vec![minimald_rpc::SessionRepoStatus::new(
                "octocat/hello".to_string(),
                "feat/x".to_string(),
                Some("main".to_string()),
                vec!["metadata:read".to_string(), "contents:rw".to_string()],
            )],
        );
        let rendered = render_status(&status);
        assert!(rendered.contains("octocat/hello @ feat/x (base main)"));
        // ScopeSet renders in canonical consent order regardless of input order.
        assert!(rendered.contains("scopes: contents:rw, metadata:read"));
    }

    #[test]
    fn render_scopes_falls_back_to_raw_join_on_unparsable_labels() {
        let rendered = render_scopes(&["not-a-scope".to_string()]);
        assert_eq!(rendered, "not-a-scope");
    }

    #[test]
    fn render_scopes_reports_dash_when_empty() {
        assert_eq!(render_scopes(&[]), "-");
    }
}
