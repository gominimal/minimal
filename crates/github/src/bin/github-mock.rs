//! Out-of-process mock GitHub for `scripts/session-e2e.sh`.
//!
//! This wraps the in-process [`github::testing::MockGithub`] as a standalone
//! process so an e2e script can point a real `minimald` (and a real `git`) at
//! the same OAuth/REST + auth-enforcing git smart-HTTP surface the unit tests
//! use. It binds a loopback port, optionally pre-creates bare fixture repos,
//! advertises its base URL, and runs until it receives SIGINT/SIGTERM.
//!
//! The base URL it prints is meant to be fed straight into the daemon's
//! `MINIMALD_GITHUB_*_BASE_URL` overrides.
//!
//! ```text
//! github-mock [--addr HOST:PORT] [--git-root DIR] [--repo OWNER/REPO[@BRANCH]]...
//!             [--exact-auth USER:PASS] [--ready-file PATH]
//! ```
//!
//! On startup it writes `GITHUB_MOCK_BASE_URL=<url>` to stdout (and to
//! `--ready-file`, if given, atomically) so a script can wait for readiness and
//! capture the URL.

use std::error::Error;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;

use github::testing::{GitAuth, MockGithub};

type BoxError = Box<dyn Error + Send + Sync>;

/// Parsed command-line configuration.
struct Config {
    addr: SocketAddr,
    git_root: Option<PathBuf>,
    repos: Vec<RepoSpec>,
    exact_auth: Option<(String, String)>,
    ready_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            git_root: None,
            repos: Vec::new(),
            exact_auth: None,
            ready_file: None,
        }
    }
}

/// A repo fixture to pre-create: `owner/repo` on `branch`.
struct RepoSpec {
    owner: String,
    repo: String,
    branch: String,
}

const USAGE: &str = "\
Usage: github-mock [OPTIONS]

A mock GitHub (OAuth device flow + REST + auth-enforcing git smart-HTTP) for
end-to-end tests. Runs until SIGINT/SIGTERM.

Options:
  --addr HOST:PORT          Listen address (default 127.0.0.1:0 — OS-chosen port)
  --git-root DIR            Directory for bare fixture repos (default: a temp dir)
  --repo OWNER/REPO[@BRANCH] Pre-create a bare fixture repo (repeatable; branch=main)
  --exact-auth USER:PASS    Require these exact git Basic credentials (default: any)
  --ready-file PATH         Write GITHUB_MOCK_BASE_URL=<url> here once listening
  -h, --help                Show this help
";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("github-mock: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), BoxError> {
    let config = match parse_args(std::env::args().skip(1))? {
        ParseOutcome::Run(config) => config,
        ParseOutcome::Help => {
            print!("{USAGE}");
            return Ok(());
        }
    };

    // Own the temp dir (when we created one) so it lives for the process and is
    // cleaned up on exit; when a git root is supplied we leave it in place.
    let (git_root, _temp_guard) = match &config.git_root {
        Some(path) => (path.clone(), None),
        None => {
            let dir = tempfile::tempdir()?;
            (dir.path().to_path_buf(), Some(dir))
        }
    };

    let mock = MockGithub::start_with_git_root_at(&git_root, config.addr).await?;

    if let Some((username, password)) = config.exact_auth {
        mock.set_git_auth(GitAuth::Exact { username, password });
    }

    for spec in &config.repos {
        mock.create_bare_repo(&spec.owner, &spec.repo, &spec.branch)
            .map_err(|e| -> BoxError {
                format!(
                    "failed to create fixture repo {}/{}@{}: {e}",
                    spec.owner, spec.repo, spec.branch
                )
                .into()
            })?;
    }

    let base_url = mock.base_url().to_string();
    announce(
        &base_url,
        &git_root,
        &config.repos,
        config.ready_file.as_deref(),
    )?;

    wait_for_shutdown().await;
    eprintln!("github-mock: shutting down");
    Ok(())
}

/// Reports readiness: a machine-readable line on stdout, a human summary on
/// stderr, and (optionally) an atomically-written ready file.
fn announce(
    base_url: &str,
    git_root: &std::path::Path,
    repos: &[RepoSpec],
    ready_file: Option<&std::path::Path>,
) -> Result<(), BoxError> {
    let line = format!("GITHUB_MOCK_BASE_URL={base_url}");

    // stdout: the one line a caller can capture/grep; flush so a reader blocked
    // on the pipe unblocks immediately.
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{line}")?;
    stdout.flush()?;

    eprintln!("github-mock: listening at {base_url}");
    eprintln!("github-mock: git root {}", git_root.display());
    for spec in repos {
        eprintln!(
            "github-mock: fixture {}/{} on {}",
            spec.owner, spec.repo, spec.branch
        );
    }

    if let Some(path) = ready_file {
        write_atomically(path, line.as_bytes())?;
    }
    Ok(())
}

/// Writes `contents` to `path` via a sibling temp file + rename, so a reader
/// polling the path never observes a partial write.
fn write_atomically(path: &std::path::Path, contents: &[u8]) -> Result<(), BoxError> {
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(contents)?;
    tmp.flush()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

enum ParseOutcome {
    Run(Config),
    Help,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<ParseOutcome, BoxError> {
    let mut config = Config::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "--addr" => config.addr = parse_value(&mut args, "--addr")?.parse()?,
            "--git-root" => config.git_root = Some(parse_value(&mut args, "--git-root")?.into()),
            "--repo" => config
                .repos
                .push(parse_repo(&parse_value(&mut args, "--repo")?)?),
            "--exact-auth" => {
                config.exact_auth = Some(parse_userpass(&parse_value(&mut args, "--exact-auth")?)?);
            }
            "--ready-file" => {
                config.ready_file = Some(parse_value(&mut args, "--ready-file")?.into());
            }
            other => return Err(format!("unexpected argument {other:?}; try --help").into()),
        }
    }
    Ok(ParseOutcome::Run(config))
}

fn parse_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, BoxError> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

/// Parses `owner/repo` or `owner/repo@branch` (branch defaults to `main`).
fn parse_repo(spec: &str) -> Result<RepoSpec, BoxError> {
    let (path, branch) = match spec.split_once('@') {
        Some((path, branch)) => (path, branch),
        None => (spec, "main"),
    };
    let (owner, repo) = path.split_once('/').ok_or_else(|| -> BoxError {
        format!("--repo {spec:?} must be OWNER/REPO[@BRANCH]").into()
    })?;
    if owner.is_empty() || repo.is_empty() || branch.is_empty() {
        return Err(format!("--repo {spec:?} has an empty owner, repo, or branch").into());
    }
    Ok(RepoSpec {
        owner: owner.to_string(),
        repo: repo.to_string(),
        branch: branch.to_string(),
    })
}

/// Parses `user:pass` into its two parts (the password may itself contain `:`).
fn parse_userpass(value: &str) -> Result<(String, String), BoxError> {
    let (user, pass) = value
        .split_once(':')
        .ok_or_else(|| -> BoxError { "--exact-auth must be USER:PASS".into() })?;
    if user.is_empty() {
        return Err("--exact-auth username must not be empty".into());
    }
    Ok((user.to_string(), pass.to_string()))
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        // If we cannot install a SIGTERM handler, fall back to SIGINT only.
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
