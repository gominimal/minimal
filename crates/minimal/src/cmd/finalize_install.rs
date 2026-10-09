//! `min finalize-install` — the one privileged step for every host need
//! (NET-122): the user-namespace profile, names, the classifier tree and
//! KVM group membership, each probed on this host and carried in one
//! script only while it is missing.

use serde::Serialize;

use super::*;

/// What a finished host is told, with exit 0.
pub(crate) const FINISHED: &str =
    "Every part of the install is finished on this machine; there is nothing to run.";

/// The last line of a completed run that added no group membership.
pub(crate) const PICKED_UP: &str = "Running boxes pick this up on their next start.";

/// The last line of a completed run that added the operator to the `kvm`
/// group: a membership is read at login, so no running process has it yet.
pub(crate) const NEEDS_LOGIN: &str = "KVM group membership starts at your next login: log out \
     and back in, or restart the daemon from a new login.";

/// The file route a caller without a terminal is pointed at.
pub(crate) const SCRIPT_POINTER: &str =
    "f=$(mktemp) && min finalize-install --show --script > \"$f\" && sudo sh \"$f\"";

/// The heading the items no script can fix are listed under.
pub(crate) const CANNOT_HEADING: &str = "can't do on this machine:";

/// What a waiting item is listed as.
pub(crate) const WAITING: &str = "waiting on a daemon";

/// The `--show --json` document's schema.
pub(crate) const SCHEMA: &str = "min/v1/finalize-install";

/// The names item's cause when no daemon reports an answerer port to
/// point the resolver at.
const NO_PORT: &str = "no daemon is reachable to report its answerer port";

/// The KVM item's id, read by the run to pick its closing line.
pub(crate) const KVM_ID: &str = "kvm-group";

/// One item's state on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ItemState {
    /// Installed and holding: nothing to run.
    Done,
    /// Wanted: the script carries this item's step.
    Missing,
    /// A host fact no script changes blocks it; `cause` says which.
    Cannot,
    /// Wanted, but not renderable until a daemon reports what the step
    /// needs; `cause` says what is awaited. Never blocks the other items.
    Waiting,
}

/// One part of the install, as `--show` lists it and the script carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Item {
    /// The stable id a caller matches on.
    pub id: &'static str,
    /// The plain-language name of what the item gives the operator.
    pub label: &'static str,
    pub state: ItemState,
    /// What the operator loses today, while the item is missing.
    pub today: Option<String>,
    /// What the step changes, when it runs.
    pub step: Option<String>,
    /// Why no script can fix it, when none can.
    pub cause: Option<String>,
    /// The step's block in the script, while the item is missing.
    #[serde(skip)]
    script: Option<String>,
}

impl Item {
    fn done(id: &'static str, label: &'static str) -> Self {
        Item {
            id,
            label,
            state: ItemState::Done,
            today: None,
            step: None,
            cause: None,
            script: None,
        }
    }

    fn missing(
        id: &'static str,
        label: &'static str,
        today: String,
        step: String,
        script: String,
    ) -> Self {
        Item {
            id,
            label,
            state: ItemState::Missing,
            today: Some(today),
            step: Some(step),
            cause: None,
            script: Some(script),
        }
    }

    fn cannot(id: &'static str, label: &'static str, cause: String) -> Self {
        Item {
            id,
            label,
            state: ItemState::Cannot,
            today: None,
            step: None,
            cause: Some(cause),
            script: None,
        }
    }

    fn waiting(id: &'static str, label: &'static str, cause: String) -> Self {
        Item {
            id,
            label,
            state: ItemState::Waiting,
            today: None,
            step: None,
            cause: Some(cause),
            script: None,
        }
    }
}

/// The `--show --json` document.
#[derive(Serialize)]
struct Report<'a> {
    schema: &'static str,
    finished: bool,
    items: &'a [Item],
}

/// Every item this host has, probed: the one source the summary, the
/// JSON and the script render from, so what `--show` names is what a run
/// installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub items: Vec<Item>,
}

impl Plan {
    /// Whether every item is done.
    pub(crate) fn finished(&self) -> bool {
        self.items.iter().all(|item| item.state == ItemState::Done)
    }

    fn missing(&self) -> impl Iterator<Item = &Item> {
        self.items
            .iter()
            .filter(|item| item.state == ItemState::Missing)
    }

    fn cannot(&self) -> impl Iterator<Item = &Item> {
        self.items
            .iter()
            .filter(|item| item.state == ItemState::Cannot)
    }

    /// The exit status `--show --json` and a run that runs nothing end
    /// with: 0 once every item is done, 1 while any is not — missing,
    /// waiting or blocked alike, since none of those is a finished host.
    pub(crate) fn exit_code(&self) -> i32 {
        i32::from(!self.finished())
    }

    /// Whether the script adds the operator to the `kvm` group, which
    /// decides the closing line: a membership is read at login.
    pub(crate) fn adds_kvm_group(&self) -> bool {
        self.missing().any(|item| item.id == KVM_ID)
    }

    /// The one script a run executes and `--show --script` prints: one
    /// header over the missing items' blocks, in order. `None` while no
    /// item is missing — a finished host, or one whose every open item no
    /// script can fix.
    pub(crate) fn script(&self) -> Option<String> {
        let missing: Vec<&Item> = self.missing().collect();
        if missing.is_empty() {
            return None;
        }
        let labels: Vec<&str> = missing.iter().map(|item| item.label).collect();
        let what = format!(
            "Finish the Minimal install on this host: {}",
            labels.join(", ")
        );
        let mut script = crate::resolver::script_header(&what, crate::resolver::FINALIZE_SHOWN_BY);
        for item in missing {
            script.push('\n');
            script.push_str(item.script.as_deref().unwrap_or_default());
        }
        Some(script)
    }

    /// The summary: a ✓/✗ line per item, what a missing one costs today
    /// and what the step changes, and the items no script can fix under
    /// their own heading. [`FINISHED`] alone on a finished host.
    pub(crate) fn summary(&self) -> String {
        if self.finished() {
            return format!("{FINISHED}\n");
        }
        let mut out = String::from("install status on this machine:\n");
        for item in self
            .items
            .iter()
            .filter(|item| item.state != ItemState::Cannot)
        {
            match item.state {
                ItemState::Done => out.push_str(&format!("  ✓ {}\n", item.label)),
                ItemState::Waiting => out.push_str(&format!(
                    "  ✗ {} — {WAITING} ({})\n",
                    item.label,
                    item.cause.as_deref().unwrap_or_default()
                )),
                _ => {
                    out.push_str(&format!("  ✗ {}\n", item.label));
                    if let Some(today) = &item.today {
                        out.push_str(&format!("      today: {today}\n"));
                    }
                    if let Some(step) = &item.step {
                        out.push_str(&format!("      this step: {step}\n"));
                    }
                }
            }
        }
        let cannot: Vec<&Item> = self.cannot().collect();
        if !cannot.is_empty() {
            out.push_str(CANNOT_HEADING);
            out.push('\n');
            for item in cannot {
                out.push_str(&format!(
                    "  ✗ {} — {}\n",
                    item.label,
                    item.cause.as_deref().unwrap_or_default()
                ));
            }
        }
        out
    }

    /// The `--show --json` document.
    pub(crate) fn json(&self) -> String {
        serde_json_lenient::to_string(&Report {
            schema: SCHEMA,
            finished: self.finished(),
            items: &self.items,
        })
        .expect("the report serializes: strings and bools only")
    }
}

/// How a run elevates, decided from whether a terminal can answer a
/// prompt: with one, `sudo sh <file>`; without one, `sudo -n sh <file>`,
/// and only when `sudo -n` can run quietly — otherwise the run is refused
/// with the file route, so no caller hangs on a prompt nothing answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunDecision {
    /// Run the script with these arguments ahead of the file's path.
    Run(Vec<&'static str>),
    /// Run nothing: print `message` and exit with `exit`.
    Refuse { message: String, exit: i32 },
}

/// [`RunDecision`] for a run with (`stdin_is_tty`) or without a terminal;
/// `sudo_runs_quietly` is whether `sudo -n true` succeeded, consulted only
/// without one.
pub(crate) fn run_decision(stdin_is_tty: bool, sudo_runs_quietly: bool) -> RunDecision {
    if stdin_is_tty {
        RunDecision::Run(vec!["sudo", "sh"])
    } else if sudo_runs_quietly {
        RunDecision::Run(vec!["sudo", "-n", "sh"])
    } else {
        RunDecision::Refuse {
            message: format!(
                "sudo needs a password and no terminal is attached to ask on; run the \
                 step yourself: {SCRIPT_POINTER}"
            ),
            exit: 1,
        }
    }
}

/// `min finalize-install`: probe every part of the install this host
/// needs, name what is missing, and run the one script that installs it
/// with `sudo sh <file>` as the only prompt. `--show` prints the summary
/// and runs nothing; `--show --script` adds the script on stdout; `--show
/// --json` prints the report and exits non-zero while anything is
/// missing; `--undo` removes everything the step installed.
pub async fn cmd_finalize_install(
    global: &GlobalArgs,
    args: FinalizeInstallArgs,
) -> Result<(), anyhow::Error> {
    if let Some(message) = undo_flags_refusal(&args) {
        use clap::CommandFactory as _;
        Cli::command()
            .error(clap::error::ErrorKind::MissingRequiredArgument, message)
            .exit();
    }
    if args.undo {
        return cmd_finalize_install_undo(args.show);
    }
    let plan = plan_for_this_host(global).await;
    if args.json {
        println!("{}", plan.json());
        if plan.exit_code() != 0 {
            std::process::exit(plan.exit_code());
        }
        return Ok(());
    }
    if args.show {
        if args.script {
            eprint!("{}", plan.summary());
            if let Some(script) = plan.script() {
                print!("{script}");
            }
        } else {
            print!("{}", plan.summary());
        }
        return Ok(());
    }
    print!("{}", plan.summary());
    let Some(script) = plan.script() else {
        // Nothing a script can do here: a finished host (exit 0), or one
        // whose every open item is blocked or waiting (exit 1).
        if plan.exit_code() != 0 {
            std::process::exit(plan.exit_code());
        }
        return Ok(());
    };
    // The installed service runs as one operator; replacing another user's
    // is not this user's call (spec 18's open question on several users).
    if let Some(refusal) = crate::resolver::other_operator_refusal_on_this_host() {
        eprintln!("min finalize-install: {refusal}");
        std::process::exit(1);
    }
    run_as_root(&script)?;
    println!("{}", closing_line(plan.adds_kvm_group()));
    Ok(())
}

/// The line a completed run ends with: [`NEEDS_LOGIN`] when the script
/// added the operator to the `kvm` group, else [`PICKED_UP`].
pub(crate) fn closing_line(added_kvm_group: bool) -> &'static str {
    if added_kvm_group {
        NEEDS_LOGIN
    } else {
        PICKED_UP
    }
}

/// Why `--undo` refuses its flags, when it does: `--undo` runs the removal
/// or, with `--show --script`, prints it; `--show` alone has no summary to
/// show for a removal, so it is refused rather than guessed at.
pub(crate) fn undo_flags_refusal(args: &FinalizeInstallArgs) -> Option<&'static str> {
    (args.undo && args.show && !args.script)
        .then_some("--undo takes --show only with --script: `min finalize-install --undo --show --script` prints the removal script")
}

/// `min finalize-install --undo`: remove everything the step installs on
/// this host (NET-122's removal). The script reads no daemon, so it works
/// with nothing running, and every step of it tolerates what is already
/// gone, so it succeeds on a clean host. With `--show --script` it prints
/// the script and runs nothing.
fn cmd_finalize_install_undo(show: bool) -> Result<(), anyhow::Error> {
    let script = crate::resolver::undo_command();
    if show {
        print!("{script}");
        return Ok(());
    }
    run_as_root(&script)
}

/// Writes `script` to a private temp file — created exclusively, mode
/// 0600, so no other user can read or swap it.
pub(crate) fn write_private_script(script: &str) -> Result<tempfile::NamedTempFile, anyhow::Error> {
    use std::io::Write as _;
    let mut file = tempfile::Builder::new()
        .prefix("min-finalize-install-")
        .suffix(".sh")
        .tempfile()
        .context("min finalize-install: could not create a private file for the script")?;
    file.write_all(script.as_bytes())
        .and_then(|()| file.flush())
        .context("min finalize-install: could not write the script")?;
    Ok(file)
}

/// Runs a host-setup script as root: written by [`write_private_script`]
/// and run under the elevation [`run_decision`] picks, whose prompt is the
/// one privilege prompt. The file is removed once the script exits, and
/// the process exits with the script's status. The script is the one
/// `--show --script` prints, byte for byte.
fn run_as_root(script: &str) -> Result<(), anyhow::Error> {
    let stdin_is_tty = std::io::stdin().is_terminal();
    let sudo_runs_quietly = !stdin_is_tty
        && std::process::Command::new("sudo")
            .args(["-n", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    let argv = match run_decision(stdin_is_tty, sudo_runs_quietly) {
        RunDecision::Run(argv) => argv,
        RunDecision::Refuse { message, exit } => {
            eprintln!("{message}");
            std::process::exit(exit);
        }
    };
    let file = write_private_script(script)?;
    let status = std::process::Command::new(argv[0])
        .args(&argv[1..])
        .arg(file.path())
        .status()
        .context("min finalize-install: could not start sudo to run the script")?;
    // Removed before the exit below, which runs no destructor.
    file.close()
        .context("min finalize-install: could not remove the script")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Every item this host has, probed in the order the summary lists them.
async fn plan_for_this_host(global: &GlobalArgs) -> Plan {
    let mut items = Vec::new();
    #[cfg(target_os = "linux")]
    if !global.use_minvmd() {
        items.extend(linux::userns_item_on_this_host());
    }
    items.push(names_item_on_this_host(global).await);
    #[cfg(target_os = "linux")]
    if global.use_minvmd() {
        items.push(linux::kvm_item_on_this_host());
    } else {
        items.push(linux::classifier_item_on_this_host(global));
    }
    Plan { items }
}

/// The names item's id and label.
const NAMES_ID: &str = "names";
const NAMES_LABEL: &str = "box names for every host program";

/// The names item from its verdict: done, missing with the facts the
/// advisory names and the step that installs them, or blocked by the
/// note's cause.
pub(crate) fn names_item(verdict: crate::resolver::NamesVerdict, port: u16) -> Item {
    use crate::resolver::NamesVerdict;
    match verdict {
        NamesVerdict::Done => Item::done(NAMES_ID, NAMES_LABEL),
        NamesVerdict::Blocked { note } => Item::cannot(
            NAMES_ID,
            NAMES_LABEL,
            note.trim_start_matches("note: ")
                .trim_end_matches('.')
                .to_string(),
        ),
        NamesVerdict::Missing { facts, install } => {
            let service = if install.is_some() {
                " and installs the Minimal box-name service"
            } else {
                ""
            };
            let range = if cfg!(target_os = "macos") {
                ", and reserves the local range on this host's loopback"
            } else {
                ""
            };
            Item::missing(
                NAMES_ID,
                NAMES_LABEL,
                facts,
                format!(
                    "points this host's resolver at the box-zone answerer on \
                     127.0.0.1:{port}{service}{range}"
                ),
                crate::resolver::names_steps(port, install.as_ref()),
            )
        }
    }
}

/// The names item on this host: its verdict over this host's reads and
/// the answerer port `min ls` reads — each listed VM's own state from its
/// VM host daemon's control socket (NET-138), else the daemon's listing.
/// It never starts a daemon: with none reachable, or none that reports a
/// port, there is no port to point a script at, and the item says so.
async fn names_item_on_this_host(global: &GlobalArgs) -> Item {
    let listings = ls_listings_best_effort(global).await;
    let mut answerer = None;
    let mut held_no_channel = None;
    for listing in &listings {
        let (port, bound, held) =
            match crate::cmd::session::vm_host_answerer_status_at(listing.control_sock.clone())
                .await
            {
                Some(status) => {
                    let read = crate::resolver::host_answerer_read(status).await;
                    (read.port, read.answerer_bound, read.held_no_channel)
                }
                None => (
                    listing.resp.zone_answerer_port,
                    listing.resp.answerer_bound,
                    false,
                ),
            };
        match port {
            // A port no channel reaches is no daemon's answerer: say that
            // fact instead of a script, unless another listing reports a
            // port that answers.
            Some(port) if held => held_no_channel = held_no_channel.or(Some(port)),
            Some(port) => {
                answerer = Some((port, bound));
                break;
            }
            None => {}
        }
    }
    let Some((port, bound)) = answerer else {
        // No port to point a script at yet: the item waits on a daemon,
        // and never blocks the items the script can carry without one.
        let cause = match held_no_channel {
            Some(port) => crate::resolver::port_held_no_channel_warning(port),
            None => NO_PORT.to_string(),
        };
        return Item::waiting(NAMES_ID, NAMES_LABEL, cause);
    };
    let (detection, answerer_step) = crate::cmd::session::advisory_host_reads(global).await;
    // The range read the live-surface verdict makes, so the item names the
    // same missing facts the surface line reports.
    let range_present =
        crate::resolver::live_name_surface_with_range_at(&detection, Some(port), bound)
            .await
            .and_then(|verdict| verdict.range_present);
    let (hook, blocker, range_step) = &detection;
    let verdict = crate::resolver::names_verdict_at(
        hook,
        port,
        false,
        range_present,
        range_step,
        &answerer_step,
        blocker.as_deref(),
    );
    names_item(verdict, port)
}

/// The Linux-only items: the user-namespace profile, the classifier tree
/// and KVM group membership. Each is pure over pre-read facts, so its
/// table is unit-tested on every platform the suite runs on.
#[cfg(any(test, target_os = "linux"))]
pub(crate) mod linux {
    use super::*;
    use crate::resolver::{
        ANSWERER_PROGRAM_DIR, APPARMOR_DIR, CLASSIFIER_PROGRAM_PATH, CLASSIFIER_SCRIPT,
        CLASSIFIER_SCRIPT_HEREDOC, CLASSIFIER_TREE_ROOT, KVM_GROUP_RECORD, PLACE_SYSTEMD_UNIT,
        PLACE_UNIT_PATH_PATH, PLACE_UNIT_SERVICE_PATH,
    };

    pub(crate) const USERNS_ID: &str = "userns-profile";
    const USERNS_LABEL: &str = "the private sandbox every box runs in";
    pub(crate) const CLASSIFIER_ID: &str = "classifier";
    const CLASSIFIER_LABEL: &str = "per-box egress limits for host-address boxes";
    const KVM_LABEL: &str = "KVM access for the Linux VM provider";

    /// The profile the step installs, the very file the checkout ships.
    const APPARMOR_PROFILE: &str = include_str!("../../../../packaging/apparmor/minimald");
    /// Its tunable: the binary paths the profile attaches to.
    const APPARMOR_TUNABLE: &str = include_str!("../../../../packaging/apparmor/tunables/minimald");
    const PROFILE_HEREDOC: &str = "MINIMAL_APPARMOR_PROFILE_EOF";
    const TUNABLE_HEREDOC: &str = "MINIMAL_APPARMOR_TUNABLE_EOF";

    /// The install locations the stock tunable already attaches the
    /// profile to; a `minimald` elsewhere needs its path appended.
    fn daemon_in_stock_path(daemon: &str) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        daemon == "/usr/bin/minimald"
            || daemon == "/usr/local/bin/minimald"
            || (!home.is_empty() && daemon == format!("{home}/.local/bin/minimald"))
    }

    /// The facts the user-namespace item decides on.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub(crate) struct UsernsFacts {
        /// `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`, when readable.
        pub apparmor_restrict: Option<String>,
        /// `/proc/sys/user/max_user_namespaces`, when readable.
        pub max_user_namespaces: Option<String>,
        /// Whether `/etc/apparmor.d/minimald` exists.
        pub profile_installed: bool,
        /// Whether the installed tunables name `daemon`.
        pub tunables_name_daemon: bool,
        /// Whether `apparmor_parser` is on this host.
        pub parser_present: bool,
        /// The `minimald` this host runs, absolute, when it is found beside
        /// this `min`.
        pub daemon: Option<String>,
    }

    /// The user-namespace item over `facts`: `None` on a host whose kernel
    /// does not restrict unprivileged user namespaces (nothing to install),
    /// done when the profile is loaded and attaches this host's daemon,
    /// and blocked where user namespaces are off altogether or no parser
    /// can load a profile.
    pub(crate) fn userns_item_over(facts: &UsernsFacts) -> Option<Item> {
        let max = facts
            .max_user_namespaces
            .as_deref()
            .and_then(|s| s.trim().parse::<u64>().ok());
        if max.is_none_or(|n| n == 0) {
            return Some(Item::cannot(
                USERNS_ID,
                USERNS_LABEL,
                "user namespaces are disabled on this machine (user.max_user_namespaces \
                 is 0 or missing), and no profile can turn them on"
                    .to_string(),
            ));
        }
        let restricted = facts
            .apparmor_restrict
            .as_deref()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .is_some_and(|v| v != 0);
        if !restricted {
            return None;
        }
        let daemon = facts.daemon.as_deref();
        let attached = daemon.is_none_or(|d| daemon_in_stock_path(d) || facts.tunables_name_daemon);
        if facts.profile_installed && attached {
            return Some(Item::done(USERNS_ID, USERNS_LABEL));
        }
        if !facts.parser_present {
            return Some(Item::cannot(
                USERNS_ID,
                USERNS_LABEL,
                "this machine restricts unprivileged user namespaces but has no \
                 apparmor_parser to load the profile that allows them for minimald"
                    .to_string(),
            ));
        }
        let extra = daemon.filter(|d| !daemon_in_stock_path(d));
        // The path is written into an AppArmor tunable, whose values are
        // whitespace-separated and `#`-commented, and into a single-quoted
        // shell word: a path those cannot carry is a fact no script fixes.
        if extra.is_some_and(|d| d.contains(['\'', '#']) || d.contains(char::is_whitespace)) {
            return Some(Item::cannot(
                USERNS_ID,
                USERNS_LABEL,
                format!(
                    "minimald's path ({}) holds a quote, a hash or whitespace, which an \
                     AppArmor tunable cannot name; install it under a plain path",
                    extra.unwrap_or_default()
                ),
            ));
        }
        Some(Item::missing(
            USERNS_ID,
            USERNS_LABEL,
            "no box can start on this machine: it restricts unprivileged user \
             namespaces (Ubuntu 24.04+), and minimald has no profile that allows them"
                .to_string(),
            "installs an AppArmor profile that allows user namespaces for minimald \
             alone and confines nothing"
                .to_string(),
            userns_steps(extra),
        ))
    }

    /// The step's block: the tunable and the profile written from the bytes
    /// this script carries, the daemon's path appended where the stock
    /// tunable does not name it, and the profile loaded.
    fn userns_steps(extra_daemon_path: Option<&str>) -> String {
        let mut script = format!(
            "# The user-namespace profile: lets minimald create the user namespace every\n\
             # box runs in, for minimald alone, and confines nothing.\n\
             mkdir -p {APPARMOR_DIR}/tunables\n\
             cat > {APPARMOR_DIR}/tunables/minimald <<\\{TUNABLE_HEREDOC}\n\
             {APPARMOR_TUNABLE}\
             {TUNABLE_HEREDOC}\n\
             cat > {APPARMOR_DIR}/minimald <<\\{PROFILE_HEREDOC}\n\
             {APPARMOR_PROFILE}\
             {PROFILE_HEREDOC}\n\
             chmod 0644 {APPARMOR_DIR}/tunables/minimald {APPARMOR_DIR}/minimald\n"
        );
        if let Some(path) = extra_daemon_path {
            script.push_str(&format!(
                "# Attach the profile to this host's minimald too. This replaces the local\n\
                 # attachment set (what install-apparmor-profile.sh --path wrote, if anything).\n\
                 mkdir -p {APPARMOR_DIR}/tunables/minimald.d\n\
                 printf '@{{minimald_bin}} += %s\\n' '{path}' > \
                 {APPARMOR_DIR}/tunables/minimald.d/local\n"
            ));
        }
        script.push_str(&format!(
            "apparmor_parser --replace {APPARMOR_DIR}/minimald\n"
        ));
        script
    }

    /// [`userns_item_over`] this host's reads.
    pub(crate) fn userns_item_on_this_host() -> Option<Item> {
        let daemon = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("minimald")))
            .filter(|path| path.is_file())
            .and_then(|path| path.to_str().map(str::to_owned));
        let tunables_name_daemon = daemon.as_deref().is_some_and(|d| {
            [
                format!("{APPARMOR_DIR}/tunables/minimald"),
                format!("{APPARMOR_DIR}/tunables/minimald.d/local"),
            ]
            .iter()
            .any(|file| std::fs::read_to_string(file).is_ok_and(|text| text.contains(d)))
        });
        let parser_present = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
            .iter()
            .map(|dir| std::path::Path::new(dir).join("apparmor_parser"))
            .chain(
                std::env::var_os("PATH")
                    .map(|path| {
                        std::env::split_paths(&path)
                            .map(|dir| dir.join("apparmor_parser"))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            )
            .any(|candidate| candidate.is_file());
        userns_item_over(&UsernsFacts {
            apparmor_restrict: std::fs::read_to_string(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            )
            .ok(),
            max_user_namespaces: std::fs::read_to_string("/proc/sys/user/max_user_namespaces").ok(),
            profile_installed: std::path::Path::new(&format!("{APPARMOR_DIR}/minimald")).is_file(),
            tunables_name_daemon,
            parser_present,
            daemon,
        })
    }

    /// The cgroup2 mount the classifier tree needs, as `/proc/self/mountinfo`
    /// reports it at the conventional mountpoint.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Cgroup2Mount {
        /// No cgroup2 filesystem is mounted at `/sys/fs/cgroup`.
        Absent,
        /// Mounted without `nsdelegate`: a box's cgroup namespace is no
        /// delegation boundary, so no leaf would hold a box for its life.
        WithoutNsdelegate,
        /// Mounted `nsdelegate`.
        Delegated,
    }

    /// [`Cgroup2Mount`] from the text of `/proc/self/mountinfo`: the line
    /// whose mountpoint is `/sys/fs/cgroup` and whose filesystem type is
    /// `cgroup2`, with `nsdelegate` among its super options.
    pub(crate) fn cgroup2_mount_from(mountinfo: &str) -> Cgroup2Mount {
        for line in mountinfo.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            let mountpoint = pre.split_whitespace().nth(4);
            let mut post = post.split_whitespace();
            let fstype = post.next();
            let super_options = post.nth(1).unwrap_or_default();
            if mountpoint == Some("/sys/fs/cgroup") && fstype == Some("cgroup2") {
                return if super_options.split(',').any(|opt| opt == "nsdelegate") {
                    Cgroup2Mount::Delegated
                } else {
                    Cgroup2Mount::WithoutNsdelegate
                };
            }
        }
        Cgroup2Mount::Absent
    }

    /// The classifier item over its facts: done once the tree's marker is
    /// there and the root-owned copy of the step is this binary's own
    /// bytes; blocked by the mount the tree needs; otherwise missing, with
    /// the step that installs the classifier for `operator`'s daemon,
    /// whose listener lives at `socket`. An un-enrolled host has no source
    /// identity, and needs none: the step classifies the two identities as
    /// two cgroup matches and translates nothing, and an association later
    /// adds the reserved addresses to the same matches without a reinstall.
    ///
    /// `copy_current` is whether the copy at [`CLASSIFIER_PROGRAM_PATH`]
    /// reads as [`CLASSIFIER_SCRIPT`] byte for byte: the copy outlives an
    /// upgrade of this binary and the placement unit runs it, so a copy
    /// that differs is a stale step, and the item reads as missing until
    /// the block below writes the current one. `other_owner` is the uid the
    /// tree is delegated to when that is not this process's own: the tree
    /// is one account's, and another account's run must not read it as its
    /// own install, nor replace it.
    pub(crate) fn classifier_item_over(
        marker_present: bool,
        copy_current: bool,
        other_owner: Option<u32>,
        mount: Cgroup2Mount,
        operator: &str,
        socket: &str,
    ) -> Item {
        if let Some(uid) = other_owner {
            return Item::cannot(
                CLASSIFIER_ID,
                CLASSIFIER_LABEL,
                format!(
                    "the classifier tree at {CLASSIFIER_TREE_ROOT} is installed for another \
                     account (uid {uid}); running this step would replace their delegation, \
                     so that account removes it with `min finalize-install --undo` first"
                ),
            );
        }
        if marker_present && copy_current {
            return Item::done(CLASSIFIER_ID, CLASSIFIER_LABEL);
        }
        let cause = match mount {
            Cgroup2Mount::Absent => {
                "no cgroup2 filesystem is mounted at /sys/fs/cgroup, which the classifier \
                 tree lives in"
            }
            Cgroup2Mount::WithoutNsdelegate => {
                "cgroup2 is mounted without nsdelegate, so a box's cgroup is no boundary it \
                 cannot leave"
            }
            // The two names ride in a shell single-quoted word and in a
            // unit file, where systemd expands `%` specifiers and, in
            // `ExecStart=`, `$` variables, and `\\` escapes; and the step
            // matches the socket path as one whitespace-delimited field of
            // /proc/net/unix. A name any of them could reach is one the
            // block cannot spell safely, and the item says so rather than
            // installing a unit that never finds the daemon.
            Cgroup2Mount::Delegated => {
                if operator.is_empty() {
                    "this process's user name did not read, so there is no account to \
                     delegate the classifier tree to"
                } else if operator.contains(UNQUOTABLE) {
                    "this process's user name cannot be quoted into the step's shell word \
                     and unit file (it carries a quote, whitespace, %, $ or a backslash)"
                } else if socket.is_empty() {
                    "this host's daemon socket path did not resolve, so there is nothing \
                     for the placement unit to watch"
                } else if socket.contains(UNQUOTABLE) {
                    "this host's daemon socket path cannot be quoted into the step's shell \
                     word and unit file (it carries a quote, whitespace, %, $ or a backslash)"
                } else {
                    return Item::missing(
                        CLASSIFIER_ID,
                        CLASSIFIER_LABEL,
                        if marker_present {
                            "the root-owned copy of the classifier's privileged step is not \
                             this build's, so the placement unit runs a stale step"
                        } else {
                            "host-address boxes run unenforced: the classifier's privileged \
                             step is not installed, so no box's egress verdict is decided per \
                             box"
                        }
                        .to_string(),
                        format!(
                            "installs the classifier's cgroup tree and packet filter for \
                             {operator}'s daemon, and a systemd path unit that places the \
                             daemon's listener in its leaf on every daemon start"
                        ),
                        classifier_steps(operator, socket),
                    );
                }
            }
        };
        Item::cannot(CLASSIFIER_ID, CLASSIFIER_LABEL, cause.to_string())
    }

    /// The characters neither the operator name nor the socket path may
    /// carry into the block: a shell quote and a newline (the single-quoted
    /// words), a space or tab (the step reads the socket path as one field
    /// of `/proc/net/unix`, and the account as one word), `%` (a systemd
    /// specifier in every unit line), `$` (a variable in `ExecStart=`), and
    /// a backslash (an escape in both).
    const UNQUOTABLE: [char; 7] = ['\'', '\n', ' ', '\t', '%', '$', '\\'];

    /// The step's block: the classifier's step written from the bytes this
    /// binary carries to its root-owned copy and run with no source
    /// identity, then the placement pair — a path unit on the daemon's
    /// socket and the oneshot it starts — enabled, and run once for the
    /// daemon that may already be listening.
    fn classifier_steps(operator: &str, socket: &str) -> String {
        format!(
            "# The egress classifier: its privileged step, from a root-owned copy of the\n\
             # bytes this binary carries, with no source identity (an un-enrolled host\n\
             # translates nothing; an association adds the reserved addresses later).\n\
             mkdir -p {ANSWERER_PROGRAM_DIR}\n\
             cat > {CLASSIFIER_PROGRAM_PATH} <<\\{CLASSIFIER_SCRIPT_HEREDOC}\n\
             {CLASSIFIER_SCRIPT}\
             {CLASSIFIER_SCRIPT_HEREDOC}\n\
             chmod 0755 {CLASSIFIER_PROGRAM_PATH}\n\
             {CLASSIFIER_PROGRAM_PATH} --user '{operator}'\n\
             # The placement pair: the path unit fires when the daemon's socket appears,\n\
             # and the service puts the listener in the daemon's leaf, so every daemon\n\
             # start is placed without a root step of its own. A socket that flaps past\n\
             # systemd's trigger limit leaves the path unit failed until\n\
             # `systemctl reset-failed {PLACE_SYSTEMD_UNIT}.path`. Without systemd the\n\
             # pair is skipped, and each daemon start is placed by hand with the step.\n\
             if ! command -v systemctl >/dev/null 2>&1 ; then\n\
             \x20 echo 'note: no systemctl on this host: the placement unit is not installed, so place each daemon start by hand with the step'\n\
             else\n\
             cat > {PLACE_UNIT_SERVICE_PATH} <<\\MINIMAL_PLACE_SERVICE_EOF\n\
             [Unit]\n\
             Description=Place minimald's listener in its classifier leaf\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             ExecStart={CLASSIFIER_PROGRAM_PATH} --user '{operator}' --place-listener '{socket}'\n\
             MINIMAL_PLACE_SERVICE_EOF\n\
             cat > {PLACE_UNIT_PATH_PATH} <<\\MINIMAL_PLACE_PATH_EOF\n\
             [Unit]\n\
             Description=Watch minimald's socket to place its listener\n\
             \n\
             [Path]\n\
             PathChanged={socket}\n\
             Unit={PLACE_SYSTEMD_UNIT}.service\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n\
             MINIMAL_PLACE_PATH_EOF\n\
             chmod 0644 {PLACE_UNIT_SERVICE_PATH} {PLACE_UNIT_PATH_PATH}\n\
             systemctl daemon-reload\n\
             systemctl enable --now {PLACE_SYSTEMD_UNIT}.path\n\
             systemctl start {PLACE_SYSTEMD_UNIT}.service\n\
             fi\n"
        )
    }

    /// [`classifier_item_over`] this host's reads: the tree's marker, the
    /// root-owned copy's bytes against this binary's, the cgroup2 mount,
    /// this process's account, and the native daemon's socket path for
    /// this `--minimal-dir`.
    pub(crate) fn classifier_item_on_this_host(global: &GlobalArgs) -> Item {
        use std::os::unix::fs::MetadataExt as _;
        let marker = std::path::Path::new(CLASSIFIER_TREE_ROOT).join("classifier-table");
        let copy_current = std::fs::read(CLASSIFIER_PROGRAM_PATH)
            .is_ok_and(|bytes| bytes == CLASSIFIER_SCRIPT.as_bytes());
        // The tree is delegated to one account: the step chowns the boxes
        // subtree to it, so its owner is the account the install is for.
        let me = nix::unistd::geteuid().as_raw();
        let other_owner =
            std::fs::metadata(std::path::Path::new(CLASSIFIER_TREE_ROOT).join("boxes"))
                .ok()
                .map(|meta| meta.uid())
                .filter(|uid| *uid != me);
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let socket = crate::client::resolve_socket_path(global.minimal_dir.as_deref(), false)
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        classifier_item_over(
            marker.is_dir(),
            copy_current,
            other_owner,
            cgroup2_mount_from(&mountinfo),
            &crate::resolver::operator_name(),
            &socket,
        )
    }

    /// The KVM item over the result of opening `/dev/kvm` for reading:
    /// done when it opens; missing — the step adds `operator` to the `kvm`
    /// group — on `EACCES`; blocked when the device is not there, or on
    /// any other error, named.
    pub(crate) fn kvm_item_over(open: Result<(), std::io::Error>, operator: &str) -> Item {
        match open {
            Ok(()) => Item::done(KVM_ID, KVM_LABEL),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                if operator.is_empty() || operator.contains(['\'', '\n', ' ']) {
                    return Item::cannot(
                        KVM_ID,
                        KVM_LABEL,
                        "this process's user name did not read, so there is no account to \
                         add to the kvm group"
                            .to_string(),
                    );
                }
                Item::missing(
                    KVM_ID,
                    KVM_LABEL,
                    format!(
                        "VM boots fail with /dev/kvm: permission denied, because {operator} is \
                         not in the kvm group"
                    ),
                    format!(
                        "adds {operator} to the kvm group (it takes effect at your next login)"
                    ),
                    format!(
                        "# KVM access: the Linux VM provider drives KVM, which the kvm group may\n\
                         # open. The record names who was added, so --undo takes back only that.\n\
                         usermod -aG kvm '{operator}'\n\
                         mkdir -p /var/lib/minimal\n\
                         printf '%s\\n' '{operator}' > {KVM_GROUP_RECORD}\n"
                    ),
                )
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Item::cannot(
                KVM_ID,
                KVM_LABEL,
                "/dev/kvm is not there: the KVM module is not loaded, or this machine has no \
                 hardware virtualization"
                    .to_string(),
            ),
            Err(err) => Item::cannot(KVM_ID, KVM_LABEL, format!("opening /dev/kvm: {err}")),
        }
    }

    /// [`kvm_item_over`] this host's read.
    pub(crate) fn kvm_item_on_this_host() -> Item {
        let open = std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/kvm")
            .map(|_| ());
        kvm_item_over(open, &crate::resolver::operator_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(id: &'static str) -> Item {
        Item::done(id, "a done item")
    }

    fn missing(id: &'static str, block: &str) -> Item {
        Item::missing(
            id,
            "a missing item",
            "what it costs today".to_string(),
            "what the step changes".to_string(),
            format!("# The step: {block}.\necho {block}\n"),
        )
    }

    fn cannot(id: &'static str, cause: &str) -> Item {
        Item::cannot(id, "an unfixable item", cause.to_string())
    }

    /// NET-122: a finished host is told so, exactly, with no script to run
    /// and exit 0 — the common case after the first run, so a success.
    #[test]
    fn finalize_install_finished_host_runs_nothing_and_exits_zero() {
        let plan = Plan {
            items: vec![done("names"), done("userns-profile")],
        };
        assert!(plan.finished());
        assert_eq!(plan.summary(), format!("{FINISHED}\n"));
        assert_eq!(plan.script(), None);
        assert_eq!(plan.exit_code(), 0);
        assert!(plan.json().contains("\"finished\":true"), "{}", plan.json());
    }

    /// NET-122: an item no script can fix is listed under its own heading
    /// with its cause, and the script still carries every item a script
    /// can fix — the run is never refused whole on the unfixable one.
    #[test]
    fn finalize_install_lists_unfixable_facts_and_runs_the_rest() {
        let plan = Plan {
            items: vec![
                missing("names", "names"),
                cannot("classifier", "cgroup2 is mounted without nsdelegate"),
            ],
        };
        let summary = plan.summary();
        assert!(summary.contains(CANNOT_HEADING), "{summary}");
        assert!(
            summary.contains("✗ an unfixable item — cgroup2 is mounted without nsdelegate"),
            "{summary}"
        );
        let script = plan.script().expect("the fixable item still runs");
        assert!(script.contains("echo names"), "{script}");
        assert!(!script.contains("nsdelegate"), "{script}");
        assert_eq!(plan.exit_code(), 1);
    }

    /// NET-122: when every missing item is one no script can fix, the run
    /// lists them under their heading, runs nothing, and exits non-zero —
    /// never the finished sentence, since a blocked host is not finished.
    #[test]
    fn finalize_install_all_blocked_runs_nothing_and_exits_non_zero() {
        let blocked = Plan {
            items: vec![cannot("userns-profile", "no user namespaces")],
        };
        assert_eq!(blocked.script(), None);
        assert!(!blocked.finished());
        assert_eq!(blocked.exit_code(), 1);
        let summary = blocked.summary();
        assert!(summary.contains(CANNOT_HEADING), "{summary}");
        assert!(!summary.contains(FINISHED), "{summary}");

        // Done beside a blocked item is the same host: no script, exit 1.
        let done_and_cannot = Plan {
            items: vec![
                done("names"),
                cannot("userns-profile", "no user namespaces"),
            ],
        };
        assert_eq!(done_and_cannot.script(), None);
        assert_eq!(done_and_cannot.exit_code(), 1);
        let summary = done_and_cannot.summary();
        assert!(!summary.contains(FINISHED), "{summary}");
        assert!(summary.contains(CANNOT_HEADING), "{summary}");
    }

    /// NET-122: with no daemon, the names item is listed as waiting on one,
    /// with its cause, under the summary — not under the unfixable heading
    /// — and the items that need no daemon still run; a waiting item never
    /// finishes the host.
    #[test]
    fn finalize_install_without_daemon_runs_the_items_that_need_none() {
        let plan = Plan {
            items: vec![
                missing("userns-profile", "userns"),
                Item::waiting("names", "box names", "no daemon is reachable".to_string()),
            ],
        };
        let summary = plan.summary();
        assert!(
            summary.contains("  ✗ box names — waiting on a daemon (no daemon is reachable)\n"),
            "{summary}"
        );
        assert!(!summary.contains(CANNOT_HEADING), "{summary}");
        assert!(!summary.contains(FINISHED), "{summary}");
        let script = plan.script().expect("the userns item still runs");
        assert!(script.contains("echo userns"), "{script}");
        assert_eq!(plan.exit_code(), 1);
        let value: serde_json_lenient::Value = serde_json_lenient::from_str(&plan.json()).unwrap();
        assert_eq!(value["items"][1]["state"], "waiting");
        assert_eq!(value["finished"], false);

        // Waiting alone: nothing to run, exit 1, no finished sentence.
        let waiting = Plan {
            items: vec![Item::waiting("names", "box names", "no daemon".to_string())],
        };
        assert_eq!(waiting.script(), None);
        assert_eq!(waiting.exit_code(), 1);
        assert!(!waiting.summary().contains(FINISHED));
    }

    /// NET-122: a run that added the operator to the KVM group ends with the
    /// login note, exactly; one that installed anything else ends with the
    /// pick-up line.
    #[test]
    fn finalize_install_kvm_group_closing_line_names_a_new_login() {
        let with_kvm = Plan {
            items: vec![missing("names", "names"), missing(KVM_ID, "kvm")],
        };
        assert!(with_kvm.adds_kvm_group());
        assert_eq!(closing_line(with_kvm.adds_kvm_group()), NEEDS_LOGIN);
        assert_eq!(
            NEEDS_LOGIN,
            "KVM group membership starts at your next login: log out and back in, or restart \
             the daemon from a new login."
        );
        let without = Plan {
            items: vec![missing("names", "names"), done(KVM_ID)],
        };
        assert!(!without.adds_kvm_group());
        assert_eq!(closing_line(without.adds_kvm_group()), PICKED_UP);
    }

    /// `--undo` takes `--show` only with `--script`: `--undo --show` alone
    /// is refused as a usage error, the other combinations are not.
    #[test]
    fn finalize_install_undo_refuses_show_without_script() {
        let args = |show, script, undo| FinalizeInstallArgs {
            show,
            script,
            json: false,
            undo,
        };
        assert!(undo_flags_refusal(&args(true, false, true)).is_some());
        assert_eq!(undo_flags_refusal(&args(true, true, true)), None);
        assert_eq!(undo_flags_refusal(&args(false, false, true)), None);
        assert_eq!(undo_flags_refusal(&args(true, false, false)), None);
    }

    /// NET-122: without a terminal the run goes through `sudo -n`, and when
    /// that cannot run quietly the run is refused with the file route and
    /// exit 1 — never a prompt nothing can answer. A cached credential
    /// still runs the step.
    #[test]
    fn finalize_install_without_tty_exits_one_with_script_pointer() {
        assert_eq!(
            run_decision(true, false),
            RunDecision::Run(vec!["sudo", "sh"])
        );
        assert_eq!(
            run_decision(false, true),
            RunDecision::Run(vec!["sudo", "-n", "sh"])
        );
        let RunDecision::Refuse { message, exit } = run_decision(false, false) else {
            panic!("a prompt with no terminal is refused");
        };
        assert_eq!(exit, 1);
        assert!(message.ends_with(SCRIPT_POINTER), "{message}");
        assert_eq!(
            SCRIPT_POINTER,
            "f=$(mktemp) && min finalize-install --show --script > \"$f\" && sudo sh \"$f\""
        );
    }

    /// NET-122: `--show` names what is missing — a ✓ or ✗ per item, what a
    /// missing one costs today and what the step changes — and nothing in
    /// it is a script, a prompt or an elevation.
    #[test]
    fn finalize_install_show_names_missing_items_without_prompt() {
        let plan = Plan {
            items: vec![done("userns-profile"), missing("names", "names")],
        };
        let summary = plan.summary();
        assert!(
            summary.starts_with("install status on this machine:\n"),
            "{summary}"
        );
        assert!(summary.contains("  ✓ a done item\n"), "{summary}");
        assert!(summary.contains("  ✗ a missing item\n"), "{summary}");
        assert!(
            summary.contains("      today: what it costs today\n"),
            "{summary}"
        );
        assert!(
            summary.contains("      this step: what the step changes\n"),
            "{summary}"
        );
        assert!(!summary.contains(CANNOT_HEADING), "{summary}");
        assert!(
            !summary.contains("#!/bin/sh") && !summary.contains("sudo") && !summary.contains('?'),
            "{summary}"
        );
    }

    /// NET-122: the JSON report carries the schema, every item's stable id
    /// and state, and the one-bit exit status — 1 while anything is not
    /// done, 0 once everything is.
    #[test]
    fn finalize_install_show_json_carries_stable_item_ids_and_exit_status() {
        let plan = Plan {
            items: vec![
                done("userns-profile"),
                missing("names", "names"),
                cannot("classifier", "no cgroup2 mount"),
            ],
        };
        let json = plan.json();
        let value: serde_json_lenient::Value = serde_json_lenient::from_str(&json).unwrap();
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["finished"], false);
        let items = value["items"].as_array().unwrap();
        let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["userns-profile", "names", "classifier"]);
        assert_eq!(items[0]["state"], "done");
        assert_eq!(items[1]["state"], "missing");
        assert_eq!(items[1]["today"], "what it costs today");
        assert_eq!(items[2]["state"], "cannot");
        assert_eq!(items[2]["cause"], "no cgroup2 mount");
        assert!(
            items[1].get("script").is_none(),
            "the script is not the report's"
        );
        assert_eq!(plan.exit_code(), 1);
        assert_eq!(
            Plan {
                items: vec![done("names")]
            }
            .exit_code(),
            0
        );
    }

    /// NET-122: a run writes the exact script `--show --script` prints to
    /// a file only the operator can read, and elevates once — `sudo sh`
    /// of that file. The closing line is the one the spec names.
    #[test]
    fn finalize_install_runs_the_script_with_one_elevation() {
        use std::os::unix::fs::PermissionsExt as _;
        let plan = Plan {
            items: vec![missing("names", "names"), missing("kvm-group", "kvm")],
        };
        let shown = plan.script().unwrap();
        let file = write_private_script(&shown).unwrap();
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), shown);
        assert_eq!(
            std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            run_decision(true, false),
            RunDecision::Run(vec!["sudo", "sh"])
        );
        assert_eq!(PICKED_UP, "Running boxes pick this up on their next start.");
    }

    /// The script is one header over the missing items' blocks, in order:
    /// its lead-in names the items, it says how it is shown and that it
    /// runs as root, and `set -eu` precedes every step.
    #[test]
    fn finalize_install_script_is_one_header_over_the_missing_items() {
        let plan = Plan {
            items: vec![
                done("userns-profile"),
                missing("names", "names"),
                missing("kvm-group", "kvm"),
            ],
        };
        let script = plan.script().unwrap();
        let lines: Vec<&str> = script.lines().collect();
        assert_eq!(lines[0], "#!/bin/sh");
        assert_eq!(
            lines[1],
            "# Finish the Minimal install on this host: a missing item, a missing item."
        );
        assert!(
            lines[2].contains("min finalize-install --show --script")
                && lines[2].contains("it must run as root: sudo sh <this file>"),
            "{script}"
        );
        assert_eq!(lines[3], "set -eu");
        let names = script.find("echo names").unwrap();
        let kvm = script.find("echo kvm").unwrap();
        assert!(names < kvm, "{script}");
        assert_eq!(script.matches("#!/bin/sh").count(), 1, "{script}");
    }

    /// The names item from its verdict: done, missing with the facts and
    /// the step's block, or blocked by the note's cause.
    #[test]
    fn names_item_follows_its_verdict() {
        use crate::resolver::NamesVerdict;
        assert_eq!(names_item(NamesVerdict::Done, 15353).state, ItemState::Done);
        let blocked = names_item(
            NamesVerdict::Blocked {
                note: "note: host lookups bypass the resolver.".to_string(),
            },
            15353,
        );
        assert_eq!(blocked.state, ItemState::Cannot);
        assert_eq!(
            blocked.cause.as_deref(),
            Some("host lookups bypass the resolver")
        );
        let missing = names_item(
            NamesVerdict::Missing {
                facts: "the resolver is not configured".to_string(),
                install: None,
            },
            15353,
        );
        assert_eq!(missing.state, ItemState::Missing);
        assert_eq!(missing.id, "names");
        assert_eq!(
            missing.today.as_deref(),
            Some("the resolver is not configured")
        );
        assert!(missing.step.as_deref().unwrap().contains("127.0.0.1:15353"));
        let script = missing.script.unwrap();
        assert!(script.starts_with("# The resolver: "), "{script}");
        assert!(!script.contains("#!/bin/sh"), "{script}");
    }

    /// The user-namespace item's table: not an item where the kernel does
    /// not restrict, done when the profile is loaded and attaches the
    /// daemon, blocked without user namespaces or a parser, and otherwise
    /// a step that writes both files from the bytes it carries and loads
    /// the profile — appending the daemon's path only where the stock
    /// tunable does not name it.
    #[test]
    fn userns_item_table() {
        use linux::{UsernsFacts, userns_item_over};
        let restricted = UsernsFacts {
            apparmor_restrict: Some("1\n".to_string()),
            max_user_namespaces: Some("15000\n".to_string()),
            profile_installed: false,
            tunables_name_daemon: false,
            parser_present: true,
            daemon: Some("/usr/local/bin/minimald".to_string()),
        };
        assert_eq!(
            userns_item_over(&UsernsFacts {
                apparmor_restrict: Some("0\n".to_string()),
                ..restricted.clone()
            }),
            None
        );
        assert_eq!(
            userns_item_over(&UsernsFacts {
                apparmor_restrict: None,
                ..restricted.clone()
            }),
            None
        );
        let disabled = userns_item_over(&UsernsFacts {
            max_user_namespaces: Some("0\n".to_string()),
            ..restricted.clone()
        })
        .unwrap();
        assert_eq!(disabled.state, ItemState::Cannot);
        assert!(disabled.cause.unwrap().contains("max_user_namespaces"));
        let done = userns_item_over(&UsernsFacts {
            profile_installed: true,
            ..restricted.clone()
        })
        .unwrap();
        assert_eq!(done.state, ItemState::Done);
        let no_parser = userns_item_over(&UsernsFacts {
            parser_present: false,
            ..restricted.clone()
        })
        .unwrap();
        assert_eq!(no_parser.state, ItemState::Cannot);
        assert!(no_parser.cause.unwrap().contains("apparmor_parser"));

        let missing = userns_item_over(&restricted).unwrap();
        assert_eq!(missing.state, ItemState::Missing);
        assert_eq!(missing.id, "userns-profile");
        let script = missing.script.unwrap();
        for step in [
            "cat > /etc/apparmor.d/tunables/minimald <<\\MINIMAL_APPARMOR_TUNABLE_EOF\n",
            "cat > /etc/apparmor.d/minimald <<\\MINIMAL_APPARMOR_PROFILE_EOF\n",
            "profile minimald @{minimald_bin} flags=(unconfined) {\n",
            "apparmor_parser --replace /etc/apparmor.d/minimald\n",
        ] {
            assert!(script.contains(step), "{step:?} in {script}");
        }
        assert!(!script.contains("minimald.d/local"), "{script}");

        // A daemon outside the stock paths: attached by the local tunable,
        // and the profile already loaded does not count until it names it.
        let dev = UsernsFacts {
            daemon: Some("/opt/minimal/bin/minimald".to_string()),
            ..restricted.clone()
        };
        let script = userns_item_over(&dev).unwrap().script.unwrap();
        assert!(
            script.contains(
                "printf '@{minimald_bin} += %s\\n' '/opt/minimal/bin/minimald' > \
                 /etc/apparmor.d/tunables/minimald.d/local\n"
            ),
            "{script}"
        );
        assert_eq!(
            userns_item_over(&UsernsFacts {
                profile_installed: true,
                ..dev.clone()
            })
            .unwrap()
            .state,
            ItemState::Missing
        );
        assert_eq!(
            userns_item_over(&UsernsFacts {
                profile_installed: true,
                tunables_name_daemon: true,
                ..dev.clone()
            })
            .unwrap()
            .state,
            ItemState::Done
        );

        // A path an AppArmor tunable cannot name is a fact no script fixes,
        // never a silently dropped attachment.
        for path in [
            "/opt/my minimal/minimald",
            "/opt/min#1/minimald",
            "/opt/it's/minimald",
        ] {
            let item = userns_item_over(&UsernsFacts {
                daemon: Some(path.to_string()),
                ..dev.clone()
            })
            .unwrap();
            assert_eq!(item.state, ItemState::Cannot, "{path}");
            assert!(item.cause.as_deref().unwrap().contains(path), "{item:?}");
        }
    }

    /// The classifier item's table: done on the marker with a current
    /// copy of the step; blocked by the mount, or by an account or socket
    /// path the step cannot quote into a shell word and a unit file;
    /// otherwise missing, with its step — a marker over a stale copy
    /// included, so an upgrade's next run refreshes what the placement
    /// unit runs.
    #[test]
    fn classifier_item_table() {
        use linux::{Cgroup2Mount, cgroup2_mount_from, classifier_item_over};
        assert_eq!(
            cgroup2_mount_from(
                "38 30 0:25 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 \
                 cgroup2 rw,nsdelegate,memory_recursiveprot\n"
            ),
            Cgroup2Mount::Delegated
        );
        assert_eq!(
            cgroup2_mount_from(
                "38 30 0:25 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 \
                 cgroup2 rw\n"
            ),
            Cgroup2Mount::WithoutNsdelegate
        );
        assert_eq!(
            cgroup2_mount_from("38 30 0:26 / / rw,relatime - ext4 /dev/root rw\n"),
            Cgroup2Mount::Absent
        );
        let sock = "/home/alice/.local/state/minimal/providers/local-minimald0/ssh.sock";
        let over = |marker: bool, current: bool, mount, operator: &str, socket: &str| {
            classifier_item_over(marker, current, None, mount, operator, socket)
        };
        assert_eq!(
            over(true, true, Cgroup2Mount::Absent, "alice", sock).state,
            ItemState::Done
        );
        let unquotable = "cannot be quoted";
        for (mount, operator, socket, word) in [
            (Cgroup2Mount::Absent, "alice", sock, "no cgroup2 filesystem"),
            (
                Cgroup2Mount::WithoutNsdelegate,
                "alice",
                sock,
                "without nsdelegate",
            ),
            (Cgroup2Mount::Delegated, "", sock, "user name did not read"),
            (Cgroup2Mount::Delegated, "al ice", sock, unquotable),
            (Cgroup2Mount::Delegated, "al'ice", sock, unquotable),
            (Cgroup2Mount::Delegated, "al%ice", sock, unquotable),
            (Cgroup2Mount::Delegated, "al$ice", sock, unquotable),
            (Cgroup2Mount::Delegated, "al\\ice", sock, unquotable),
            (
                Cgroup2Mount::Delegated,
                "alice",
                "",
                "socket path did not resolve",
            ),
            (
                Cgroup2Mount::Delegated,
                "alice",
                "/run/it's.sock",
                unquotable,
            ),
            (
                Cgroup2Mount::Delegated,
                "alice",
                "/run/my dir/ssh.sock",
                unquotable,
            ),
            (
                Cgroup2Mount::Delegated,
                "alice",
                "/run/my\tdir/ssh.sock",
                unquotable,
            ),
            (
                Cgroup2Mount::Delegated,
                "alice",
                "/run/%h/ssh.sock",
                unquotable,
            ),
            (
                Cgroup2Mount::Delegated,
                "alice",
                "/run/$HOME/ssh.sock",
                unquotable,
            ),
            (
                Cgroup2Mount::Delegated,
                "alice",
                "/run/a\\b/ssh.sock",
                unquotable,
            ),
        ] {
            let item = over(false, false, mount, operator, socket);
            assert_eq!(item.state, ItemState::Cannot, "{item:?}");
            assert_eq!(item.id, "classifier");
            assert!(item.cause.as_deref().unwrap().contains(word), "{item:?}");
        }
        let item = over(false, false, Cgroup2Mount::Delegated, "alice", sock);
        assert_eq!(item.state, ItemState::Missing, "{item:?}");
        assert!(item.today.as_deref().unwrap().contains("unenforced"));
        assert!(item.step.as_deref().unwrap().contains("every daemon start"));
        // The marker over a stale copy: the step is there, but the one the
        // placement unit runs is not this build's, so it is missing again
        // and the block (the same block) refreshes it.
        let stale = over(true, false, Cgroup2Mount::Delegated, "alice", sock);
        assert_eq!(stale.state, ItemState::Missing, "{stale:?}");
        assert!(
            stale.today.as_deref().unwrap().contains("stale step"),
            "{stale:?}"
        );
        assert_eq!(
            stale.script, item.script,
            "one block installs and refreshes"
        );
        // A stale copy on a mount the tree cannot live in is still the mount's fault.
        assert_eq!(
            over(true, false, Cgroup2Mount::Absent, "alice", sock).state,
            ItemState::Cannot
        );
        // A tree delegated to another account is that account's install:
        // never Done for this one, never replaced by this one, whatever
        // else the host looks like.
        for (marker, current, mount) in [
            (true, true, Cgroup2Mount::Delegated),
            (false, false, Cgroup2Mount::Delegated),
            (true, false, Cgroup2Mount::Absent),
        ] {
            let theirs = classifier_item_over(marker, current, Some(1001), mount, "alice", sock);
            assert_eq!(theirs.state, ItemState::Cannot, "{theirs:?}");
            let cause = theirs.cause.as_deref().unwrap();
            assert!(
                cause.contains("installed for another account (uid 1001)")
                    && cause.contains("--undo"),
                "{cause}"
            );
        }
    }

    /// The classifier step leaves the daemon placed on every start without
    /// a root step of its own: the install runs the step from a root-owned
    /// copy of the bytes this binary carries (no fetch, no placeholder, no
    /// source identity), and installs a path unit on the daemon's socket
    /// whose oneshot runs the step's `--place-listener` — so a daemon
    /// restart is placed by the manager, never by a per-restart `--pid`.
    #[test]
    fn classifier_step_places_the_daemon_on_every_start() {
        use crate::resolver::{
            CLASSIFIER_PROGRAM_PATH, CLASSIFIER_SCRIPT, CLASSIFIER_SCRIPT_HEREDOC,
            PLACE_UNIT_PATH_PATH, PLACE_UNIT_SERVICE_PATH,
        };
        use linux::{Cgroup2Mount, classifier_item_over};
        let sock = "/home/alice/.local/state/minimal/providers/local-minimald0/ssh.sock";
        let item = classifier_item_over(false, false, None, Cgroup2Mount::Delegated, "alice", sock);
        let script = item.script.expect("a missing item carries its block");
        for line in [
            format!("cat > {CLASSIFIER_PROGRAM_PATH} <<\\{CLASSIFIER_SCRIPT_HEREDOC}\n"),
            format!("{CLASSIFIER_SCRIPT}{CLASSIFIER_SCRIPT_HEREDOC}\n"),
            format!("chmod 0755 {CLASSIFIER_PROGRAM_PATH}\n"),
            format!("{CLASSIFIER_PROGRAM_PATH} --user 'alice'\n"),
            format!("cat > {PLACE_UNIT_SERVICE_PATH} <<"),
            format!(
                "ExecStart={CLASSIFIER_PROGRAM_PATH} --user 'alice' --place-listener '{sock}'\n"
            ),
            format!("cat > {PLACE_UNIT_PATH_PATH} <<"),
            format!("PathChanged={sock}\n"),
            "Unit=minimald-place.service\n".to_string(),
            "WantedBy=multi-user.target\n".to_string(),
            "systemctl daemon-reload\n".to_string(),
            "systemctl enable --now minimald-place.path\n".to_string(),
            "systemctl start minimald-place.service\n".to_string(),
            "if ! command -v systemctl >/dev/null 2>&1 ; then\n".to_string(),
            "systemctl reset-failed minimald-place.path".to_string(),
        ] {
            assert!(script.contains(&line), "the block runs {line:?}: {script}");
        }
        // The step's own run is unconditional; only the unit pair waits on
        // systemd, so a host without it still gets the tree and the table.
        let (step_part, unit_part) = script
            .split_once("if ! command -v systemctl")
            .expect("the unit guard splits the block");
        assert!(
            step_part.contains("--user 'alice'\n") && !step_part.contains("systemctl"),
            "the step runs before and outside the systemd guard: {step_part}"
        );
        assert!(unit_part.trim_end().ends_with("fi"), "{unit_part}");
        for absent in [
            "--pid",
            "--cohort-address",
            "--node-plane-address",
            "curl",
            "raw.githubusercontent.com",
        ] {
            assert!(
                !script.replace(CLASSIFIER_SCRIPT, "").contains(absent),
                "the block's own lines never carry {absent:?}: {script}"
            );
        }
        assert!(
            !CLASSIFIER_SCRIPT
                .lines()
                .any(|line| line == CLASSIFIER_SCRIPT_HEREDOC),
            "the delimiter never occurs in the script it delimits"
        );
    }

    /// The KVM item's table: done when the device opens, a group step on
    /// permission denied, blocked when the device is not there.
    #[test]
    fn kvm_item_table() {
        use linux::kvm_item_over;
        use std::io::{Error, ErrorKind};
        assert_eq!(kvm_item_over(Ok(()), "alice").state, ItemState::Done);
        let missing = kvm_item_over(Err(Error::from(ErrorKind::PermissionDenied)), "alice");
        assert_eq!(missing.state, ItemState::Missing);
        assert_eq!(missing.id, "kvm-group");
        let script = missing.script.unwrap();
        assert!(script.contains("usermod -aG kvm 'alice'\n"), "{script}");
        assert!(
            script
                .contains("printf '%s\\n' 'alice' > /var/lib/minimal/finalize-install-kvm-group\n"),
            "{script}"
        );
        assert!(missing.step.unwrap().contains("next login"));
        let absent = kvm_item_over(Err(Error::from(ErrorKind::NotFound)), "alice");
        assert_eq!(absent.state, ItemState::Cannot);
        assert!(absent.cause.unwrap().contains("/dev/kvm is not there"));
        assert_eq!(
            kvm_item_over(Err(Error::from(ErrorKind::PermissionDenied)), "").state,
            ItemState::Cannot
        );
    }
}
