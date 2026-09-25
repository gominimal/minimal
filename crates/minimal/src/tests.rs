use super::*;

/// Interactive attach over a non-terminal stdin must fail fast rather than
/// force `ssh -tt` into an indefinite block (#953). A real terminal (or a
/// pty driver) passes the guard so the shell can open.
#[test]
fn interactive_attach_requires_a_tty_on_stdin() {
    let err = ensure_interactive_attach_tty(false)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("not a TTY"),
        "expected an actionable non-TTY error, got: {err}"
    );
    ensure_interactive_attach_tty(true).expect("a real terminal must pass the guard");
}

/// The interactive attach no longer `exec()`s ssh — it waits on it so the
/// terminal can be put back afterwards (#1210) — so the status ssh reports
/// has to become this process's own, signalled children included.
#[test]
fn ssh_status_becomes_the_clients_exit_code() {
    use std::os::unix::process::ExitStatusExt as _;

    assert_eq!(exit_code_of(std::process::ExitStatus::from_raw(0)), 0);
    // wait(2) encoding: the exit code sits in the high byte.
    assert_eq!(exit_code_of(std::process::ExitStatus::from_raw(3 << 8)), 3);
    // A signalled child reports no code of its own; the shell's 128 + n.
    // 9 is SIGKILL, in the low bits where wait(2) puts the signal.
    assert_eq!(exit_code_of(std::process::ExitStatus::from_raw(9)), 137);
}

/// A CLI upgraded past its daemon must be refused up front, naming both
/// builds and the recovery. Before #1251 the skew surfaced only at
/// `FinalizeSession`, by which point the activation's cleanup had already
/// destroyed the session it had just created.
#[test]
fn version_skew_is_reported_with_both_builds_and_a_recovery() {
    let msg = client::version_skew_message("0.6.0", "0.5.0-dev.12.g86ce5c3a")
        .expect("differing builds are a skew");
    assert!(msg.contains("0.6.0"), "missing the CLI version: {msg}");
    assert!(
        msg.contains("0.5.0-dev.12.g86ce5c3a"),
        "missing the daemon version: {msg}"
    );
    assert!(msg.contains("min stop"), "missing the recovery: {msg}");
    assert!(
        msg.contains(client::SKEW_OVERRIDE_VAR),
        "missing the override: {msg}"
    );
}

/// Every direct daemon connection in this crate is either version-gated or
/// deliberately not, and this test is where that decision is recorded.
///
/// #1251 shipped the gate but wired it to two call sites; the rest reached
/// activations and live-session hand-offs ungated. A new connection is easy
/// to add and easy to forget, so the inventory is asserted rather than
/// documented: adding, removing, or un-gating one fails here and forces the
/// same judgement — can this path leave daemon state half-built (gate it),
/// or must it work *because* the pair is skewed (leave it, with a comment
/// saying why)?
#[test]
fn every_daemon_connection_is_classified() {
    assert_eq!(
        connect_site_inventory(env!("CARGO_MANIFEST_DIR")),
        [
            "cmd/admin.rs::cmd_ssh_forward = gated",
            "cmd/admin.rs::cmd_version = ungated",
            "cmd/list.rs::cmd_bare = gated",
            "cmd/mod.rs::arm_activation_interrupt = ungated",
            "cmd/mod.rs::connect_daemon_unchecked = ungated",
            "cmd/session.rs::cmd_attach = gated",
            "cmd/session.rs::cmd_exec = gated",
            "cmd/session.rs::cmd_session_run = gated",
            "cmd/session.rs::cmd_session_setup_zed = gated",
            "diag/net.rs::probe_socket = ungated",
            "task.rs::arm_task_run_interrupt = ungated",
        ]
    );
}

/// Every `CreateSession` this crate sends states, in the request itself,
/// whether it asserts the daemon's build.
///
/// The struct field makes omitting the decision a compile error; this
/// makes answering it "no" a visible one. Both session-creating paths
/// assert — they are the ones #1251 is about — and the inventory is what
/// stops a third from quietly passing `None`.
#[test]
fn every_create_session_asserts_the_daemon_build() {
    assert_eq!(
        create_site_inventory(env!("CARGO_MANIFEST_DIR")),
        [
            "cmd/session.rs::activate_session = asserts",
            "task.rs::cmd_task_run = asserts",
        ]
    );
}

/// The activation path must not spend a round trip on the version.
///
/// That was the cost of #1251's first fix: a `GetVersion` ahead of the
/// create, on the one path where an extra RTT is felt. The check now rides
/// on the `CreateSession` the path was already sending, so the marks of
/// the old mechanism — `GetVersion`, `ensure_version_match`, or the
/// `connect_daemon` that issues it — must be absent from both creators,
/// and the marks of the new one present.
#[test]
fn the_activation_path_makes_no_version_round_trip() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, func) in [
        ("src/cmd/session.rs", "activate_session"),
        ("src/task.rs", "cmd_task_run"),
    ] {
        let text = std::fs::read_to_string(manifest.join(file)).expect("readable source");
        let body =
            function_body(&text, func).unwrap_or_else(|| panic!("{file} no longer defines {func}"));
        for round_trip in ["GetVersion", "ensure_version_match", "connect_daemon("] {
            assert!(
                !body.contains(round_trip),
                "{func} reintroduced a version round trip ({round_trip})"
            );
        }
        assert!(
            body.contains("must_match_version"),
            "{func} no longer asserts its build on the create"
        );
        assert!(
            body.contains("ensure_version_reported"),
            "{func} no longer checks the build the create echoed back"
        );
    }
}

/// The code of the named free function, from its `fn` line to the next
/// one, with comment lines dropped — the prose here talks *about* the
/// mechanisms the caller is scanning for, and a rationale comment naming
/// `GetVersion` must not read as a call to it.
fn function_body(text: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let decls = fn_decl_lines(&lines);
    let start = decls.iter().position(|(_, n)| n == name)?;
    let from = decls[start].0;
    let to = decls.get(start + 1).map_or(lines.len(), |(d, _)| *d);
    Some(
        lines[from..to]
            .iter()
            .filter(|l| !l.trim_start().starts_with("//"))
            .copied()
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Every free-function declaration in `lines`, as `(line index, name)`.
fn fn_decl_lines(lines: &[&str]) -> Vec<(usize, String)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let t = l.trim_start();
            let t = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            let t = t.strip_prefix("async ").unwrap_or(t);
            t.strip_prefix("fn ")
                .map(|rest| (i, rest.split(['(', '<']).next().unwrap_or("").to_string()))
        })
        .collect()
}

/// Every `.rs` file under `<crate>/src`, sorted.
fn crate_sources(manifest_dir: &str) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    let src = std::path::Path::new(manifest_dir).join("src");
    let mut files = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("crate src must be readable") {
            let path = entry.expect("readable dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    (src, files)
}

/// Attributes every line matching `needle` under `<crate>/src` to the
/// function containing it, labelling that function by whether its body
/// carries one of `markers`.
fn source_inventory(
    manifest_dir: &str,
    needle: &str,
    markers: &[&str],
    labels: (&str, &str),
) -> Vec<String> {
    let (src, files) = crate_sources(manifest_dir);
    let mut sites = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("source file must be readable");
        let lines: Vec<&str> = text.lines().collect();
        let decls = fn_decl_lines(&lines);
        let rel = path
            .strip_prefix(&src)
            .expect("scanned under src")
            .to_string_lossy()
            .into_owned();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(needle) {
                continue;
            }
            let (start, name) = decls
                .iter()
                .rev()
                .find(|(d, _)| *d < i)
                .cloned()
                .unwrap_or((0, "<top level>".to_string()));
            let end = decls
                .iter()
                .find(|(d, _)| *d > start)
                .map_or(lines.len(), |(d, _)| *d);
            let marked = lines[start..end]
                .iter()
                .any(|l| markers.iter().any(|m| l.contains(m)));
            sites.push(format!(
                "{rel}::{name} = {}",
                if marked { labels.0 } else { labels.1 }
            ));
        }
    }
    sites.sort();
    sites
}

/// Attributes every `CreateSessionRequest` construction under
/// `<crate>/src` to its function, and reports whether it asserts this
/// build.
fn create_site_inventory(manifest_dir: &str) -> Vec<String> {
    // Built by concatenation so this scanner does not match itself.
    const NEEDLE: &str = concat!("CreateSession", "Request {");
    source_inventory(
        manifest_dir,
        NEEDLE,
        &[
            "must_match_version: version_assertion()",
            "must_match_version: minimal_client::version_assertion()",
        ],
        ("asserts", "asserts nothing"),
    )
}

/// Attributes every direct `Client` connection under `<crate>/src` to the
/// function that opens it, and reports whether that function also applies
/// the version gate. Source-level on purpose: the alternative is a live
/// daemon per call site.
///
/// A path counts as gated whichever way it gets its answer: the
/// `GetVersion` round trip (`ensure_version_match`), a build a reply it was
/// already making carried (`ensure_version_reported`, directly or through a
/// `*_version_gated` lookup helper), or the assertion it puts on its own
/// `CreateSession`. What the inventory records is that the decision was
/// made, not which mechanism made it.
fn connect_site_inventory(manifest_dir: &str) -> Vec<String> {
    // Built by concatenation so this scanner does not match itself.
    const NEEDLE: &str = concat!("Client", "::connect(");
    source_inventory(
        manifest_dir,
        NEEDLE,
        &[
            "ensure_version_match",
            "ensure_version_reported",
            "_version_gated(",
            "must_match_version",
        ],
        ("gated", "ungated"),
    )
}

/// Matching builds are the overwhelmingly common case and must cost the
/// operator nothing.
#[test]
fn matching_versions_are_not_a_skew() {
    assert!(client::version_skew_message(version::VERSION, version::VERSION).is_none());
}

/// The host-cache warm-up is gated on the session provider: a VM-backed
/// provider caches on its own guest volume and never reads the host cache,
/// so `--provider local-minvmd` (and macOS, always minvmd-backed) skip the
/// warm-up, while the native daemon shares the host cache and downloads.
#[test]
fn host_cache_warmup_skips_vm_backed_providers() {
    assert!(
        !should_warm_host_cache(true),
        "a VM-backed provider must not warm the host cache"
    );
    // macOS is always minvmd-backed regardless of the flag; elsewhere the
    // native daemon shares the host cache, so the warm-up runs.
    assert_eq!(should_warm_host_cache(false), !cfg!(target_os = "macos"));
}

/// The `Cli` command tree must stay well-formed: a malformed clap
/// definition panics in `debug_assert`/render, not at parse time, so
/// `min --help` (which bare `min` no longer prints, but which must keep
/// working unchanged) stays renderable.
#[test]
fn cli_command_tree_stays_renderable() {
    use clap::CommandFactory as _;
    Cli::command().debug_assert();
}

/// Entry constructor for the bare-`min` state-report tests.
fn twin_entry(
    id: &str,
    name: Option<&str>,
    path: Option<&str>,
    status: sessions::SessionStatus,
) -> minimald_rpc::ListSessionsEntry {
    minimald_rpc::ListSessionsEntry {
        id: sessions::SessionId::parse_str(id).unwrap(),
        name: name.map(str::to_owned),
        project_path: path.map(|p| paths::HostAbsPath::try_new(p).unwrap()),
        status,
        git: None,
        attrs: None,
    }
}

/// One cwd-matching session: the report names it with its status, and the
/// `Next:` attach line carries its real name — every line verbatim.
#[test]
fn bare_status_renders_a_cwd_session_verbatim() {
    let entries = vec![twin_entry(
        "019f5d0f-0a99-78b1-9165-0809440f0052",
        Some("web"),
        Some("/w"),
        sessions::SessionStatus::Active,
    )];
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    assert_eq!(
        render_bare_status("~/w", &entries, &cwd, true),
        "No terminal: not attaching. State for ~/w:\n\
             \x20 sessions: 1 (web, active)\n\
             \x20 blueprint: minimal.toml present\n\
             Next:\n\
             \x20 min session attach --command 'min task run <task>' web\n\
             \x20 min ls --json\n"
    );
}

/// A session already tracked for the target path warns with that
/// session's handle and the `attach` reuse hint; a path with no session
/// stays silent.
#[test]
fn duplicate_session_warning_flags_only_a_matching_path() {
    let entries = vec![twin_entry(
        "019f5d0f-0a99-78b1-9165-0809440f0052",
        Some("web"),
        Some("/w"),
        sessions::SessionStatus::Active,
    )];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(warning.contains("web"), "warning names the existing handle");
    assert!(
        warning.contains("min session attach web"),
        "warning points at attach for reuse"
    );

    let free = paths::HostAbsPath::try_new("/elsewhere").unwrap();
    assert!(
        duplicate_session_warning(&entries, &free).is_none(),
        "an untaken path does not warn"
    );
}

/// An unnamed existing session must still be reusable: the reuse hint must
/// carry the full id, which `SessionLookup::parse` resolves back to an id.
/// The short unnamed handle would parse as a nonexistent name, so the attach
/// lookup would miss.
#[test]
fn duplicate_session_warning_reuses_unnamed_session_by_id() {
    let id = "019f5d0f-0a99-78b1-9165-0809440f0052";
    let entries = vec![twin_entry(
        id,
        None,
        Some("/w"),
        sessions::SessionStatus::Active,
    )];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(
        warning.contains(&format!("min session attach {id}")),
        "unnamed reuse hint carries the full id, got: {warning}"
    );
    // The id the hint prints must resolve through the attach lookup path.
    assert!(
        matches!(SessionLookup::parse(id), SessionLookup::Id(_)),
        "the full id resolves as an id, not a name"
    );
}

/// Attach refuses a `Materializing` session, so the warning must not point
/// at it; the duplicate is still flagged, just without an attach hint.
#[test]
fn duplicate_session_warning_skips_attach_for_materializing() {
    let entries = vec![twin_entry(
        "019f5d0f-0a99-78b1-9165-0809440f0052",
        Some("web"),
        Some("/w"),
        sessions::SessionStatus::Materializing,
    )];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(
        !warning.contains("min session attach"),
        "no attach hint for a non-attachable session, got: {warning}"
    );
}

/// When several sessions track the target path with mixed statuses, the
/// warning must recommend the `Active` one — the only status `attach`
/// accepts — even when a non-active match sorts first in the listing.
#[test]
fn duplicate_session_warning_prefers_active_over_pending_match() {
    let pending_id = "019f5d0f-0a99-78b1-9165-0809440f0052";
    let active_id = "019f5d0f-0a99-78b1-9165-0809440f0053";
    let entries = vec![
        twin_entry(
            pending_id,
            Some("mzing"),
            Some("/w"),
            sessions::SessionStatus::Materializing,
        ),
        twin_entry(
            active_id,
            Some("live"),
            Some("/w"),
            sessions::SessionStatus::Active,
        ),
    ];

    let taken = paths::HostAbsPath::try_new("/w").unwrap();
    let warning = duplicate_session_warning(&entries, &taken)
        .expect("a session on the target path must warn");
    assert!(
        warning.contains("min session attach live"),
        "warning points at the active match for reuse, got: {warning}"
    );
    assert!(
        !warning.contains("still being created"),
        "an attachable active match must not print the wait guidance, got: {warning}"
    );
}

/// No sessions anywhere and no blueprint: the report says so and the
/// `Next:` lines become the create-and-attach pair — every line verbatim.
#[test]
fn bare_status_renders_the_empty_state_verbatim() {
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    assert_eq!(
        render_bare_status("/w", &[], &cwd, false),
        "No terminal: not attaching. State for /w:\n\
             \x20 sessions: none\n\
             \x20 blueprint: none (min init to create one)\n\
             Next:\n\
             \x20 min session activate --attach .\n\
             \x20 min ls --json\n"
    );
}

/// Sessions exist but none for this cwd: counted as elsewhere, and the
/// `Next:` lines still offer create-and-attach (attaching to another
/// project's session is not the suggestion).
#[test]
fn bare_status_counts_elsewhere_sessions() {
    let entries = vec![
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            Some("api"),
            Some("/other"),
            sessions::SessionStatus::Active,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0066",
            None,
            Some("/third"),
            sessions::SessionStatus::Pending,
        ),
    ];
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    let out = render_bare_status("/w", &entries, &cwd, true);
    assert!(
        out.contains("  sessions: 0 here (2 elsewhere)\n"),
        "elsewhere count: {out}"
    );
    assert!(
        out.contains("  min session activate --attach .\n"),
        "no cwd session must suggest activate: {out}"
    );
    assert!(
        !out.contains("session attach --command"),
        "must not suggest attaching elsewhere: {out}"
    );
}

/// More than two cwd matches: the count is the full total, the listing
/// stops at two, and an unnamed session shows its short id — which is
/// also what the attach suggestion substitutes for the first match.
#[test]
fn bare_status_lists_at_most_two_cwd_sessions() {
    let entries = vec![
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            None,
            Some("/w"),
            sessions::SessionStatus::Pending,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0066",
            Some("web"),
            Some("/w"),
            sessions::SessionStatus::Materializing,
        ),
        twin_entry(
            "019f5d0f-0a99-78b1-9165-0809440f0077",
            Some("spare"),
            Some("/w"),
            sessions::SessionStatus::Active,
        ),
    ];
    let cwd = paths::HostAbsPath::try_new("/w").unwrap();
    let out = render_bare_status("/w", &entries, &cwd, true);
    assert!(
        out.contains("  sessions: 3 (019f5d0f, pending), (web, materializing)\n"),
        "count-then-two listing: {out}"
    );
    assert!(
        !out.contains("spare"),
        "third session must not be listed: {out}"
    );
    assert!(
        out.contains("  min session attach --command 'min task run <task>' 019f5d0f\n"),
        "attach suggestion uses the first match's handle: {out}"
    );
}

/// `~` abbreviation: exactly under home, home itself, and a path outside
/// home (which renders absolute, untouched).
#[test]
fn display_with_home_tilde_abbreviates_only_under_home() {
    fn p(s: &str) -> &camino::Utf8Path {
        camino::Utf8Path::new(s)
    }
    assert_eq!(
        display_with_home_tilde(p("/home/u/code/app"), Some(p("/home/u"))),
        "~/code/app"
    );
    assert_eq!(
        display_with_home_tilde(p("/home/u"), Some(p("/home/u"))),
        "~"
    );
    assert_eq!(
        display_with_home_tilde(p("/srv/app"), Some(p("/home/u"))),
        "/srv/app"
    );
    assert_eq!(display_with_home_tilde(p("/srv/app"), None), "/srv/app");
}

/// The attach/create confirmation prefers the session name and appends a
/// short id so two same-named sessions built from the same directory are
/// still distinguishable; an unnamed session falls back to the short id
/// alone rather than the full 36-character UUID.
#[test]
fn session_announce_label_prefers_name_with_short_id() {
    let id = sessions::SessionId::parse_str("a1b2c3d4-0000-0000-0000-000000000000").unwrap();
    assert_eq!(session_announce_label(&id, Some("api")), "api (a1b2c3d4)");
    assert_eq!(session_announce_label(&id, None), "a1b2c3d4");
}

/// A session created without `--name` gets a typable `<dir>-<hex>` handle:
/// the basename is lowercased and stripped to the name alphabet, and the
/// caller-supplied hex tails it.
#[test]
fn autogen_session_name_slugs_the_basename() {
    assert_eq!(
        autogen_session_name(camino::Utf8Path::new("/home/u/code/foo"), "9c1e"),
        "foo-9c1e"
    );
    // Disallowed characters are dropped and the rest lowercased.
    assert_eq!(
        autogen_session_name(camino::Utf8Path::new("/tmp/My Project!"), "4f2a"),
        "myproject-4f2a"
    );
    // A basename that sanitizes to nothing falls back to `session`.
    assert_eq!(
        autogen_session_name(camino::Utf8Path::new("/"), "0001"),
        "session-0001"
    );
}

/// Sanitization drops out-of-alphabet characters, trims leading/trailing
/// separators, and falls back to `session` for an all-symbol basename, so
/// the minted name always clears `validate_session_name`.
#[test]
fn sanitize_name_component_trims_and_falls_back() {
    assert_eq!(sanitize_name_component("--foo--"), "foo");
    assert_eq!(sanitize_name_component("café"), "caf");
    assert_eq!(sanitize_name_component("...."), "session");
    assert_eq!(sanitize_name_component("a\tb"), "ab");
}

/// The minted suffix is exactly four lowercase hex digits.
#[test]
fn random_hex4_is_four_lowercase_hex_digits() {
    let h = random_hex4();
    assert_eq!(h.len(), 4);
    assert!(
        h.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "expected four lowercase hex digits, got {h:?}"
    );
}

/// Only an autogen name retries on collision, and only within the bounded
/// budget; a user-supplied name never retries, so its collision passes
/// through, and a non-collision failure is never retried.
#[test]
fn autogen_collision_retry_is_bounded_and_skips_user_names() {
    let collision = "A session with that name already exists";
    assert!(should_retry_autogen(true, 0, collision));
    assert!(should_retry_autogen(
        true,
        AUTOGEN_NAME_RETRIES - 1,
        collision
    ));
    // Budget spent: stop retrying.
    assert!(!should_retry_autogen(true, AUTOGEN_NAME_RETRIES, collision));
    // A user-supplied name never retries — its collision surfaces verbatim.
    assert!(!should_retry_autogen(false, 0, collision));
    // A non-collision failure is never retried.
    assert!(!should_retry_autogen(true, 0, "CreateSession failed: boom"));
}

#[test]
fn provider_local_minvmd_selects_the_vm_backend() {
    use clap::Parser as _;
    let cli = Cli::try_parse_from(["min", "--provider", "local-minvmd", "ls"]).unwrap();
    assert!(cli.global_args.use_minvmd());
}

#[test]
fn provider_local_minimald_is_the_host_backend() {
    use clap::Parser as _;
    let cli = Cli::try_parse_from(["min", "--provider", "local-minimald", "ls"]).unwrap();
    assert!(!cli.global_args.use_minvmd());
}

#[test]
fn no_provider_defaults_to_the_host_backend() {
    use clap::Parser as _;
    let cli = Cli::try_parse_from(["min", "ls"]).unwrap();
    assert!(!cli.global_args.use_minvmd());
}

/// `min session list` is the canonical `<noun> list` spelling of the
/// flagship list command; `min ls` (top-level) and `min session ls`
/// (noun-level) are visible aliases. All three parse to the same `LsArgs`,
/// so `--raw`/`--json` reach the one `cmd_ls` implementation identically.
#[test]
fn session_list_spellings_all_reach_ls() {
    use clap::Parser as _;
    let ls_args = |args: &[&str]| -> LsArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Ls(a))
            | Some(Command::Session(SessionArgs {
                command: SessionCommand::List(a),
            })) => a,
            _ => panic!("expected an ls command for {args:?}"),
        }
    };

    for spelling in [
        ["min", "session", "list"].as_slice(),
        ["min", "session", "ls"].as_slice(),
        ["min", "ls"].as_slice(),
    ] {
        let a = ls_args(spelling);
        assert!(
            !a.raw && !a.json,
            "{spelling:?} must default both flags off"
        );
    }

    // `--raw`/`--json` are accepted on the canonical and the bare form alike.
    let canonical = ls_args(&["min", "session", "list", "--raw"]);
    assert!(canonical.raw && !canonical.json);
    let bare = ls_args(&["min", "ls", "--json"]);
    assert!(bare.json && !bare.raw);
}

/// `setup-zed` takes the session the way every other session verb does —
/// `min session <verb> <session>`. The project path is not an option: it is
/// always the in-box workspace root.
#[test]
fn setup_zed_parses_as_a_session_verb() {
    use clap::Parser as _;
    let setup_zed_args = |args: &[&str]| -> SetupZedArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Session(SessionArgs {
                command: SessionCommand::SetupZed(a),
            })) => a,
            _ => panic!("expected a setup-zed command for {args:?}"),
        }
    };

    let args = setup_zed_args(&["min", "session", "setup-zed", "my-box"]);
    assert_eq!(args.session, "my-box");
    assert!(!args.print);
    assert!(args.settings.is_none());

    let printing = setup_zed_args(&["min", "session", "setup-zed", "my-box", "--print"]);
    assert!(printing.print);

    // The project path is fixed, so there is no flag to set it.
    assert!(
        Cli::try_parse_from([
            "min",
            "session",
            "setup-zed",
            "my-box",
            "--path",
            "/elsewhere"
        ])
        .is_err(),
        "--path must not be accepted"
    );
}

/// Hidden for now: absent from `min session --help` and from the
/// completions clap generates, while still parsing and running.
#[test]
fn setup_zed_is_hidden() {
    use clap::CommandFactory as _;
    let cli = Cli::command();
    let session = cli.find_subcommand("session").expect("session subcommand");
    let setup_zed = session
        .find_subcommand("setup-zed")
        .expect("setup-zed subcommand");
    assert!(setup_zed.is_hide_set(), "setup-zed must stay hidden");
    // The visible siblings are unaffected.
    assert!(!session.find_subcommand("attach").unwrap().is_hide_set());
}

/// `--raw` and `--json` select mutually exclusive output formats, so
/// passing both must be rejected rather than silently letting one win.
#[test]
fn ls_raw_and_json_conflict() {
    use clap::Parser as _;
    assert!(Cli::try_parse_from(["min", "ls", "--raw", "--json"]).is_err());
}

/// `repo_dir` and `minimal_dir` are global, so they must be accepted after
/// the subcommand — not just before it (#1039).
#[test]
fn repo_and_minimal_dir_are_accepted_after_the_subcommand() {
    use clap::Parser as _;
    let cli =
        Cli::try_parse_from(["min", "ls", "-C", "/tmp/x", "--minimal-dir", "/tmp/y"]).unwrap();
    let p = std::path::Path::new;
    assert_eq!(cli.global_args.repo_dir.as_deref(), Some(p("/tmp/x")));
    assert_eq!(cli.global_args.minimal_dir.as_deref(), Some(p("/tmp/y")));
}

/// `session destroy` must present `[SESSION]` and `--all` as mutually
/// exclusive alternatives, one required. Regression for #1038: the error
/// path used to hide `--all` and demand a session outright, yielding a
/// usage line that could never parse.
#[test]
fn destroy_models_session_and_all_as_required_alternatives() {
    use clap::Parser as _;
    let parse = |args: &[&str]| Cli::try_parse_from(args);

    // Exactly one of a session or --all is required; both together conflict.
    assert!(parse(&["min", "session", "destroy", "web"]).is_ok());
    assert!(parse(&["min", "session", "destroy", "--all"]).is_ok());
    assert!(parse(&["min", "session", "destroy"]).is_err());
    assert!(parse(&["min", "session", "destroy", "--all", "web"]).is_err());

    // --force skips the confirm on either target: --all, or — since the
    // single-session confirm landed — a bare session too.
    assert!(parse(&["min", "session", "destroy", "--all", "--force"]).is_ok());
    assert!(parse(&["min", "session", "destroy", "web", "--force"]).is_ok());
    assert!(parse(&["min", "session", "destroy", "web", "-f"]).is_ok());
    // ... but never stands in for the required target.
    assert!(parse(&["min", "session", "destroy", "-f"]).is_err());
}

/// The single-session destroy gate is dirty-only: `--force` and a
/// proven-clean session proceed promptless in every mode (including
/// headless); dirty and unknowable states prompt interactively and
/// refuse headless, naming `--force` — EOF must never read as consent.
#[test]
fn destroy_gate_fires_only_for_dirty_or_unknowable_state() {
    let dirty = || AtRiskState::Dirty(vec!["1 file with uncommitted changes:".to_string()]);

    // --force proceeds promptless regardless of state or mode.
    for state in [AtRiskState::Clean, dirty(), AtRiskState::Unknowable] {
        assert_eq!(
            destroy_gate(true, &state, true, false).unwrap(),
            DestroyGate::Proceed
        );
    }

    // Proven clean proceeds without --force — even headless.
    for (no_input, tty) in [(false, true), (true, true), (false, false)] {
        assert_eq!(
            destroy_gate(false, &AtRiskState::Clean, no_input, tty).unwrap(),
            DestroyGate::Proceed
        );
    }

    // Dirty and unknowable prompt interactively...
    assert_eq!(
        destroy_gate(false, &dirty(), false, true).unwrap(),
        DestroyGate::Confirm
    );
    assert_eq!(
        destroy_gate(false, &AtRiskState::Unknowable, false, true).unwrap(),
        DestroyGate::Confirm
    );

    // ...and refuse headless (no tty, or --no-input), naming --force.
    for state in [dirty(), AtRiskState::Unknowable] {
        for (no_input, tty) in [(true, true), (false, false), (true, false)] {
            let err = destroy_gate(false, &state, no_input, tty)
                .expect_err("headless without --force must refuse")
                .to_string();
            assert!(err.contains("--force"), "error must name --force: {err}");
        }
    }
}

/// Classification of the daemon's at-risk report: proven-clean VCS
/// state and an empty activation delta are `Clean`; uncommitted or
/// unpushed work is `Dirty` with truthful headers; the fallback header
/// admits it may include committed work; absent or `Unavailable`
/// responses are `Unknowable`.
#[test]
fn assess_at_risk_classifies_clean_dirty_and_unknowable() {
    use minimald_rpc::SessionDeltaResponse as R;

    assert_eq!(assess_at_risk(None), AtRiskState::Unknowable);
    assert_eq!(
        assess_at_risk(Some(R::Unavailable)),
        AtRiskState::Unknowable
    );

    // Committed and pushed: proven clean.
    assert_eq!(
        assess_at_risk(Some(R::Vcs {
            uncommitted: vec![],
            unpushed_commits: 0
        })),
        AtRiskState::Clean
    );
    // Nothing changed since activation: clean in fallback mode too.
    assert_eq!(
        assess_at_risk(Some(R::ChangedSinceActivation { rows: vec![] })),
        AtRiskState::Clean
    );

    // Uncommitted files and unpushed commits both render.
    let lines = match assess_at_risk(Some(R::Vcs {
        uncommitted: vec!["M src/main.rs".to_string(), "A notes.md".to_string()],
        unpushed_commits: 2,
    })) {
        AtRiskState::Dirty(lines) => lines,
        other => panic!("expected Dirty, got {other:?}"),
    };
    assert_eq!(lines[0], "2 files with uncommitted changes:");
    assert!(lines.contains(&"  M src/main.rs".to_string()), "{lines:?}");
    assert_eq!(
        lines.last().unwrap(),
        "2 commits not pushed to any remote",
        "{lines:?}"
    );

    // Unpushed commits alone still gate, without a files header.
    let lines = match assess_at_risk(Some(R::Vcs {
        uncommitted: vec![],
        unpushed_commits: 1,
    })) {
        AtRiskState::Dirty(lines) => lines,
        other => panic!("expected Dirty, got {other:?}"),
    };
    assert_eq!(lines, vec!["1 commit not pushed to any remote".to_string()]);

    // The fallback header must not over-claim.
    let lines = match assess_at_risk(Some(R::ChangedSinceActivation {
        rows: vec!["A scratch.txt".to_string()],
    })) {
        AtRiskState::Dirty(lines) => lines,
        other => panic!("expected Dirty, got {other:?}"),
    };
    assert_eq!(
        lines,
        vec![
            "1 file differs from activation (may include committed work):".to_string(),
            "  A scratch.txt".to_string(),
        ]
    );
}

/// `min session run <session> <task>` names both the session to run in and
/// the task to run, in that order — the session-scoped counterpart to
/// `min task run <task>`, which composes a session of its own.
#[test]
fn session_run_takes_a_session_then_a_task() {
    let cli = Cli::try_parse_from(["min", "session", "run", "web", "build"]).unwrap();
    let Some(Command::Session(SessionArgs {
        command: SessionCommand::Run(a),
    })) = cli.command
    else {
        panic!("expected a session run command");
    };
    assert_eq!(a.session, "web");
    assert_eq!(a.task, "build");

    // Both operands are required: a lone session names no task.
    assert!(Cli::try_parse_from(["min", "session", "run", "web"]).is_err());
    assert!(Cli::try_parse_from(["min", "session", "run"]).is_err());
}

/// The task reaches the daemon as a named form, so a task whose name
/// collides with a program on the session's `PATH` is still a task —
/// nothing is inferred from the text (gominimal/inbox#558). `min session
/// run` sends no owns-box flag (NET-131): the task runs in a session
/// someone else keeps.
#[test]
fn session_run_encodes_a_task_form_not_a_command() {
    let request = minimald_rpc::exec::ExecRequest::TaskRun {
        task: "check".to_string(),
        owns_box: false,
    };
    let wire = request.encode();
    assert_eq!(
        minimald_rpc::exec::ExecRequest::parse(&wire),
        Ok(minimald_rpc::exec::ExecRequest::TaskRun {
            task: "check".to_string(),
            owns_box: false,
        })
    );
}

/// `min task run <task>` parses with `--keep` off by default; the flag
/// and the optional path positional are accepted in any order.
#[test]
fn task_run_parses_task_keep_and_path() {
    use clap::Parser as _;
    let run_args = |args: &[&str]| -> TaskRunArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Task(TaskArgs {
                command: TaskCommand::Run(a),
            })) => a,
            _ => panic!("expected `task run` for {args:?}"),
        }
    };

    let a = run_args(&["min", "task", "run", "build"]);
    assert_eq!(a.task, "build");
    assert!(!a.keep);
    assert!(a.path.is_none());

    let a = run_args(&["min", "task", "run", "build", "--keep"]);
    assert!(a.keep);

    let a = run_args(&["min", "task", "run", "--keep", "build", "sub/dir"]);
    assert_eq!(a.task, "build");
    assert_eq!(a.path.as_deref(), Some("sub/dir"));
    assert!(a.keep);

    // The task name is required.
    assert!(Cli::try_parse_from(["min", "task", "run"]).is_err());
    assert!(Cli::try_parse_from(["min", "task"]).is_err());
}

/// The hidden top-level `run` swallows any spelling — flags included —
/// so every muscle-memory invocation reaches the redirect error rather
/// than a clap parse error; and it stays hidden from help.
#[test]
fn hidden_run_swallows_any_spelling_and_stays_hidden() {
    use clap::CommandFactory as _;
    use clap::Parser as _;

    match Cli::try_parse_from(["min", "run", "build", "--keep"])
        .unwrap()
        .command
    {
        Some(Command::Run(a)) => assert_eq!(a.rest, ["build", "--keep"]),
        _ => panic!("expected the hidden run catch"),
    }
    // A bare `min run` parses too; the redirect copy handles it.
    match Cli::try_parse_from(["min", "run"]).unwrap().command {
        Some(Command::Run(a)) => assert!(a.rest.is_empty()),
        _ => panic!("expected the hidden run catch"),
    }

    let cmd = Cli::command();
    let run = cmd
        .find_subcommand("run")
        .expect("the run subcommand must exist");
    assert!(run.is_hide_set(), "`min run` must stay hidden from help");
}

#[test]
fn ingress_spec_defaults_to_tcp() {
    let m = parse_ingress_mapping("18080:80").unwrap();
    assert_eq!(m.external_port, 18080);
    assert_eq!(m.internal_port, 80);
    assert_eq!(m.proto, sessions::IpProto::Tcp);
}

#[test]
fn ingress_spec_parses_explicit_proto() {
    let m = parse_ingress_mapping("5353:53/udp").unwrap();
    assert_eq!(m.external_port, 5353);
    assert_eq!(m.internal_port, 53);
    assert_eq!(m.proto, sessions::IpProto::Udp);
}

#[test]
fn ingress_spec_rejects_malformed_and_bad_proto() {
    assert!(parse_ingress_mapping("18080").is_err());
    assert!(parse_ingress_mapping("notaport:80").is_err());
    assert!(parse_ingress_mapping("18080:80/icmp").is_err());
}

/// Regression: a config in the `.minimal/` layout must be detected so
/// `activate` returns without prompting and never scaffolds over it.
/// The old naive `join(MFILE_NAME)` check missed this path.
#[test]
fn project_has_mfile_detects_dot_minimal_layout() {
    let dir = tempfile::tempdir().unwrap();
    let mfile_dir = dir.path().join(".minimal");
    std::fs::create_dir(&mfile_dir).unwrap();
    std::fs::write(
        mfile_dir.join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();

    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert!(
        project_has_mfile(path),
        "config under .minimal/ must be detected",
    );
}

/// A project with no config in either layout is genuinely missing an
/// mfile, so detection reports false and the caller falls through to
/// the (tty-gated) prompt.
#[test]
fn project_has_mfile_false_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert!(!project_has_mfile(path));
}

/// With no mfile anywhere up the tree, `resolve_upload_root` returns the
/// input directory unchanged — the original activate behaviour.
///
/// The temp dir is rooted directly in `$HOME` rather than `$TMPDIR`: the
/// upward walk stops at `$HOME`, so this is the only placement where "no
/// mfile up the tree" is guaranteed. Under `$TMPDIR` the walk escapes to
/// whatever encloses it — with `TMPDIR` inside a checkout of this repo it
/// finds the repo's own `minimal.toml` and the test fails.
#[test]
fn resolve_upload_root_returns_input_when_no_mfile() {
    let Some(home) = std::env::home_dir() else {
        return; // no HOME: no walk boundary to anchor the test to
    };
    let Ok(dir) = tempfile::tempdir_in(&home) else {
        return; // can't create temp dir in HOME, such as on a read only file system  
    };
    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert_eq!(resolve_upload_root(path).unwrap(), path);
}

/// `resolve_upload_root` walks up to the nearest mfile and returns its
/// repo root, so activating from a subdir still uploads the whole
/// project. Covers both the root (`./minimal.toml`) and `.minimal/`
/// layouts.
#[test]
fn resolve_upload_root_walks_up_to_mfile_root_layout() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    let subdir = root.join("nested/deep");
    std::fs::create_dir_all(&subdir).unwrap();

    assert_eq!(resolve_upload_root(&subdir).unwrap(), root);
}

#[test]
fn resolve_upload_root_walks_up_to_mfile_dot_minimal_layout() {
    let dir = tempfile::tempdir().unwrap();
    let mfile_dir = dir.path().join(".minimal");
    std::fs::create_dir(&mfile_dir).unwrap();
    std::fs::write(
        mfile_dir.join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    let subdir = root.join("nested");
    std::fs::create_dir_all(&subdir).unwrap();

    assert_eq!(resolve_upload_root(&subdir).unwrap(), root);
}

/// A malformed mfile is a real error, not a "not found": propagate it
/// so the user sees the parse failure instead of silently uploading a
/// subdir with no config and letting the daemon fabricate a default.
#[test]
fn resolve_upload_root_errors_on_malformed_mfile() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(mfile::MFILE_NAME), "not valid toml = =").unwrap();
    let path = camino::Utf8Path::from_path(dir.path()).expect("temp path is UTF-8");
    assert!(resolve_upload_root(path).is_err());
}

/// A refused composition is reported in the user's terms — the
/// directory the activation ran from — with the daemon's own text kept
/// as subordinate detail rather than as the headline (#581).
///
/// The daemon error below is the one from the report: it names an
/// internal package server the caller never asked for and cannot reach.
#[test]
fn composition_failure_leads_with_the_directory_not_the_daemon_step() {
    let daemon_error = "init of minimal context: other: git command 'fetch' failed \
                            (exit status: 128): fatal: unable to access \
                            'http://:8898/pkgs-local.git/': Failed to connect to server";
    let msg =
        composition_failure_message(camino::Utf8Path::new("/home/dev/myproject"), daemon_error);

    let headline = msg.lines().next().expect("a first line");
    assert!(
        headline.contains("/home/dev/myproject"),
        "the headline must name the directory: {msg}"
    );
    assert!(
        !headline.contains("pkgs-local.git") && !headline.contains("ConfigureLoadout"),
        "the headline must not lead with the internal step: {msg}"
    );
    assert!(
        msg.contains(daemon_error),
        "the daemon's error is the only diagnostic and must survive: {msg}"
    );
}

/// Every site that reports an uncomposable session goes through the one
/// helper: the refused `ConfigureLoadout` and the headless gating bail in
/// each creator, plus the interactive gating bail they share via
/// [`drive_pending_to_active`]. Asserted rather than documented — the
/// wording was already duplicated across the creators once, and the
/// interactive site was missed the first time precisely because it lives
/// in a third function.
#[test]
fn both_creators_share_the_composition_failure_message() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, func, uses) in [
        ("src/cmd/session.rs", "activate_session", 2),
        ("src/task.rs", "cmd_task_run", 2),
        ("src/cmd/mod.rs", "drive_pending_to_active", 1),
    ] {
        let text = std::fs::read_to_string(manifest.join(file)).expect("readable source");
        let body =
            function_body(&text, func).unwrap_or_else(|| panic!("{file} no longer defines {func}"));
        assert_eq!(
            body.matches("composition_failure_message").count(),
            uses,
            "{func} must route its composition failures through the shared message"
        );
        for bare in ["ConfigureLoadout failed", "Composition gating failed"] {
            assert!(
                !body.contains(bare),
                "{func} still names the internal step instead of the directory ({bare})"
            );
        }
    }
}

/// A project outside a VCS root that declares lifecycle hooks must be
/// detected as hook-carrying, so the headless activation path refuses
/// rather than silently dropping the hooks with the skipped tree
/// upload. A project with no `[session]` hooks reports zero and keeps
/// the quiet skip-and-warn behaviour.
#[test]
fn project_lifecycle_hook_count_detects_declared_hooks() {
    let with_hook = tempfile::tempdir().unwrap();
    std::fs::write(
        with_hook.path().join(mfile::MFILE_NAME),
        "[[session.lifecycle_hooks]]\n\
             on_activate = { type = \"inline\", value = \"echo hi\" }\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(with_hook.path()).expect("temp path is UTF-8");
    assert_eq!(project_lifecycle_hook_count(root), 1);

    let no_hook = tempfile::tempdir().unwrap();
    std::fs::write(
        no_hook.path().join(mfile::MFILE_NAME),
        "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n",
    )
    .unwrap();
    let root = camino::Utf8Path::from_path(no_hook.path()).expect("temp path is UTF-8");
    assert_eq!(project_lifecycle_hook_count(root), 0);
}

/// On a VM target the daemon is the guest's pid-1, so an accepted shutdown
/// takes the SSH transport down with it and the reply can be lost on the
/// way out. `stop` gates on the observable goal, not on the transport: a
/// daemon that reached the stopped state is a stop that worked.
#[tokio::test]
async fn stop_succeeds_when_a_lost_reply_still_stopped_the_daemon() {
    stop_outcome(
        Err(anyhow::anyhow!("EOF while parsing a value")
            .context("decode response for shutdown")
            .context("Shutdown RPC failed")),
        async || Ok(()),
        async || true,
    )
    .await
    .expect("a daemon that reached the stopped state is a successful stop");
}

/// The other half of that judgement: a failed RPC over a daemon that is
/// still there is a real failure, and the RPC's own error — context and all
/// — is what the user needs.
#[tokio::test]
async fn stop_reports_the_rpc_error_when_the_daemon_is_still_running() {
    let err = stop_outcome(
        Err(anyhow::anyhow!("connection reset").context("Shutdown RPC failed")),
        async || Ok(()),
        async || false,
    )
    .await
    .unwrap_err();

    let chain = format!("{err:#}");
    assert!(
        chain.contains("Shutdown RPC failed") && chain.contains("connection reset"),
        "expected the original RPC error chain, got: {chain}"
    );
}

/// A refusal is an answer, not a lost reply: it keeps its own message and
/// its non-zero exit, and observes nothing — the daemon it names is staying
/// up on purpose.
#[tokio::test]
async fn stop_with_live_sessions_bails_without_waiting() {
    let observed = std::cell::Cell::new(false);
    let err = stop_outcome(
        Ok(minimald_rpc::ShutdownResponse::SessionsLive),
        async || {
            observed.set(true);
            Ok(())
        },
        async || {
            observed.set(true);
            true
        },
    )
    .await
    .unwrap_err();

    assert_eq!(
        err.to_string(),
        "daemon has active sessions; pass --force to shut down anyway"
    );
    assert!(
        !observed.get(),
        "a refused shutdown has nothing to wait for"
    );
}

/// An acknowledged shutdown still has to finish, and its wait is the whole
/// judgement: a daemon that never reaches a stopped state fails with the
/// wait's own error, and the extra liveness probe — which exists only to
/// judge a *failed* RPC — never races a teardown the daemon acknowledged.
#[tokio::test]
async fn stop_fails_when_an_accepted_shutdown_never_completes() {
    stop_outcome(
        Ok(minimald_rpc::ShutdownResponse::ShuttingDown),
        async || Ok(()),
        async || false,
    )
    .await
    .expect("an acknowledged shutdown that completes is a successful stop");

    let probed = std::cell::Cell::new(false);
    let err = stop_outcome(
        Ok(minimald_rpc::ShutdownResponse::ShuttingDown),
        async || Err(anyhow::anyhow!("the VM is still shutting down after 20s")),
        async || {
            probed.set(true);
            true
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("still shutting down"),
        "expected the wait's error, got: {err}"
    );
    assert!(
        !probed.get(),
        "an accepted shutdown is judged by its wait alone"
    );
}

/// The recovery's actual observation, not a stand-in for it: the real
/// probe `cmd_stop` hands `stop_outcome`, run against a state dir no daemon
/// ever ran in. Nothing is listening and no lifecycle is active, which is
/// exactly the post-shutdown reading a lost reply has to be judged on, so
/// it must confirm the stop.
#[tokio::test]
async fn the_real_probe_confirms_a_daemon_that_is_not_there() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        daemon_confirmed_stopped(true, Some(dir.path().to_path_buf())).await,
        "a state dir with no live daemon is a confirmed stop"
    );
}

/// The already-down fast path: against a state dir no daemon ever ran in,
/// `stop` reports the goal state and exits 0 without connecting or
/// spawning anything.
#[tokio::test]
async fn stop_is_a_no_op_when_the_daemon_is_already_down() {
    let dir = tempfile::tempdir().unwrap();
    let global = GlobalArgs {
        repo_dir: None,
        minimal_dir: Some(dir.path().to_path_buf()),
        config_dir: None,
        provider: None,
        no_input: true,
    };

    cmd_stop(&global, StopArgs { force: false })
        .await
        .expect("an already-stopped daemon is the goal state, not an error");
}

/// A `min proxy` bridge must not outlive the daemon socket: when the daemon
/// tears the connection down, the proxy exits even though its stdin — held
/// open by the driving `ssh` — never closes. Otherwise the proxy, and the
/// `ssh` process feeding it, orphan against a dead socket.
#[tokio::test]
async fn proxy_exits_when_the_daemon_closes_the_socket() {
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("proxy.sock");
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();

    // Stand in for the daemon: accept the proxy's connection, then drop it,
    // the way `min stop` tears the socket down under a live proxy.
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        drop(conn);
    });

    let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();

    // Stdin that stays open with no data, the way `ssh` holds it; the other
    // duplex half must outlive the bridge so the reader never sees EOF.
    let (client_stdin, _ssh_stdin) = tokio::io::duplex(64);

    tokio::time::timeout(
        Duration::from_secs(5),
        proxy_bridge(stream, client_stdin, tokio::io::sink()),
    )
    .await
    .expect("proxy must exit once the socket closes, not hang on open stdin")
    .expect("a bridge that ends on a closed socket is not an error");
}

/// `--network` and `--ingress` are visible in `min session activate --help`
/// (NET-035), with the `--network` value advertising the current
/// `none|host_ip|own_ip` spellings.
#[test]
fn activate_help_shows_network_flags() {
    use clap::CommandFactory as _;

    let mut cmd = Cli::command();
    let activate = cmd
        .find_subcommand_mut("session")
        .expect("`session` stays a subcommand")
        .find_subcommand_mut("activate")
        .expect("`session activate` stays a subcommand");
    let help = activate.render_help().to_string();
    assert!(
        help.contains("--network <none|host_ip|own_ip>"),
        "--help must advertise the network modes and their spellings: {help}"
    );
    assert!(
        help.contains("--ingress <EXT:INT[/PROTO]>"),
        "--help must show the ingress flag: {help}"
    );
}

/// Runs `f` with the process's stderr redirected into a pipe and returns
/// what it wrote alongside `f`'s result.
///
/// The capture watches the real fd 2, so it observes what `eprintln!` prints
/// while it prints — a dropped or rerouted diagnostic fails the caller's
/// assertion instead of only going missing for users.
///
/// Serialized by a process-wide lock: plain `cargo test` shares fd 2 across
/// test threads, so two captures must never overlap. Under nextest — the lane
/// this crate's tests run in — every test owns its process to begin with.
fn capture_stderr<T>(f: impl FnOnce() -> T) -> (String, T) {
    use std::io::Read as _;

    static STDERR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    let _lock = STDERR_LOCK.lock().expect("stderr capture lock");

    let (read_fd, write_fd) = nix::unistd::pipe().expect("pipe to capture stderr");
    // Save the current stderr first: the guard restores it even when `f`
    // panics with fd 2 still pointed at the pipe.
    struct RestoreStderr(std::os::fd::OwnedFd);
    impl Drop for RestoreStderr {
        fn drop(&mut self) {
            nix::unistd::dup2_stderr(&self.0).expect("restore stderr after capture");
        }
    }
    let restore =
        RestoreStderr(nix::unistd::dup(std::io::stderr()).expect("dup stderr for capture"));
    nix::unistd::dup2_stderr(&write_fd).expect("redirect stderr into the capture pipe");
    // fd 2 now holds a copy of the write end; close the original so the read
    // below reaches EOF once the restore has taken fd 2 back.
    drop(write_fd);

    let result = f();

    drop(restore);
    let mut captured = String::new();
    std::fs::File::from(read_fd)
        .read_to_string(&mut captured)
        .expect("read captured stderr");
    (captured, result)
}

/// Every legacy `--network` spelling still parses to the mode its current
/// spelling names (NET-037), and the parser prints the hint to the process's
/// stderr — exactly one line naming both spellings, captured around the real
/// clap parse so the print itself is under test. The current spellings and
/// the default print nothing, and anything else is refused.
#[test]
fn legacy_network_spellings_parse_with_hint() {
    use clap::Parser as _;

    let activate_args = |args: &[&str]| -> ActivateArgs {
        match Cli::try_parse_from(args).unwrap().command {
            Some(Command::Session(SessionArgs {
                command: SessionCommand::Activate(a),
            })) => a,
            _ => panic!("expected an activate command for {args:?}"),
        }
    };

    for (legacy, current, mode) in [
        ("no-net", "none", CliNetworkMode::NoNet),
        ("host-net", "host_ip", CliNetworkMode::HostNet),
        ("own-ip", "own_ip", CliNetworkMode::OwnIp),
    ] {
        let hint = legacy_network_hint(legacy).expect("a legacy spelling carries a hint");
        let (stderr, args) =
            capture_stderr(|| activate_args(&["min", "session", "activate", "--network", legacy]));
        assert_eq!(
            args.network, mode,
            "--network {legacy} must parse to {current}'s mode"
        );
        assert_eq!(
            stderr,
            format!("{hint}\n"),
            "--network {legacy} must print exactly the hint line to stderr"
        );
        assert!(
            hint.contains(legacy),
            "the hint must name the spelling typed: {hint}"
        );
        assert!(
            hint.contains(current),
            "the hint must name the current spelling: {hint}"
        );
    }

    for (current, mode) in [
        ("none", CliNetworkMode::NoNet),
        ("host_ip", CliNetworkMode::HostNet),
        ("own_ip", CliNetworkMode::OwnIp),
    ] {
        let (stderr, args) =
            capture_stderr(|| activate_args(&["min", "session", "activate", "--network", current]));
        assert_eq!(args.network, mode);
        assert!(
            stderr.is_empty(),
            "a current spelling must print nothing to stderr: {stderr:?}"
        );
    }

    let (stderr, args) = capture_stderr(|| activate_args(&["min", "session", "activate"]));
    assert_eq!(args.network, CliNetworkMode::HostNet);
    assert!(
        stderr.is_empty(),
        "the default network mode must print nothing to stderr: {stderr:?}"
    );

    let err = Cli::try_parse_from(["min", "session", "activate", "--network", "bogus"])
        .map(|_| ())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("none, host_ip, own_ip"),
        "the error must name the accepted spellings: {err}"
    );
}

/// The CLI reference documents the network flags on `session activate`
/// (NET-036), read from the real file so a docs edit cannot silently drop
/// either row.
#[test]
fn cli_reference_documents_network_flags() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/reference/cli-min.md");
    let doc = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let section = doc
        .split_once("### `session activate`")
        .expect("a `session activate` section in the CLI reference")
        .1;
    let section = section.split("### ").next().unwrap();
    // Table cells escape their pipes as `\|`; compare against the rendered
    // form.
    let section = section.replace("\\|", "|");
    for row in [
        "--network <none|host_ip|own_ip>",
        "--ingress <EXT:INT[/PROTO]>",
    ] {
        assert!(
            section.contains(row),
            "the CLI reference's `session activate` rows must document `{row}`"
        );
    }
}
