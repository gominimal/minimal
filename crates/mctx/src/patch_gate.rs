//! The `[patches]` gate for the tasks `mip` runs by name (inbox#1128).
//!
//! A task's `patch.dir` and `patch.file` entries come from the project's
//! `minimal.toml`, which is untrusted input: an entry can name any host path
//! the invoking user can read, and the task's sandbox binds it in. `min`
//! judges a project's patches against the user's `[patches]` policy in
//! `user_policy.toml`. This module judges a task's entries against the same
//! file, with the same precedence, before the sandbox is built.
//!
//! [`gate_task_patches`] is the one gate. Both ways a task is run by name in
//! a [`Context`] call it after the task is looked up and before
//! [`Context::make_env`]: `mip run <task>` on the host, and a nested
//! `run <task>` that a sandbox sends over its `/run/minenv_sock` channel
//! (the in-sandbox `min run <task>` helper). Whether it judges anything is
//! the context's [`TaskPatchPolicy`]: `mip` sets
//! [`TaskPatchPolicy::UserPolicy`]; the default, [`TaskPatchPolicy::Ungated`],
//! keeps the daemon's behaviour, whose task patches are inbox#602.
//!
//! Each entry is decided as one path, since the sandbox binds it whole:
//!
//! - The declared path (`~/` expanded against the invoking user's home, the
//!   home the sandbox mounts it from) and, when it resolves somewhere else on
//!   this machine through a symlink, the resolved path. Both must pass, and
//!   the stricter decision wins, so a symlink cannot carry an entry past a
//!   deny on its target or onto a target no rule allows.
//! - For a directory, a probe of what it holds: a `deny` that matches a
//!   contained path denies the entry, since the mount would expose it. The
//!   probe runs only when some `deny` pattern can reach inside the directory,
//!   and it is bounded: a tree it cannot read whole is refused, not mounted.
//!
//! A denied entry refuses the run (`policy denied ...`). An ignored entry is
//! dropped from the sandbox, and the caller says so. An entry no rule decides
//! needs approval, and `mip` has no prompt, so the run is refused with the
//! `[patches] allow` snippet that would approve it, as `min` does when it
//! cannot prompt.
//!
//! Package-declared mappings (`env_dir_mappings` / `env_file_mappings`) are
//! not judged here: they join the task's patches inside `Env::build`, from
//! the package set, and are a separate issue.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use boxes::core::compose::ComposeError;
use boxes::core::decision::{CheckOutcome, Decision};
use boxes::core::expansion::VarLookup;
use boxes::core::policy::{ExpandedPatchesPolicy, PatchesPolicy, UserPolicy};
use boxes::core::source::{Provenanced, Source};
use camino::{Utf8Path, Utf8PathBuf};

use crate::{Context, Error, PatchHome, TaskPatchPolicy};

/// The most entries a directory's deny probe walks before it refuses the
/// entry rather than mount a tree it has not checked whole.
pub(crate) const DIR_PROBE_LIMIT: usize = 10_000;

/// A task that passed [`gate_task_patches`].
#[derive(Debug)]
pub struct GatedTask {
    /// The task, with only the patch entries the sandbox may mount.
    pub task: mfile::Task,
    /// The entries an `ignore` rule dropped, as declared, for the caller to
    /// tell the user about: the task runs without them.
    pub ignored: Vec<String>,
}

impl GatedTask {
    /// One line naming the dropped entries, or `None` when nothing was
    /// dropped.
    #[must_use]
    pub fn ignored_notice(&self, task_name: &str) -> Option<String> {
        if self.ignored.is_empty() {
            return None;
        }
        Some(format!(
            "task `{task_name}`: not mounting {} (ignored by `[patches]` in user_policy.toml)",
            self.ignored.join(", ")
        ))
    }
}

/// The one `[patches]` gate for a task run by name in `ctx` (inbox#1128).
///
/// Judges the `patch.dir` / `patch.file` entries `task` declares against the
/// user policy `ctx`'s [`TaskPatchPolicy`] names, and returns the task with
/// only the entries the sandbox may mount. Under
/// [`TaskPatchPolicy::Ungated`], and for a task without patches, the task is
/// returned untouched and no policy file is read.
///
/// `~/` expands against [`PatchHome::Ambient`], the home both callers hand
/// to [`Context::make_env`].
///
/// # Errors
///
/// - `policy denied ...` when a `deny` rule matches an entry, its resolved
///   path, or a path a directory entry holds.
/// - A refusal carrying the `[patches] allow` snippet when an entry is
///   undecided: there is no prompt.
/// - The policy file cannot be found, read or parsed; a pattern in it does
///   not expand; a directory's contents cannot be checked whole; or a path
///   cannot be resolved.
pub fn gate_task_patches(
    ctx: &Context,
    task_name: &str,
    mut task: mfile::Task,
) -> Result<GatedTask, Error> {
    let policy_path = match ctx.daemon.config.task_patch_policy() {
        TaskPatchPolicy::Ungated => None,
        _ if task.patch.dir.is_empty() && task.patch.file.is_empty() => None,
        TaskPatchPolicy::UserPolicy => Some(user_policy_path().map_err(Error::Other)?),
        TaskPatchPolicy::UserPolicyAt(path) => Some(path.clone()),
    };
    let Some(policy_path) = policy_path else {
        return Ok(GatedTask {
            task,
            ignored: Vec::new(),
        });
    };
    let policy = boxes::core::policy::read_user_policy_or_default(&policy_path)
        .map_err(|e| Error::Other(anyhow!("{e}")))?;
    let (kept, ignored) = judge_task_patches(
        task_name,
        &task.patch,
        &policy,
        &policy_path,
        ctx.repo_dir()?,
        PatchHome::Ambient.resolve().as_deref(),
        &ProcessEnv::current(),
    )
    .map_err(Error::Other)?;
    task.patch = kept;
    Ok(GatedTask { task, ignored })
}

/// What the policy says about one path. Ordered by strictness, so the
/// combined decision over several paths is their [`Ord::max`]: `Denied` >
/// `Ignored` > `NeedsApproval` > `Allowed`, the precedence `min`'s patch
/// gate combines a link and its target with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Allowed,
    NeedsApproval,
    Ignored,
    Denied,
}

/// The provenance the policy check reads. Every entry gated here is the
/// project's, so the allow step applies to all of them.
struct Entry<'a> {
    source: &'a Source,
}

impl Provenanced for Entry<'_> {
    fn source(&self) -> &Source {
        self.source
    }
}

/// The invoking user's environment, for `$NAME` references in the policy's
/// patterns. `mip` has no session and no loadouts, so the variables a
/// pattern can name are the process's own.
struct ProcessEnv(Vec<(String, String)>);

impl ProcessEnv {
    /// This process's environment. A variable whose name or value is not
    /// UTF-8 is left out, so a pattern naming it fails to expand and the
    /// run is refused.
    fn current() -> Self {
        Self(
            std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                .collect(),
        )
    }

    #[cfg(test)]
    fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }
}

impl VarLookup for ProcessEnv {
    fn lookup(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// `<config>/minimal/user_policy.toml`, the file `min` reads its policy
/// from (without `min`'s `--config-dir` override, which `mip` does not have).
///
/// # Errors
///
/// When there is no config directory to name: `XDG_CONFIG_HOME` is not an
/// absolute path and there is no home directory.
fn user_policy_path() -> anyhow::Result<PathBuf> {
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .is_some_and(|p| p.is_absolute());
    if !xdg && std::env::home_dir().is_none() {
        return Err(anyhow!(
            "cannot find user_policy.toml to check this task's patches against: \
             XDG_CONFIG_HOME is not set to an absolute path and there is no home directory"
        ));
    }
    Ok(paths::minimal_config_dir_with_override(None).join("user_policy.toml"))
}

/// Judge `patches`, the entries task `task_name` declares, against `policy`
/// (read from `policy_path`, which the refusal names). Returns the entries
/// the sandbox may mount, every allowed one, and the declared form of each
/// entry an `ignore` rule dropped.
///
/// `project_root` is the project the entries come from, named in a denial.
/// `home` is what `~/` expands to, the home the sandbox mounts them from.
///
/// # Errors
///
/// - `policy denied ...` when a `deny` rule matches an entry, its resolved
///   path, or a path a directory entry holds. The first denial is returned,
///   before any undecided entry is reported.
/// - A refusal carrying the `[patches] allow` snippet when an entry is
///   undecided: there is no prompt.
/// - A directory entry whose contents cannot be checked whole, a path that
///   cannot be resolved, or a policy pattern that does not expand.
fn judge_task_patches(
    task_name: &str,
    patches: &mfile::EnvPatches,
    policy: &UserPolicy,
    policy_path: &Path,
    project_root: &Path,
    home: Option<&Path>,
    vars: &ProcessEnv,
) -> anyhow::Result<(mfile::EnvPatches, Vec<String>)> {
    if patches.dir.is_empty() && patches.file.is_empty() {
        return Ok((patches.clone(), Vec::new()));
    }
    let home_str = home.and_then(Path::to_str);
    let expanded = policy
        .patches()
        .expand_with(vars, home_str)
        .map_err(|e| anyhow!("`[patches]` in {}: {e}", policy_path.display()))?;
    let root = Utf8PathBuf::from_path_buf(project_root.to_path_buf())
        .map_err(|p| anyhow!("project directory `{}` is not UTF-8", p.display()))?;
    let source = Source::Project {
        path: paths::HostPath::try_new(root).context("invalid project directory")?,
    };

    let mut kept = mfile::EnvPatches::default();
    let mut ignored: Vec<String> = Vec::new();
    let mut undecided: Vec<String> = Vec::new();
    for (is_file, entries) in [(false, &patches.dir), (true, &patches.file)] {
        for (declared, setting) in entries {
            let kind = if is_file { "patch.file" } else { "patch.dir" };
            let at = mfile::EnvPatches::expand_home(declared, home)
                .map_err(|e| anyhow!("task `{task_name}`: {e}"))?;
            let at = Utf8PathBuf::from(at);
            let decided = decide_entry(&expanded, &source, &at, is_file).map_err(|e| {
                anyhow!("task `{task_name}`: {kind}.\"{declared}\": {e}; refusing to mount it")
            })?;
            match decided.verdict {
                Verdict::Allowed => {
                    let table = if is_file {
                        &mut kept.file
                    } else {
                        &mut kept.dir
                    };
                    table.insert(declared.clone(), setting.clone());
                }
                Verdict::Ignored => ignored.push(declared.clone()),
                Verdict::Denied => {
                    let denied = ComposeError::Denied {
                        what: decided.denied_path.unwrap_or_else(|| declared.clone()),
                        from: source.clone(),
                    };
                    return Err(anyhow!(
                        "task `{task_name}` declares {kind}.\"{declared}\": {denied}. \
                         The rule is in `[patches]` of {}.",
                        policy_path.display()
                    ));
                }
                Verdict::NeedsApproval => {
                    for form in decided.undecided_forms {
                        if !undecided.contains(&form) {
                            undecided.push(form);
                        }
                    }
                }
            }
        }
    }
    if undecided.is_empty() {
        return Ok((kept, ignored));
    }
    let count = undecided.len();
    let snippet = allow_snippet(undecided)?;
    Err(anyhow!(
        "{count} patch path{s} declared by task `{task_name}` would require approval, \
         but there is no prompt to ask for it.\n\n\
         Add the following to {}:\n\n{snippet}\n\
         Then re-run this command.",
        policy_path.display(),
        s = if count == 1 { "" } else { "s" },
    ))
}

/// The `[patches] allow` snippet approving `paths`, through the policy's own
/// serializer so a path that needs TOML escaping still yields a snippet that
/// parses.
fn allow_snippet(paths: Vec<String>) -> anyhow::Result<String> {
    let policy = UserPolicy::empty().with_patches(PatchesPolicy::empty().with_allow(paths));
    toml::to_string(&policy).context("formatting the `[patches] allow` snippet")
}

/// One entry's decision.
struct Decided {
    verdict: Verdict,
    /// For a denial, the path the `deny` rule matched, when it is not the
    /// declared entry itself (a resolved target, or a path inside it).
    denied_path: Option<String>,
    /// For an undecided entry, the forms an `allow` rule must name: the
    /// declared path, and the resolved one when that differs and is itself
    /// undecided.
    undecided_forms: Vec<String>,
}

/// Decide one entry at `at`, its declared path with `~/` expanded.
fn decide_entry(
    expanded: &ExpandedPatchesPolicy,
    source: &Source,
    at: &Utf8Path,
    is_file: bool,
) -> anyhow::Result<Decided> {
    let dotted = at.as_str().split('/').any(|s| s == "." || s == "..");
    if dotted {
        return Err(anyhow!("a patch path may not hold a `.` or `..` segment"));
    }
    let own = decide(expanded, source, at);
    let resolved = resolve(at)?.filter(|r| r.as_path() != at);
    let target = resolved.as_ref().map(|r| decide(expanded, source, r));
    let mut verdict = own.max(target.unwrap_or(Verdict::Allowed));
    let mut denied_path = match (&resolved, target) {
        (Some(r), Some(Verdict::Denied)) if own != Verdict::Denied => Some(r.to_string()),
        _ => None,
    };
    if verdict != Verdict::Denied && !is_file && !expanded.deny().is_empty() {
        let probe_root = resolved.as_deref().unwrap_or(at);
        if let Some(hit) = probe_dir_for_deny(expanded, source, at, probe_root)? {
            verdict = Verdict::Denied;
            denied_path = Some(hit);
        }
    }
    let mut undecided_forms = Vec::new();
    if verdict == Verdict::NeedsApproval {
        if own == Verdict::NeedsApproval {
            undecided_forms.push(at.to_string());
        }
        if let (Some(r), Some(Verdict::NeedsApproval)) = (&resolved, target) {
            undecided_forms.push(r.to_string());
        }
    }
    Ok(Decided {
        verdict,
        denied_path,
        undecided_forms,
    })
}

/// The policy's decision about one path, as a project-origin item.
fn decide(expanded: &ExpandedPatchesPolicy, source: &Source, path: &Utf8Path) -> Verdict {
    match expanded.check(None, path, Entry { source }) {
        CheckOutcome::Decided(Decision::Allowed(_)) => Verdict::Allowed,
        CheckOutcome::Decided(Decision::Ignored) => Verdict::Ignored,
        CheckOutcome::Decided(Decision::Denied(_)) => Verdict::Denied,
        CheckOutcome::NeedsApproval(_) => Verdict::NeedsApproval,
    }
}

/// Where `path` leads on this machine: its deepest existing ancestor
/// canonicalized, with the missing tail joined back on. `None` when no
/// ancestor exists.
///
/// # Errors
///
/// When the answer cannot be trusted: a symlink on the way that does not
/// resolve (a read-write mapping would create its target, wherever that
/// is), an error other than "not found", or a result that is not UTF-8.
fn resolve(path: &Utf8Path) -> anyhow::Result<Option<Utf8PathBuf>> {
    let mut tail: Vec<&str> = Vec::new();
    let mut cur = path;
    loop {
        match std::fs::canonicalize(cur) {
            Ok(real) => {
                let mut real = Utf8PathBuf::from_path_buf(real)
                    .map_err(|p| anyhow!("`{}` resolves to a non-UTF-8 path", p.display()))?;
                for seg in tail.iter().rev().copied() {
                    real.push(seg);
                }
                return Ok(Some(real));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if std::fs::symlink_metadata(cur).is_ok_and(|m| m.file_type().is_symlink()) {
                    return Err(anyhow!("`{cur}` is a symlink that does not resolve"));
                }
            }
            Err(e) => return Err(anyhow!("cannot resolve `{cur}`: {e}")),
        }
        let (Some(parent), Some(name)) = (cur.parent(), cur.file_name()) else {
            return Ok(None);
        };
        tail.push(name);
        cur = parent;
    }
}

/// Look inside the directory entry for a path a `deny` rule matches. The
/// directory is walked at `on_disk` (its resolved form) and every path in it
/// is checked both there and under `declared`, the path the mount exposes.
/// Returns the first denied path.
///
/// A symlink inside the directory is judged as the link, not at its target.
/// The bind mount carries the link itself, and the sandbox resolves it in its
/// own mount namespace, where a host target is reachable only if some entry
/// mounts it, and that entry is gated on its own. Following contained links
/// here would also make the answer depend on whether a `deny` happens to
/// reach inside the directory, since only then is it walked.
///
/// Nothing is walked when no `deny` pattern can reach inside the directory.
/// A missing directory holds nothing yet (a read-write mapping creates it).
///
/// # Errors
///
/// When the walk cannot check the tree whole: more than
/// [`DIR_PROBE_LIMIT`] entries, or a part it cannot read. The entry is then
/// refused rather than mounted unchecked.
fn probe_dir_for_deny(
    expanded: &ExpandedPatchesPolicy,
    source: &Source,
    declared: &Utf8Path,
    on_disk: &Utf8Path,
) -> anyhow::Result<Option<String>> {
    let reaches = expanded.deny().iter().any(|fs| {
        deny_reaches_inside(fs.pattern(), declared.as_str())
            || deny_reaches_inside(fs.pattern(), on_disk.as_str())
    });
    if !reaches || !on_disk.as_std_path().is_dir() {
        return Ok(None);
    }
    let denied = |p: &Utf8Path| decide(expanded, source, p) == Verdict::Denied;
    let mut seen = 0usize;
    for item in walkdir::WalkDir::new(on_disk.as_std_path())
        .follow_links(false)
        .min_depth(1)
    {
        let item = match item {
            Ok(item) => item,
            Err(e) => return Err(anyhow!("cannot read it to check `[patches] deny`: {e}")),
        };
        seen += 1;
        if seen > DIR_PROBE_LIMIT {
            return Err(anyhow!(
                "it holds more than {DIR_PROBE_LIMIT} entries, too many to check against \
                 `[patches] deny`"
            ));
        }
        let real = Utf8PathBuf::from(item.path().to_string_lossy().into_owned());
        if denied(real.as_path()) {
            return Ok(Some(real.to_string()));
        }
        if let Ok(rel) = real.strip_prefix(on_disk) {
            let exposed = declared.join(rel);
            if exposed != real && denied(exposed.as_path()) {
                return Ok(Some(exposed.to_string()));
            }
        }
    }
    Ok(None)
}

/// Whether the expanded `deny` pattern `pattern` can match a path strictly
/// inside the directory `dir`. Errs towards `true`, which costs a walk; a
/// false `false` would skip a deny.
///
/// The pattern's literal prefix, read up to its first glob metacharacter
/// (`*`, `?`, `[`, `{`, or a `\` escape), decides. A pattern with no
/// metacharacter names one path, so it must lie under `dir`. Otherwise a `*`
/// can cross `/`, so the prefix only has to agree with `dir/` as far as the
/// shorter of the two reaches.
fn deny_reaches_inside(pattern: &str, dir: &str) -> bool {
    let inside = format!("{}/", dir.trim_end_matches('/'));
    match pattern.find(['*', '?', '[', '{', '\\']) {
        None => pattern.starts_with(&inside),
        Some(i) => {
            let literal = pattern.get(..i).unwrap_or_default();
            literal.starts_with(&inside) || inside.starts_with(literal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mfile::{EnvPatches, PatchSetting};

    /// A scratch tree under a canonical root, so no symlinked prefix (macOS's
    /// `/var` → `/private/var`) gives the entries a second, resolved form.
    struct Tree {
        _tmp: tempfile::TempDir,
        root: Utf8PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let real = std::fs::canonicalize(tmp.path()).unwrap();
            let root = Utf8PathBuf::from_path_buf(real).unwrap();
            Self { _tmp: tmp, root }
        }

        fn dir(&self, rel: &str) -> Utf8PathBuf {
            let p = self.root.join(rel);
            std::fs::create_dir_all(&p).unwrap();
            p
        }

        fn file(&self, rel: &str) -> Utf8PathBuf {
            let p = self.root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, "secret").unwrap();
            p
        }
    }

    fn policy(text: &str) -> UserPolicy {
        toml::from_str(text).unwrap()
    }

    fn dir_patch(path: &Utf8Path) -> EnvPatches {
        let mut p = EnvPatches::default();
        p.dir.insert(path.to_string(), PatchSetting::ReadOnly);
        p
    }

    fn file_patch(path: &Utf8Path) -> EnvPatches {
        let mut p = EnvPatches::default();
        p.file.insert(path.to_string(), PatchSetting::ReadWrite);
        p
    }

    fn judge(
        t: &Tree,
        patches: &EnvPatches,
        policy: &UserPolicy,
    ) -> anyhow::Result<(EnvPatches, Vec<String>)> {
        judge_task_patches(
            "peek",
            patches,
            policy,
            Path::new("/cfg/minimal/user_policy.toml"),
            t.root.join("proj").as_std_path(),
            Some(t.root.join("home").as_std_path()),
            &ProcessEnv::from_pairs(&[]),
        )
    }

    /// The entries `judge` keeps, for the tests that only look at those.
    fn gate(t: &Tree, patches: &EnvPatches, policy: &UserPolicy) -> anyhow::Result<EnvPatches> {
        judge(t, patches, policy).map(|(kept, _)| kept)
    }

    /// The shape scenario 812 runs: a directory `[patches] deny` names,
    /// declared as a task's `patch.dir`. The run is refused with the policy
    /// text, naming the entry and the policy file.
    #[test]
    fn mip_run_refuses_a_patch_the_policy_denies() {
        let t = Tree::new();
        let sec = t.dir("s812sec");
        t.file("s812sec/key.txt");
        let pol = policy(&format!("[patches]\ndeny = [\"{sec}\", \"{sec}/**\"]\n"));
        let err = gate(&t, &dir_patch(&sec), &pol).unwrap_err().to_string();
        assert!(err.contains("policy denied"), "{err}");
        assert!(err.contains(&format!("patch.dir.\"{sec}\"")), "{err}");
        assert!(err.contains("/cfg/minimal/user_policy.toml"), "{err}");
    }

    /// An entry the policy allows is mounted as declared, mode and all.
    #[test]
    fn mip_run_allows_a_patch_the_policy_permits() {
        let t = Tree::new();
        let ok = t.dir("cache");
        let pol = policy(&format!("[patches]\nallow = [\"{ok}\"]\n"));
        let kept = gate(&t, &dir_patch(&ok), &pol).unwrap();
        assert_eq!(kept, dir_patch(&ok));

        let f = t.file("conf/tool.toml");
        let pol = policy(&format!(
            "[patches]\nallow = [\"{}/**\"]\n",
            t.root.join("conf")
        ));
        assert_eq!(gate(&t, &file_patch(&f), &pol).unwrap(), file_patch(&f));
    }

    /// A task without patches never reads the policy's patterns: even one
    /// that cannot expand does not stop it.
    #[test]
    fn a_task_without_patches_passes_untouched() {
        let t = Tree::new();
        let pol = policy("[patches]\ndeny = [\"$UNSET_IN_THIS_TEST/**\"]\n");
        assert_eq!(
            gate(&t, &EnvPatches::default(), &pol).unwrap(),
            EnvPatches::default()
        );
    }

    /// No rule decides the entry: there is no prompt, so the run is refused
    /// with the `[patches] allow` snippet, and the snippet parses back into a
    /// policy that lets the same entry through.
    #[test]
    fn an_undecided_patch_is_refused_with_the_allow_snippet() {
        let t = Tree::new();
        let d = t.dir("data");
        let err = gate(&t, &dir_patch(&d), &UserPolicy::empty())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no prompt"), "{err}");
        let snippet = err
            .split("Add the following to /cfg/minimal/user_policy.toml:\n\n")
            .nth(1)
            .and_then(|s| s.split("\nThen re-run").next())
            .unwrap();
        assert!(snippet.contains("[patches]"), "{snippet}");
        let approved: UserPolicy = toml::from_str(snippet).unwrap();
        assert_eq!(gate(&t, &dir_patch(&d), &approved).unwrap(), dir_patch(&d));
    }

    /// An `ignore` on the entry drops it from the sandbox without failing the
    /// run; the other entries stay. The dropped entry is reported, so the
    /// caller can say why a mount is missing.
    #[test]
    fn an_ignored_patch_is_dropped_and_reported() {
        let t = Tree::new();
        let keep = t.dir("keep");
        let drop = t.dir("drop");
        let mut patches = dir_patch(&keep);
        patches.dir.insert(drop.to_string(), PatchSetting::ReadOnly);
        let rules = format!("[patches]\nallow = [\"{keep}\"]\nignore = [\"{drop}\"]\n");
        let pol = policy(&rules);
        let (kept, ignored) = judge(&t, &patches, &pol).unwrap();
        assert_eq!(kept, dir_patch(&keep));
        assert_eq!(ignored, vec![drop.to_string()]);
        let gated = GatedTask {
            task: mfile::Task::default(),
            ignored,
        };
        let notice = gated.ignored_notice("peek").unwrap();
        assert!(notice.contains(drop.as_str()), "{notice}");
    }

    /// A symlink inside an allowed directory is judged as the link: the mount
    /// carries the link, which resolves in the sandbox's namespace, not the
    /// host's. Its host target is not looked up, so the result does not
    /// depend on whether some `deny` reaches inside the directory.
    #[cfg(unix)]
    #[test]
    fn a_contained_symlink_is_judged_as_the_link() {
        let t = Tree::new();
        let sec = t.dir("secret");
        t.file("secret/key.txt");
        let d = t.dir("proj-cfg");
        std::os::unix::fs::symlink(&sec, d.join("to-secret")).unwrap();
        let rules = format!("[patches]\nallow = [\"{d}\"]\ndeny = [\"{sec}\", \"{sec}/**\"]\n");
        assert_eq!(gate(&t, &dir_patch(&d), &policy(&rules)).unwrap(), dir_patch(&d));
        // With a deny that reaches inside, the walk runs and still judges the
        // link by its own path, which no rule denies.
        let rules = format!(
            "[patches]\nallow = [\"{d}\"]\ndeny = [\"{sec}\", \"{sec}/**\", \"{d}/*.pem\"]\n"
        );
        assert_eq!(gate(&t, &dir_patch(&d), &policy(&rules)).unwrap(), dir_patch(&d));
    }

    /// Deny outranks allow: an allowed directory holding a denied file is
    /// refused, since the mount would expose the file, and the refusal names
    /// the file.
    #[test]
    fn a_directory_holding_a_denied_file_is_refused() {
        let t = Tree::new();
        let d = t.dir("proj-cfg");
        let key = t.file("proj-cfg/nested/id.pem");
        let pol = policy(&format!("[patches]\nallow = [\"{d}\"]\ndeny = [\"**/*.pem\"]\n"));
        let err = gate(&t, &dir_patch(&d), &pol).unwrap_err().to_string();
        assert!(err.contains("policy denied"), "{err}");
        assert!(err.contains(key.as_str()), "{err}");
    }

    /// Which `deny` patterns make the gate walk a directory entry: only those
    /// that can match a path inside it, so a deny elsewhere leaves a large
    /// allowed tree unwalked.
    #[test]
    fn a_deny_elsewhere_does_not_walk_the_directory() {
        assert!(!deny_reaches_inside("/home/u/.ssh/**", "/home/u/cache"));
        assert!(!deny_reaches_inside("/home/u/.ssh", "/home/u/cache"));
        assert!(!deny_reaches_inside("/home/u/.ssh", "/home/u/.ssh"));
        assert!(deny_reaches_inside("/home/u/.ssh", "/home/u"));
        assert!(deny_reaches_inside("/home/u/.ssh/**", "/home/u"));
        assert!(deny_reaches_inside("/home/u/**", "/home/u/cache"));
        assert!(deny_reaches_inside("**/*.pem", "/home/u/cache"));
    }

    /// `~/` expands against the home `mip` mounts from, and the policy's own
    /// `~/` expands against the same home, so a `~/` deny meets a `~/` entry.
    #[test]
    fn a_home_relative_entry_meets_a_home_relative_deny() {
        let t = Tree::new();
        t.file("home/.ssh/id_ed25519");
        let mut patches = EnvPatches::default();
        patches.dir.insert("~/.ssh".to_owned(), PatchSetting::ReadOnly);
        let pol = policy("[patches]\ndeny = [\"~/.ssh/**\"]\n");
        let err = gate(&t, &patches, &pol).unwrap_err().to_string();
        assert!(err.contains("policy denied"), "{err}");
    }

    /// A symlink cannot launder a denied target: the entry is checked where
    /// it resolves as well as where it is declared.
    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_denied_directory_is_refused() {
        let t = Tree::new();
        let sec = t.dir("secret");
        t.file("secret/key.txt");
        let link = t.dir("ok").join("link");
        std::os::unix::fs::symlink(&sec, &link).unwrap();
        let ok = t.root.join("ok");
        let rules = format!("[patches]\nallow = [\"{ok}/**\"]\ndeny = [\"{sec}\", \"{sec}/**\"]\n");
        let pol = policy(&rules);
        let err = gate(&t, &dir_patch(&link), &pol).unwrap_err().to_string();
        assert!(err.contains("policy denied"), "{err}");
    }

    /// A `..` segment is refused outright: under a parent that does not exist
    /// yet it resolves nowhere, and a read-write mapping would create it.
    #[test]
    fn a_parent_dir_segment_is_refused() {
        let t = Tree::new();
        let p = t.root.join("missing/../elsewhere");
        let pol = policy(&format!("[patches]\nallow = [\"{}/**\"]\n", t.root));
        let err = gate(&t, &dir_patch(&p), &pol).unwrap_err().to_string();
        assert!(err.contains("`..` segment"), "{err}");
    }

    /// A dangling symlink is refused: a read-write mapping would create its
    /// target, and the gate cannot say where that is.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_is_refused() {
        let t = Tree::new();
        let link = t.dir("ok").join("dangling");
        std::os::unix::fs::symlink(t.root.join("nowhere/at/all"), &link).unwrap();
        let pol = policy(&format!("[patches]\nallow = [\"{}/**\"]\n", t.root.join("ok")));
        let err = gate(&t, &file_patch(&link), &pol).unwrap_err().to_string();
        assert!(err.contains("does not resolve"), "{err}");
    }

    /// A `$NAME` in the policy expands against the invoking user's
    /// environment.
    #[test]
    fn policy_variables_expand_against_the_process_environment() {
        let t = Tree::new();
        let sec = t.dir("vault");
        let env = ProcessEnv::from_pairs(&[("VAULT", sec.as_str())]);
        let err = judge_task_patches(
            "peek",
            &dir_patch(&sec),
            &policy("[patches]\ndeny = [\"$VAULT\"]\n"),
            Path::new("/cfg/minimal/user_policy.toml"),
            t.root.as_std_path(),
            None,
            &env,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("policy denied"), "{err}");
    }
}
