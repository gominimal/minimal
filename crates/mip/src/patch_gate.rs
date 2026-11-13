//! The `[patches]` gate for the tasks `mip` runs by name (inbox#1128).
//!
//! A task's `patch.dir` and `patch.file` entries come from the project's
//! `minimal.toml`, which is untrusted input: an entry can name any host path
//! the invoking user can read, and the task's sandbox binds it in. `min`
//! judges a project's patches against the user's `[patches]` policy in
//! `user_policy.toml`. This module judges a task's entries against the same
//! file, with the same precedence, before the sandbox is built.
//!
//! [`UserPolicyGate`] is the gate. `mip` builds every context with
//! [`mctx::TaskPatchPolicy::Gated`] holding one (see `base_config`), and
//! both ways a task is run by name in a [`mctx::Context`] reach it through
//! [`mctx::gate_task_patches`], the hook in `mctx`: `mip run <task>` on the
//! host, and a nested `run <task>` that a sandbox sends over its
//! `/run/minenv_sock` channel (the in-sandbox `min run <task>` helper). The
//! policy lives here, not in `mctx`, because its types are in `boxes`, a
//! session-plane crate the build-plane facade may not depend on.
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
//!   probe runs only when some `deny` pattern can reach inside the directory
//!   and the entry would otherwise be mounted (an ignored entry exposes
//!   nothing, so it is not probed), and it is bounded: a tree it cannot read
//!   whole is refused, not mounted. A symlink the directory holds that
//!   resolves inside the directory is followed, and what it leads to is
//!   judged under the link's name too, since the mount exposes it there.
//!
//! The gate judges the entries as they are on disk when it runs, and
//! `Context::make_env` binds them afterwards, from the declared path. Nothing
//! is checked again in between or later: a symlink swapped in for an entry
//! after the check is followed by the bind, and a path created inside a
//! directory entry after the check is visible through the mount. Only
//! someone who can write the entry's parent directory, or the directory
//! itself, can do that: the user, a process running as the user, or a
//! sandbox the user gave a read-write mount of that directory (whose nested
//! `run <task>` is gated here as well). Binding the path the gate resolved
//! would close the first half; nothing checked before the mount closes the
//! second, since a bind mount shows the directory live.
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
use mctx::{Context, Error, GatedTask, PatchHome, TaskPatchGate};

/// The most entries a directory's deny probe walks before it refuses the
/// entry rather than mount a tree it has not checked whole.
pub(crate) const DIR_PROBE_LIMIT: usize = 10_000;

/// The `[patches]` gate `mip` runs a named task's patches through
/// (inbox#1128), behind [`mctx::TaskPatchGate`].
///
/// Judges the `patch.dir` / `patch.file` entries a task declares against the
/// user policy, and returns the task with only the entries the sandbox may
/// mount. `~/` expands against [`PatchHome::Ambient`], the home both callers
/// hand to `Context::make_env`.
#[derive(Debug)]
pub struct UserPolicyGate {
    /// The policy file; `None` for the user's own
    /// `<config>/minimal/user_policy.toml`, resolved only when a task has
    /// patches.
    policy_file: Option<PathBuf>,
}

impl UserPolicyGate {
    /// Judge against the `[patches]` section of the user's
    /// `<config>/minimal/user_policy.toml`, the file `min` reads.
    #[must_use]
    pub fn user() -> Self {
        Self { policy_file: None }
    }

    /// Judge against the policy in `policy_file`.
    #[cfg(test)]
    #[must_use]
    pub fn at(policy_file: PathBuf) -> Self {
        Self {
            policy_file: Some(policy_file),
        }
    }
}

impl TaskPatchGate for UserPolicyGate {
    /// # Errors
    ///
    /// - `policy denied ...` when a `deny` rule matches an entry, its
    ///   resolved path, or a path a directory entry holds.
    /// - A refusal carrying the `[patches] allow` snippet when an entry is
    ///   undecided: there is no prompt.
    /// - The policy file cannot be found, read or parsed; a pattern in it
    ///   does not expand; a directory's contents cannot be checked whole; or
    ///   a path cannot be resolved.
    fn gate(
        &self,
        ctx: &Context,
        task_name: &str,
        mut task: mfile::Task,
    ) -> Result<GatedTask, Error> {
        if task.patch.dir.is_empty() && task.patch.file.is_empty() {
            return Ok(GatedTask {
                task,
                ignored: Vec::new(),
            });
        }
        let policy_path = match &self.policy_file {
            Some(path) => path.clone(),
            None => user_policy_path().map_err(Error::Other)?,
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
        // judged as the entries are now; the module docs say what can change
        // before `make_env` binds them
        task.patch = kept;
        Ok(GatedTask { task, ignored })
    }
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
    // the one resolution `paths` makes, without its panics: `None` when no
    // config directory can be named at all
    paths::try_minimal_config_dir_with_override(None)
        .map(|dir| dir.join("user_policy.toml"))
        .ok_or_else(|| {
            anyhow!(
                "cannot find user_policy.toml to check this task's patches against: \
                 XDG_CONFIG_HOME is not set to an absolute path and there is no home directory \
                 whose path is valid UTF-8"
            )
        })
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
                // The policy file is named only where a rule in it is one of
                // the things the person can change: a probe the `deny`
                // pattern reaching inside the directory set off. A path that
                // cannot be judged (a `..` segment, a dangling link, an
                // unreadable ancestor) is the entry's own.
                let rules = if e.downcast_ref::<ProbeRefusal>().is_some() {
                    format!(" The `[patches]` rules are in {}.", policy_path.display())
                } else {
                    String::new()
                };
                anyhow!(
                    "task `{task_name}`: the run was refused because of \
                     {kind}.\"{declared}\". {e}{rules}"
                )
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
                         The rule is in `[patches]` of {}. Remove the entry from the task in \
                         the project's minimal.toml, or remove the rule that denies it.",
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
        return Err(anyhow!(
            "The path holds a `.` or `..` segment. Write the entry without one."
        ));
    }
    let own = decide(expanded, source, at);
    let resolved = resolve(at)?.filter(|r| r.as_path() != at);
    let target = resolved.as_ref().map(|r| decide(expanded, source, r));
    let mut verdict = own.max(target.unwrap_or(Verdict::Allowed));
    let mut denied_path = match (&resolved, target) {
        (Some(r), Some(Verdict::Denied)) if own != Verdict::Denied => Some(r.to_string()),
        _ => None,
    };
    // Only an entry that would be mounted is probed: an ignored one is
    // dropped from the sandbox and exposes nothing, so a `deny` hit inside
    // it, or a part of it that cannot be read, refuses nothing.
    if matches!(verdict, Verdict::Allowed | Verdict::NeedsApproval)
        && !is_file
        && !expanded.deny().is_empty()
    {
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
                let mut real = Utf8PathBuf::from_path_buf(real).map_err(|p| {
                    anyhow!(
                        "`{}` resolves to a path that is not UTF-8. Point the entry at \
                             a path that is.",
                        p.display()
                    )
                })?;
                for seg in tail.iter().rev().copied() {
                    real.push(seg);
                }
                return Ok(Some(real));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if std::fs::symlink_metadata(cur).is_ok_and(|m| m.file_type().is_symlink()) {
                    return Err(anyhow!(
                        "`{cur}` is a symbolic link that does not resolve. Fix the link, or \
                         point the entry at a path that exists."
                    ));
                }
            }
            Err(e) => {
                return Err(anyhow!(
                    "`{cur}` cannot be resolved: {e}. Point the entry at a path you can read."
                ));
            }
        }
        let (Some(parent), Some(name)) = (cur.parent(), cur.file_name()) else {
            return Ok(None);
        };
        tail.push(name);
        cur = parent;
    }
}

/// A directory entry the deny probe could not check whole. It is the one
/// refusal a `[patches]` rule sets off (the `deny` pattern that reaches
/// inside the directory is one of the two things the person can narrow),
/// so the refusal that reaches the person names the policy file for it.
#[derive(Debug)]
struct ProbeRefusal(String);

impl std::fmt::Display for ProbeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProbeRefusal {}

/// Look inside the directory entry for a path a `deny` rule matches. The
/// directory is walked at `on_disk` (its resolved form) and every path in it
/// is checked both there and under `declared`, the path the mount exposes.
/// Returns the first denied path.
///
/// A symlink inside the directory is judged by its own name, and where it
/// leads decides whether the probe looks further:
///
/// - A link that resolves to a directory inside `on_disk` is followed, and
///   every path under its target is judged under the link's name as well as
///   its own. The bind mount mirrors the directory one-for-one, so in the
///   sandbox the link resolves inside the same mount and exposes the target
///   under the link's name: with `patch.dir."~"` and `~/.ssh -> dotfiles/ssh`,
///   the sandbox reads `~/.ssh/id_ed25519`, and `deny = ["**/.ssh/**"]` must
///   see that name. Such a link is followed whether the walk covers the whole
///   directory or starts at a deny's own root, so every spelling of a deny
///   reaches the same paths.
/// - A link that leads out of `on_disk` is not followed. The sandbox resolves
///   it in its own mount namespace, where a host target is reachable only if
///   some entry mounts it, and that entry is gated on its own.
/// - A link whose target holds the link (a link to an ancestor), or a link
///   already followed on the way to it, is not followed again, so a cycle
///   ends. What it would add are further names, such as `a/up/a/...`, for
///   paths the walk already judges under their own names: a deny that
///   matches a path only under such a looped name is not seen.
///
/// Nothing is walked when no `deny` pattern can reach inside the directory.
/// A missing directory holds nothing yet (a read-write mapping creates it).
///
/// # Errors
///
/// When the walk cannot check the tree whole: more than
/// [`DIR_PROBE_LIMIT`] entries, counting those under followed links, or a
/// part it cannot read. The entry is then refused rather than mounted
/// unchecked.
fn probe_dir_for_deny(
    expanded: &ExpandedPatchesPolicy,
    source: &Source,
    declared: &Utf8Path,
    on_disk: &Utf8Path,
) -> Result<Option<String>, ProbeRefusal> {
    let Some(starts) = probe_starts(expanded, declared, on_disk) else {
        return Ok(None);
    };
    if !on_disk.as_std_path().is_dir() {
        return Ok(None);
    }
    let mut probe = Probe {
        expanded,
        source,
        declared,
        on_disk,
        seen: 0,
    };
    // each walk carries the contained links followed to reach it
    let mut work: std::collections::VecDeque<(ProbeStart, Vec<Utf8PathBuf>)> =
        starts.into_iter().map(|s| (s, Vec::new())).collect();
    while let Some((start, chain)) = work.pop_front() {
        if let Some(hit) = probe.walk(&start, &chain, &mut work)? {
            return Ok(Some(hit));
        }
    }
    Ok(None)
}

/// Where one walk of the deny probe starts: `real`, a directory on disk
/// inside `on_disk`, seen in the sandbox as `seen_as`. The two differ under
/// a contained symlink the probe followed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProbeStart {
    real: Utf8PathBuf,
    seen_as: Utf8PathBuf,
}

impl ProbeStart {
    fn at(path: &Utf8Path) -> Self {
        Self {
            real: path.to_path_buf(),
            seen_as: path.to_path_buf(),
        }
    }
}

/// The state of one directory's deny probe: what it judges against, and how
/// many entries its walks have met so far, shared by every walk so the
/// probe stays within [`DIR_PROBE_LIMIT`] however many links it follows.
struct Probe<'a> {
    expanded: &'a ExpandedPatchesPolicy,
    source: &'a Source,
    declared: &'a Utf8Path,
    on_disk: &'a Utf8Path,
    seen: usize,
}

impl Probe<'_> {
    /// Walk the tree at `start`, judging each path; queue a walk for each
    /// contained link the probe follows, with `chain` (the links followed to
    /// reach `start`) plus that link.
    fn walk(
        &mut self,
        start: &ProbeStart,
        chain: &[Utf8PathBuf],
        work: &mut std::collections::VecDeque<(ProbeStart, Vec<Utf8PathBuf>)>,
    ) -> Result<Option<String>, ProbeRefusal> {
        // a root under the directory that holds nothing has nothing to match;
        // a root that cannot be looked at is a part of the tree left unchecked
        match std::fs::symlink_metadata(start.real.as_std_path()) {
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(None);
            }
            Err(e) => {
                return Err(ProbeRefusal(format!(
                    "A part of it cannot be read to check it against `[patches] deny`: \
                     `{}`: {e}. Narrow the entry in the project's minimal.toml to the part \
                     you can read.",
                    start.real
                )));
            }
        }
        // the directory itself was decided already; a deny's own root is a path to judge
        let min_depth = usize::from(start.real == self.on_disk);
        for item in walkdir::WalkDir::new(start.real.as_std_path())
            .follow_links(false)
            .min_depth(min_depth)
        {
            let item = match item {
                Ok(item) => item,
                Err(e) => {
                    return Err(ProbeRefusal(format!(
                        "A part of it cannot be read to check it against `[patches] deny`: {e}. \
                         Narrow the entry in the project's minimal.toml to the part you can read."
                    )));
                }
            };
            self.seen += 1;
            if self.seen > DIR_PROBE_LIMIT {
                return Err(ProbeRefusal(format!(
                    "It holds more than {DIR_PROBE_LIMIT} entries, too many to check against \
                     `[patches] deny`. Narrow the entry in the project's minimal.toml, or narrow \
                     the `deny` pattern so it does not reach inside this directory."
                )));
            }
            let real = Utf8PathBuf::from(item.path().to_string_lossy().into_owned());
            let seen_as = match real.strip_prefix(&start.real) {
                Ok(rel) if !rel.as_str().is_empty() => start.seen_as.join(rel),
                _ => start.seen_as.clone(),
            };
            if let Some(hit) = self.denied_name(&real, &seen_as) {
                return Ok(Some(hit));
            }
            if item.file_type().is_symlink()
                && let Some(target) = contained_target(self.on_disk, &real, chain)
            {
                let mut followed = chain.to_vec();
                followed.push(real);
                work.push_back((
                    ProbeStart {
                        real: target,
                        seen_as,
                    },
                    followed,
                ));
            }
        }
        Ok(None)
    }

    /// The first name a `deny` matches among those `real` is seen by: its
    /// own, `seen_as` (its name through the links followed to it), and each
    /// of those under `declared`, the path the mount exposes.
    fn denied_name(&self, real: &Utf8Path, seen_as: &Utf8Path) -> Option<String> {
        let mut names: Vec<Utf8PathBuf> = Vec::with_capacity(4);
        for name in [real, seen_as] {
            let exposed = match name.strip_prefix(self.on_disk) {
                Ok(rel) if !rel.as_str().is_empty() => self.declared.join(rel),
                Ok(_) => self.declared.to_path_buf(),
                Err(_) => name.to_path_buf(),
            };
            for n in [name.to_path_buf(), exposed] {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
        names
            .into_iter()
            .find(|n| decide(self.expanded, self.source, n) == Verdict::Denied)
            .map(|n| n.to_string())
    }
}

/// Where the contained symlink at `link` leads, when the deny probe follows
/// it (see [`probe_dir_for_deny`]): a directory inside `on_disk`. `None` for
/// a link out of `on_disk`, a link to a file (judged by the link's own name
/// already), a link that does not resolve or cannot be resolved (the sandbox,
/// running as the same user, cannot follow it either), and a link that would
/// close a cycle: its target holds the link, or `chain`, the links followed
/// on the way here, holds it already.
fn contained_target(
    on_disk: &Utf8Path,
    link: &Utf8Path,
    chain: &[Utf8PathBuf],
) -> Option<Utf8PathBuf> {
    let target = std::fs::canonicalize(link.as_std_path()).ok()?;
    let target = Utf8PathBuf::from(target.to_string_lossy().into_owned());
    let followed = target.starts_with(on_disk)
        && !link.starts_with(&target)
        && !chain.iter().any(|c| c.as_path() == link)
        && target.as_std_path().is_dir();
    followed.then_some(target)
}

/// Where the probe of a directory walks: `None` when no `deny` can reach
/// inside it, else the roots to walk, each mapped into `on_disk`. A deny
/// whose literal prefix lies under the directory can match only under that
/// prefix, so only that part is walked: `~/.ssh/**` against `patch.dir."~"`
/// counts the entries of `~/.ssh`, not of the home. A deny with no prefix,
/// or one whose prefix is the directory or above it, walks the directory
/// whole, and one such deny makes the whole walk the only one.
fn probe_starts(
    expanded: &ExpandedPatchesPolicy,
    declared: &Utf8Path,
    on_disk: &Utf8Path,
) -> Option<Vec<ProbeStart>> {
    let mut starts: Vec<ProbeStart> = Vec::new();
    let mut whole = false;
    let mut any = false;
    for fs in expanded.deny() {
        for base in [declared, on_disk] {
            if !deny_reaches_inside(fs, base.as_str()) {
                continue;
            }
            any = true;
            let inside = format!("{}/", base.as_str().trim_end_matches('/'));
            match fs.walk_root() {
                Some(root) if root.as_str().starts_with(&inside) => {
                    let rel = root.as_str()[inside.len()..].trim_end_matches('/');
                    let start = narrowed_root(on_disk, rel);
                    if !starts.contains(&start) {
                        starts.push(start);
                    }
                }
                _ => whole = true,
            }
        }
    }
    if !any {
        return None;
    }
    Some(if whole {
        vec![ProbeStart::at(on_disk)]
    } else {
        starts
    })
}

/// Where a probe narrowed to `rel` under `on_disk` may start: `on_disk`
/// joined with the longest leading part of `rel` the probe can follow.
///
/// A path lookup follows every symlink on the way, whatever the walk's
/// `follow_links`, so a walk rooted at `<dir>/link/sub` would read the
/// target of a link the directory holds. A link the probe follows (one that
/// resolves to a directory inside `on_disk`, see [`contained_target`]) is
/// narrowed through: the walk starts at its target, seen under the link's
/// name. At any other link the root stops at the link's parent, where the
/// walk meets the link as an entry and does not descend into it. A part
/// that does not exist, or cannot be looked at, is joined as is: the probe
/// skips a root that is not there and refuses one it cannot read.
fn narrowed_root(on_disk: &Utf8Path, rel: &str) -> ProbeStart {
    let mut start = ProbeStart::at(on_disk);
    for seg in rel.split('/').filter(|s| !s.is_empty()) {
        let next = start.real.join(seg);
        let is_link =
            std::fs::symlink_metadata(next.as_std_path()).is_ok_and(|m| m.file_type().is_symlink());
        start.real = if is_link {
            match contained_target(on_disk, &next, &[]) {
                Some(target) => target,
                None => break,
            }
        } else {
            next
        };
        start.seen_as.push(seg);
    }
    start
}

/// Whether the expanded `deny` pattern can match a path strictly inside the
/// directory `dir`. Errs towards `true`, which costs a walk; a false `false`
/// would skip a deny.
///
/// The pattern's own walk root decides ([`FileSet::walk_root`], the one
/// reading of a glob's literal prefix): a pattern with no metacharacter is
/// its own root and names one path, so it must lie under `dir`; one with no
/// literal prefix at all can reach anywhere; otherwise a `*` can cross `/`,
/// so the root only has to agree with `dir/` as far as the shorter of the
/// two reaches.
fn deny_reaches_inside(fs: &boxes::core::primitives::FileSet, dir: &str) -> bool {
    let inside = format!("{}/", dir.trim_end_matches('/'));
    match fs.walk_root() {
        None => true,
        Some(root) if root.as_str() == fs.pattern() => fs.pattern().starts_with(&inside),
        Some(root) => {
            let root = format!("{}/", root.as_str().trim_end_matches('/'));
            root.starts_with(&inside) || inside.starts_with(&root)
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

    /// An ignored entry is dropped from the sandbox and exposes nothing, so
    /// what it holds is not probed: a `deny` that refuses the same directory
    /// as an allowed entry refuses nothing here, and the run goes on without
    /// the entry.
    #[test]
    fn an_ignored_directory_is_not_probed() {
        let t = Tree::new();
        let keep = t.dir("keep");
        let drop = t.dir("drop");
        t.file("drop/nested/id.pem");
        let mut patches = dir_patch(&keep);
        patches.dir.insert(drop.to_string(), PatchSetting::ReadOnly);
        let rules = format!(
            "[patches]\nallow = [\"{keep}\"]\nignore = [\"{drop}\"]\ndeny = [\"**/*.pem\"]\n"
        );
        let (kept, ignored) = judge(&t, &patches, &policy(&rules)).unwrap();
        assert_eq!(kept, dir_patch(&keep));
        assert_eq!(ignored, vec![drop.to_string()]);
        // The same directory as an allowed entry is probed, and refused.
        let allowed =
            format!("[patches]\nallow = [\"{keep}\", \"{drop}\"]\ndeny = [\"**/*.pem\"]\n");
        let err = judge(&t, &patches, &policy(&allowed))
            .unwrap_err()
            .to_string();
        assert!(err.contains("policy denied"), "{err}");
    }

    /// What the person at `mip run` reads when an entry cannot be judged:
    /// that the run was refused because of the entry, then why. The policy
    /// file is named only for a probe a `deny` pattern set off; a path that
    /// cannot be resolved names no rule, since none caused it.
    #[cfg(unix)]
    #[test]
    fn a_refusal_names_the_entry_and_the_policy_file_only_for_a_probe() {
        let t = Tree::new();
        let d = t.dir("cfg");
        let dangling = t.root.join("cfg/gone");
        std::os::unix::fs::symlink("/nowhere/at/all", &dangling).unwrap();
        let pol = policy(&format!("[patches]\nallow = [\"{d}\"]\n"));
        let err = gate(&t, &dir_patch(&dangling), &pol)
            .unwrap_err()
            .to_string();
        let head =
            format!("task `peek`: the run was refused because of patch.dir.\"{dangling}\". ");
        assert!(err.starts_with(&head), "{err}");
        assert!(err.contains("does not resolve"), "{err}");
        assert!(!err.contains("rules are in"), "{err}");
        assert!(!err.contains("not mounted"), "{err}");
    }

    /// A `deny` with a fixed root inside the directory is probed under that
    /// root alone: a home past the probe limit with `deny = ["<home>/.ssh/**"]`
    /// is not walked whole, so it is not refused for its size, and a key under
    /// `.ssh` is still found; a `deny` with no fixed root walks it whole.
    #[test]
    fn the_probe_walks_from_each_denys_root_not_the_whole_directory() {
        let t = Tree::new();
        let home = t.dir("home");
        let bulk = t.dir("home/bulk");
        for i in 0..=DIR_PROBE_LIMIT {
            std::fs::write(bulk.join(format!("f{i}")), "").unwrap();
        }
        let rules = format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"{home}/.ssh/**\"]\n");
        assert_eq!(
            gate(&t, &dir_patch(&home), &policy(&rules)).unwrap(),
            dir_patch(&home)
        );
        t.file("home/.ssh/id_ed25519");
        let err = gate(&t, &dir_patch(&home), &policy(&rules))
            .unwrap_err()
            .to_string();
        assert!(err.contains("policy denied"), "{err}");
        assert!(err.contains("id_ed25519"), "{err}");
        let whole = format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"**/*.pem\"]\n");
        let err = gate(&t, &dir_patch(&home), &policy(&whole))
            .unwrap_err()
            .to_string();
        assert!(err.contains("too many to check"), "{err}");
    }

    /// A symlink inside an allowed directory that leads out of it is judged
    /// as the link: the mount carries the link, which resolves in the
    /// sandbox's namespace, where its host target is not mounted. The target
    /// is not followed, so the result does not depend on whether some `deny`
    /// reaches inside the directory.
    #[cfg(unix)]
    #[test]
    fn a_contained_symlink_is_judged_as_the_link() {
        let t = Tree::new();
        let sec = t.dir("secret");
        t.file("secret/key.txt");
        let d = t.dir("proj-cfg");
        std::os::unix::fs::symlink(&sec, d.join("to-secret")).unwrap();
        let rules = format!("[patches]\nallow = [\"{d}\"]\ndeny = [\"{sec}\", \"{sec}/**\"]\n");
        assert_eq!(
            gate(&t, &dir_patch(&d), &policy(&rules)).unwrap(),
            dir_patch(&d)
        );
        // With a deny that reaches inside, the walk runs and still judges the
        // link by its own path, which no rule denies.
        let rules = format!(
            "[patches]\nallow = [\"{d}\"]\ndeny = [\"{sec}\", \"{sec}/**\", \"{d}/*.pem\"]\n"
        );
        assert_eq!(
            gate(&t, &dir_patch(&d), &policy(&rules)).unwrap(),
            dir_patch(&d)
        );
    }

    /// A `deny` whose root lies under a symlink out of the directory does not
    /// narrow the probe through the link: a walk rooted past the link would
    /// read the link's host target, which the probe does not follow. The link
    /// is judged as the link, as when the directory is walked whole, while
    /// the same `deny` under a real subdirectory still narrows and finds what
    /// it names.
    #[cfg(unix)]
    #[test]
    fn the_probe_does_not_narrow_through_a_contained_symlink() {
        let t = Tree::new();
        let vault = t.dir("vault");
        t.file("vault/sub/id.pem");
        let home = t.dir("home");
        std::os::unix::fs::symlink(&vault, home.join("link")).unwrap();
        assert_eq!(narrowed_root(&home, "link/sub"), ProbeStart::at(&home));
        let rules =
            format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"{home}/link/sub/*.pem\"]\n");
        assert_eq!(
            gate(&t, &dir_patch(&home), &policy(&rules)).unwrap(),
            dir_patch(&home)
        );

        let key = t.file("home/real/sub/id.pem");
        assert_eq!(
            narrowed_root(&home, "real/sub"),
            ProbeStart::at(&home.join("real/sub"))
        );
        let rules =
            format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"{home}/real/sub/*.pem\"]\n");
        let err = gate(&t, &dir_patch(&home), &policy(&rules))
            .unwrap_err()
            .to_string();
        assert!(err.contains("policy denied"), "{err}");
        assert!(err.contains(key.as_str()), "{err}");
    }

    /// A stow layout: `patch.dir` is the home, and `~/.ssh` is a link to a
    /// directory inside it. The mount mirrors the home, so the sandbox reads
    /// the key as `~/.ssh/id_ed25519`, and both spellings of the deny refuse
    /// the entry: one with no root, which walks the home and follows the
    /// link, and one rooted at `~/.ssh`, which narrows through the link.
    #[cfg(unix)]
    #[test]
    fn a_link_inside_the_directory_is_judged_under_its_name() {
        let t = Tree::new();
        let home = t.dir("home");
        t.file("home/dotfiles/ssh/id_ed25519");
        std::os::unix::fs::symlink("dotfiles/ssh", home.join(".ssh")).unwrap();
        assert_eq!(
            narrowed_root(&home, ".ssh"),
            ProbeStart {
                real: home.join("dotfiles/ssh"),
                seen_as: home.join(".ssh"),
            }
        );
        for deny in ["**/.ssh/**".to_owned(), format!("{home}/.ssh/**")] {
            let rules = format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"{deny}\"]\n");
            let err = gate(&t, &dir_patch(&home), &policy(&rules))
                .unwrap_err()
                .to_string();
            assert!(err.contains("policy denied"), "{deny}: {err}");
            let exposed = home.join(".ssh/id_ed25519");
            assert!(err.contains(exposed.as_str()), "{deny}: {err}");
        }
    }

    /// A link out of the directory is not followed, with or without a root
    /// on the deny: its target is reachable in the sandbox only if another
    /// entry mounts it, and that entry is gated on its own.
    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_directory_is_not_followed() {
        let t = Tree::new();
        let home = t.dir("home");
        let outside = t.dir("elsewhere/ssh");
        t.file("elsewhere/ssh/id_ed25519");
        std::os::unix::fs::symlink(&outside, home.join(".ssh")).unwrap();
        assert_eq!(narrowed_root(&home, ".ssh"), ProbeStart::at(&home));
        for deny in ["**/.ssh/**".to_owned(), format!("{home}/.ssh/**")] {
            let rules = format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"{deny}\"]\n");
            assert_eq!(
                gate(&t, &dir_patch(&home), &policy(&rules)).unwrap(),
                dir_patch(&home),
                "{deny}"
            );
        }
    }

    /// Link cycles inside the directory end: a link to an ancestor, two
    /// links into each other, and a link to itself. The probe stays far
    /// below its limit, and a denied file inside the loop is still found.
    #[cfg(unix)]
    #[test]
    fn a_link_cycle_inside_the_directory_ends() {
        let t = Tree::new();
        let home = t.dir("home");
        let a = t.dir("home/a");
        let b = t.dir("home/b");
        std::os::unix::fs::symlink(&home, a.join("up")).unwrap();
        std::os::unix::fs::symlink(&b, a.join("to-b")).unwrap();
        std::os::unix::fs::symlink(&a, b.join("to-a")).unwrap();
        std::os::unix::fs::symlink("self", home.join("self")).unwrap();
        let rules = format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"**/*.pem\"]\n");
        assert_eq!(
            gate(&t, &dir_patch(&home), &policy(&rules)).unwrap(),
            dir_patch(&home)
        );
        let key = t.file("home/b/id.pem");
        let err = gate(&t, &dir_patch(&home), &policy(&rules))
            .unwrap_err()
            .to_string();
        assert!(err.contains("policy denied"), "{err}");
        assert!(err.contains(key.as_str()), "{err}");
    }

    /// A `deny` root under the directory that is not there holds nothing to
    /// match; one the probe cannot look at is a part of the tree left
    /// unchecked, so the entry is refused, not mounted. Here the lookup fails
    /// because the name is longer than a file name may be.
    #[test]
    fn a_probe_root_that_cannot_be_looked_at_refuses_the_entry() {
        let t = Tree::new();
        let home = t.dir("home");
        let rules = format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"{home}/.ssh/**\"]\n");
        assert_eq!(
            gate(&t, &dir_patch(&home), &policy(&rules)).unwrap(),
            dir_patch(&home)
        );

        let long = "n".repeat(300);
        let rules = format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"{home}/{long}/**\"]\n");
        let err = gate(&t, &dir_patch(&home), &policy(&rules))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be read to check it"), "{err}");
        assert!(err.contains("rules are in"), "{err}");
    }

    /// As above, for the case the probe exists for: a `deny` root under a
    /// directory the user cannot search. Skipped when the process can read
    /// the directory anyway (it runs as root).
    #[cfg(unix)]
    #[test]
    fn a_probe_root_under_an_unsearchable_directory_refuses_the_entry() {
        use std::os::unix::fs::PermissionsExt as _;
        let t = Tree::new();
        let home = t.dir("home");
        let locked = t.dir("home/locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let privileged = std::fs::read_dir(&locked).is_ok();
        let rules =
            format!("[patches]\nallow = [\"{home}\"]\ndeny = [\"{home}/locked/.ssh/**\"]\n");
        let judged = gate(&t, &dir_patch(&home), &policy(&rules));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if privileged {
            return;
        }
        let err = judged.unwrap_err().to_string();
        assert!(err.contains("cannot be read to check it"), "{err}");
        assert!(err.contains("locked/.ssh"), "{err}");
    }

    /// The gate as `mip`'s contexts carry it, through the hook in `mctx`: the
    /// fixture's task `peek-denied` declares a patch the policy file denies,
    /// and the refusal names that file. A task without patches passes.
    #[test]
    fn the_user_policy_gate_refuses_through_the_context_hook() {
        let state = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        let policy_file = cfg.path().join("user_policy.toml");
        std::fs::write(
            &policy_file,
            "[patches]\ndeny = [\"/min-test-1128-denied\", \"/min-test-1128-denied/**\"]\n",
        )
        .unwrap();
        let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let user_gate = UserPolicyGate::at(policy_file.clone());
        let config = mctx::ConfigBuilder::new()
            .with_state_dir(state.path().to_path_buf())
            .with_repo_dir(manifest_dir.join("../mctx/testdata/patchrepo"))
            .with_stdlib_dir(manifest_dir.join("../stdlib/minimal-ncl"))
            .with_no_fetch(true)
            .with_task_patch_policy(mctx::TaskPatchPolicy::Gated(std::sync::Arc::new(user_gate)))
            .build()
            .unwrap();
        let mut ctx = Context::new(config).unwrap();
        let graph = ctx.graph_from_all_packages().unwrap();
        let (task, graph) = ctx.task(graph, "peek-denied").unwrap().unwrap();
        let err = mctx::gate_task_patches(&ctx, "peek-denied", task)
            .unwrap_err()
            .to_string();
        assert!(err.contains("policy denied"), "{err}");
        assert!(err.contains("/min-test-1128-denied"), "{err}");
        assert!(err.contains(policy_file.to_str().unwrap()), "{err}");

        let (task, _) = ctx.task(graph, "no-patches").unwrap().unwrap();
        let gated = mctx::gate_task_patches(&ctx, "no-patches", task).unwrap();
        assert!(gated.task.patch.dir.is_empty() && gated.task.patch.file.is_empty());
    }

    /// Deny outranks allow: an allowed directory holding a denied file is
    /// refused, since the mount would expose the file, and the refusal names
    /// the file.
    #[test]
    fn a_directory_holding_a_denied_file_is_refused() {
        let t = Tree::new();
        let d = t.dir("proj-cfg");
        let key = t.file("proj-cfg/nested/id.pem");
        let pol = policy(&format!(
            "[patches]\nallow = [\"{d}\"]\ndeny = [\"**/*.pem\"]\n"
        ));
        let err = gate(&t, &dir_patch(&d), &pol).unwrap_err().to_string();
        assert!(err.contains("policy denied"), "{err}");
        assert!(err.contains(key.as_str()), "{err}");
    }

    /// Which `deny` patterns make the gate walk a directory entry: only those
    /// that can match a path inside it, so a deny elsewhere leaves a large
    /// allowed tree unwalked.
    #[test]
    fn a_deny_elsewhere_does_not_walk_the_directory() {
        let reaches = |pattern: &str, dir: &str| {
            deny_reaches_inside(
                &boxes::core::primitives::FileSet::try_new(pattern).unwrap(),
                dir,
            )
        };
        assert!(!reaches("/home/u/.ssh/**", "/home/u/cache"));
        assert!(!reaches("/home/u/.ssh", "/home/u/cache"));
        assert!(!reaches("/home/u/.ssh", "/home/u/.ssh"));
        assert!(reaches("/home/u/.ssh", "/home/u"));
        assert!(reaches("/home/u/.ssh/**", "/home/u"));
        assert!(reaches("/home/u/**", "/home/u/cache"));
        assert!(reaches("**/*.pem", "/home/u/cache"));
        // A root that is a prefix of the name, not of the path, reaches no
        // further than its own directory.
        assert!(!reaches("/home/u/**", "/home/user/cache"));
    }

    /// `~/` expands against the home `mip` mounts from, and the policy's own
    /// `~/` expands against the same home, so a `~/` deny meets a `~/` entry.
    #[test]
    fn a_home_relative_entry_meets_a_home_relative_deny() {
        let t = Tree::new();
        t.file("home/.ssh/id_ed25519");
        let mut patches = EnvPatches::default();
        patches
            .dir
            .insert("~/.ssh".to_owned(), PatchSetting::ReadOnly);
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
        let pol = policy(&format!(
            "[patches]\nallow = [\"{}/**\"]\n",
            t.root.join("ok")
        ));
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
