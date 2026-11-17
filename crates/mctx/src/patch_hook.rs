//! The hook a task run by name has its `[patches]` judged through
//! (inbox#1128).
//!
//! A task's `patch.dir` and `patch.file` entries come from the project's
//! `minimal.toml`, which is untrusted input: an entry can name any host path
//! the invoking user can read, and the task's sandbox binds it in. Both ways
//! a task is run by name in a [`Context`] pass [`gate_task_patches`] after the
//! task is looked up and before [`Context::make_env`]: `mip run <task>` on the
//! host, and a nested `run <task>` that a sandbox sends over its
//! `/run/minenv_sock` channel (the in-sandbox `min run <task>` helper).
//!
//! What the gate decides is the context's [`TaskPatchPolicy`]. The default,
//! [`TaskPatchPolicy::Ungated`], mounts the entries as declared, which is the
//! daemon's behaviour (its task patches are inbox#602).
//! [`TaskPatchPolicy::Gated`] hands them to a [`TaskPatchGate`]. The policy
//! itself, the user's `[patches]` in `user_policy.toml`, lives in `mip`: its
//! types belong to the session plane, which this crate does not reach.

use crate::{Context, Error, TaskPatchPolicy};

/// Judges the patch entries of a task run by name, for a context built with
/// [`TaskPatchPolicy::Gated`].
pub trait TaskPatchGate: Send + Sync + std::fmt::Debug {
    /// Judge the `patch.dir` / `patch.file` entries `task` declares, and
    /// return the task with only the entries its sandbox may mount.
    ///
    /// Called only for a task that declares patches.
    ///
    /// # Errors
    ///
    /// When the task must not run: an entry is refused, or the entries
    /// cannot be judged. The error is shown to the person who ran the task.
    fn gate(&self, ctx: &Context, task_name: &str, task: mfile::Task) -> Result<GatedTask, Error>;
}

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
/// Under [`TaskPatchPolicy::Ungated`], and for a task without patches, the
/// task is returned untouched and no gate is called. Under
/// [`TaskPatchPolicy::Gated`] the context's [`TaskPatchGate`] decides.
///
/// # Errors
///
/// Whatever the context's gate refuses the task with.
pub fn gate_task_patches(
    ctx: &Context,
    task_name: &str,
    task: mfile::Task,
) -> Result<GatedTask, Error> {
    let has_patches = !(task.patch.dir.is_empty() && task.patch.file.is_empty());
    match ctx.daemon.config.task_patch_policy() {
        TaskPatchPolicy::Gated(gate) if has_patches => gate.gate(ctx, task_name, task),
        TaskPatchPolicy::Ungated | TaskPatchPolicy::Gated(_) => Ok(GatedTask {
            task,
            ignored: Vec::new(),
        }),
    }
}
