//! The `update` operation: refresh upstream/sideload checkouts and re-pin them
//! in the project's `minimal.toml`.

use anyhow::anyhow;
use mfile::LinkConfig;
use toml_edit::{DocumentMut, Item, TableLike, Value, value};

use super::{ProjectEnv, ProjectOp};
use crate::Error;

/// Refreshes a project's upstream and sideload checkouts to the head of their
/// tracking branches and re-pins the new commits in `minimal.toml`.
///
/// Downloading any newly-reachable packages is deliberately left to the caller:
/// this operation only concerns the `minimal.toml` and its checkouts.
#[derive(Debug, Default, Clone, Copy)]
pub struct UpdateProject;

/// A single pin that moved during an update.
#[derive(Debug, Clone)]
pub struct RevChange {
    /// The repository whose pin changed.
    pub repo: String,
    /// The tracking branch the new commit was taken from.
    pub branch: String,
    /// The previously pinned commit, if any (`None` when previously unpinned).
    pub from: Option<String>,
    /// The newly pinned commit.
    pub to: String,
}

/// A summary of what [`UpdateProject`] changed, for the caller to report.
#[derive(Debug, Default, Clone)]
pub struct UpdateReport {
    /// The upstream pin, if it moved.
    pub upstream: Option<RevChange>,
    /// Any sideload pins that moved.
    pub sideloads: Vec<RevChange>,
    /// Pins whose branch moved but were not written, because `minimal.toml`
    /// changed under the update and no link still names the pin's repo,
    /// branch and old commit.
    pub skipped: Vec<RevChange>,
}

impl UpdateReport {
    /// Whether any pin was written to `minimal.toml`.
    pub fn repinned(&self) -> bool {
        self.upstream.is_some() || !self.sideloads.is_empty()
    }
}

impl RevChange {
    /// The line telling the user this pin was skipped and to run `command`
    /// (such as `min update`) again.
    pub fn skipped_message(&self, command: &str) -> String {
        format!(
            "minimal.toml changed during the update, so {}:{} was not re-pinned. Run {command} again",
            self.repo, self.branch,
        )
    }
}

impl ProjectOp for UpdateProject {
    type Result = UpdateReport;

    fn run<E: ProjectEnv>(&mut self, env: &mut E) -> Result<UpdateReport, Error> {
        // Snapshot everything we need from the minimal file before taking the
        // mutable borrows the checkout/update calls require.
        let Some(mfile) = env.minimal_file() else {
            // No minimal file to re-pin; still refresh checkouts best-effort.
            env.invalidate_remote_index();
            env.update_checkouts()?;
            return Ok(UpdateReport::default());
        };
        let mfile_path = mfile.file_path().cloned();

        let upstream: Option<(String, Option<String>, Option<String>)> =
            match mfile.upstream.as_ref().map(|u| &u.link) {
                Some(LinkConfig::Git {
                    repo,
                    branch,
                    locked_commit,
                }) => Some((repo.clone(), branch.clone(), locked_commit.clone())),
                Some(LinkConfig::Dir { .. }) | None => None,
            };

        // Each git sideload with a tracking branch, as read before the lock.
        // The write below finds each one again by identity, not by index.
        let sideloads: Vec<(String, String, Option<String>)> = mfile
            .upstream
            .as_ref()
            .map(|u| u.sideloads())
            .unwrap_or_default()
            .iter()
            .filter_map(|s| match s.link() {
                LinkConfig::Git {
                    repo,
                    branch: Some(branch),
                    locked_commit,
                } => Some((repo.clone(), branch.clone(), locked_commit.clone())),
                _ => None,
            })
            .collect();

        // best effort, yeet any cached remote index so a fresh fetch occurs
        env.invalidate_remote_index();
        env.update_checkouts()?;

        // If a tracking branch is specified for the upstream, check out its head.
        let upstream_pin = match upstream {
            Some((repo, Some(branch), from)) => {
                let to = env.checkout_branch(&repo, &branch)?;
                (Some(&to) != from.as_ref()).then_some(RevChange {
                    repo,
                    branch,
                    from,
                    to,
                })
            }
            _ => None,
        };

        // Update all the sideloads, if present.
        let mut sideload_pins = Vec::new();
        for (repo, branch, from) in sideloads {
            let to = env.checkout_branch(&repo, &branch)?;
            if Some(&to) != from.as_ref() {
                sideload_pins.push(RevChange {
                    repo,
                    branch,
                    from,
                    to,
                });
            }
        }

        // If theres a minimal file on disk with at least one new rev, write the
        // revs to the minimal file.
        let Some(p) = mfile_path else {
            return Ok(UpdateReport::default());
        };
        if upstream_pin.is_none() && sideload_pins.is_empty() {
            return Ok(UpdateReport::default());
        }

        // The checkouts above run outside the lock, because they fetch over
        // the network. So another command can edit `minimal.toml` between
        // the snapshot and this write. The re-read under the lock is the
        // truth: each pin lands only on a link that still names the same
        // repo, branch and old commit, wherever that link now sits.
        let mut report = UpdateReport::default();
        mfile::File::edit_exclusively::<anyhow::Error>(&p, |content| {
            let toml =
                content.ok_or_else(|| anyhow!("reading {} for update: not found", p.display()))?;
            let mut doc = toml.parse::<DocumentMut>().map_err(anyhow::Error::from)?;
            report = apply_pins(&mut doc, upstream_pin, sideload_pins);
            Ok(report.repinned().then(|| doc.to_string()))
        })?;

        Ok(report)
    }
}

/// Writes each pin into `doc` on the link that still matches it: the same
/// `repo`, `branch` and old `locked_commit`. A pin whose link changed or
/// went away since the snapshot is not written. Returns the pins that landed,
/// and those that did not in [`UpdateReport::skipped`].
fn apply_pins(
    doc: &mut DocumentMut,
    upstream: Option<RevChange>,
    sideloads: Vec<RevChange>,
) -> UpdateReport {
    let mut report = UpdateReport::default();
    // The loader reads `[base]` as `[upstream]`, and `sideloads` as
    // `sideload`, so the pins look under every spelling it accepts.
    let Some(up) = ["upstream", "base"]
        .into_iter()
        .find(|k| doc.contains_key(k))
        .and_then(|k| doc.get_mut(k))
        .and_then(Item::as_table_like_mut)
    else {
        report.skipped.extend(upstream);
        report.skipped.extend(sideloads);
        return report;
    };
    if let Some(pin) = upstream {
        if repin(up, &pin) {
            report.upstream = Some(pin);
        } else {
            report.skipped.push(pin);
        }
    }
    let mut links: Vec<&mut dyn TableLike> = Vec::new();
    for (key, item) in up.iter_mut() {
        if key.get() != "sideload" && key.get() != "sideloads" {
            continue;
        }
        match item {
            Item::ArrayOfTables(a) => {
                links.extend(a.iter_mut().map(|t| t as &mut dyn TableLike));
            }
            Item::Value(Value::Array(a)) => links.extend(
                a.iter_mut()
                    .filter_map(Value::as_inline_table_mut)
                    .map(|t| t as &mut dyn TableLike),
            ),
            _ => {}
        }
    }
    // Each pin lands on one link, which it then consumes. Two sideloads with
    // the same repo, branch and old commit give two equal pins, and each one
    // must repin its own link rather than the first pin taking both.
    for pin in sideloads {
        match links.iter_mut().position(|link| repin(*link, &pin)) {
            Some(i) => {
                links.remove(i);
                report.sideloads.push(pin);
            }
            None => report.skipped.push(pin),
        }
    }
    report
}

/// Sets `locked_commit` to `pin.to` when `link` still names the pin's repo,
/// branch and old commit.
fn repin(link: &mut dyn TableLike, pin: &RevChange) -> bool {
    let field = |k: &str| link.get(k).and_then(Item::as_str).map(str::to_owned);
    if field("repo").as_deref() != Some(pin.repo.as_str())
        || field("branch").as_deref() != Some(pin.branch.as_str())
        || field("locked_commit") != pin.from
    {
        return false;
    }
    link.insert("locked_commit", value(pin.to.clone()));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(repo: &str, from: Option<&str>, to: &str) -> RevChange {
        RevChange {
            repo: repo.into(),
            branch: "main".into(),
            from: from.map(Into::into),
            to: to.into(),
        }
    }

    #[test]
    fn apply_pins_finds_a_sideload_that_moved() {
        // The snapshot saw `a` then `b`. A concurrent edit put `c` first.
        let mut doc = r#"
[upstream]
repo = "up"
branch = "main"
locked_commit = "u0"

[[upstream.sideload]]
repo = "c"
branch = "main"
locked_commit = "c0"

[[upstream.sideload]]
repo = "a"
branch = "main"
locked_commit = "a0"

[[upstream.sideload]]
repo = "b"
branch = "main"
"#
        .parse::<DocumentMut>()
        .unwrap();
        let report = apply_pins(
            &mut doc,
            Some(pin("up", Some("u0"), "u1")),
            vec![pin("a", Some("a0"), "a1"), pin("b", None, "b1")],
        );
        let up = &doc["upstream"];
        assert_eq!(up["locked_commit"].as_str(), Some("u1"));
        let sl = up["sideload"].as_array_of_tables().unwrap();
        let commits: Vec<_> = sl
            .iter()
            .map(|t| t.get("locked_commit").and_then(Item::as_str))
            .collect();
        assert_eq!(commits, [Some("c0"), Some("a1"), Some("b1")]);
        assert!(report.upstream.is_some());
        assert_eq!(report.sideloads.len(), 2);
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn apply_pins_lands_equal_pins_once_each() {
        // Two sideloads share repo, branch and old commit, so the snapshot
        // gives two equal pins. Each pin must land on its own link.
        let mut doc = r#"
[upstream]
repo = "up"
branch = "main"
locked_commit = "u0"

[[upstream.sideload]]
repo = "a"
branch = "main"
locked_commit = "a0"

[[upstream.sideload]]
repo = "a"
branch = "main"
locked_commit = "a0"
"#
        .parse::<DocumentMut>()
        .unwrap();
        let report = apply_pins(
            &mut doc,
            None,
            vec![pin("a", Some("a0"), "a1"), pin("a", Some("a0"), "a1")],
        );
        let sl = doc["upstream"]["sideload"].as_array_of_tables().unwrap();
        let commits: Vec<_> = sl
            .iter()
            .map(|t| t.get("locked_commit").and_then(Item::as_str))
            .collect();
        assert_eq!(commits, [Some("a1"), Some("a1")]);
        assert_eq!(report.sideloads.len(), 2);
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn apply_pins_drops_a_pin_whose_link_changed_or_went_away() {
        let mut doc = r#"
[upstream]
repo = "up"
branch = "main"
locked_commit = "other"
sideload = [{ repo = "a", branch = "main", locked_commit = "a0" }]
"#
        .parse::<DocumentMut>()
        .unwrap();
        let before = doc.to_string();
        let report = apply_pins(
            &mut doc,
            Some(pin("up", Some("u0"), "u1")),
            vec![pin("gone", Some("g0"), "g1")],
        );
        assert_eq!(doc.to_string(), before);
        assert!(report.upstream.is_none());
        assert!(report.sideloads.is_empty());
        assert!(!report.repinned());
        let skipped: Vec<_> = report.skipped.iter().map(|p| p.repo.as_str()).collect();
        assert_eq!(skipped, ["up", "gone"]);

        let report = apply_pins(&mut doc, None, vec![pin("a", Some("a0"), "a1")]);
        assert_eq!(report.sideloads.len(), 1);
        assert_eq!(
            doc["upstream"]["sideload"][0]["locked_commit"].as_str(),
            Some("a1")
        );
    }

    #[test]
    fn apply_pins_honours_the_base_alias() {
        let mut doc = r#"
[base]
repo = "up"
branch = "main"
locked_commit = "u0"

[[base.sideload]]
repo = "a"
branch = "main"
locked_commit = "a0"
"#
        .parse::<DocumentMut>()
        .unwrap();
        let report = apply_pins(
            &mut doc,
            Some(pin("up", Some("u0"), "u1")),
            vec![pin("a", Some("a0"), "a1")],
        );
        assert!(report.upstream.is_some());
        assert_eq!(report.sideloads.len(), 1);
        assert_eq!(doc["base"]["locked_commit"].as_str(), Some("u1"));
        assert_eq!(
            doc["base"]["sideload"][0]["locked_commit"].as_str(),
            Some("a1")
        );
    }

    #[test]
    fn apply_pins_honours_the_sideloads_spelling() {
        let mut doc = r#"
[upstream]
repo = "up"
branch = "main"

[[upstream.sideloads]]
repo = "a"
branch = "main"
locked_commit = "a0"
"#
        .parse::<DocumentMut>()
        .unwrap();
        let report = apply_pins(&mut doc, None, vec![pin("a", Some("a0"), "a1")]);
        assert_eq!(report.sideloads.len(), 1);
        assert_eq!(
            doc["upstream"]["sideloads"][0]["locked_commit"].as_str(),
            Some("a1")
        );
    }

    #[test]
    fn apply_pins_without_an_upstream_table_changes_nothing() {
        let mut doc = "[tasks]\n".parse::<DocumentMut>().unwrap();
        let report = apply_pins(
            &mut doc,
            Some(pin("up", None, "u1")),
            vec![pin("a", None, "a1")],
        );
        assert!(report.upstream.is_none());
        let skipped: Vec<_> = report.skipped.iter().map(|p| p.repo.as_str()).collect();
        assert_eq!(skipped, ["up", "a"]);
        assert_eq!(doc.to_string(), "[tasks]\n");
    }

    #[test]
    fn skipped_message_names_the_pin_and_the_command() {
        assert_eq!(
            pin("gominimal/packages", None, "x").skipped_message("mip update"),
            "minimal.toml changed during the update, so gominimal/packages:main was not \
             re-pinned. Run mip update again"
        );
    }
}
