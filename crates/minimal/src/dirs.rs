//! `minimal dirs` — print the important directories and files a user
//! might want to inspect when debugging.

use std::path::PathBuf;

use crate::GlobalArgs;
use crate::config::resolve_minimal_config_dir;
#[cfg(feature = "remote-access")]
use crate::mesh_enrolment_path;

/// Print the important directories and files a user might want to
/// inspect when debugging. Grouped by role (config / state / cache)
/// with an "exists?" marker so unused paths don't look identical to
/// misconfigured ones.
pub fn cmd_dirs(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    print!("{}", report(global));
    Ok(())
}

/// The `cmd_dirs` table as a string — also captured verbatim into `min bug`
/// diagnostic bundles as `host/dirs.txt`.
pub(crate) fn report(global: &GlobalArgs) -> String {
    let dirs = DirsLookup {
        config: resolve_minimal_config_dir(global),
        #[cfg(feature = "remote-access")]
        mesh_enrolment: mesh_enrolment_path(global),
        // `mesh_enrolment_path` follows `--minimal-dir` when set,
        // so the row groups with State in that case rather than
        // Config — otherwise a user reading `minimal dirs` would
        // find the mesh file under the wrong header.
        #[cfg(feature = "remote-access")]
        mesh_group: if global.minimal_dir.is_some() {
            MeshGroup::State
        } else {
            MeshGroup::Config
        },
        state: match &global.minimal_dir {
            Some(dir) => dir.clone(),
            None => paths::minimal_state_dir()
                .as_utf8_path()
                .as_std_path()
                .to_path_buf(),
        },
        cache: paths::minimal_cache_dir()
            .as_utf8_path()
            .as_std_path()
            .to_path_buf(),
        provider: crate::client::client_provider_kind(global.use_minvmd()),
    };
    format_dir_rows(&build_dir_rows(&dirs))
}

/// Resolved locations `cmd_dirs` prints, materialized once so
/// [`build_dir_rows`] stays a pure function of its inputs (easy to
/// snapshot-test without touching env or the filesystem).
struct DirsLookup {
    /// `<config>/minimal` — root for `config.toml`, `loadouts/`,
    /// mTLS certs.
    config: PathBuf,
    /// The specific path `min mesh join` writes to. Kept separate
    /// so a `--minimal-dir` override that redirects the mesh file
    /// (but not the loadouts subsystem) still shows up correctly.
    #[cfg(feature = "remote-access")]
    mesh_enrolment: PathBuf,
    /// Which group heading the mesh row prints under —
    /// `Config` in the common case, `State` when
    /// `--minimal-dir` redirected the mesh file to the state tree.
    #[cfg(feature = "remote-access")]
    mesh_group: MeshGroup,
    /// `<state>/minimal` (or the `--minimal-dir` override).
    state: PathBuf,
    /// `<cache>/minimal`.
    cache: PathBuf,
    /// The backend whose provider dir the CLI would connect to, so the SSH
    /// socket row names the right `providers/local-<kind>0` path.
    provider: paths::ProviderKind,
}

/// Which top-level group the mesh-enrolment row prints under. Values
/// match the row group labels one-to-one via [`Self::as_row_group`].
#[cfg(feature = "remote-access")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshGroup {
    Config,
    State,
}

#[cfg(feature = "remote-access")]
impl MeshGroup {
    /// Group label used in [`DirRow::group`] and printed as the
    /// column header. Kept as a method (not `Display`) so the mapping
    /// is grep-friendly and callers can't accidentally pass an
    /// unrelated `&str`.
    fn as_row_group(self) -> &'static str {
        match self {
            Self::Config => "Config",
            Self::State => "State",
        }
    }
}

/// Build the `cmd_dirs` row list from a resolved [`DirsLookup`].
/// Pure function of its input — no env reads, no filesystem stat
/// calls beyond what [`DirRow::existence_marker`] does at print
/// time.
fn build_dir_rows(dirs: &DirsLookup) -> Vec<DirRow> {
    #[cfg(feature = "remote-access")]
    let mesh_row = || {
        (
            dirs.mesh_group.as_row_group(),
            "Mesh enrolment",
            Some(dirs.mesh_enrolment.clone()),
            None,
        )
            .into_row()
    };

    let mut rows = vec![
        ("Config", "Config dir", Some(dirs.config.clone()), None).into_row(),
        (
            "Config",
            "config.toml",
            Some(dirs.config.join("config.toml")),
            None,
        )
            .into_row(),
        (
            "Config",
            "Loadouts dir",
            Some(dirs.config.join("loadouts")),
            None,
        )
            .into_row(),
    ];
    #[cfg(feature = "remote-access")]
    if dirs.mesh_group == MeshGroup::Config {
        rows.push(mesh_row());
    }
    rows.extend([
        ("State", "State dir", Some(dirs.state.clone()), None).into_row(),
        ("State", "Sessions", Some(dirs.state.join("sessions")), None).into_row(),
        (
            "State",
            "Daemon logs",
            Some(dirs.state.join("logs")),
            Some("daily-rotated: minimald.log*, minvmd.log*".to_string()),
        )
            .into_row(),
        (
            "State",
            "SSH socket",
            Some(dirs.state.join(format!(
                "providers/{}/ssh.sock",
                paths::provider_instance_name(dirs.provider, 0)
            ))),
            None,
        )
            .into_row(),
    ]);
    #[cfg(feature = "remote-access")]
    if dirs.mesh_group == MeshGroup::State {
        // After the SSH-socket row so the mesh file lands at the
        // tail of the State group — visually adjacent to the state
        // dir root it lives under.
        rows.push(mesh_row());
    }
    rows.extend([
        ("Cache", "Cache dir", Some(dirs.cache.clone()), None).into_row(),
        (
            "Cache",
            "Built artifacts",
            Some(dirs.cache.join("built")),
            None,
        )
            .into_row(),
    ]);
    rows
}

/// Format the row list produced by [`build_dir_rows`] with per-column
/// width-alignment and a blank line between groups.
fn format_dir_rows(rows: &[DirRow]) -> String {
    use std::fmt::Write as _;

    let group_w = rows.iter().map(|r| r.group.len()).max().unwrap_or(6);
    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    let path_w = rows
        .iter()
        .map(|r| r.path_display().len())
        .max()
        .unwrap_or(4);

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{group:<group_w$}     {name:<name_w$}  {path:<path_w$}",
        group = "GROUP",
        name = "NAME",
        path = "PATH",
    );

    let mut current_group = "";
    for row in rows {
        if row.group != current_group {
            if !current_group.is_empty() {
                out.push('\n');
            }
            current_group = row.group;
        }
        let mark = row.existence_marker();
        let path = row.path_display();
        let note = row
            .note
            .as_deref()
            .map(|n| format!("  ({n})"))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "{group:<group_w$}  {mark}  {name:<name_w$}  {path:<path_w$}{note}",
            group = row.group,
            name = row.name,
        );
    }
    out.push('\n');
    out.push_str("  * = exists   - = missing   ? = unknown (path unresolved)\n");
    out
}

/// One row emitted by [`cmd_dirs`]. Kept as a struct rather than
/// a tuple so the group / mark / path / note columns can be widened
/// independently at print time.
struct DirRow {
    group: &'static str,
    name: &'static str,
    path: Option<PathBuf>,
    note: Option<String>,
}

impl DirRow {
    fn path_display(&self) -> String {
        match &self.path {
            Some(p) => p.display().to_string(),
            None => "<unresolved>".to_string(),
        }
    }
    fn existence_marker(&self) -> char {
        match &self.path {
            None => '?',
            Some(p) if p.exists() => '*',
            Some(_) => '-',
        }
    }
}

trait IntoDirRow {
    fn into_row(self) -> DirRow;
}
impl IntoDirRow for (&'static str, &'static str, Option<PathBuf>, Option<String>) {
    fn into_row(self) -> DirRow {
        DirRow {
            group: self.0,
            name: self.1,
            path: self.2,
            note: self.3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `build_dir_rows` produces the fixed layout [Config, State × 4,
    /// Cache × 2] — plus a "Mesh enrolment" row under Config (the
    /// common case) only when the `remote-access` feature is compiled
    /// in — each with the right group tag, name, and derived path.
    /// Guards against a future edit that drops a row or shuffles
    /// groups without noticing.
    #[test]
    fn build_dir_rows_layout_is_stable() {
        let dirs = DirsLookup {
            config: PathBuf::from("/home/u/.config/minimal"),
            #[cfg(feature = "remote-access")]
            mesh_enrolment: PathBuf::from("/home/u/.config/minimal/mesh-enrolment"),
            #[cfg(feature = "remote-access")]
            mesh_group: MeshGroup::Config,
            state: PathBuf::from("/home/u/.local/state/minimal"),
            cache: PathBuf::from("/home/u/.cache/minimal"),
            provider: paths::ProviderKind::Minimald,
        };
        let rows = build_dir_rows(&dirs);
        let shape: Vec<(&str, &str, String)> = rows
            .iter()
            .map(|r| (r.group, r.name, r.path_display()))
            .collect();
        #[allow(unused_mut)]
        let mut expected = vec![
            (
                "Config",
                "Config dir",
                "/home/u/.config/minimal".to_string(),
            ),
            (
                "Config",
                "config.toml",
                "/home/u/.config/minimal/config.toml".to_string(),
            ),
            (
                "Config",
                "Loadouts dir",
                "/home/u/.config/minimal/loadouts".to_string(),
            ),
            (
                "State",
                "State dir",
                "/home/u/.local/state/minimal".to_string(),
            ),
            (
                "State",
                "Sessions",
                "/home/u/.local/state/minimal/sessions".to_string(),
            ),
            (
                "State",
                "Daemon logs",
                "/home/u/.local/state/minimal/logs".to_string(),
            ),
            (
                "State",
                "SSH socket",
                "/home/u/.local/state/minimal/providers/local-minimald0/ssh.sock".to_string(),
            ),
            ("Cache", "Cache dir", "/home/u/.cache/minimal".to_string()),
            (
                "Cache",
                "Built artifacts",
                "/home/u/.cache/minimal/built".to_string(),
            ),
        ];
        // Mesh enrolment prints under Config, right after "Loadouts
        // dir", only in `remote-access` builds where `min mesh` exists.
        #[cfg(feature = "remote-access")]
        expected.insert(
            3,
            (
                "Config",
                "Mesh enrolment",
                "/home/u/.config/minimal/mesh-enrolment".to_string(),
            ),
        );
        assert_eq!(shape, expected);
    }

    /// The "Daemon logs" row's note names both daemons' rotated files so
    /// operators know which filenames to look at.
    #[test]
    fn build_dir_rows_daemon_logs_note_names_both_daemons() {
        let dirs = DirsLookup {
            config: PathBuf::from("/c"),
            #[cfg(feature = "remote-access")]
            mesh_enrolment: PathBuf::from("/c/mesh-enrolment"),
            #[cfg(feature = "remote-access")]
            mesh_group: MeshGroup::Config,
            state: PathBuf::from("/s"),
            cache: PathBuf::from("/x"),
            provider: paths::ProviderKind::Minimald,
        };
        let rows = build_dir_rows(&dirs);
        let daemon_logs = rows.iter().find(|r| r.name == "Daemon logs").unwrap();
        assert_eq!(
            daemon_logs.note.as_deref(),
            Some("daily-rotated: minimald.log*, minvmd.log*"),
        );
    }

    /// `DirRow::existence_marker` returns `?` when path is `None`,
    /// `-` for a resolved-but-missing file, `*` for one that exists.
    #[test]
    fn dir_row_existence_marker_covers_all_three_states() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("here");
        std::fs::write(&real, "x").unwrap();
        let missing = tmp.path().join("gone");

        let row_present = ("_", "_", Some(real), None).into_row();
        let row_missing = ("_", "_", Some(missing), None).into_row();
        let row_unresolved = ("_", "_", None, None).into_row();

        assert_eq!(row_present.existence_marker(), '*');
        assert_eq!(row_missing.existence_marker(), '-');
        assert_eq!(row_unresolved.existence_marker(), '?');
    }

    /// When `--minimal-dir` redirects the mesh file to the state
    /// tree, the Mesh row must render under the State group so the
    /// output stays semantically honest. Guards the `mesh_group`
    /// branching added to `build_dir_rows`.
    #[cfg(feature = "remote-access")]
    #[test]
    fn build_dir_rows_places_mesh_under_state_when_minimal_dir_overrides() {
        let dirs = DirsLookup {
            config: PathBuf::from("/c"),
            mesh_enrolment: PathBuf::from("/override/mesh-enrolment"),
            mesh_group: MeshGroup::State,
            state: PathBuf::from("/override"),
            cache: PathBuf::from("/x"),
            provider: paths::ProviderKind::Minimald,
        };
        let rows = build_dir_rows(&dirs);
        let mesh = rows.iter().find(|r| r.name == "Mesh enrolment").unwrap();
        assert_eq!(mesh.group, "State");
        assert_eq!(mesh.path_display(), "/override/mesh-enrolment");

        // And there must be no "Mesh enrolment" row under Config
        // (bug: the row was duplicated when we introduced the flag).
        let mesh_count = rows.iter().filter(|r| r.name == "Mesh enrolment").count();
        assert_eq!(mesh_count, 1, "mesh row must appear exactly once");
    }
}
