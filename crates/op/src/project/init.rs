//! The `init` operation: detect a project's stack and produce the `minimal.toml`
//! it should be initialized with.

use std::path::{Path, PathBuf};

use anyhow::anyhow;
use common::{SpecOrigin, Target, repo_spec::Repo};
use decode::Stack;
use mfile::LinkConfig;

use super::{ProjectEnv, ProjectOp};
use crate::Error;

const DEFAULT_PKGS: &str = "https://github.com/gominimal/pkgs";
const DEFAULT_PKGS_BRANCH: &str = "main";

/// Detects the stack matching an existing codebase and produces the
/// `minimal.toml` it should be initialized with.
///
/// The operation does not touch the filesystem beyond what the [`ProjectEnv`]
/// performs (checkouts, graph loading); writing the file and confirming with the
/// user are left to the caller, which inspects the returned [`InitPlan`].
#[derive(Debug, Default, Clone, Copy)]
pub struct InitProject;

/// The result of running [`InitProject`]: the `minimal.toml` to write and where.
#[derive(Debug, Clone)]
pub struct InitPlan {
    /// Path the `minimal.toml` should be written to.
    pub toml_path: PathBuf,
    /// The generated file contents.
    pub content: String,
    /// Whether a project-specific stack matched (as opposed to the fallback).
    pub matched: bool,
}

/// A matched stack: its name, plus the additional build and runtime packages
/// detected for the project.
type MatchedStack = (String, Vec<String>, Vec<String>);

impl ProjectOp for InitProject {
    type Result = InitPlan;

    fn run<E: ProjectEnv>(&mut self, env: &mut E) -> Result<InitPlan, Error> {
        // Stacks carry the match rules, so we need a graph: either from the
        // existing minimal file's upstream (the user may be re-initializing) or
        // from a default packages repo we check out for the occasion.
        let existing = env
            .minimal_file()
            .and_then(|m| m.upstream.clone().map(|up| (up, m.file_path().cloned())));

        let (origin, link, toml_path) = match existing {
            Some((upstream, file_path)) => {
                let origin = upstream.as_ref().as_spec_origin().ok_or_else(|| {
                    Error::Other(anyhow!("Could not use upstream as a spec origin"))
                })?;
                let link = LinkConfig::Dir {
                    dir: env.repo_dir().to_string_lossy().into_owned(),
                };
                (origin, link, file_path)
            }
            None => {
                env.update_checkouts()?;
                let rev = env.checkout_branch(DEFAULT_PKGS, DEFAULT_PKGS_BRANCH)?;
                let origin = SpecOrigin::Repo(Repo::Git {
                    url: DEFAULT_PKGS.to_string(),
                    rev: rev.clone(),
                    tracking: Some(common::repo_spec::GitRef::Branch(
                        DEFAULT_PKGS_BRANCH.to_string(),
                    )),
                });
                let link = LinkConfig::Git {
                    repo: DEFAULT_PKGS.to_string(),
                    branch: Some(DEFAULT_PKGS_BRANCH.to_string()),
                    locked_commit: Some(rev),
                };
                (origin, link, None)
            }
        };

        let graph = env.graph_from_chain(link, Target::host())?;
        let repo_dir = env.repo_dir().to_path_buf();
        let toml_path = toml_path.unwrap_or_else(|| repo_dir.join(mfile::MFILE_NAME));

        let matched_stack = match_stack(graph.iter_stacks(), &repo_dir);
        let matched = matched_stack.is_some();
        let content = generate_mfile(matched_stack, &origin, &repo_dir);

        Ok(InitPlan {
            toml_path,
            content,
            matched,
        })
    }
}

/// Applies every stack's match rules against `repo_dir`, returning the
/// highest-priority match along with any additional build and runtime packages.
fn match_stack<'a>(
    stacks: impl IntoIterator<Item = (&'a String, &'a Stack)>,
    repo_dir: &Path,
) -> Option<MatchedStack> {
    let mut stacks = stacks.into_iter().collect::<Vec<_>>();
    // Sort stacks so those with a higher priority are iterated first.
    stacks.sort_by(|a, b| {
        a.1.matches_project_priority
            .cmp(&b.1.matches_project_priority)
            .reverse()
    });

    stacks.into_iter().find_map(|(name, stack)| {
        stack.matches_project_if_any.as_ref().and_then(|matchers| {
            matchers
                .iter()
                .find(|m| m.match_dir(repo_dir).unwrap_or(false))
                .map(|matcher| {
                    (
                        name.clone(),
                        matcher
                            .build_package_matchers
                            .iter()
                            .filter_map(|(pkg, if_any)| {
                                if_any
                                    .iter()
                                    .any(|c| c.match_dir(repo_dir).unwrap_or(false))
                                    .then_some(pkg)
                            })
                            .cloned()
                            .collect::<Vec<_>>(),
                        matcher
                            .runtime_package_matchers
                            .iter()
                            .filter_map(|(pkg, if_any)| {
                                if_any
                                    .iter()
                                    .any(|c| c.match_dir(repo_dir).unwrap_or(false))
                                    .then_some(pkg)
                            })
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                })
        })
    })
}

/// Renders the `minimal.toml` contents for the (optional) matched stack and the
/// resolved upstream `origin`.
fn generate_mfile(
    matched_stack: Option<MatchedStack>,
    origin: &SpecOrigin,
    repo_dir: &Path,
) -> String {
    let mut content = String::new();
    content.push_str("# Generated by `min init`\n\n");

    // [upstream]
    content.push_str("[upstream] # Source of software & tooling\n");
    match &origin {
        SpecOrigin::Repo(Repo::Git { url, rev, tracking }) => {
            content.push_str(&format!("repo = \"{url}\"\n"));
            if let Some(common::repo_spec::GitRef::Branch(b)) = tracking {
                content.push_str(&format!("branch = \"{b}\"\n"));
            }
            content.push_str(&format!("locked_commit = \"{rev}\"\n"));
        }
        SpecOrigin::LocalDir { given, .. } => {
            content.push_str(&format!("dir = \"{}\"\n", given.to_str().unwrap()))
        }
        SpecOrigin::Inline => unreachable!(),
    }
    content.push('\n');

    if let Some((stack_name, build_packages, runtime_packages)) = matched_stack {
        content.push_str("[stack]\n");
        content.push_str(&format!("use = \"{stack_name}\"\n"));
        if !build_packages.is_empty() {
            content.push_str(&format!(
                "build_packages = [{}]\n",
                build_packages
                    .into_iter()
                    .map(|s| format!("\"{s}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !runtime_packages.is_empty() {
            content.push_str(&format!(
                "runtime_packages = [{}]\n",
                runtime_packages
                    .into_iter()
                    .map(|s| format!("\"{s}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        content.push('\n');
    }

    content.push_str("[defaults]\n");
    content.push_str("state_key = \"dev\"\n");
    content.push('\n');
    content.push_str("[session] # min session attach\n");
    content.push_str("packages = [\"base\", \"vim\"");
    if std::fs::exists(repo_dir.join(".git")).unwrap_or_default() {
        content.push_str(", \"git\"");
    }
    content.push_str("]\n");
    content
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::repo_spec::GitRef;
    use decode::{PackageMatcherPredicate, StackMatcher};
    use tempfile::TempDir;

    /// A predicate that matches when `file` merely exists in the project.
    fn exists(file: &str) -> PackageMatcherPredicate {
        PackageMatcherPredicate {
            file_regexes: [(file.to_string(), "*".to_string())].into_iter().collect(),
            ..Default::default()
        }
    }

    /// A stack that applies when `file` exists, at the given match priority.
    fn stack_for(name: &str, priority: i32, file: &str) -> Stack {
        Stack {
            name: name.to_string(),
            matches_project_priority: priority,
            matches_project_if_any: Some(vec![StackMatcher {
                file_regexes: [(file.to_string(), "*".to_string())].into_iter().collect(),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    #[test]
    fn match_stack_picks_highest_priority_that_actually_matches() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();
        std::fs::write(dir.path().join("go.mod"), "module x").unwrap();

        // `python` has the highest priority but does not match (no
        // requirements.txt); `rust` outranks `go` among the matching stacks.
        let stacks = [
            ("go".to_string(), stack_for("go", 5, "go.mod")),
            (
                "python".to_string(),
                stack_for("python", 100, "requirements.txt"),
            ),
            ("rust".to_string(), stack_for("rust", 10, "Cargo.toml")),
        ];

        let matched = match_stack(stacks.iter().map(|(n, s)| (n, s)), dir.path());
        assert_eq!(matched.map(|m| m.0), Some("rust".to_string()));
    }

    #[test]
    fn match_stack_returns_none_when_nothing_matches() {
        let dir = TempDir::new().unwrap();
        let stacks = [("rust".to_string(), stack_for("rust", 0, "Cargo.toml"))];

        assert!(match_stack(stacks.iter().map(|(n, s)| (n, s)), dir.path()).is_none());
    }

    #[test]
    fn match_stack_collects_only_matching_build_and_runtime_packages() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "x").unwrap();
        std::fs::write(dir.path().join("build.rs"), "x").unwrap();

        let stack = Stack {
            name: "rust".to_string(),
            matches_project_if_any: Some(vec![StackMatcher {
                file_regexes: [("Cargo.toml".to_string(), "*".to_string())]
                    .into_iter()
                    .collect(),
                build_package_matchers: [("cc".to_string(), vec![exists("build.rs")])]
                    .into_iter()
                    .collect(),
                runtime_package_matchers: [
                    ("openssl".to_string(), vec![exists("Cargo.toml")]),
                    // No matching file, so this package must be excluded.
                    ("absent".to_string(), vec![exists("nonexistent")]),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            }]),
            ..Default::default()
        };

        let stacks = [("rust".to_string(), stack)];
        let (name, build, runtime) =
            match_stack(stacks.iter().map(|(n, s)| (n, s)), dir.path()).unwrap();

        assert_eq!(name, "rust");
        assert_eq!(build, vec!["cc".to_string()]);
        assert_eq!(runtime, vec!["openssl".to_string()]);
    }

    #[test]
    fn generate_mfile_renders_git_origin_and_matched_stack() {
        let origin = SpecOrigin::Repo(Repo::Git {
            url: "https://github.com/gominimal/pkgs".to_string(),
            rev: "abc123".to_string(),
            tracking: Some(GitRef::Branch("main".to_string())),
        });
        let matched = Some((
            "rust".to_string(),
            vec!["cc".to_string()],
            vec!["openssl".to_string()],
        ));
        let cwd = TempDir::new().unwrap();

        let out = generate_mfile(matched, &origin, cwd.path());

        assert!(out.contains("repo = \"https://github.com/gominimal/pkgs\""));
        assert!(out.contains("branch = \"main\""));
        assert!(out.contains("locked_commit = \"abc123\""));
        assert!(out.contains("use = \"rust\""));
        assert!(out.contains("build_packages = [\"cc\"]"));
        assert!(out.contains("runtime_packages = [\"openssl\"]"));
    }

    #[test]
    fn generate_mfile_falls_back_to_upstream_with_session() {
        let origin = SpecOrigin::Repo(Repo::Git {
            url: "u".to_string(),
            rev: "r".to_string(),
            tracking: None,
        });
        let cwd = TempDir::new().unwrap();

        let out = generate_mfile(None, &origin, cwd.path());

        assert!(!out.contains("[stack]"));
        // No tracking branch and no detected packages.
        assert!(!out.contains("branch ="));
        assert!(!out.contains("build_packages"));
        assert!(!out.contains("runtime_packages"));

        // Has some session config
        assert!(out.contains("[session]"));
    }
}
