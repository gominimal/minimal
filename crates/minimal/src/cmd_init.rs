//! Command to initialize a minimal file based on matching the source tree to a valid harness.

use std::io::Write;

use common::{SpecOrigin, Target, repo_spec::Repo};
use graph::Graph;
use mctx::{Config, Context, Error};

#[derive(clap::Args)]
pub struct InitArgs {
    /// Skip confirmation, writing configuration based on auto-detection
    #[arg(long, short, default_value_t = false)]
    yes: bool,
}

const DEFAULT_PKGS: &str = "https://github.com/gominimal/pkgs";
const DEFAULT_PKGS_BRANCH: &str = "main";
const FALLBACK_HARNESS: &str = "shell";

pub async fn cmd_init(args: InitArgs, config: Config) -> Result<(), Error> {
    // Harnesses have the match rules, so we need a graph, either from the repo
    // minimal file or some default based on the MPPR.
    let (upstream_origin, repo_dir, toml_path, graph) = match Context::new(config.clone()) {
        // We are in a repo where theres a minimal file, and the minimal file has an upstream.
        // Lets use that upstream. Maybe the user is re-initializing?
        Ok(mut ctx) if ctx.minimal_file().upstream.is_some() => (
            ctx.minimal_file()
                .upstream
                .as_ref()
                .unwrap()
                .as_spec_origin()
                .unwrap(),
            ctx.repo_dir().to_path_buf(),
            ctx.minimal_file().file_path().cloned(),
            ctx.graph_from_all_packages()?,
        ),
        // Unsurprisingly, theres no minimal file yet, or theres no upstream so theres no
        // useful information. We need the harnesses though for auto-detection, so lets
        // wire up a default graph.
        Err(Error::MFile(mfile::Error::NotFound)) | Ok(_) => {
            let (mut vcs, _cache, stdlib_dir) = Context::sub_setup(&config)?;
            let (_dir, rev) = vcs.checkout_of(
                DEFAULT_PKGS,
                checkouts::GitRef::Branch(DEFAULT_PKGS_BRANCH.to_string()),
            )?;

            (
                SpecOrigin::Repo(common::repo_spec::Repo::Git {
                    url: DEFAULT_PKGS.to_string(),
                    rev: rev.clone(),
                    tracking: Some(common::repo_spec::GitRef::Branch(
                        DEFAULT_PKGS_BRANCH.to_string(),
                    )),
                }),
                config
                    .repo_dir_override()
                    .clone()
                    .unwrap_or_else(|| std::env::current_dir().unwrap()),
                None,
                Graph::new_from_chain(
                    vcs,
                    &mut (),
                    SpecOrigin::Repo(common::repo_spec::Repo::Git {
                        url: "https://github.com/gominimal/pkgs".to_string(),
                        rev,
                        tracking: Some(common::repo_spec::GitRef::Branch("main".to_string())),
                    }),
                    stdlib_dir,
                    Target::host(),
                )?,
            )
        }
        Err(e) => {
            return Err(e);
        }
    };
    let toml_path = toml_path.unwrap_or_else(|| repo_dir.join(mfile::MFILE_NAME));

    // Apply all predicates, collecting the harness name, any additional build packages, and any additional runtime packages.
    let harnesses = {
        let mut h = graph.iter_harnesses().collect::<Vec<_>>();
        // Sort harnesses so those with a higher priority are iterated first.
        h.sort_by(|a, b| {
            a.1.matches_project_priority
                .cmp(&b.1.matches_project_priority)
                .reverse()
        });
        h
    };
    let matched_harness: Option<(String, Vec<String>, Vec<String>)> =
        harnesses.into_iter().find_map(|(name, harness)| {
            harness
                .matches_project_if_any
                .as_ref()
                .and_then(|matchers| {
                    matchers
                        .iter()
                        .find(|m| m.match_dir(&repo_dir).unwrap_or(false))
                        .map(|harness| {
                            (
                                name.clone(),
                                harness
                                    .build_package_matchers
                                    .iter()
                                    .filter_map(|(pkg, if_any)| {
                                        if_any
                                            .iter()
                                            .any(|c| c.match_dir(&repo_dir).unwrap_or(false))
                                            .then_some(pkg)
                                    })
                                    .cloned()
                                    .collect::<Vec<_>>(),
                                harness
                                    .runtime_package_matchers
                                    .iter()
                                    .filter_map(|(pkg, if_any)| {
                                        if_any
                                            .iter()
                                            .any(|c| c.match_dir(&repo_dir).unwrap_or(false))
                                            .then_some(pkg)
                                    })
                                    .cloned()
                                    .collect::<Vec<_>>(),
                            )
                        })
                })
        });

    let has_matched = matched_harness.is_some();
    let content = generate_mfile(matched_harness, &upstream_origin);

    // -- Confirmation prompt (unless --yes) --
    if !args.yes {
        eprintln!("\nWill create {}:\n", toml_path.display());
        eprintln!("---");
        eprint!("{}", content);
        eprintln!("---");
        eprintln!();
        eprint!("Continue? [Y/n] ");
        std::io::stderr().flush().ok();

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| Error::Other(anyhow::anyhow!("reading stdin: {}", e)))?;
        if !(input.trim().eq_ignore_ascii_case("y") || input.trim() == "") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    std::fs::write(&toml_path, &content)
        .map_err(|e| Error::Other(anyhow::anyhow!("writing {}: {}", toml_path.display(), e)))?;

    eprintln!("Created {}", toml_path.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  minimal update      # pin package versions");
    eprintln!("  minimal run shell   # enter development shell");
    if has_matched {
        eprintln!("  minimal build       # build the project");
    }

    Ok(())
}

fn generate_mfile(
    matched_harness: Option<(String, Vec<String>, Vec<String>)>,
    origin: &SpecOrigin,
) -> String {
    // Fall back to the "shell" harness if no project-specific matcher hit.
    let (harness_name, build_packages, runtime_packages) = matched_harness
        .map(|h| (h.0, h.1, h.2))
        .unwrap_or_else(|| (FALLBACK_HARNESS.to_string(), vec![], vec![]));

    let mut content = String::new();
    content.push_str("# Generated by `minimal init`\n\n");

    // [upstream]
    content.push_str("[upstream] # Source of software & tooling\n");
    match &origin {
        SpecOrigin::Repo(Repo::Git { url, rev, tracking }) => {
            content.push_str(&format!("repo = \"{}\"\n", url));
            if let Some(common::repo_spec::GitRef::Branch(b)) = tracking {
                content.push_str(&format!("branch = \"{}\"\n", b));
            }
            content.push_str(&format!("locked_commit = \"{}\"\n", rev,));
        }
        SpecOrigin::LocalDir { given, .. } => {
            content.push_str(&format!("dir = \"{}\"\n", given.to_str().unwrap()))
        }
        SpecOrigin::Inline => unreachable!(),
    }
    content.push('\n');

    content.push_str("[harness]\n");
    content.push_str(&format!("use = \"{}\"\n", harness_name));
    if !build_packages.is_empty() {
        content.push_str(&format!(
            "build_packages = [{}]\n",
            build_packages
                .into_iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !runtime_packages.is_empty() {
        content.push_str(&format!(
            "runtime_packages = [{}]\n",
            runtime_packages
                .into_iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    content.push('\n');

    content.push_str("[defaults]\n");
    content.push_str("state_key = \"dev\"\n");
    content.push('\n');
    content.push_str("[tasks.shell]\n");
    content.push_str("packages = [\"base\"]\n");
    content.push_str("exec = \"bash --noprofile -l\"\n");
    content
}
