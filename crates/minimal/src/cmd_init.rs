//! Command to initialize a minimal file based on matching the source tree to a valid harness.

use std::io::Write;
use std::path::PathBuf;

use anyhow::anyhow;
use common::{SpecOrigin, Target};
use graph::Graph;
use mctx::{Config, Context, DEFAULT_PKGS, DEFAULT_PKGS_BRANCH, Error, generate_mfile};
use mfile::LinkConfig;

#[derive(clap::Args)]
pub struct InitArgs {
    /// Skip confirmation, writing configuration based on auto-detection
    #[arg(long, short, default_value_t = false)]
    yes: bool,
}

pub async fn cmd_init(args: InitArgs, config: Config) -> Result<(), Error> {
    let mfile_strategy = match config.repo_dir_override() {
        Some(path) => mctx::MFileSearchStrategy::Override(path.to_path_buf()),
        _ => mctx::MFileSearchStrategy::CurrentDirOnly,
    };
    // Stacks have the match rules, so we need a graph, either from the repo
    // minimal file or some default based on the MPPR.
    let (upstream_origin, repo_dir, toml_path, graph) =
        match Context::new_with_strategy(config.clone(), mfile_strategy) {
            // We are in a repo where theres a minimal file, and the minimal file has an upstream.
            // Lets use that upstream. Maybe the user is re-initializing?
            Ok(mut ctx) if ctx.minimal_file().upstream.is_some() => {
                let upstream = ctx.minimal_file().upstream.clone().unwrap();
                let origin = upstream.as_ref().as_spec_origin().ok_or_else(|| {
                    Error::Other(anyhow!(
                        "Could not use upstream{} as a spec origin",
                        ctx.minimal_file()
                            .file_path()
                            .map(|p| format!(" from minimal file at {}", p.to_string_lossy()))
                            .unwrap_or("".into())
                    ))
                })?;
                (
                    origin,
                    ctx.repo_dir().to_path_buf(),
                    ctx.minimal_file().file_path().cloned(),
                    ctx.graph_from_all_packages()?,
                )
            }
            // Unsurprisingly, theres no minimal file yet, or theres no upstream so theres no
            // useful information. We need the stacks though for auto-detection, so lets
            // wire up a default graph.
            Err(Error::MFile(mfile::Error::NotFound)) | Ok(_) => {
                let (mut vcs, _cache, stdlib_dir) = Context::sub_setup(&config)?;
                let (_dir, rev) = vcs.checkout_of(
                    DEFAULT_PKGS,
                    checkouts::GitRef::Branch(DEFAULT_PKGS_BRANCH.to_string()),
                )?;

                let repo_dir = match config.repo_dir_override() {
                    Some(path) => path.to_path_buf(),
                    _ => std::env::current_dir()
                        .map_err(|e| Error::IO("Getting current directory", PathBuf::new(), e))?,
                };

                (
                    SpecOrigin::Repo(common::repo_spec::Repo::Git {
                        url: DEFAULT_PKGS.to_string(),
                        rev: rev.clone(),
                        tracking: Some(common::repo_spec::GitRef::Branch(
                            DEFAULT_PKGS_BRANCH.to_string(),
                        )),
                    }),
                    repo_dir,
                    None,
                    Graph::new_from_chain(
                        vcs,
                        &mut (),
                        LinkConfig::Git {
                            repo: DEFAULT_PKGS.to_string(),
                            branch: Some(DEFAULT_PKGS_BRANCH.to_string()),
                            locked_commit: Some(rev),
                        },
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

    // Apply all predicates, collecting the stacks name, any additional build packages, and any additional runtime packages.
    let stacks = {
        let mut h = graph.iter_stacks().collect::<Vec<_>>();
        // Sort stacks so those with a higher priority are iterated first.
        h.sort_by(|a, b| {
            a.1.matches_project_priority
                .cmp(&b.1.matches_project_priority)
                .reverse()
        });
        h
    };
    let matched_stack: Option<(String, Vec<String>, Vec<String>)> =
        stacks.into_iter().find_map(|(name, stack)| {
            stack.matches_project_if_any.as_ref().and_then(|matchers| {
                matchers
                    .iter()
                    .find(|m| m.match_dir(&repo_dir).unwrap_or(false))
                    .map(|stack| {
                        (
                            name.clone(),
                            stack
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
                            stack
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

    let has_matched = matched_stack.is_some();
    let content = generate_mfile(matched_stack, &upstream_origin);

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
