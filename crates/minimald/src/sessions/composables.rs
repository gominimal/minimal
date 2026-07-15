//! Free helpers that assemble the daemon-side composables for a
//! `CreateSession` request.
//!
//! The three pipeline stages sit here rather than on `Manager`
//! so each can be unit-tested in isolation without spinning the
//! actor mainloop:
//! - [`resolve_project_ctx_and_graph`] parses the client's project
//!   `minimal.toml` and resolves its graph.
//! - [`build_composables`] derives the [`ProjectComposable`] and
//!   per-package [`PackageComposable`]s from that resolution.
//! - [`run_composer`] drives [`SessionComposer::add`] +
//!   [`SessionComposer::compose`], pre-mapping every failure to
//!   [`InvalidInput`].
//!
//! [`ProjectComposable`]: mfile::ProjectComposable
//! [`PackageComposable`]: mfile::PackageComposable
//! [`SessionComposer::add`]: sessions::daemon::composer::SessionComposer::add
//! [`SessionComposer::compose`]: sessions::daemon::composer::SessionComposer::compose
//! [`InvalidInput`]: std::io::ErrorKind::InvalidInput

use std::sync::Arc;

use mctx::PackageSelection;
use paths::DaemonAbsPath;
use sessions::{
    SessionId,
    core::compose::ComposeOptions,
    daemon::composer::{ComposeOutcome, SessionComposer},
    wire::request::WireContribution,
};

/// The runtime-env attrs a package can declare on
/// `BuildSpec.attrs`. See
/// [`extract_package_attrs`] for the extraction rules — in
/// particular, `class = 'Credential` mappings are silently dropped
/// pending the future secrets strategy.
#[derive(Debug)]
struct PackageAttrs {
    state_wiring: Vec<mfile::StateWiring>,
    /// Copy-source paths pulled off `env_dir_mappings` and
    /// `env_file_mappings` (post credential filter). Each string is
    /// used verbatim as both source and destination — see
    /// [`mfile::PackageComposable::new`]'s docs.
    fs_mapping_paths: Vec<String>,
}

/// Read the runtime-env attrs off a package's `BuildSpec.attrs`
/// into domain-typed pieces for [`mfile::PackageComposable`].
///
/// Credential-class mappings are dropped (see `TODO(secrets)`);
/// `read_only` is ignored (minimal is copy-based). Malformed
/// entries are silently skipped — the nickel schema is the
/// authority on shape.
fn extract_package_attrs(b: &graph::BuildSpec) -> Result<PackageAttrs, std::io::Error> {
    Ok(PackageAttrs {
        state_wiring: extract_state_wiring(b)?,
        fs_mapping_paths: extract_fs_mapping_paths(b),
    })
}

fn extract_state_wiring(b: &graph::BuildSpec) -> Result<Vec<mfile::StateWiring>, std::io::Error> {
    let Some(wiring) = b.attrs.get("env_state_wiring") else {
        return Ok(Vec::new());
    };
    attr_entries(wiring)
        .into_iter()
        .filter_map(|entry| {
            let m = entry.as_map()?;
            let env_var = m.get("env_var")?.as_string()?.clone();
            let prefix = m.get("prefix")?.as_string()?.clone();
            Some(mfile::StateWiring { env_var, prefix })
        })
        .map(|w| {
            // Multi-component prefixes (`foo/bar`) are unused by
            // any package in `gominimal/pkgs` today. The composition
            // path's state-dir derivation would silently drop them
            // while the legacy `SetupForPackages` path would
            // `mkdir -p` them — a task-vs-session divergence for
            // the same nickel entry. Reject at extraction so the
            // divergence never gets exercised; if a package
            // legitimately needs this shape, both branches will
            // need to agree on how to handle it and this check can
            // relax then.
            if w.prefix.contains('/') {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "package `{}` declares `env_state_wiring` with prefix `{}` \
                         containing '/'; multi-component prefixes are not supported \
                         on the session composition path. Split into a single \
                         component or open an issue if you need this shape.",
                        b.name, w.prefix,
                    ),
                ));
            }
            Ok(w)
        })
        .collect()
}

/// The string form of the nickel enum tag `'Credential` as it
/// appears after `decode`'s AttrValue conversion. Compared as a
/// plain string at runtime in [`extract_fs_mapping_paths`], so if
/// `decode::AttrValue::EnumTag` ever changes its rendering
/// (angle-brackets, hash prefix, etc.) the check here silently
/// stops matching — credential mappings would then flow through
/// unfiltered.
///
/// The actual regression guard is the
/// `credential_class_fs_mappings_are_filtered_out` test in this
/// module, which asserts a `'Credential`-tagged mapping is dropped.
/// If `decode`'s enum-tag rendering changes, that test will fail
/// and this constant is where to update.
// TODO(schema-stability): keep in sync with `decode::AttrValue::EnumTag`
// rendering.
const CREDENTIAL_CLASS_TAG: &str = "Credential";

fn extract_fs_mapping_paths(b: &graph::BuildSpec) -> Vec<String> {
    // TODO(secrets): `class = 'Credential` mappings are filtered
    // out here rather than routed through a separate secrets
    // channel. When the secrets strategy lands, teach this
    // extractor to emit them via that channel; today they simply
    // aren't seen by the sandbox on the composition path.
    ["env_dir_mappings", "env_file_mappings"]
        .iter()
        .filter_map(|attr| b.attrs.get(*attr))
        .flat_map(|v| attr_entries(v).into_iter())
        .filter_map(|entry| {
            let m = entry.as_map()?;
            let path = m.get("path")?.as_string()?.clone();
            // The two filters differ in what they do with the entry:
            // - Credential-class drops the entry entirely (with a
            //   warn naming the package + path).
            // - read_only=true keeps the entry (the mapping still
            //   reaches the sandbox) but warns that the flag was
            //   ignored, since minimal is copy-based and there's
            //   no read-only enforcement to apply.
            // Both warn so an operator reading daemon logs sees
            // exactly which package's mapping had its declared
            // intent altered.
            //
            // Missing/malformed `class` still returns silently —
            // that's a nickel-schema violation on the package side
            // and the extractor isn't the right layer to surface
            // it.
            if m.get("class")
                .and_then(|c| c.as_string())
                .map(String::as_str)
                == Some(CREDENTIAL_CLASS_TAG)
            {
                tracing::warn!(
                    package = %b.name,
                    path = %path,
                    "dropping Credential-class fs mapping from session composition; \
                     the secrets strategy is deferred, so credentials do not reach the \
                     session sandbox via the composition path",
                );
                return None;
            }
            if m.get("read_only").and_then(|c| c.as_bool()).copied() == Some(true) {
                tracing::warn!(
                    package = %b.name,
                    path = %path,
                    "ignoring `read_only = true` on fs mapping; minimal is copy-based \
                     and the resulting sandbox file is writable regardless of the \
                     package author's declared intent",
                );
            }
            Some(path)
        })
        .collect()
}

/// Normalize the list-or-single-map wire shape into a slice of
/// entry `AttrValue`s.
fn attr_entries(v: &graph::AttrValue) -> Vec<&graph::AttrValue> {
    match v {
        graph::AttrValue::List(l) => l.iter().collect(),
        graph::AttrValue::Map(_) => vec![v],
        _ => Vec::new(),
    }
}

/// Outcome of resolving the client's project mfile + graph at
/// `CreateSession` time.
///
/// Three variants make the reachable states explicit: no mfile, a
/// parsed mfile whose graph didn't resolve, or both. The
/// unreachable `(None, Some)` shape is impossible by
/// construction — hence an enum rather than a tuple.
///
/// [`graph::Graph`] is boxed to keep the enum's size closer to the
/// smaller variants — `graph::Graph` runs into the several-hundred-
/// bytes range.
pub(crate) enum ProjectResolution {
    /// No project `minimal.toml` visible (missing on disk, or on
    /// DM1 the daemon can't reach the host path). Project +
    /// package contributions are empty.
    NoMFile,
    /// Mfile parsed but graph resolution failed (unreachable
    /// upstream, stale layer cache, malformed nickel). Only
    /// project-scoped contributions can land; package contributions
    /// are empty.
    MFileOnly(mctx::Context),
    /// Mfile parsed and graph resolved. Both project- and
    /// package-scoped contributions can land.
    Full(mctx::Context, Box<graph::Graph>),
}

/// Parse the client's project `minimal.toml` and resolve its graph.
/// A missing mfile yields [`ProjectResolution::NoMFile`]; a
/// graph-resolve failure yields [`ProjectResolution::MFileOnly`]
/// (transient failures shouldn't sink the whole compose). Other
/// mfile errors are returned as `InvalidInput`.
pub(crate) fn resolve_project_ctx_and_graph(
    daemon_ctx: &Arc<mctx::DaemonContext>,
    project_path: &DaemonAbsPath,
) -> Result<ProjectResolution, std::io::Error> {
    let project_path_std = project_path.as_utf8_path().as_std_path().to_path_buf();
    let mfile = match mctx::MFileSearchStrategy::Override(project_path_std).find_mfile() {
        Ok(mf) => mf,
        Err(mctx::Error::MFile(mfile::Error::NotFound)) => {
            tracing::debug!(
                project_path = %project_path,
                "no project mfile at CreateSession; project contribution will be empty",
            );
            return Ok(ProjectResolution::NoMFile);
        }
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("project `minimal.toml` at {project_path} is invalid: {e}"),
            ));
        }
    };
    let mut ctx = mctx::Context::from_daemon(Arc::clone(daemon_ctx), mfile);
    match ctx.graph_from_all_packages() {
        Ok(graph) => Ok(ProjectResolution::Full(ctx, Box::new(graph))),
        Err(e) => {
            tracing::debug!(
                project_path = %project_path,
                error = %e,
                "graph resolution failed at CreateSession; \
                 package contributions will be empty",
            );
            Ok(ProjectResolution::MFileOnly(ctx))
        }
    }
}

/// Fold stack-declared env vars into `session`, dropping any that
/// already have a session-declared entry. Strict-POSIX names land
/// in `vars`, lenient names in `vars_lenient`, anything else is
/// warned and skipped. `stack_name` appears only in that warning.
fn fold_stack_vars_into_session<'a, I>(
    session: &mut mfile::Session,
    stack_name: &str,
    build_env_vars: I,
) where
    I: IntoIterator<Item = (&'a String, &'a mfile::EnvVarValue)>,
{
    for (name, mfile_val) in build_env_vars {
        let value = match mfile_val {
            mfile::EnvVarValue::Value(v) => {
                sessions::core::primitives::VarValue::specified(v.clone())
            }
            mfile::EnvVarValue::Inherit => sessions::core::primitives::VarValue::Inherit,
        };
        if let Ok(strict) = sessions::core::primitives::StrictVarName::try_new(name.clone()) {
            session.vars.entry(strict).or_insert(value);
        } else if let Ok(entry) =
            sessions::core::primitives::LenientVarEntry::try_new(name.as_str(), value)
        {
            let already_present = session
                .vars_lenient
                .iter()
                .any(|existing| existing.name() == entry.name());
            if !already_present {
                session.vars_lenient.push(entry);
            }
        } else {
            tracing::warn!(
                stack = %stack_name,
                var = %name,
                "skipping stack build_env_var: name is neither strict nor lenient POSIX-shaped",
            );
        }
    }
}

/// Build the daemon-side composables for this session:
/// - A [`mfile::ProjectComposable`] unioning `[session]`, `[stack]`
///   additions, and the graph-level [`graph::Stack`]'s own
///   packages/env-vars. Session-declared entries win on conflict.
///   Graph-Stack material is only available on
///   [`ProjectResolution::Full`].
/// - One [`mfile::PackageComposable`] per package in the transitive
///   runtime closure of `(client requested_packages ∪ project
///   packages)` that contributes at least one `env_state_wiring` or
///   fs-mapping entry.
///
/// BSR-resolution failures are logged at debug and yield an empty
/// package-composables list; the client's wire contribution still
/// lands.
pub(crate) fn build_composables(
    project_path: &DaemonAbsPath,
    resolution: &ProjectResolution,
    contribution: &WireContribution,
) -> Result<
    (
        Option<mfile::ProjectComposable>,
        Vec<mfile::PackageComposable>,
    ),
    std::io::Error,
> {
    // The project composable only needs the mfile; a missing graph
    // doesn't stop it. The package composables need both the mfile
    // (for the project's own package list) and the graph (for
    // closure resolution).
    let (ctx, graph) = match resolution {
        ProjectResolution::NoMFile => return Ok((None, Vec::new())),
        ProjectResolution::MFileOnly(ctx) => (ctx, None),
        ProjectResolution::Full(ctx, graph) => (ctx, Some(graph.as_ref())),
    };
    let mfile = ctx.minimal_file();

    // The graph-level `Stack` this project references by name, if
    // the mfile names one and the graph is available. Contributes
    // its own `build_packages`, `runtime_packages`, and
    // `build_env_vars` alongside the mfile-side session/stack
    // material.
    //
    // `MFileOnly` (graph resolve failed) skips the graph-Stack
    // lookup; the project still gets its explicit `[session]` and
    // mfile `[stack]` extras, just not what the graph would have
    // contributed on top.
    let graph_stack = mfile
        .stack
        .as_ref()
        .and_then(|s| graph.and_then(|g| g.stack(&s.name)));

    // The complete set of packages this project asks to be in every
    // session it activates: explicit `[session] packages` unioned
    // with both `[stack] build_packages`/`runtime_packages` (mfile
    // side) and the graph-level `Stack`'s own build/runtime lists.
    // `BTreeSet` handles sort + dedup in one pass. Consumed twice
    // below — once folded into `top_level_names` for the closure
    // walk, once moved into the effective Session block so those
    // packages actually land in the sandbox.
    let project_declared_packages: std::collections::BTreeSet<String> = {
        let mut all = std::collections::BTreeSet::<String>::new();
        if let Some(s) = mfile.session.as_ref() {
            all.extend(s.packages.iter().cloned());
        }
        if let Some(stack) = mfile.stack.as_ref() {
            all.extend(stack.build_packages.iter().cloned());
            all.extend(stack.runtime_packages.iter().cloned());
        }
        if let Some(gstack) = graph_stack {
            all.extend(gstack.build_packages.iter().cloned());
            all.extend(gstack.runtime_packages.iter().cloned());
        }
        all
    };

    // Build the closure's top-level name set as a superset of
    // `project_declared_packages` extended by the client's request.
    // Again `BTreeSet` for one-pass sort + dedup.
    let top_level_names: Vec<String> = {
        let mut set = project_declared_packages.clone();
        set.extend(
            contribution
                .requested_packages
                .iter()
                .map(|p| p.name.clone()),
        );
        set.into_iter().collect()
    };

    // Synthesize the Session block ProjectComposable materializes.
    // Short-circuit when there's clearly nothing to contribute:
    // no project packages, no on-disk `[session]` block, no
    // graph-Stack `build_env_vars`. Skips the `mfile.session.clone()`
    // allocation on the common bare-mfile path.
    let has_material = !project_declared_packages.is_empty()
        || mfile.session.as_ref().is_some_and(|s| !s.is_empty())
        || graph_stack.is_some_and(|g| !g.build_env_vars.is_empty());
    let project_composable = if !has_material {
        None
    } else {
        // Starts from the on-disk `[session]` block (or an empty
        // default), then folds in the union package list and any
        // graph-Stack `build_env_vars`. Session-declared vars win
        // over stack-inherited ones for the same name.
        let mut effective = mfile.session.clone().unwrap_or_default();
        effective.packages = project_declared_packages.into_iter().collect();
        if let Some(gstack) = graph_stack {
            fold_stack_vars_into_session(&mut effective, &gstack.name, &gstack.build_env_vars);
        }
        // Post-fold recheck: every stack var could theoretically
        // fail both strict and lenient validation, leaving
        // `effective` empty despite the pre-check. Rare, but the
        // recheck is cheap.
        (!effective.is_empty()).then(|| {
            mfile::ProjectComposable::new(
                paths::AbsPath::<paths::Host>::new_unchecked(project_path.as_utf8_path()).into(),
                effective,
            )
        })
    };

    let Some(graph) = graph else {
        return Ok((project_composable, Vec::new()));
    };
    let package_composables = match top_level_names.as_bsrs(graph) {
        Ok(top_levels) => {
            let mut out = Vec::new();
            for bsr in graph::Transitives::for_toplevels(graph, top_levels, false).keys() {
                let Some(bs) = graph.get(bsr) else { continue };
                let PackageAttrs {
                    state_wiring,
                    fs_mapping_paths,
                } = extract_package_attrs(bs)?;
                if state_wiring.is_empty() && fs_mapping_paths.is_empty() {
                    continue;
                }
                out.push(mfile::PackageComposable::new(
                    bs.name.clone(),
                    state_wiring,
                    fs_mapping_paths,
                ));
            }
            out
        }
        Err(e) => {
            tracing::debug!(
                project_path = %project_path,
                error = %e,
                "package name → BSR resolution failed at CreateSession; \
                 package composables will be empty",
            );
            Vec::new()
        }
    };
    Ok((project_composable, package_composables))
}

/// The full compose chain for a create flow: resolve the project,
/// build its composables, and run the composer. Synchronous and
/// potentially expensive (nickel evaluation, graph resolution) —
/// callers on an async runtime should wrap it in a blocking-safe
/// helper. Kept free of `.await`s so its non-`Send` intermediaries
/// ([`mctx::Context`], nickel-`Rc`-carrying errors) never cross one.
pub(crate) fn run_compose(
    daemon_ctx: &Arc<mctx::DaemonContext>,
    project_path: &DaemonAbsPath,
    contribution: WireContribution,
) -> Result<ComposeOutcome, std::io::Error> {
    let resolution = resolve_project_ctx_and_graph(daemon_ctx, project_path)?;
    let (project_composable, package_composables) =
        build_composables(project_path, &resolution, &contribution)?;
    run_composer(contribution, project_composable, package_composables)
}

/// Assemble the [`SessionComposer`], `add()` the daemon-side
/// composables (which may fail on unresolvable-inherit vars,
/// malformed state_wiring, etc.), and drive
/// [`SessionComposer::compose`]. Every error is pre-mapped to
/// [`std::io::ErrorKind::InvalidInput`] with a contextualized
/// message so the async handler can propagate it verbatim.
pub(crate) fn run_composer(
    contribution: WireContribution,
    project_composable: Option<mfile::ProjectComposable>,
    package_composables: Vec<mfile::PackageComposable>,
) -> Result<ComposeOutcome, std::io::Error> {
    let mut composer = SessionComposer::new(contribution);
    if let Some(pc) = project_composable {
        composer.add(pc).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("project contribution failed: {e}"),
            )
        })?;
    }
    for pc in package_composables {
        let name = pc.package_name().to_string();
        composer.add(pc).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("package `{name}` contribution failed: {e}"),
            )
        })?;
    }
    composer
        .compose(SessionId::nil(), ComposeOptions::default())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;
    use sessions::core::compose::Composable;

    /// A package with `env_state_wiring` produces, via the
    /// composition path, the same env vars and `/state/<prefix>`
    /// state-dir set that the pre-composition
    /// [`graph::SetupForPackages::build`] path produced. Blocks a
    /// silent regression when Phase 3 flipped the session sandbox
    /// off the `SetupForPackages` output.
    ///
    /// Only env-vars and state-dirs are compared here — Phase 2
    /// (composition patches → sandbox) is still deferred, so the
    /// fs-mapping parity check waits until that lands. The
    /// composition side of that path is already exercised by
    /// `contribute_maps_fs_mappings_to_patches` in `mfile`.
    #[test]
    fn state_wiring_composition_matches_setup_for_packages() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                {
                    name = \"go\",
                    build_deps = [],
                    cmd = \"\",
                    attrs.env_state_wiring = [
                      { env_var = \"GOCACHE\", prefix = \"gocache\" },
                      { env_var = \"GOMODCACHE\", prefix = \"gomodcache\" },
                    ],
                } | BuildSpec
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let g = graph::Graph::new().ingest(layer).unwrap();
        let bsr = g.by_name("go").unwrap();
        let bs = g.get(bsr).unwrap();

        let legacy = graph::SetupForPackages::build(&g, [bsr]).unwrap();

        let PackageAttrs {
            state_wiring,
            fs_mapping_paths,
        } = extract_package_attrs(bs).unwrap();
        assert!(
            fs_mapping_paths.is_empty(),
            "no fs mappings on this fixture"
        );
        let composable = mfile::PackageComposable::new("go", state_wiring, fs_mapping_paths);
        let env = |_: &str| Err(std::env::VarError::NotPresent);
        let contribution = composable.contribute(&env).unwrap();

        let composition_env_vars: std::collections::HashMap<String, String> = contribution
            .vars()
            .iter()
            .map(|pv| (pv.var().name().to_string(), pv.var().value().to_string()))
            .collect();
        assert_eq!(composition_env_vars, legacy.env_vars);

        // Composition's state-dir derivation (values shaped
        // `/state/<prefix>` → `prefix`) matches what
        // `SetupForPackages` extracted from `env_state_wiring`.
        let composition_state_dirs: std::collections::HashSet<String> = composition_env_vars
            .values()
            .filter_map(|v| v.strip_prefix("/state/"))
            .filter(|p| !p.is_empty() && !p.contains('/'))
            .map(str::to_owned)
            .collect();
        assert_eq!(composition_state_dirs, legacy.state_dirs);
    }

    /// `class = 'Credential` fs mappings are dropped by
    /// [`extract_fs_mapping_paths`] pending the future secrets
    /// strategy. Regression guard: a package that declares one
    /// Credential entry alongside one State entry contributes only
    /// the State one to the composition path.
    #[test]
    fn credential_class_fs_mappings_are_filtered_out() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                {
                    name = \"claude-code\",
                    build_deps = [],
                    cmd = \"\",
                    attrs = {
                        env_dir_mappings = [{ read_only = false, path = \"~/.claude\", class = 'State }],
                        env_file_mappings = [{ read_only = false, path = \"~/.claude.json\", class = 'Credential }],
                    },
                } | BuildSpec
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let g = graph::Graph::new().ingest(layer).unwrap();
        let bs = g.get(g.by_name("claude-code").unwrap()).unwrap();

        let PackageAttrs {
            fs_mapping_paths, ..
        } = extract_package_attrs(bs).unwrap();
        let paths: Vec<&str> = fs_mapping_paths.iter().map(String::as_str).collect();
        assert_eq!(paths, vec!["~/.claude"]);
        assert!(
            !paths.contains(&"~/.claude.json"),
            "Credential-class mapping should be filtered out",
        );
    }

    /// Strict-shaped names go to `session.vars`; lenient-shaped
    /// names go to `session.vars_lenient`; unusable names are
    /// dropped (with a warn tucked into the log stream).
    ///
    /// The helper's generic bound is
    /// `IntoIterator<Item = (&String, &EnvVarValue)>`, which is
    /// satisfied by both `&IndexMap<_, _>` (the production input
    /// from `graph::Stack::build_env_vars`) and by iterators over
    /// tuples like the one this test uses. The fold logic is
    /// container-agnostic — the iteration order the container
    /// happens to provide doesn't affect correctness — so this
    /// test exercises exactly the same fold code the production
    /// path does.
    #[test]
    fn fold_stack_vars_splits_by_name_shape() {
        let mut session = mfile::Session::default();
        let vars = [
            (
                "RUST_LOG".to_string(),
                mfile::EnvVarValue::Value("info".into()),
            ),
            (
                "some-dashed-name".to_string(),
                mfile::EnvVarValue::Value("x".into()),
            ),
            (
                "a=bad=name".to_string(),
                mfile::EnvVarValue::Value("x".into()),
            ),
        ];
        fold_stack_vars_into_session(&mut session, "test-stack", vars.iter().map(|(k, v)| (k, v)));

        let strict_name = sessions::core::primitives::StrictVarName::try_new("RUST_LOG").unwrap();
        assert!(
            session.vars.contains_key(&strict_name),
            "strict-shaped went to vars"
        );
        assert_eq!(
            session.vars_lenient.len(),
            1,
            "lenient-shaped went to vars_lenient"
        );
        assert_eq!(session.vars_lenient[0].name().as_ref(), "some-dashed-name",);
    }

    /// Session-declared vars always beat stack-inherited ones.
    /// A stack fold that would clobber a session-declared var is a
    /// no-op instead — both for strict-shaped (BTreeMap `.entry`)
    /// and lenient (linear scan).
    #[test]
    fn fold_stack_vars_never_overrides_session_declared() {
        let strict_name = sessions::core::primitives::StrictVarName::try_new("RUST_LOG").unwrap();
        let mut session = mfile::Session::default();
        session.vars.insert(
            strict_name.clone(),
            sessions::core::primitives::VarValue::specified("debug"),
        );
        let lenient_entry = sessions::core::primitives::LenientVarEntry::try_new(
            "some-dashed-name",
            sessions::core::primitives::VarValue::specified("session-wins"),
        )
        .unwrap();
        session.vars_lenient.push(lenient_entry);

        let stack_vars = [
            (
                "RUST_LOG".to_string(),
                mfile::EnvVarValue::Value("info".into()),
            ),
            (
                "some-dashed-name".to_string(),
                mfile::EnvVarValue::Value("stack-loses".into()),
            ),
        ];
        fold_stack_vars_into_session(
            &mut session,
            "test-stack",
            stack_vars.iter().map(|(k, v)| (k, v)),
        );

        // Strict value untouched.
        match session.vars.get(&strict_name).unwrap() {
            sessions::core::primitives::VarValue::Specified { value } => {
                assert_eq!(value, "debug", "session-declared value survives");
            }
            other => panic!("expected Specified, got {other:?}"),
        }
        // Lenient — only the original entry, no duplicate.
        assert_eq!(session.vars_lenient.len(), 1);
        match session.vars_lenient[0].value() {
            sessions::core::primitives::VarValue::Specified { value } => {
                assert_eq!(value, "session-wins", "session-declared value survives");
            }
            other => panic!("expected Specified, got {other:?}"),
        }
    }

    /// A package declaring `env_state_wiring` with a multi-component
    /// `prefix` (e.g. `"cache/artifacts"`) is rejected at extraction
    /// with a descriptive `InvalidData` error. Guards the
    /// task-vs-session divergence — the legacy `SetupForPackages`
    /// path would silently `mkdir -p` such a prefix, but the
    /// composition path's state-dir derivation would drop it. Rather
    /// than pick a behavior arbitrarily, fail loudly so a package
    /// author sees the "novel schema shape not yet supported"
    /// message.
    #[test]
    fn multi_component_state_wiring_prefix_errors() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                {
                    name = \"bad\",
                    build_deps = [],
                    cmd = \"\",
                    attrs.env_state_wiring = [
                      { env_var = \"WEIRD\", prefix = \"cache/artifacts\" },
                    ],
                } | BuildSpec
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let g = graph::Graph::new().ingest(layer).unwrap();
        let bs = g.get(g.by_name("bad").unwrap()).unwrap();

        let err = extract_package_attrs(bs)
            .expect_err("multi-component prefix should error at extraction");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(msg.contains("bad"), "error should name the package: {msg}");
        assert!(
            msg.contains("cache/artifacts"),
            "error should name the offending prefix: {msg}"
        );
    }
}
