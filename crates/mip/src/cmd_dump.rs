use std::{fmt::Display, io::stdout};

use common::Target;
use common::fuzzy_search::fuzzy_match;
use common::target::{Arch, OS};
use decode::{AttrValue, Stack};
use graph::{BuildDep, BuildOutput, BuildSpec, BuildSpecRef, Graph, RuntimeDep, SourceInput};
use mctx::{Cache, Context, Error};
use nickel_lang_core::term::IndexMap;
use serde::Serialize;

#[derive(clap::Args)]
pub struct DumpArgs {
    #[command(flatten)]
    pub kind: DumpKind,

    #[arg(short, long, default_value_t = Format::Json)]
    pub format: Format,

    #[arg(long, default_value_t = false)]
    pub exact: bool,

    /// Target architecture to evaluate packages against (e.g., "amd64",
    /// "arm64"). When a package's `build_deps` uses
    /// `match { arch = 'Amd64 } => ..., { arch = 'Arm64 } => ... } target`
    /// to select between per-arch source URLs, only the matching arm's
    /// output appears in the dump. Overrides the host default so tools
    /// downstream can aggregate both arches by running the dump twice.
    #[arg(long)]
    pub arch: Option<String>,

    pub name: Option<String>,
}

#[derive(clap::Args, Debug)]
#[group(required = true, multiple = false)]
pub struct DumpKind {
    /// Dump the packages
    #[arg(short, long)]
    packages: bool,

    /// Dump the stacks
    #[arg(long)]
    stacks: bool,
}

#[derive(Debug, Default, Clone, clap::ValueEnum)]
pub enum Format {
    #[default]
    Json,
}

impl Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Format::Json => write!(f, "json"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PkgInfo {
    name: String,
    spec_hash: String,
    is_prebuilt: bool,
    is_collection: bool,
    target: String,

    build_deps: Vec<PkgRef>,
    runtime_deps: Vec<PkgRef>,
    outputs: IndexMap<String, BuildOutput>,

    build_args: Option<IndexMap<String, String>>,

    attrs: IndexMap<String, PkgAttr>,
    needs: IndexMap<String, PkgAttr>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PkgRef {
    Package {
        name: String,
    },
    LocalFile {
        filename: String,
        hash: String,
    },
    SubsetOf {
        package: String,
        outputs: Vec<String>,
    },
    Source(SourceInput),
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PkgAttr {
    Bool(bool),
    Number(f64),
    List(Vec<PkgAttr>),
    Map(IndexMap<String, PkgAttr>),
    EnumVariant(String, Box<PkgAttr>),
    #[serde(untagged)]
    String {
        value: String,
        pos: Option<(usize, usize)>,
    },
}

impl From<&AttrValue> for PkgAttr {
    fn from(value: &AttrValue) -> Self {
        match value {
            AttrValue::Bool(b) => PkgAttr::Bool(*b),
            AttrValue::Number(n) => PkgAttr::Number(*n),
            AttrValue::String(s, pos) => PkgAttr::String {
                value: s.clone(),
                pos: pos.as_ref().map(|s| (s.start_offset, s.end_offset)),
            },
            AttrValue::List(v) => PkgAttr::List(v.iter().map(PkgAttr::from).collect()),
            AttrValue::EnumVariant(n, b) => {
                PkgAttr::EnumVariant(n.clone(), Box::new(b.as_ref().into()))
            }
            AttrValue::Map(m) => {
                PkgAttr::Map(m.iter().map(|(k, v)| (k.clone(), v.into())).collect())
            }
        }
    }
}

pub async fn cmd_dump(args: DumpArgs, ctx: &mut Context) -> Result<(), Error> {
    let mut out_packages = Vec::new();

    let target = resolve_target(args.arch.as_deref())?;
    let graph = ctx.graph_from_all_packages_with_target(target)?;
    let cache = ctx.local_cache();

    if args.kind.packages {
        for bsr in graph.all() {
            let b = graph.get(&bsr).unwrap();
            if let Some(name) = &args.name {
                if args.exact && name != &b.name {
                    continue;
                }
                if fuzzy_match(name, &b.name).is_none() {
                    continue;
                }
            }

            out_packages.push(build_pkg_info(&graph, &bsr, b, &cache)?);
        }
    }

    let w = stdout();
    match args.kind {
        DumpKind {
            packages: true,
            stacks: false,
        } => {
            serde_json::to_writer_pretty(&w, &out_packages).unwrap();
        }
        DumpKind {
            packages: false,
            stacks: true,
        } => {
            let out_stacks = select_stacks(
                graph.iter_stacks().map(|(_, stack)| stack),
                args.name.as_deref(),
                args.exact,
            );
            serde_json::to_writer_pretty(&w, &out_stacks).unwrap();
        }
        // The `DumpKind` clap group is `required = true, multiple = false`,
        // so exactly one of `--packages`/`--stacks` is ever set.
        DumpKind { packages, stacks } => unreachable!(
            "dump requires exactly one of --packages/--stacks (packages={packages}, stacks={stacks})"
        ),
    }

    Ok(())
}

/// Selects the stacks to dump: keeps those matching the optional `--name`
/// query (fuzzy unless `--exact`) and returns them sorted by name. Stacks are
/// stored in a `HashMap`, so sorting keeps the dump output stable across runs
/// — consumers regenerate the CLI reference from it.
fn select_stacks<'a>(
    stacks: impl Iterator<Item = &'a Stack>,
    name: Option<&str>,
    exact: bool,
) -> Vec<&'a Stack> {
    let mut selected: Vec<&Stack> = stacks
        .filter(|stack| match name {
            None => true,
            Some(filter) if exact => stack.name.as_str() == filter,
            Some(filter) => fuzzy_match(filter, &stack.name).is_some(),
        })
        .collect();
    selected.sort_by(|a, b| a.name.cmp(&b.name));
    selected
}

fn build_pkg_info(
    g: &Graph,
    bsr: &BuildSpecRef,
    b: &BuildSpec,
    c: &Cache,
) -> Result<PkgInfo, Error> {
    Ok(PkgInfo {
        name: b.name.clone(),
        spec_hash: g.spec_hash(bsr).0.to_string(),
        is_prebuilt: b.is_pure_prebuilt(),
        is_collection: b.is_pure_collection(),
        target: b.target.as_ref().to_string(),
        build_deps: b
            .build_deps
            .iter()
            .map(|i| pkg_ref_from_input(g, i, c))
            .collect::<Result<_, _>>()?,
        runtime_deps: b
            .runtime_deps
            .iter()
            .map(|rd| pkg_ref_from_runtime_dep(g, rd, c))
            .collect::<Result<_, _>>()?,
        outputs: b.outputs.clone(),
        build_args: b.build_args.clone(),
        attrs: b.attrs.iter().map(|(k, v)| (k.clone(), v.into())).collect(),
        needs: b
            .abstract_deps
            .iter()
            .map(|(k, v)| (k.clone(), v.into()))
            .collect(),
    })
}

fn pkg_ref_from_runtime_dep(g: &Graph, i: &RuntimeDep, _c: &Cache) -> Result<PkgRef, Error> {
    match i {
        RuntimeDep::Build(b) => Ok(PkgRef::Package {
            name: g.get(b).unwrap().name.clone(),
        }),
        RuntimeDep::Subset(s) => Ok(PkgRef::SubsetOf {
            package: g.get(&s.from).unwrap().name.clone(),
            outputs: s.outputs.iter().cloned().collect(),
        }),
    }
}

fn pkg_ref_from_input(g: &Graph, i: &BuildDep, _c: &Cache) -> Result<PkgRef, Error> {
    match i {
        BuildDep::Build(b) => Ok(PkgRef::Package {
            name: g.get(b).unwrap().name.clone(),
        }),
        BuildDep::Local {
            full_path: _,
            filename,
            file_hash,
        } => Ok(PkgRef::LocalFile {
            filename: filename.clone(),
            hash: format!("{}", file_hash.to_hex()),
        }),
        BuildDep::Subset(s) => Ok(PkgRef::SubsetOf {
            package: g.get(&s.from).unwrap().name.clone(),
            outputs: s.outputs.iter().cloned().collect(),
        }),
        BuildDep::Source(s) => Ok(PkgRef::Source(s.clone())),
    }
}

/// Resolve the `--arch` flag into a [`Target`]. Delegates the string
/// parsing to the shared `Arch::from_str` impl in common so the alias
/// set (arm64/aarch64, amd64/x86_64) stays consistent with every other
/// consumer. When the flag is absent, defaults to [`Target::host`]. OS
/// is always Linux — dump consumers want per-arch evaluation of the
/// same pkgs repo, not cross-OS.
fn resolve_target(arch: Option<&str>) -> Result<Target, Error> {
    let Some(arch_str) = arch else {
        return Ok(Target::host());
    };
    let arch: Arch = arch_str
        .parse()
        .map_err(|e: common::target::ArchParseError| Error::Other(e.into()))?;
    Ok(Target::new(arch, OS::Linux))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack_named(name: &str) -> Stack {
        Stack {
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn select_stacks_sorts_by_name() {
        let stacks = [stack_named("beta"), stack_named("alpha")];
        let selected = select_stacks(stacks.iter(), None, false);
        let names: Vec<&str> = selected.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn select_stacks_honours_exact_and_fuzzy_name_filter() {
        let stacks = [stack_named("alpha"), stack_named("beta")];

        let exact = select_stacks(stacks.iter(), Some("alpha"), true);
        assert_eq!(exact.len(), 1);
        assert_eq!(exact[0].name, "alpha");

        // A substring that is only a subsequence of "alpha".
        let fuzzy = select_stacks(stacks.iter(), Some("alph"), false);
        assert_eq!(fuzzy.len(), 1);
        assert_eq!(fuzzy[0].name, "alpha");

        // Exact match requires the whole name, so a partial misses.
        let missed = select_stacks(stacks.iter(), Some("alph"), true);
        assert!(missed.is_empty());
    }

    #[test]
    fn resolve_target_defaults_to_host_when_arg_missing() {
        let target = resolve_target(None).unwrap();
        assert_eq!(target.arch(), Target::host().arch());
        assert_eq!(target.os(), Target::host().os());
    }

    #[test]
    fn resolve_target_wraps_parsed_arch_with_linux_os() {
        let target = resolve_target(Some("amd64")).unwrap();
        assert!(matches!(target.arch(), Arch::Amd64));
        assert!(matches!(target.os(), OS::Linux));

        let target = resolve_target(Some("arm64")).unwrap();
        assert!(matches!(target.arch(), Arch::Arm64));
        assert!(matches!(target.os(), OS::Linux));
    }

    #[test]
    fn resolve_target_propagates_arch_parse_error() {
        // String-to-arch parsing (and its error message) lives in
        // common::target; this test confirms cmd_dump surfaces that
        // error to the caller rather than silently eating it.
        let err = resolve_target(Some("riscv64")).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("riscv64"),
            "error should name the bad input, got: {msg}"
        );
    }
}
