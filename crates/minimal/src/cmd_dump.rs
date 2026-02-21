use std::{fmt::Display, io::stdout};

use decode::AttrValue;
use graph::{BuildOutput, BuildSpec, BuildSpecInput, DepGraph, RuntimeDep, SourceInput};
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

    pub name: Option<String>,
}

#[derive(clap::Args, Debug)]
#[group(required = true, multiple = false)]
pub struct DumpKind {
    /// Dump the packages
    #[arg(short, long)]
    packages: bool,

    /// Dump the harnesses
    #[arg(long)]
    harnesses: bool,
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
    is_prebuilt: bool,
    is_collection: bool,
    target: String,

    inputs: Vec<PkgRef>,
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
            AttrValue::String(s, pos) => PkgAttr::String {
                value: s.clone(),
                pos: pos
                    .map(|p| p.into_opt())
                    .flatten()
                    .map(|s| (s.start.to_usize(), s.end.to_usize())),
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

    let graph = ctx.graph_from_all_packages()?;
    let cache = ctx.local_cache();

    if args.kind.packages {
        for bsr in graph.all() {
            let b = graph.get(&bsr).unwrap();
            if let Some(name) = &args.name
                && !fuzzy_match(args.exact, name, &b.name)
            {
                continue;
            }

            out_packages.push(build_pkg_info(&graph, b, &cache)?);
        }
    }

    let w = stdout();
    match args.kind {
        DumpKind {
            packages: true,
            harnesses: false,
        } => {
            serde_json::to_writer_pretty(&w, &out_packages).unwrap();
        }
        _ => todo!("output not implemented: {:?}", args.kind),
    }

    Ok(())
}

/// Simple subsequence fuzzy matcher: all query chars appear in order in target.
fn fuzzy_match(exact: bool, query: &str, target: &str) -> bool {
    if exact {
        return query == target;
    }

    let mut query_chars = query.chars();
    let mut current = query_chars.next();
    for c in target.chars() {
        if let Some(q) = current {
            if c == q {
                current = query_chars.next();
            }
        } else {
            return true;
        }
    }
    current.is_none()
}

fn build_pkg_info(g: &DepGraph, b: &BuildSpec, c: &Cache) -> Result<PkgInfo, Error> {
    Ok(PkgInfo {
        name: b.name.clone(),
        is_prebuilt: b.is_pure_prebuilt(),
        is_collection: b.is_pure_collection(),
        target: b.target.as_ref().to_string(),
        inputs: b
            .inputs
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

fn pkg_ref_from_runtime_dep(g: &DepGraph, i: &RuntimeDep, _c: &Cache) -> Result<PkgRef, Error> {
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

fn pkg_ref_from_input(g: &DepGraph, i: &BuildSpecInput, _c: &Cache) -> Result<PkgRef, Error> {
    match i {
        BuildSpecInput::Build(b) => Ok(PkgRef::Package {
            name: g.get(b).unwrap().name.clone(),
        }),
        BuildSpecInput::Local {
            full_path: _,
            filename,
            file_hash,
        } => Ok(PkgRef::LocalFile {
            filename: filename.clone(),
            hash: format!("{}", file_hash.to_hex()),
        }),
        BuildSpecInput::Subset(s) => Ok(PkgRef::SubsetOf {
            package: g.get(&s.from).unwrap().name.clone(),
            outputs: s.outputs.iter().cloned().collect(),
        }),
        BuildSpecInput::Source(s) => Ok(PkgRef::Source(s.clone())),
        _ => todo!("bsi variant {:?}", i),
    }
}
