#![allow(unused_imports, unused_variables)]
use crate::PackagesArg;
use clap::{ArgAction, ValueEnum};
use graph::{
    BuildSpec, BuildSpecInput, BuildSpecRef, DepGraph, RuntimeDep, SourceFetch, SourceInput,
    SubsetInput, Transitives,
};
use mctx::{Context, Error};
use nickel_lang_core::bytecode::ast::Node;
use nickel_lang_core::traverse::TraverseControl;
use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex, NodeWeightsMut};
use petgraph::visit::{
    Dfs, EdgeFiltered, EdgeRef, GraphBase, IntoEdges, IntoNeighbors, NodeFiltered, Walker,
};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Dot,
    Mermaid,
}

/// CLI options to control what goes in the generated graph
#[derive(Debug, clap::Args)]
pub struct DepArgs {
    #[command(flatten)]
    packages: PackagesArg,

    /// Packages left out of graph and not traversed. Overrides matching -p entries
    #[arg(short, long, alias="exclude", value_delimiter=',', num_args=0..)]
    excludes: Option<Vec<String>>,

    /// Whether build spec "inputs" are in the graph (does not affect runtime deps)
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("true"),action = ArgAction::Set,
    )]
    build_spec_deps: bool,

    /// Whether source code "inputs" are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action = ArgAction::Set,
    )]
    source_deps: bool,

    /// Whether Local (build.sh) "input" deps are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action = ArgAction::Set,
    )]
    local_deps: bool,

    /// Whether host path "inputs" are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action=ArgAction::Set,
    )]
    hostpath_deps: bool,

    /// Whether "Needs" nodes and edges are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action = ArgAction::Set,
    )]
    needs: bool,

    /// Whether "Provides" edges & "Needs" Nodes are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action = ArgAction::Set,
    )]
    provides: bool,

    /// Whether "replace on cycle"/prebuilts/bootstrap are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action = ArgAction::Set,
    )]
    bootstrap: bool,

    /// Whether runtime and input deps must have non-zero subtree deps
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action = ArgAction::Set,
    )]
    subtrees_only: bool,

    /// How deeply input dependencies are followed. Use -1 for all.
    #[arg(long,num_args(1),default_value_t=-1,action=ArgAction::Set)]
    input_deps_depth: i32,

    /// How deeply runtime dependencies are followed. Use -1 for all.
    #[arg(long,num_args(1),default_value_t=-1,action=ArgAction::Set)]
    runtime_deps_depth: i32,

    /// Discard graph nodes with no edges
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action = ArgAction::Set,
    )]
    prune_edgeless: bool,

    #[arg(long, default_value("dot"), value_parser = clap::value_parser!(OutputFormat))]
    output_format: OutputFormat,
}

/// Data per node in the package petgraph DiGraph (aka "weight") that identifies
/// the type of node (BuildSpec, HostPath, Local, Need, Source) and holds
/// its related data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NodeData {
    /// represents a BuildSpec/BuildDecl
    BuildSpec(BuildSpecRef),
    /// Hostpath is a host filepath to go in the sandbox as an input
    HostPath(PathBuf),
    /// Local is a local file (e.g. build.sh) to go in the sandbox as an input
    Local {
        full_path: PathBuf,
        filename: String,
        file_hash: blake3::Hash,
    },
    /// represents something a buildspec needs during build, like Internat access
    Need(String),
    /// represents a source tarball with a url and its hash
    Source(SourceNode),
}

/// Data per edge in the package petgraph DiGraph
#[derive(Clone, PartialEq, Eq, Hash)]
enum EdgeData {
    /// can link BuildSpec to a BuildSpec, HostPath, Local or Source input node
    InputDep(InputDepEdge),
    /// can link a BuildSpec to a BuildSpec runtime dep node
    RuntimeDep(RuntimeDepEdge),
    /// can link a BuildSpec to a BuildSpec for a prebuilt/bootstrap binary
    ReplaceOnCycle,
    /// can link a BuildSpec to a Need node
    Needs,
    /// can link a BuildSpec marked with needed_for_* Attr to the Need node it fulfills
    Provides,
}

struct TraversalState {
    depth: i32,
}

/// Edge between a BuildSpec and an Input (BuildSpec, HostPath, Local or Source input node)
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct InputDepEdge {
    /// applies if the target node is a BuildSpec, lists the named outputs it needs
    outputs: SmallVec<[String; 4]>,
    /// applies if the target node is Source, says to unpack the tarball etc in the sandbox
    extract: bool,
    /// applies if the target node is Source, how much of the tarball's path to remove when unpacked
    strip_prefix: Option<String>,
}

/// links between a BuildSpec the it's runtime dep, with option named outputs
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct RuntimeDepEdge {
    //// applies if the target node is a BuildSpec
    outputs: SmallVec<[String; 4]>,
}

/// Link between an BuildSpec an a Source input
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SourceNode {
    url: String,
    sha256: String,
}

struct GraphData {
    pgraph: DiGraph<NodeData, EdgeData>,
    bsname_to_node_index: HashMap<String, NodeIndex>,
}

/// Returns the NodeIndex of a node with the given NodeData and whether the node already existed.
fn add_uniq_node(
    pgraph: &mut DiGraph<NodeData, EdgeData>,
    m: &mut HashMap<NodeData, NodeIndex>,
    nd: NodeData,
) -> (NodeIndex, bool) {
    if let Some(node_index) = m.get(&nd) {
        (*node_index, true)
    } else {
        let node_index = pgraph.add_node(nd.clone());
        m.insert(nd, node_index);
        (node_index, false)
    }
}

/// Returns a perhaps easier to understand and work with petgraph DiGraph derived
/// from the given [`graph::DepGraph`].  See the [`NodeData`] and [`EdgeData`] types and the
/// petgraph API docs for how to work with them
fn pgraph_from(graph: &graph::DepGraph) -> Result<GraphData, Error> {
    let mut pgraph: DiGraph<NodeData, EdgeData> = DiGraph::new();
    let mut processed_nodes = HashMap::new();
    let mut bsname_to_node_index = HashMap::new();
    let iter = graph.iter();
    for (bsr, bs) in iter {
        let node_data = NodeData::BuildSpec(bsr);
        let (node_index, _) = add_uniq_node(&mut pgraph, &mut processed_nodes, node_data);
        bsname_to_node_index.insert(bs.name.clone(), node_index);

        bs.inputs.iter().for_each(|input| match input {
            BuildSpecInput::Build(ibsr) => {
                let (inode_index, _) = add_uniq_node(
                    &mut pgraph,
                    &mut processed_nodes,
                    NodeData::BuildSpec(*ibsr),
                );
                let edge_data = EdgeData::InputDep(InputDepEdge::default());
                pgraph.add_edge(node_index, inode_index, edge_data);
            }
            BuildSpecInput::HostPath(hp) => {
                let (inode_index, _) = add_uniq_node(
                    &mut pgraph,
                    &mut processed_nodes,
                    NodeData::HostPath(hp.clone()),
                );
                let edge_data = EdgeData::InputDep(InputDepEdge::default());
                pgraph.add_edge(node_index, inode_index, edge_data);
            }
            BuildSpecInput::Local {
                full_path,
                filename,
                file_hash,
            } => {
                let (inode_index, _) = add_uniq_node(
                    &mut pgraph,
                    &mut processed_nodes,
                    NodeData::Local {
                        full_path: full_path.clone(),
                        filename: filename.clone(),
                        file_hash: *file_hash,
                    },
                );
                let edge_data = EdgeData::InputDep(InputDepEdge::default());
                pgraph.add_edge(node_index, inode_index, edge_data);
            }
            BuildSpecInput::Source(SourceInput {
                from: SourceFetch::Web { url, sha256 },
                extract,
                strip_prefix,
            }) => {
                let (inode_index, _) = add_uniq_node(
                    &mut pgraph,
                    &mut processed_nodes,
                    NodeData::Source(SourceNode {
                        url: url.to_string(),
                        sha256: sha256.to_string(),
                    }),
                );
                let edge_data = EdgeData::InputDep(InputDepEdge {
                    outputs: SmallVec::new(),
                    extract: *extract,
                    strip_prefix: strip_prefix.clone(),
                });
                pgraph.add_edge(node_index, inode_index, edge_data);
            }
            BuildSpecInput::Source(SourceInput {
                from: SourceFetch::Local { .. },
                ..
            }) => todo!(),
            BuildSpecInput::Subset(SubsetInput { from, outputs }) => {
                let (inode_index, _) = add_uniq_node(
                    &mut pgraph,
                    &mut processed_nodes,
                    NodeData::BuildSpec(*from),
                );
                let edge_data = EdgeData::InputDep(InputDepEdge {
                    outputs: outputs.clone(),
                    extract: false,
                    strip_prefix: None,
                });
                pgraph.add_edge(node_index, inode_index, edge_data);
            }
        });

        // Runtime deps in the petgraph can only be BuildSpec to BuildSpec
        // Convert from graph where runtime deps may be BuildSpecRef, Subtree or Hostpatgh
        bs.runtime_deps.iter().for_each(|rtd| match rtd {
            RuntimeDep::Build(rtd_bsr) => {
                let (tgt_node_index, _) = add_uniq_node(
                    &mut pgraph,
                    &mut processed_nodes,
                    NodeData::BuildSpec(*rtd_bsr),
                );
                let edge_data = EdgeData::RuntimeDep(RuntimeDepEdge::default());
                pgraph.add_edge(node_index, tgt_node_index, edge_data);
            }
            RuntimeDep::Subset(SubsetInput { from, outputs }) => {
                let (tgt_node_index, _) = add_uniq_node(
                    &mut pgraph,
                    &mut processed_nodes,
                    NodeData::BuildSpec(*from),
                );
                let edge_data = EdgeData::RuntimeDep(RuntimeDepEdge {
                    outputs: outputs.clone(),
                });
                pgraph.add_edge(node_index, tgt_node_index, edge_data);
            }
        });

        if let Some(roc_bsr) = bs.replace_on_cycle {
            let (roc_node_index, _) = add_uniq_node(
                &mut pgraph,
                &mut processed_nodes,
                NodeData::BuildSpec(roc_bsr),
            );
            let edge_data = EdgeData::ReplaceOnCycle;
            pgraph.add_edge(node_index, roc_node_index, edge_data);
        }

        bs.abstract_deps.iter().for_each(|need_entry| {
            let need = need_entry.0;
            let (tgt_node_index, _) = add_uniq_node(
                &mut pgraph,
                &mut processed_nodes,
                NodeData::Need(need.clone()),
            );
            let edge_data = EdgeData::Needs;
            pgraph.add_edge(node_index, tgt_node_index, edge_data);
        });

        bs.attrs.iter().for_each(|attr| {
            let attr_name = attr.0;
            if !attr_name.eq("needed_for_internet") {
                return;
            }
            let (tgt_node_index, _) = add_uniq_node(
                &mut pgraph,
                &mut processed_nodes,
                NodeData::Need(String::from("internet")),
            );
            let edge_data = EdgeData::Provides;
            pgraph.add_edge(node_index, tgt_node_index, edge_data);
        });
    }

    Ok(GraphData {
        pgraph,
        bsname_to_node_index,
    })
}

/// Creates a copy of the pgraph with only the nodes and edges as specified by the args
fn pgraph_copy_subset(
    graph: &DepGraph,
    pgraph: &DiGraph<NodeData, EdgeData>,
    bsname_to_node_index: &HashMap<String, NodeIndex>,
    args: &DepArgs,
) -> Result<DiGraph<NodeData, EdgeData>, Error> {
    // if the listest packages with -p reduce to just those node indices
    let node_indices = match args.packages.packages.clone() {
        Some(strs) if !strs.is_empty() => strs
            .iter()
            .filter_map(|s| bsname_to_node_index.get(s))
            .copied()
            .collect::<Vec<_>>(),
        _ => pgraph.node_indices().collect::<Vec<_>>(),
    };

    let mut cpy = DiGraph::new();
    let mut copied_nodes = HashMap::new();
    for nd in node_indices.iter() {
        if let Some(NodeData::BuildSpec(bsr)) = pgraph.node_weight(*nd) {
            let state = TraversalState { depth: 0 };
            pgraph_copy_subset_for_node(
                graph,
                pgraph,
                args,
                *nd,
                bsr,
                &state,
                &mut cpy,
                &mut copied_nodes,
            );
        }
    }
    Ok(cpy)
}

/// Recursive function for traversing the graph and collecting (copying) nodes
/// and edges that match the criteria given in the CLI args.  Resulting petgraph
/// is the mutabe cpy output parameter.
#[allow(clippy::too_many_arguments)]
fn pgraph_copy_subset_for_node(
    graph: &DepGraph,
    pgraph: &DiGraph<NodeData, EdgeData>,
    args: &DepArgs,
    node_index: NodeIndex,
    bsr: &BuildSpecRef,
    state: &TraversalState,
    cpy: &mut DiGraph<NodeData, EdgeData>,
    copied_nodes: &mut HashMap<NodeData, NodeIndex>,
) {
    let bs = graph.get(bsr).unwrap();
    if matches!(args.excludes, Some(ref strs) if strs.contains(&bs.name)) {
        return;
    }
    let node_data = pgraph[node_index].clone();

    let (cpy_node_index, _) = add_uniq_node(cpy, copied_nodes, node_data);

    let edges = pgraph.edges_directed(node_index, Direction::Outgoing);
    for e in edges {
        let source = node_index;
        let target = e.target();
        let edge_data = e.weight();
        let target_data = &pgraph[target];

        match edge_data {
            EdgeData::InputDep(InputDepEdge {
                outputs,
                extract,
                strip_prefix,
            }) if state.depth < 10000
                && (args.input_deps_depth == -1 || state.depth < args.input_deps_depth)
                && (!args.subtrees_only || !outputs.is_empty()) =>
            {
                match target_data {
                    NodeData::BuildSpec(target_bsr) => {
                        let target_data_bsname =
                            graph.get(target_bsr).map(|bs| bs.name.clone()).unwrap();
                        if args.build_spec_deps
                            && !args
                                .excludes
                                .as_ref()
                                .is_some_and(|names| names.contains(&target_data_bsname))
                        {
                            let (cpy_target, already_exists) =
                                add_uniq_node(cpy, copied_nodes, target_data.clone());
                            cpy.add_edge(cpy_node_index, cpy_target, edge_data.clone());
                            if !already_exists {
                                pgraph_copy_subset_for_node(
                                    graph,
                                    pgraph,
                                    args,
                                    target,
                                    target_bsr,
                                    &TraversalState {
                                        depth: state.depth + 1,
                                    },
                                    cpy,
                                    copied_nodes,
                                );
                            }
                        }
                    }
                    NodeData::HostPath(path) => {
                        if args.hostpath_deps {
                            let (cpy_target, _) =
                                add_uniq_node(cpy, copied_nodes, target_data.clone());
                            cpy.add_edge(cpy_node_index, cpy_target, edge_data.clone());
                        }
                    }
                    NodeData::Local {
                        full_path,
                        filename,
                        file_hash,
                    } => {
                        if args.local_deps {
                            let (cpy_target, _) =
                                add_uniq_node(cpy, copied_nodes, target_data.clone());
                            cpy.add_edge(cpy_node_index, cpy_target, edge_data.clone());
                        }
                    }
                    NodeData::Source(SourceNode { url, sha256 }) => {
                        if args.source_deps {
                            let (cpy_target, _) =
                                add_uniq_node(cpy, copied_nodes, target_data.clone());
                            cpy.add_edge(cpy_node_index, cpy_target, edge_data.clone());
                        }
                    }
                    _ => panic!("Unexpected input dep target node type"),
                }
            }
            EdgeData::RuntimeDep(RuntimeDepEdge { outputs })
                if state.depth < 10000
                    && (args.runtime_deps_depth == -1 || state.depth < args.runtime_deps_depth)
                    && (!args.subtrees_only || !outputs.is_empty()) =>
            {
                match target_data {
                    NodeData::BuildSpec(target_bsr) => {
                        let target_data_bsname =
                            graph.get(target_bsr).map(|bs| bs.name.clone()).unwrap();
                        if !args
                            .excludes
                            .as_ref()
                            .is_some_and(|names| names.contains(&target_data_bsname))
                        {
                            let (cpy_target, already_exists) =
                                add_uniq_node(cpy, copied_nodes, target_data.clone());
                            cpy.add_edge(cpy_node_index, cpy_target, edge_data.clone());
                            if !already_exists {
                                pgraph_copy_subset_for_node(
                                    graph,
                                    pgraph,
                                    args,
                                    target,
                                    target_bsr,
                                    &TraversalState {
                                        depth: state.depth + 1,
                                    },
                                    cpy,
                                    copied_nodes,
                                );
                            }
                        }
                    }
                    _ => panic!("Unexpected input dep target node type"),
                }
            }
            EdgeData::ReplaceOnCycle => match target_data {
                NodeData::BuildSpec(target_bsr) => {
                    if args.bootstrap {
                        let (cpy_target, already_exists) =
                            add_uniq_node(cpy, copied_nodes, target_data.clone());
                        cpy.add_edge(cpy_node_index, cpy_target, edge_data.clone());
                    }
                }
                _ => panic!("Unexpected input dep target node type"),
            },
            EdgeData::Needs => match target_data {
                NodeData::Need(name) => {
                    if args.needs {
                        let (cpy_target, already_exists) =
                            add_uniq_node(cpy, copied_nodes, target_data.clone());
                        cpy.add_edge(cpy_node_index, cpy_target, edge_data.clone());
                    }
                }
                _ => panic!("Unexpected input dep target node type"),
            },
            EdgeData::Provides => match target_data {
                NodeData::Need(name) => {
                    if args.provides {
                        let (cpy_target, already_exists) =
                            add_uniq_node(cpy, copied_nodes, target_data.clone());
                        cpy.add_edge(cpy_node_index, cpy_target, edge_data.clone());
                    }
                }
                _ => panic!("Unexpected input dep target node type"),
            },
            _ => {}
        }
    }
}

/// Removes all nodes with no incoming and no outgoing edges from the given graph
fn prune_edgeless(pgraph: &mut DiGraph<NodeData, EdgeData>) {
    // retain_nodes removes nodes that don't return true.
    // Otherwise must use repeated find()s because later node indices
    // are invalidated when you remove a node
    pgraph.retain_nodes(|frozen, node_index| {
        frozen
            .edges_directed(node_index, Direction::Incoming)
            .chain(frozen.edges_directed(node_index, Direction::Outgoing))
            .count()
            > 0
    });
}

/// Prints graphviz DOT or Mermaid for the dependency graph as constrained by the CLI args to stdout.
pub async fn cmd_dep(args: DepArgs, ctx: &mut Context) -> Result<(), Error> {
    crate::enforce_science_mode()?;

    let graph = args.packages.resolve(ctx)?;
    let GraphData {
        pgraph,
        bsname_to_node_index,
    } = pgraph_from(&graph)?;
    let mut cpy = pgraph_copy_subset(&graph, &pgraph, &bsname_to_node_index, &args)?;

    if args.prune_edgeless {
        prune_edgeless(&mut cpy);
    }
    match args.output_format {
        OutputFormat::Dot => gen_dot(&cpy, &graph),
        OutputFormat::Mermaid => gen_mermaid(&cpy, &graph),
    }
}

fn mermaid_node_id(
    pgraph: &DiGraph<NodeData, EdgeData>,
    graph: &DepGraph,
    node_id: NodeIndex,
) -> String {
    let node_data = pgraph[node_id].clone();
    match node_data {
        NodeData::BuildSpec(bsr) => {
            let name = graph
                .get(&bsr)
                .map(|bs| bs.name.clone())
                .unwrap_or(String::from("<unknown!>"));
            format!("Pkg:{name}")
        }
        NodeData::Source(SourceNode { url, .. }) => {
            format!("Src:{url}")
        }
        NodeData::HostPath(hp) => {
            let label = hp.to_string_lossy();
            format!("Hostpath:{label}")
        }
        NodeData::Local { full_path, .. } => {
            let label = full_path.to_string_lossy();
            format!("Local:{label}")
        }
        NodeData::Need(name) => {
            format!("Need:{name}")
        }
    }
}

fn gen_mermaid(pgraph: &DiGraph<NodeData, EdgeData>, graph: &DepGraph) -> Result<(), Error> {
    println!("graph LR");

    // just print edge declarations to keep compat with mermaid-ascii subsut
    for edge_ref in pgraph.edge_references() {
        let source_index = edge_ref.source();
        let target_index = edge_ref.target();
        let edge_data = edge_ref.weight();
        let source_id = source_index.index();
        let target_id = target_index.index();
        let source_name = mermaid_node_id(pgraph, graph, source_index);
        let target_name = mermaid_node_id(pgraph, graph, target_index);

        match edge_data {
            EdgeData::InputDep(InputDepEdge { outputs, .. }) => {
                if outputs.is_empty() {
                    println!("{source_name} -->|input| {target_name}");
                } else {
                    let subsets = outputs.join(",");
                    println!("{source_name} -->|input subsets {subsets}| {target_name}");
                }
            }
            EdgeData::RuntimeDep(RuntimeDepEdge { outputs, .. }) => {
                if outputs.is_empty() {
                    println!("{source_name} -->|runtime dep| {target_name}");
                } else {
                    let subsets = outputs.join(",");
                    println!("{source_id} -->|runtime dep subsets {subsets}| {target_name}");
                }
            }
            EdgeData::ReplaceOnCycle => {
                println!("{source_name} -->|bootstrap| {target_name}");
            }
            EdgeData::Needs => {
                println!("{source_name} -->|needs| {target_name}");
            }
            EdgeData::Provides => {
                println!("{source_name} -->|provides| {target_name}");
            }
        }
    }

    println!();

    Ok(())
}

fn gen_dot(pgraph: &DiGraph<NodeData, EdgeData>, graph: &DepGraph) -> Result<(), Error> {
    println!("digraph {{");
    println!("  graph [rankdir=LR];");
    println!("  node [shape=circle, style=filled, fillcolor=lightblue];");
    println!("  edge [color=gray];");
    println!();

    // print the DOT graph node declarations and build a pkg-name to buildspecref map.
    for node_index in pgraph.node_indices() {
        let node_data = pgraph[node_index].clone();
        let id = node_index.index();
        match node_data {
            NodeData::BuildSpec(bsr) => {
                let name = graph
                    .get(&bsr)
                    .map(|bs| bs.name.clone())
                    .unwrap_or(String::from("<unknown!>"));
                println!("  \"{id}\" [label=\"Pkg {name}\"];");
            }
            NodeData::Source(SourceNode { url, .. }) => {
                println!(
                    "  \"{id}\" [label=\"Src {url}\", shape=rectangle, fillcolor=lightgreen];"
                );
            }
            NodeData::HostPath(hp) => {
                let label = hp.to_string_lossy();
                println!(
                    "  \"{id}\" [label=\"Hostpath {label}\", shape=rectangle, fillcolor=lightred];"
                );
            }
            NodeData::Local {
                full_path,
                filename,
                file_hash,
            } => {
                let label = full_path.to_string_lossy();
                println!(
                    "  \"{id}\" [label=\"Local {label}\", shape=rectangle, fillcolor=lightyellow];"
                );
            }
            NodeData::Need(name) => {
                println!("  \"{id}\" [label=\"Need {name}\", shape=hexagon, fillcolor=turquoise];");
            }
        }
    }

    for edge_ref in pgraph.edge_references() {
        let source_index = edge_ref.source();
        let target_index = edge_ref.target();
        let edge_data = edge_ref.weight();
        let source_id = source_index.index();
        let target_id = target_index.index();

        match edge_data {
            EdgeData::InputDep(InputDepEdge { outputs, .. }) => {
                if outputs.is_empty() {
                    println!("  \"{source_id}\" -> \"{target_id}\" [label=\"input\"];");
                } else {
                    let subsets = outputs.join(",");
                    println!(
                        "  \"{source_id}\" -> \"{target_id}\" [label=\"input subsets {subsets}\"];"
                    );
                }
            }
            EdgeData::RuntimeDep(RuntimeDepEdge { outputs, .. }) => {
                if outputs.is_empty() {
                    println!("  \"{source_id}\" -> \"{target_id}\" [label=\"runtime dep\"];");
                } else {
                    let subsets = outputs.join(",");
                    println!(
                        "  \"{source_id}\" -> \"{target_id}\" [label=\"runtime dep subsets {subsets}\"];"
                    );
                }
            }
            EdgeData::ReplaceOnCycle => {
                println!("  \"{source_id}\" -> \"{target_id}\" [label=\"bootstrap\"];");
            }
            EdgeData::Needs => {
                println!("  \"{source_id}\" -> \"{target_id}\" [label=\"needs\"];");
            }
            EdgeData::Provides => {
                println!("  \"{source_id}\" -> \"{target_id}\" [label=\"provides\"];");
            }
        }
    }

    println!();
    println!("}}");
    Ok(())
}
