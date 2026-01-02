use crate::{Context, Error, PackagesArg};
use clap::ArgAction;
use graph::{BuildSpecInput, RuntimeDep, SourceFetch, Transitives};
use std::collections::HashSet;

#[derive(clap::Args)]
pub struct DependenciesArgs {
    #[command(flatten)]
    packages: PackagesArg,

    /// Controls whether source code "inputs" are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action = ArgAction::Set,
    )]
    source_deps: bool,

    /// Controls whether non-subsetted "inputs" are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("true"),action=ArgAction::Set,
    )]
    full_input_deps: bool,

    /// Controls whether subsetted "inputs" are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("true"),action=ArgAction::Set,
    )]
    subset_input_deps: bool,

    /// Controls whether non-subsetted "runtime_deps" are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("true"),action=ArgAction::Set,
    )]
    full_runtime_deps: bool,

    /// Controls whether subsetted "runtime_deps" are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("true"),action=ArgAction::Set,
    )]
    subset_runtime_deps: bool,

    /// Controls whether host path "runtime_deps" are in the graph
    #[arg(
        long,num_args(0..=1),default_missing_value("true"),default_value("false"),action=ArgAction::Set,
    )]
    hostpath_runtime_deps: bool,
}

/// Prints graphviz DOT for the dependency graph to stdout.
//  Preliminary implementation needs:
//  - better colors
//  - filtering of packages to just those listed
//  - source deps rendered in a way that doesn't create huge nodes
pub async fn cmd_dependencies(args: DependenciesArgs, ctx: &mut Context) -> Result<(), Error> {
    crate::enforce_science_mode()?;

    let graph = args.packages.graph(ctx)?;
    let specified_pkgs_and_deps: HashSet<_> =
        Transitives::for_toplevels(&graph, graph.top_levels.to_vec(), false)
            .into_keys()
            .collect();

    println!("digraph {{");
    println!("  graph [rankdir=LR];");
    println!("  node [shape=circle, style=filled, fillcolor=lightblue];");
    println!("  edge [color=gray];");
    println!();

    // print the DOT graph node declarations
    let iter = graph.iter();
    for (bsr, bs) in iter {
        // if packages were explicitly specified, only create nodes for those and their deps
        if !specified_pkgs_and_deps.is_empty() && !specified_pkgs_and_deps.contains(&bsr) {
            continue;
        }
        let id = bsr.index();
        let name = &bs.name;
        println!("  \"{id}\" [label=\"{name}\"];")
    }
    println!();

    // print the DOT graph edge declarations
    let iter = graph.iter();
    for (bsr, bs) in iter {
        // if packages were explicitly specified, skip those not specified
        if !specified_pkgs_and_deps.is_empty() && !specified_pkgs_and_deps.contains(&bsr) {
            continue;
        }
        // INPUTS EDGES - ignores local ones (e.g. build.sh refs)

        // show inputs that are all of the ref'd build spec's outputs
        let id = bsr.index(); // node whose dependencies are being printed
        if args.full_input_deps {
            bs.inputs
                .iter()
                .filter_map(|input| match input {
                    BuildSpecInput::Build(bsr) => Some(bsr),
                    _ => None,
                })
                .for_each(|ibsr| {
                    let dep_id = ibsr.index();
                    println!("  \"{id}\" -> \"{dep_id}\" [label=\"input\"];")
                });
        }
        // show inputs that are subsets of the ref'd build spec's outputs
        if args.subset_input_deps {
            bs.inputs
                .iter()
                .filter_map(|input| match input {
                    BuildSpecInput::Subset(s) => Some(s),
                    _ => None,
                })
                .for_each(|s| {
                    let dep_id = s.from.index();
                    let subsets = s.outputs.join(",");
                    println!("  \"{id}\" -> \"{dep_id}\" [label=\"input subsets {subsets}\"];")
                });
        }
        // show inputs that are source code
        if args.source_deps {
            bs.inputs
                .iter()
                .filter_map(|input| match input {
                    BuildSpecInput::Source(src) => Some(src),
                    _ => None,
                })
                .for_each(|src| {
                    let SourceFetch::URL(dep_id) = &src.from;
                    println!("  \"{dep_id}\" [label=\"{dep_id}\", shape=rectangle, fillcolor=lightgreen];");
                    println!("  \"{id}\" -> \"{dep_id}\" [label=\"source code\"];")
                });
        }

        // RUNTIME DEPS EDGES
        // show runtime_deps that are Host path deps
        if args.hostpath_runtime_deps {
            bs.inputs
                .iter()
                .filter_map(|input| match input {
                    BuildSpecInput::HostPath(hp) => Some(hp),
                    _ => None,
                })
                .for_each(|hp| {
                    let dep_id = hp.to_string_lossy();
                    println!("  \"{id}\" -> \"{dep_id}\" [label=\"host path\"];")
                });
        }
        // show runtime_deps on all of the ref'd build spec's outputs
        if args.full_runtime_deps {
            bs.runtime_deps
                .iter()
                .filter_map(|input| match input {
                    RuntimeDep::Build(bsr) => Some(bsr),
                    _ => None,
                })
                .for_each(|bsr| {
                    let dep_id = &bsr.index();
                    println!("  \"{id}\" -> \"{dep_id}\" [label=\"runtime dep\"];")
                });
        }
        // show runtime_deps on subsets of the ref'd build spec's outputs
        if args.subset_runtime_deps {
            bs.runtime_deps
                .iter()
                .filter_map(|input| match input {
                    RuntimeDep::Subset(s) => Some(s),
                    _ => None,
                })
                .for_each(|s| {
                    let dep_id = s.from.index();
                    let subsets = s.outputs.join(",");
                    println!(
                        "  \"{id}\" -> \"{dep_id}\" [label=\"runtime dep subsets {subsets}\"];"
                    )
                });
        }
    }
    // end the graph declaration
    println!();
    println!("}}");
    Ok(())
}
