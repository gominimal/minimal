use graph::{BuildSpecInput, RuntimeDep, SourceFetch};
use crate::{Context, Error, PackagesArg};

#[derive(clap::Args)]
pub struct DependenciesArgs {
    #[command(flatten)]
    packages: PackagesArg,
}

/// Prints graphviz DOT for the dependency graph to stdout.
//  Preliminary implementation needs:
//  - better colors
//  - filtering to specific dep types 
//  - filtering of packages to just those listed
//  - source deps rendered in a way that doesn't create huge nodes (see FIXME below)
pub async fn cmd_dependencies(args: DependenciesArgs, ctx: &mut Context) -> Result<(), Error> {
    let graph = args.packages.graph(ctx)?;

    println!("digraph {{");
    println!("  graph [rankdir=LR];");
    println!("  node [shape=circle, style=filled, fillcolor=lightblue];");
    println!("  edge [color=gray];");
    println!();

    // print the DOT graph node declarations
    let iter = graph.iter();
    for (bsr, bs) in iter {
        let id = bsr.index();
        let name = &bs.name;
        println!("  \"{id}\" [label=\"{name}\"];")
    }
    println!();

    // print the DOT graph edge declarations
    let iter = graph.iter();
    for (bsr, bs) in iter {
        // INPUTS EDGES - ignores local ones (e.g. build.sh refs)
        // all of the ref'd build spec's outputs
        let id = bsr.index(); // node whose dependencies are being printed
        bs.inputs.iter().filter_map(|input| match input {
            BuildSpecInput::Build(bsr) => Some(bsr),
            _ => None,
        }).for_each(|ibsr| {
            let dep_id = ibsr.index();
            println!("  \"{id}\" -> \"{dep_id}\" [label=\"input\"];")
        });

        // subsets of the ref'd build spec's outputs
        bs.inputs.iter().filter_map(|input| match input {
            BuildSpecInput::Subset(s) => Some(s),
            _ => None,
        }).for_each(|s| {
            let dep_id = s.from.index();
            let subsets = s.outputs.join(",");
            println!("  \"{id}\" -> \"{dep_id}\" [label=\"input subsets {subsets}\"];")
        });

        // Source code inputs - FIXME - SKIP FOR NOW Nodes are too large
        bs.inputs.iter().filter_map(|input| match input {
            BuildSpecInput::Source(src) => Some(src),
            _ => None,
        }).for_each(|src| {
            let SourceFetch::URL(_dep_id) = &src.from;
        //println!("  \"{id}\" -> \"{dep_id}\" [label=\"source code\"];")
        });
        
        // Host path deps
        bs.inputs.iter().filter_map(|input| match input {
            BuildSpecInput::HostPath(hp) => Some(hp),
            _ => None,
        }).for_each(|hp| {
            let dep_id = hp.to_string_lossy();
            println!("  \"{id}\" -> \"{dep_id}\" [label=\"host path\"];")
        });

        // RUNTIME DEPS EDGES
        // runtime dep on all of the ref'd build spec's outputs
        bs.runtime_deps.iter().filter_map(|input| match input {
            RuntimeDep::Build(bsr) => Some(bsr),
            _ => None,
        }).for_each(|bsr| {
            let dep_id = &bsr.index();
            println!("  \"{id}\" -> \"{dep_id}\" [label=\"runtime dep\"];")
        });
        // runtime dep on subsets of the ref'd build spec's outputs
        bs.runtime_deps.iter().filter_map(|input| match input {
            RuntimeDep::Subset(s) => Some(s),
            _ => None,
        }).for_each(|s| {
            let dep_id = s.from.index();
            let subsets = s.outputs.join(",");
            println!("  \"{id}\" -> \"{dep_id}\" [label=\"runtime dep subsets {subsets}\"];")
        });
    }
    // end the graph declaration
    println!();
    println!("}}");
    Ok(())
}
