use graph::dep_graph::{BuildSpec, BuildSpecInput, DepGraph};
use petgraph::Graph;
use petgraph::graph::NodeIndex;
use std::collections::HashMap;
use tracing::info;

/// Represents the execution order and dependencies between BuildSpecs
pub struct ExecutionGraph {
    /// The underlying directed graph, storing build names as node weights
    graph: Graph<String, ()>,
    /// Mapping from build name to NodeIndex in the graph
    #[allow(dead_code)]
    node_map: HashMap<String, NodeIndex>,
    /// All build specs indexed by name for easy lookup
    builds_by_name: HashMap<String, BuildSpec>,
}

impl ExecutionGraph {
    /// Create a new execution graph from a dependency graph
    pub fn from_dep_graph(dep_graph: DepGraph) -> Self {
        let mut graph = Graph::new();
        let mut node_map = HashMap::new();
        let mut builds_by_name = HashMap::new();

        for (_idx, build_spec) in dep_graph.builds.iter() {
            builds_by_name.insert(build_spec.name.clone(), build_spec.clone());
        }

        for build_spec in builds_by_name.values() {
            let node_idx = graph.add_node(build_spec.name.clone());
            node_map.insert(build_spec.name.clone(), node_idx);
        }

        for (_idx, build_spec) in dep_graph.builds.iter() {
            let from_node = node_map[&build_spec.name];

            for input in &build_spec.inputs {
                if let BuildSpecInput::Build(dep_ref) = input
                    && let Some(dep_spec) = dep_ref.resolve(&dep_graph)
                    && let Some(&to_node) = node_map.get(&dep_spec.name)
                {
                    graph.add_edge(to_node, from_node, ());
                }
            }
        }

        info!(
            "Created execution graph with {} nodes and {} edges",
            graph.node_count(),
            graph.edge_count()
        );

        ExecutionGraph {
            graph,
            node_map,
            builds_by_name,
        }
    }

    /// Get the topological ordering of builds (dependencies first)
    pub fn execution_order(&self) -> Result<Vec<String>, String> {
        match petgraph::algo::toposort(&self.graph, None) {
            Ok(order) => {
                let build_names: Vec<String> = order
                    .into_iter()
                    .map(|node_idx| self.graph[node_idx].clone())
                    .collect();

                info!(
                    "Execution order determined for {} builds",
                    build_names.len()
                );

                Ok(build_names)
            }
            Err(cycle) => {
                let cycle_node = cycle.node_id();
                let build_name = &self.graph[cycle_node];
                Err(format!(
                    "Circular dependency detected involving build: {}",
                    build_name
                ))
            }
        }
    }

    /// Get a BuildSpec by name
    pub fn get_build_spec(&self, build_name: &str) -> Option<&BuildSpec> {
        self.builds_by_name.get(build_name)
    }
}
