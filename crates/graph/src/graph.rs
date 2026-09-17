//! The dependency graph.
//!
//! This file owns the [Graph] data structure and its query / mutation surface.
//! The construction path (decoding [decode::Layer]s, walking upstream chains,
//! ingesting build declarations) lives in `loader.rs`.

#![allow(clippy::result_large_err)]
#![allow(clippy::single_match)]

use common::{SpecOrigin, Target};
use decode::{Container, Stack};
use nickel_lang_core::term::IndexMap;

use generational_arena::Arena;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use crate::BuildSpecRef;
use crate::builds::*;
use crate::spec_hasher::SubsetHasher;
use crate::{ContainerHasher, Error, SpecHash, SpecHasher};

/// Describes a match between a search term and a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    pub name: Option<common::fuzzy_search::SearchMatch>,
    pub outputs: IndexMap<String, common::fuzzy_search::SearchMatch>,
}

impl Ord for SearchMatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use common::fuzzy_search::SearchMatch as FuzzyMatch;

        fn is_strong(m: &FuzzyMatch) -> bool {
            matches!(m, FuzzyMatch::ExactMatch | FuzzyMatch::PrefixMatch { .. })
        }

        // Precedence tiers (higher = better):
        // 3: name is ExactMatch or PrefixMatch
        // 2: best output is ExactMatch or PrefixMatch
        // 1: name matches (ContainsMatch, Fuzzy)
        // 0: output matches (ContainsMatch, Fuzzy)
        fn tier(s: &SearchMatch) -> u8 {
            if s.name.as_ref().is_some_and(is_strong) {
                3
            } else if s.outputs.values().any(is_strong) {
                2
            } else if s.name.is_some() {
                1
            } else {
                0
            }
        }

        tier(self).cmp(&tier(other)).then_with(|| match tier(self) {
            3 | 1 => self.name.cmp(&other.name),
            _ => self
                .outputs
                .values()
                .max()
                .cmp(&other.outputs.values().max()),
        })
    }
}

impl PartialOrd for SearchMatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The in-memory representation of the software supply chain: all packages, profiles, and stacks.
///
/// Fields are crate-visible so `loader.rs` can mutate them during ingest. External
/// callers should go through the accessor methods below.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Graph {
    /// All the build-specs known to this dependency graph.
    pub(crate) builds: Arena<BuildSpec>,
    /// The top level build-specs (i.e. non-transitive) that were read when
    /// constructing this dependency graph.
    pub top_levels: Vec<BuildSpecRef>,

    /// Stacks (a way to build a directory of software) by name.
    ///
    /// Ordered by name so `iter_stacks` is deterministic: `min init` selects a
    /// stack with a stable sort that preserves the iteration order for ties.
    pub(crate) stacks: BTreeMap<String, Stack>,

    /// Container specs by name.
    ///
    /// Ordered by name for the same reason as [`Self::stacks`]: `iter_containers`
    /// feeds the wire writers, so hash order would make the serialised bytes
    /// differ run to run for the same graph.
    pub(crate) containers: BTreeMap<String, Container>,

    /// Indexes build-specs by name.
    pub(crate) by_name: HashMap<String, BuildSpecRef>,

    /// The series of layers which were chained together to build this graph.
    pub(crate) supply_chain: Vec<SpecOrigin>,

    /// The [Target] this graph was built for.
    pub(crate) target: Target,

    /// The cache of build specs to their [SpecHash]. There is also a
    /// reverse cache of [SpecHash]'s to the build spec they correspond to.
    #[allow(clippy::type_complexity)]
    hash_cache: Arc<
        RwLock<(
            HashMap<BuildSpecRef, SpecHash>,
            HashMap<SpecHash, BuildSpecRef>,
        )>,
    >,
}

impl Default for Graph {
    fn default() -> Self {
        Self::new()
    }
}

impl Graph {
    /// Constructs an empty dependency graph targeting the host system.
    pub fn new() -> Self {
        Self {
            builds: Arena::with_capacity(4096),
            by_name: HashMap::with_capacity(2048),
            top_levels: Vec::new(),
            stacks: BTreeMap::new(),
            containers: BTreeMap::new(),
            supply_chain: Vec::with_capacity(6),
            target: Target::host(),
            hash_cache: Arc::new(RwLock::new((
                HashMap::with_capacity(4096),
                HashMap::with_capacity(4096),
            ))),
        }
    }

    /// Returns the [Target] this graph was built for.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Fetches a build-spec by reference.
    pub fn get(&self, bsr: &BuildSpecRef) -> Option<&BuildSpec> {
        self.builds.get(bsr.0)
    }

    /// Returns the build-spec reference with the given name.
    pub fn by_name<S: AsRef<str>>(&self, name: S) -> Option<&BuildSpecRef> {
        self.by_name.get(name.as_ref())
    }

    /// Returns the specification hash of the given build spec.
    pub fn spec_hash(&self, bsr: &BuildSpecRef) -> SpecHash {
        {
            if let Some(hash) = self.hash_cache.read().unwrap().0.get(bsr) {
                return hash.clone();
            }
        }

        let hash = SpecHasher::hash(self, bsr);

        {
            let mut hashes = self.hash_cache.write().unwrap();
            hashes.0.insert(*bsr, hash.clone());
            hashes.1.insert(hash.clone(), *bsr);
        }
        hash
    }

    /// Returns the specification hash of a subset.
    pub fn subset_hash(&self, subset: &SubsetInput) -> SpecHash {
        SubsetHasher::hash_single(self, &subset.from, subset.outputs.to_vec())
    }

    /// Returns an iterator over all build-spec references.
    pub fn all(&self) -> impl Iterator<Item = BuildSpecRef> + use<'_> {
        self.builds.iter().map(|e| BuildSpecRef(e.0))
    }

    /// Returns an iterator over all build-spec references which originated from the
    /// given layer/repository.
    pub fn from_origin(&self, origin: &SpecOrigin) -> impl Iterator<Item = BuildSpecRef> {
        self.builds
            .iter()
            .filter(move |(_bsr, b)| b.from.as_ref() == origin)
            .map(|(bsr, _b)| BuildSpecRef(bsr))
    }

    /// Returns the number of build-specs in the graph.
    pub fn len(&self) -> usize {
        self.builds.len()
    }
    /// Returns true if the graph contains no build-specs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterates over all build specs and their keys.
    pub fn iter(&self) -> impl Iterator<Item = (BuildSpecRef, &BuildSpec)> + use<'_> {
        self.builds
            .iter()
            .map(|(index, spec)| (BuildSpecRef(index), spec))
    }

    /// Returns the unique set of transitive build-spec dependencies of the given toplevel.
    ///
    /// Dependencies of a build-spec are its build dependencies and its runtime dependencies.
    pub fn transitive_specs_of(&self, toplevel: &BuildSpecRef) -> Vec<BuildSpecRef> {
        let mut seen: HashMap<BuildSpecRef, ()> = HashMap::with_capacity(self.builds.len());
        let mut reachable = Vec::with_capacity(self.builds.len());
        self.collect_transitive_buildspecs(toplevel, &mut seen, &mut reachable);

        reachable
    }

    fn collect_transitive_buildspecs(
        &self,
        bsr: &BuildSpecRef,
        seen: &mut HashMap<BuildSpecRef, ()>,
        reachable: &mut Vec<BuildSpecRef>,
    ) {
        let build_spec = self.get(bsr).unwrap();

        use BuildDep::*;
        build_spec
            .build_deps
            .iter()
            .filter_map(|input| match input {
                Build(bsr) => Some(bsr),
                Subset(si) => Some(&si.from),
                Source(_) | Local { .. } => None,
            })
            .chain(build_spec.runtime_deps.iter().map(|dep| match dep {
                RuntimeDep::Build(bsr) => bsr,
                RuntimeDep::Subset(si) => &si.from,
            }))
            .for_each(|bsr| {
                if !seen.contains_key(bsr) {
                    seen.insert(*bsr, ());
                    reachable.push(*bsr);
                    self.collect_transitive_buildspecs(bsr, seen, reachable);
                }
            })
    }

    /// Hydrates a minimal task with configuration based on the stack and
    /// any profile it calls for, if any.
    pub fn hydrate_task(&self, stack: Option<&str>, task: &mut mfile::Task) -> Result<(), Error> {
        if let Some(name) = stack {
            let stack = self.stack(name).ok_or_else(|| Error::NoSuchStack {
                name: name.to_string(),
            })?;
            // Upsert the packages list
            task.packages.extend(
                stack
                    .build_packages
                    .iter()
                    .chain(stack.runtime_packages.iter())
                    .filter(|p| !task.packages.contains(p))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            // Set environment variables, but only if they are not set already
            for (k, v) in &stack.build_env_vars {
                if !task.vars.contains_key(k) {
                    task.vars.insert(k.clone(), v.clone());
                }
            }
        }

        match &task.profile {
            Some(profile) if !profile.is_empty() => {
                tracing::warn!(
                    "Ignoring declared profile `{profile}`, profile support was removed"
                );
            }
            _ => (),
        };
        Ok(())
    }

    /// Returns the named stack, if it exists.
    pub fn stack(&self, name: &str) -> Option<&Stack> {
        self.stacks.get(name)
    }

    /// Returns an iterator over all stacks configured in the graph.
    pub fn iter_stacks(&self) -> impl Iterator<Item = (&String, &Stack)> {
        self.stacks.iter()
    }

    /// Returns an iterator over all containers configured in the graph.
    pub fn iter_containers(&self) -> impl Iterator<Item = (&String, &Container)> {
        self.containers.iter()
    }

    /// Returns the container declared under `name`, if any.
    pub fn container<S: AsRef<str>>(&self, name: S) -> Option<&Container> {
        self.containers.get(name.as_ref())
    }

    /// Returns the specification hash of the given container.
    pub fn container_hash(&self, container: &Container) -> Result<SpecHash, Error> {
        ContainerHasher::hash(self, container)
    }

    /// Returns a list of [BuildSpecRef] objects who's names matched the given search term.
    pub fn fuzzy_name_search(
        &self,
        term: &str,
        num_results: usize,
    ) -> Vec<(BuildSpecRef, SearchMatch)> {
        use common::fuzzy_search::{SearchMatch as FuzzyMatch, fuzzy_match};

        #[derive(Debug, Clone, PartialEq, Eq)]
        struct SearchEntry {
            score: SearchMatch,
            bsr: BuildSpecRef,
        }

        impl Ord for SearchEntry {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.score
                    .cmp(&other.score)
                    .then_with(|| self.bsr.cmp(&other.bsr))
            }
        }
        impl PartialOrd for SearchEntry {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        use std::collections::BinaryHeap;
        let mut results = BinaryHeap::with_capacity(num_results);

        for (bsr, build) in self.builds.iter() {
            let min_output_match = FuzzyMatch::Fuzzy { score: 50 };

            let name_match = fuzzy_match(term, &build.name);
            let output_matches: IndexMap<String, FuzzyMatch> = build
                .outputs
                .iter()
                .filter_map(|(name, o)| {
                    match (name.as_str(), o) {
                        // Filter low-signal outputs.
                        ("bins", BuildOutput::Binary { .. }) => None,
                        ("libs", BuildOutput::Library { .. }) => None,
                        (_, BuildOutput::Data { .. }) => None,
                        // Match binaries by name or usr/bin/{s}
                        (_, BuildOutput::Binary { glob, .. }) => {
                            if let Some(m) = fuzzy_match(term, name.as_str())
                                && m > min_output_match
                            {
                                return Some((name.to_string(), m));
                            }
                            if let Some(bin_name) = glob.strip_prefix("usr/bin/")
                                && let Some(m) = fuzzy_match(term, bin_name)
                                && m > min_output_match
                            {
                                return Some((name.to_string(), m));
                            }

                            None
                        }
                        _ => None,
                    }
                })
                .collect();

            if name_match.is_none() && output_matches.is_empty() {
                continue;
            };
            results.push(std::cmp::Reverse(SearchEntry {
                score: SearchMatch {
                    name: name_match,
                    outputs: output_matches,
                },
                bsr: BuildSpecRef(bsr),
            }));
            if results.len() > num_results {
                results.pop();
            }
        }

        // Little-known fact: into_iter() of a vec followed by a collect into a vec
        // where the memory needed is less, doesnt allocate.
        results
            .into_sorted_vec()
            .into_iter()
            .map(|std::cmp::Reverse(SearchEntry { score, bsr })| (bsr, score))
            .collect()
    }

    /// Returns the links in the software supply chain used to build this graph.
    pub fn software_supply_chain(&self) -> &Vec<SpecOrigin> {
        &self.supply_chain
    }

    /// Builds an arbitrary graph and asserts it survives a wire round-trip:
    /// `from_bytes(to_bytes(g))` must preserve every spec (name + spec-hash)
    /// and the top-level count. The in-crate entry point for the
    /// `graph_roundtrip` fuzz target — graphs aren't hand-constructible from
    /// outside the crate, so the builder lives here.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_roundtrip(data: &[u8]) {
        use arbitrary::Unstructured;
        let mut u = Unstructured::new(data);
        let Ok(n) = u.int_in_range::<usize>(0..=64) else {
            return;
        };
        let mut graph = Graph::new();
        let mut refs = Vec::with_capacity(n);
        for i in 0..n {
            // Unique names keep `by_name` unambiguous for the differential.
            let bsr = graph.insert_build(BuildSpec {
                name: format!("s{i}"),
                ..Default::default()
            });
            refs.push(bsr);
        }
        // An arbitrary subset become top-levels (exercises ref remapping).
        let mut tops = Vec::new();
        for &r in &refs {
            if u.arbitrary().unwrap_or(false) {
                tops.push(r);
            }
        }
        graph.top_levels = tops;

        let Ok(bytes) = graph.to_bytes() else {
            return;
        };
        let restored = Graph::from_bytes(&bytes).expect("a valid graph failed to decode");
        assert_eq!(
            graph.len(),
            restored.len(),
            "spec count changed across round-trip"
        );
        assert_eq!(
            graph.top_levels.len(),
            restored.top_levels.len(),
            "top-level count changed across round-trip"
        );
        for (bsr, spec) in graph.iter() {
            let r = restored
                .by_name(&spec.name)
                .expect("spec missing after round-trip");
            assert_eq!(
                graph.spec_hash(&bsr),
                restored.spec_hash(r),
                "spec_hash mismatch for {} across round-trip",
                spec.name
            );
        }
    }

    /// Inserts a build spec into the arena and registers it by name.
    /// Returns the [`BuildSpecRef`] for the inserted spec.
    ///
    /// Test/fuzzing-only: production graphs are built by the decoder via
    /// [`Graph::from_parts`].
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn insert_build(&mut self, spec: BuildSpec) -> BuildSpecRef {
        let name = spec.name.clone();
        let idx = self.builds.insert(spec);
        let bsr = BuildSpecRef(idx);
        self.by_name.insert(name, bsr);
        bsr
    }

    /// Assembles a graph from pre-built components (used by the wire reader).
    pub(crate) fn from_parts(
        builds: Arena<BuildSpec>,
        top_levels: Vec<BuildSpecRef>,
        stacks: BTreeMap<String, Stack>,
        containers: BTreeMap<String, Container>,
        by_name: HashMap<String, BuildSpecRef>,
        supply_chain: Vec<SpecOrigin>,
        target: Target,
    ) -> Self {
        Self {
            builds,
            top_levels,
            stacks,
            containers,
            by_name,
            supply_chain,
            target,
            hash_cache: Default::default(),
        }
    }

    /// Serialises the graph to a byte vector using the streaming wire format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::wire::WireError> {
        let mut buf = Vec::new();
        crate::wire::GraphWriter::new(&mut buf).write_graph(self)?;
        Ok(buf)
    }

    /// Deserialises a graph from a byte slice using the streaming wire format.
    ///
    /// If the stream contains inlined local files, a temporary directory is
    /// created but dropped when this function returns.  Use
    /// [`wire::GraphReader`] directly when you need to keep materialised files.
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::wire::WireError> {
        let (graph, _temp_dir) =
            crate::wire::GraphReader::new(std::io::Cursor::new(data)).read_graph()?;
        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decode::Layer;
    use indoc::indoc;

    #[test]
    fn transitive_specs_of() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, Source, ..} = import \"minimal.ncl\" in

                let shared = {
                    name = \"shared\",
                    build_deps = [
                        {url = \"http://uwu.com\", sha256 = \"abcdef\"} | Source,
                    ],
                    cmd = \"\",
                } | BuildSpec
                in

                {
                    name = \"top build\",
                    build_deps = [
                        shared,
                        {
                            name = \"second build\",
                            build_deps = [],
                            cmd = \"\",
                        } | BuildSpec,
                    ],
                    cmd = \"\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = Graph::new().ingest(layer).unwrap();
        assert_eq!(
            dp.transitive_specs_of(&dp.top_levels[0]),
            vec![
                BuildSpecRef(dp.builds.iter().find(|b| b.1.name == "shared").unwrap().0),
                BuildSpecRef(
                    dp.builds
                        .iter()
                        .find(|b| b.1.name == "second build")
                        .unwrap()
                        .0
                )
            ]
        );
    }

    #[test]
    fn fuzzy_name_search() {
        use common::fuzzy_search::SearchMatch as FuzzyMatch;

        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in

                let
                    b1 = {
                        name = \"libffi\",
                        build_deps = [],
                        cmd = \"\",
                    } | BuildSpec,
                    b2 = {
                        name = \"libxml2\",
                        build_deps = [],
                        cmd = \"\",
                    } | BuildSpec,
                    b3 = {
                        name = \"zlib\",
                        build_deps = [],
                        cmd = \"\",
                    } | BuildSpec,
                in
                [b1, b2, b3]
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let dp = Graph::new().ingest(layer).unwrap();

        // Exact match should rank highest
        let results = dp.fuzzy_name_search("libffi", 3);
        assert_eq!(results.len(), 3);
        assert_eq!(dp.get(&results[0].0).unwrap().name, "libffi");
        assert_eq!(results[0].1.name, Some(FuzzyMatch::ExactMatch));

        // Partial match: "lib" should prefer libffi/libxml2 over zlib
        let results = dp.fuzzy_name_search("lib", 2);
        let names: Vec<&str> = results
            .iter()
            .map(|r| dp.get(&r.0).unwrap().name.as_str())
            .collect();
        assert!(names.contains(&"libffi") || names.contains(&"libxml2"));
        // "lib" is a prefix of libffi/libxml2
        assert!(matches!(
            results[0].1.name,
            Some(FuzzyMatch::PrefixMatch { .. })
        ));

        // Limiting num_results works
        let results = dp.fuzzy_name_search("lib", 1);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn serde_roundtrip() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, Source, OutputBin, ..} = import \"minimal.ncl\" in

                let shared = {
                    name = \"shared\",
                    build_deps = [
                        {url = \"http://example.com/src.tar.gz\", sha256 = \"abc123\"} | Source,
                    ],
                    cmd = \"make install\",
                    outputs.thing = { glob = \"usr/bin/*\" } | OutputBin,
                } | BuildSpec
                in

                {
                    name = \"top\",
                    build_deps = [shared],
                    runtime_deps = [shared],
                    cmd = \"gcc -o main main.c\",
                } | BuildSpec"
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });

        let graph = Graph::new().ingest(layer).unwrap();

        // Serialize and deserialize
        let bytes = graph.to_bytes().expect("serialization failed");
        let restored = Graph::from_bytes(&bytes).expect("deserialization failed");

        // Verify by_name lookups work
        assert!(restored.by_name("shared").is_some());
        assert!(restored.by_name("top").is_some());

        // Verify spec_hash returns identical values
        for (bsr, build) in graph.iter() {
            let restored_bsr = restored.by_name(&build.name).unwrap();
            assert_eq!(
                graph.spec_hash(&bsr),
                restored.spec_hash(restored_bsr),
                "spec_hash mismatch for {}",
                build.name
            );
        }

        // Verify top_levels match
        assert_eq!(graph.top_levels.len(), restored.top_levels.len());
        for (orig, rest) in graph.top_levels.iter().zip(restored.top_levels.iter()) {
            assert_eq!(orig, rest);
        }

        // Verify cross-references resolve correctly
        let top = restored.get(restored.by_name("top").unwrap()).unwrap();
        assert_eq!(top.build_deps.len(), 1);
        let shared_bsr = restored.by_name("shared").unwrap();
        assert_eq!(top.build_deps[0].as_build().unwrap(), shared_bsr);
        assert_eq!(top.runtime_deps[0].bsr(), shared_bsr);

        // Verify supply chain preserved
        assert_eq!(
            graph.software_supply_chain().len(),
            restored.software_supply_chain().len()
        );
    }
}
