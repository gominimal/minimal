//! The dependency graph.
//!
//! This file owns the [Graph] data structure and its query / mutation surface.
//! The construction path (decoding [decode::Layer]s, walking upstream chains,
//! ingesting build declarations) lives in `loader.rs`.

#![allow(clippy::result_large_err)]
#![allow(clippy::single_match)]

use common::{SpecOrigin, Target};
use decode::{Profile, Stack};
use nickel_lang_core::term::IndexMap;

use generational_arena::Arena;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::BuildSpecRef;
use crate::builds::*;
use crate::spec_hasher::SubsetHasher;
use crate::{Error, SpecHash, SpecHasher};

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

    /// Profiles (custom packages, env vars etc) by name.
    pub(crate) profiles: HashMap<String, Profile>,
    /// Stacks (a way to build a directory of software) by name.
    pub(crate) stacks: HashMap<String, Stack>,

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
            profiles: HashMap::with_capacity(32),
            stacks: HashMap::with_capacity(32),
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

    /// The CYCLE-BROKEN transitive dependency set of `toplevel`, for recording
    /// as in-toto `resolvedDependencies` under CHAIN_ENFORCE.
    ///
    /// [`transitive_specs_of`](Self::transitive_specs_of) returns the RAW
    /// build+runtime closure and IGNORES `replace_on_cycle` (honored only by the
    /// planner). On a bootstrap graph whose rungs import a from-source userland
    /// that loops back through the cycle-broken toolchain, that raw set is
    /// mutually-referential (spec A lists B and B lists A, plus a self-reference)
    /// — which the signer's chain walk rejects as an attestation cycle.
    ///
    /// This returns the closure with every *cyclic peer* of `toplevel` — a
    /// dependency `D` from which `toplevel` is itself reachable (so `D` and
    /// `toplevel` sit on a common dependency cycle) — replaced by `D`'s declared
    /// `replace_on_cycle` breaker (a pure prebuilt bootstrap leaf the signer
    /// terminates on). `toplevel` itself is never included (a build is not its
    /// own dependency; this also drops the self-reference the raw walk emits when
    /// `toplevel` sits on a cycle).
    ///
    /// GLOBAL acyclicity: a recorded, non-substituted edge `toplevel -> D` exists
    /// only when `D` does NOT reach `toplevel`, whereas a dependency edge always
    /// means `toplevel` reaches `D`. A cycle in the union of all such per-rung
    /// records would require a node both to reach and to not-reach another — a
    /// contradiction. So when every rung records this way, the union of all
    /// envelopes is a DAG rooted above the prebuilt breaker leaves.
    ///
    /// Deterministic: a pure function of graph topology + `replace_on_cycle`,
    /// independent of any cache. Output sorted by spec hash.
    ///
    /// `Err` lists every cyclic peer that declares NO breaker: its cyclic edge
    /// cannot be represented acyclically, so the caller must fail shut rather
    /// than emit a known cycle.
    pub fn cycle_broken_deps_of(
        &self,
        toplevel: &BuildSpecRef,
    ) -> Result<Vec<BuildSpecRef>, Vec<BuildSpecRef>> {
        let mut out: Vec<BuildSpecRef> = Vec::new();
        let mut unbreakable: Vec<BuildSpecRef> = Vec::new();
        for dep in self.transitive_specs_of(toplevel) {
            if dep == *toplevel {
                continue; // self-reference: a build is never its own dependency
            }
            // `dep` is a cyclic peer of `toplevel` iff `toplevel` is reachable
            // from it (they sit on a common dependency cycle).
            let reaches_toplevel = self
                .transitive_specs_of(&dep)
                .iter()
                .any(|reached| reached == toplevel);
            if !reaches_toplevel {
                out.push(dep); // genuinely acyclic dep — record as-is
            } else if let Some(breaker) = self.get(&dep).and_then(|s| s.replace_on_cycle) {
                out.push(breaker); // record the prebuilt breaker leaf instead
            } else {
                unbreakable.push(dep); // cyclic peer with no breaker — fail shut
            }
        }
        // Deterministic content-based order (SpecHash is not Ord; its blake3
        // hash bytes are). sort_by_cached_key hashes each spec once, not per
        // comparison.
        if !unbreakable.is_empty() {
            unbreakable.sort_by_cached_key(|b| *self.spec_hash(b).0.as_bytes());
            unbreakable.dedup();
            return Err(unbreakable);
        }
        out.sort_by_cached_key(|b| *self.spec_hash(b).0.as_bytes());
        out.dedup();
        Ok(out)
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
                Source(_) | HostPath(_) | Local { .. } => None,
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
            None => Ok(()),
            Some(s) if s.is_empty() => Ok(()),
            Some(profile) => {
                if let Some(profile) = self.profiles.get(profile) {
                    // Upsert the packages list
                    task.packages.extend(
                        profile
                            .packages
                            .iter()
                            .filter(|p| !task.packages.contains(p))
                            .cloned()
                            .collect::<Vec<_>>(),
                    );
                    // Set environment variables, but only if they are not set already
                    for (k, v) in &profile.env_vars {
                        if !task.vars.contains_key(k) {
                            task.vars.insert(k.clone(), v.clone());
                        }
                    }
                    // Union any file patches, if they are not set already
                    let mut patches = profile.patch.clone();
                    patches.union(&task.patch);
                    task.patch = patches;
                    Ok(())
                } else {
                    Err(Error::NoSuchProfile {
                        name: profile.clone(),
                    })
                }
            }
        }
    }

    /// Returns the named stack, if it exists.
    pub fn stack(&self, name: &str) -> Option<&Stack> {
        self.stacks.get(name)
    }

    /// Returns an iterator over all stacks configured in the graph.
    pub fn iter_stacks(&self) -> impl Iterator<Item = (&String, &Stack)> {
        self.stacks.iter()
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

    /// Returns an iterator over all profiles configured in the graph.
    pub fn iter_profiles(&self) -> impl Iterator<Item = (&String, &Profile)> {
        self.profiles.iter()
    }

    /// Returns the links in the software supply chain used to build this graph.
    pub fn software_supply_chain(&self) -> &Vec<SpecOrigin> {
        &self.supply_chain
    }

    /// Inserts a build spec into the arena and registers it by name.
    /// Returns the [`BuildSpecRef`] for the inserted spec.
    #[cfg(test)]
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
        profiles: HashMap<String, Profile>,
        stacks: HashMap<String, Stack>,
        by_name: HashMap<String, BuildSpecRef>,
        supply_chain: Vec<SpecOrigin>,
        target: Target,
    ) -> Self {
        Self {
            builds,
            top_levels,
            profiles,
            stacks,
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

    /// #14 D1: a package on a build cycle must record its cyclic peer's
    /// `replace_on_cycle` breaker (a prebuilt leaf), NOT the from-source peer
    /// (which re-creates the cycle the signer rejects) and NOT itself.
    #[test]
    fn cycle_broken_deps_substitutes_breaker_and_drops_self() {
        // a <-> b cycle, b carries a breaker; c <-> d cycle with NO breaker.
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let rec
                    a = { name = \"a\", build_deps = [ b ], cmd = \"\" } | BuildSpec,
                    b = {
                        name = \"b\",
                        build_deps = [ a ],
                        replace_on_cycle = { name = \"b-prebuilt\", build_deps = [], cmd = \"\" } | BuildSpec,
                        cmd = \"\",
                    } | BuildSpec,
                    c = { name = \"c\", build_deps = [ d ], cmd = \"\" } | BuildSpec,
                    d = { name = \"d\", build_deps = [ c ], cmd = \"\" } | BuildSpec,
                in
                [a, b, c, d]
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let g = Graph::new().ingest(layer).unwrap();
        let names = |refs: &[BuildSpecRef]| -> Vec<String> {
            refs.iter().map(|r| g.get(r).unwrap().name.clone()).collect()
        };

        // a's RAW closure is mutually-referential: contains peer b AND self-ref a.
        let a = *g.by_name("a").unwrap();
        let raw = names(&g.transitive_specs_of(&a));
        assert!(
            raw.contains(&"b".to_string()) && raw.contains(&"a".to_string()),
            "raw closure should be cyclic (peer + self-ref): {raw:?}"
        );

        // cycle_broken: b substituted by its breaker; no from-source b, no self a.
        let broken = names(
            &g.cycle_broken_deps_of(&a)
                .expect("a's cycle is breakable via b's replace_on_cycle"),
        );
        assert!(
            !broken.contains(&"b".to_string()),
            "the from-source cyclic peer must be substituted, not recorded (the trap): {broken:?}"
        );
        assert!(!broken.contains(&"a".to_string()), "no self-reference: {broken:?}");
        assert!(
            broken.contains(&"b-prebuilt".to_string()),
            "the prebuilt breaker must be recorded: {broken:?}"
        );

        // c <-> d has no breaker => fail shut (Err), never a silent cycle.
        let c = *g.by_name("c").unwrap();
        let err = names(
            &g.cycle_broken_deps_of(&c)
                .expect_err("c's cycle has no breaker => must fail shut"),
        );
        assert!(err.contains(&"d".to_string()), "unbreakable peer must be reported: {err:?}");
    }

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
