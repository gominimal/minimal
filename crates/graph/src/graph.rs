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

/// A failure of [`Graph::cycle_broken_deps_of`]. Every variant is fail-shut:
/// emitting a record despite it would either contain a known dependency
/// cycle or violate an invariant the signer's attestation-chain walk relies
/// on. The machine-checked counterexamples motivating the three breaker
/// variants live in `formal/Formal/CycleBroken.lean`
/// (`finding_toplevel_recorded_via_breaker`,
/// `finding_breaker_nonterminal_cycle`,
/// `finding_enforced_checks_insufficient`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleBreakError {
    /// Cyclic peers of the toplevel that declare NO `replace_on_cycle`
    /// breaker: their cyclic edge cannot be represented acyclically.
    /// Sorted by spec hash and deduped.
    Unbreakable(Vec<BuildSpecRef>),
    /// A cyclic peer (`peer`) declares a breaker that IS the toplevel
    /// itself. Substituting it would record the toplevel inside its own
    /// provenance — the SELF-REF trust bug reintroduced through the breaker
    /// channel (the `gBreakerAliasesTop` witness).
    BreakerAliasesToplevel { peer: BuildSpecRef },
    /// A cyclic peer (`peer`) declares a breaker that itself sits on a
    /// dependency cycle (it appears in its own transitive closure) —
    /// breaker-terminality (axiom A2 of the global-DAG theorem) violated.
    /// With such a breaker the union of per-rung records genuinely cycles
    /// (the `gSelfBreaker` witness).
    BreakerOnCycle {
        peer: BuildSpecRef,
        breaker: BuildSpecRef,
    },
    /// A cyclic peer (`peer`) declares a breaker that is off-cycle ITSELF
    /// but whose transitive closure reaches a node (`via`) that sits on a
    /// dependency cycle — the F8 residual (`BreakersCycleFree`), the
    /// `gBreakerWithDeps` witness: with such a breaker the toplevel's
    /// record substitutes the breaker (F7+F8 both pass) while the
    /// breaker's own record keeps a path back into the toplevel's cycle,
    /// so the UNION of per-rung records still contains a genuine cycle
    /// even though every individual record looks acyclic.
    BreakerReachesCycle {
        peer: BuildSpecRef,
        breaker: BuildSpecRef,
        /// The first on-cycle node found in the breaker's transitive
        /// closure — the concrete acyclicity-violation witness.
        via: BuildSpecRef,
    },
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

    /// Returns whether the given build-spec sits on a dependency cycle
    /// through itself, i.e. it appears in its own transitive closure.
    /// (`collect_transitive_buildspecs` never pre-seeds `seen` with the
    /// root, so the root is reachable only via a genuine cycle.)
    fn on_own_cycle(&self, bsr: &BuildSpecRef) -> bool {
        self.transitive_specs_of(bsr).contains(bsr)
    }

    /// The `BreakersCycleFree` scan (F8, closure-strengthened): returns the
    /// first on-cycle node in `{breaker} ∪ closure(breaker)` —
    /// `Some(breaker)` when the breaker itself sits on a cycle (the
    /// original F8 check), `Some(via)` for an on-cycle node merely
    /// REACHABLE from it, `None` when the breaker's entire closure is
    /// cycle-free. The closure-level scan is the condition the global-DAG
    /// theorem actually needs: `gBreakerWithDeps` in
    /// `formal/Formal/CycleBroken.lean` is the machine-checked witness that
    /// the breaker-only check is insufficient (F7+F8 alone still let the
    /// union of per-rung records form a 2-cycle through a breaker WITH
    /// deps). O(closure²) worst case per breaker (one `on_own_cycle` walk
    /// per closure node), computed once per distinct breaker — breakers
    /// are few, declared only on bootstrap rungs.
    fn breaker_cycle_witness(&self, breaker: &BuildSpecRef) -> Option<BuildSpecRef> {
        if self.on_own_cycle(breaker) {
            return Some(*breaker);
        }
        self.transitive_specs_of(breaker)
            .into_iter()
            .find(|reached| self.on_own_cycle(reached))
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
    /// Three invariants the global-DAG argument depends on are ENFORCED
    /// here (fail shut, distinct [`CycleBreakError`] variants — all were
    /// previously assumed-by-convention only; see
    /// `formal/Formal/CycleBroken.lean` for the machine-checked
    /// counterexamples showing each is necessary):
    ///
    /// * A breaker must not ALIAS the toplevel itself
    ///   ([`CycleBreakError::BreakerAliasesToplevel`]): pushing it would put
    ///   the toplevel inside its own record — the self-reference trust bug
    ///   reintroduced through the breaker channel (`gBreakerAliasesTop`).
    /// * A breaker must not itself sit on a dependency cycle
    ///   ([`CycleBreakError::BreakerOnCycle`]): with such a breaker the
    ///   union of per-rung records contains a genuine cycle
    ///   (`gSelfBreaker`).
    /// * NOTHING REACHABLE from a breaker may sit on a dependency cycle
    ///   ([`CycleBreakError::BreakerReachesCycle`]) — `BreakersCycleFree`,
    ///   the closure-strengthened form of axiom A2 of the acyclicity
    ///   theorem. The first two checks alone are NOT enough: a breaker
    ///   that is off-cycle but reaches back into a cycle lets every
    ///   individual record emit Ok while their union still cycles
    ///   (`gBreakerWithDeps` / `finding_enforced_checks_insufficient`).
    ///   With all three enforced, the global-DAG theorem
    ///   (`provenance_acyclic_enforced`) is hypothesis-free.
    ///
    /// `Err(Unbreakable)` lists every cyclic peer that declares NO breaker:
    /// its cyclic edge cannot be represented acyclically, so the caller must
    /// fail shut rather than emit a known cycle.
    pub fn cycle_broken_deps_of(
        &self,
        toplevel: &BuildSpecRef,
    ) -> Result<Vec<BuildSpecRef>, CycleBreakError> {
        let mut out: Vec<BuildSpecRef> = Vec::new();
        let mut unbreakable: Vec<BuildSpecRef> = Vec::new();
        // A2 memo: the same breaker is typically declared by many cyclic
        // peers; scan its closure once.
        let mut breaker_witness: HashMap<BuildSpecRef, Option<BuildSpecRef>> = HashMap::new();
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
                if breaker == *toplevel {
                    // F7: the breaker IS the toplevel — recording it would
                    // emit `toplevel ∈ record(toplevel)` (SELF-REF).
                    return Err(CycleBreakError::BreakerAliasesToplevel { peer: dep });
                }
                let witness = *breaker_witness
                    .entry(breaker)
                    .or_insert_with(|| self.breaker_cycle_witness(&breaker));
                match witness {
                    // F8 / axiom A2: a breaker on a cycle is not a terminal
                    // leaf; substituting it re-emits a representable cycle.
                    Some(via) if via == breaker => {
                        return Err(CycleBreakError::BreakerOnCycle { peer: dep, breaker });
                    }
                    // F8 residual / BreakersCycleFree: the breaker is
                    // off-cycle itself but REACHES an on-cycle node — the
                    // breaker's own record would keep a path back into
                    // bootstrap territory, so the union of per-rung records
                    // cycles even though each record looks acyclic
                    // (gBreakerWithDeps).
                    Some(via) => {
                        return Err(CycleBreakError::BreakerReachesCycle {
                            peer: dep,
                            breaker,
                            via,
                        });
                    }
                    None => out.push(breaker), // record the cycle-free breaker leaf instead
                }
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
            return Err(CycleBreakError::Unbreakable(unbreakable));
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
        let err = g
            .cycle_broken_deps_of(&c)
            .expect_err("c's cycle has no breaker => must fail shut");
        let CycleBreakError::Unbreakable(unbreakable) = err else {
            panic!("expected Unbreakable, got {err:?}");
        };
        let err = names(&unbreakable);
        assert!(err.contains(&"d".to_string()), "unbreakable peer must be reported: {err:?}");
    }

    /// F7 (SELF-REF via the breaker channel): a cyclic peer whose
    /// `replace_on_cycle` breaker ALIASES the toplevel must fail shut with a
    /// distinct error, never record the toplevel inside its own provenance.
    /// This reproduces the machine-checked witness `gBreakerAliasesTop` in
    /// `formal/Formal/CycleBroken.lean` (`cycleBrokenDepsOf
    /// gBreakerAliasesTop 3 0 = Ok [0]` before this check existed).
    #[test]
    fn breaker_aliasing_toplevel_fails_shut() {
        // a <-> b cycle; b's declared breaker IS a (node 0 <-> 1 with
        // breaker(1) = 0 in the Lean model).
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let rec
                    a = { name = \"a\", build_deps = [ b ], cmd = \"\" } | BuildSpec,
                    b = {
                        name = \"b\",
                        build_deps = [ a ],
                        replace_on_cycle = a,
                        cmd = \"\",
                    } | BuildSpec,
                in
                [a, b]
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let g = Graph::new().ingest(layer).unwrap();
        let a = *g.by_name("a").unwrap();
        let b = *g.by_name("b").unwrap();

        // The Lean witness: without the check, record(a) = [a].
        let err = g
            .cycle_broken_deps_of(&a)
            .expect_err("breaker aliasing the toplevel must fail shut");
        assert_eq!(
            err,
            CycleBreakError::BreakerAliasesToplevel { peer: b },
            "must be the distinct aliasing error naming the offending peer"
        );

        // Sanity (matches the Lean model's second example): from b's side the
        // cycle is breaker-less (a declares none) => plain Unbreakable.
        let err = g
            .cycle_broken_deps_of(&b)
            .expect_err("b's cyclic peer a declares no breaker");
        assert_eq!(err, CycleBreakError::Unbreakable(vec![a]));
    }

    /// F8 (axiom A2, breaker-terminality): a breaker that itself sits on a
    /// dependency cycle must be rejected — with such breakers the union of
    /// per-rung records genuinely cycles (`finding_breaker_nonterminal_cycle`
    /// / `gSelfBreaker` in `formal/Formal/CycleBroken.lean`).
    #[test]
    fn breaker_on_cycle_fails_shut() {
        // a <-> b cycle broken (allegedly) by c — but c sits on its own
        // c <-> d cycle, so it is not a terminal leaf.
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let rec
                    a = { name = \"a\", build_deps = [ b ], cmd = \"\" } | BuildSpec,
                    b = {
                        name = \"b\",
                        build_deps = [ a ],
                        replace_on_cycle = c,
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
        let a = *g.by_name("a").unwrap();
        let b = *g.by_name("b").unwrap();
        let c = *g.by_name("c").unwrap();

        let err = g
            .cycle_broken_deps_of(&a)
            .expect_err("a non-terminal breaker must fail shut");
        assert_eq!(
            err,
            CycleBreakError::BreakerOnCycle { peer: b, breaker: c },
            "must be the distinct terminality error naming peer + breaker"
        );
    }

    /// F8, the self-breaker shape (the exact `gSelfBreaker` witness): a
    /// cyclic peer declaring ITSELF as its breaker is a special case of a
    /// non-terminal breaker and must fail shut, not silently re-record the
    /// from-source cyclic peer.
    #[test]
    fn self_breaker_fails_shut() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let rec
                    a = { name = \"a\", build_deps = [ b ], cmd = \"\" } | BuildSpec,
                    b = {
                        name = \"b\",
                        build_deps = [ a ],
                        replace_on_cycle = b,
                        cmd = \"\",
                    } | BuildSpec,
                in
                [a, b]
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let g = Graph::new().ingest(layer).unwrap();
        let a = *g.by_name("a").unwrap();
        let b = *g.by_name("b").unwrap();

        let err = g
            .cycle_broken_deps_of(&a)
            .expect_err("a self-breaker on a cycle must fail shut");
        assert_eq!(err, CycleBreakError::BreakerOnCycle { peer: b, breaker: b });
    }

    /// F8 RESIDUAL (`BreakersCycleFree`): a breaker that is off-cycle
    /// ITSELF but whose transitive closure reaches an on-cycle node must be
    /// rejected. This is the exact `gBreakerWithDeps` witness from
    /// `formal/Formal/CycleBroken.lean`
    /// (`finding_enforced_checks_insufficient`): under F7+F8 alone,
    /// record(a) = [c] and record(c) = [a, b] BOTH emit Ok, and their union
    /// contains the genuine 2-cycle a -> c -> a. The closure-level gate
    /// makes a's side fail shut with the distinct error naming peer,
    /// breaker, and the on-cycle witness node.
    #[test]
    fn breaker_reaching_cycle_fails_shut() {
        // a <-> b cycle; b's breaker c is on no cycle (nothing reaches c)
        // but c depends on a — the breaker's closure re-enters the cycle.
        // Lean model: nodes 0 <-> 1, breaker(1) = 2, deps(2) = [0].
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let rec
                    a = { name = \"a\", build_deps = [ b ], cmd = \"\" } | BuildSpec,
                    b = {
                        name = \"b\",
                        build_deps = [ a ],
                        replace_on_cycle = c,
                        cmd = \"\",
                    } | BuildSpec,
                    c = { name = \"c\", build_deps = [ a ], cmd = \"\" } | BuildSpec,
                in
                [a, b, c]
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let g = Graph::new().ingest(layer).unwrap();
        let a = *g.by_name("a").unwrap();
        let b = *g.by_name("b").unwrap();
        let c = *g.by_name("c").unwrap();

        // Pre-fix behavior (must now be dead): Ok [c]. The strengthened
        // gate fails shut, naming the on-cycle node reachable from c.
        let err = g
            .cycle_broken_deps_of(&a)
            .expect_err("a breaker whose closure reaches a cycle must fail shut");
        assert_eq!(
            err,
            CycleBreakError::BreakerReachesCycle { peer: b, breaker: c, via: a },
            "must be the distinct closure-level error naming peer + breaker + witness"
        );

        // Sanity (matches the Lean model's `cycleBrokenDepsOf gBreakerWithDeps
        // 4 2 = Ok [0, 1]`): c's OWN record is fine — no cyclic peers — and
        // it is exactly the record that would have completed the union cycle
        // had a's side been allowed to emit.
        let ok = g
            .cycle_broken_deps_of(&c)
            .expect("c has no cyclic peer; its record emits Ok");
        let names: Vec<String> = ok.iter().map(|r| g.get(r).unwrap().name.clone()).collect();
        assert!(
            names.contains(&"a".to_string()) && names.contains(&"b".to_string()),
            "c's record keeps its acyclic deps: {names:?}"
        );
    }

    /// #14 D2 (durable mirror-slot ownership, cross-language contract): the
    /// signer's leaf-owns-slot ranker (signer/main.go `mirrorSlotWinner`)
    /// keys on resolvedDependencies COUNT — a non-CHAIN_ENFORCE production
    /// leaf emits ZERO deps, so it always outranks a CHAIN_ENFORCE rung
    /// (which records this non-empty cycle-broken closure). This test pins
    /// the graph-level source of that asymmetry: a pure leaf's cycle-broken
    /// closure is EMPTY, while a rung on a breakable cycle is NON-empty. If
    /// this ever regressed (a leaf recording phantom deps), the signer could
    /// no longer distinguish leaf from rung by count.
    #[test]
    fn leaf_records_empty_closure_rung_records_nonempty() {
        let layer = Layer::new_for_test(
            indoc! {
                "
                let {BuildSpec, ..} = import \"minimal.ncl\" in
                let rec
                    leaf = { name = \"leaf\", build_deps = [], cmd = \"\" } | BuildSpec,
                    a = { name = \"a\", build_deps = [ b ], cmd = \"\" } | BuildSpec,
                    b = {
                        name = \"b\",
                        build_deps = [ a ],
                        replace_on_cycle = { name = \"b-prebuilt\", build_deps = [], cmd = \"\" } | BuildSpec,
                        cmd = \"\",
                    } | BuildSpec,
                in
                [leaf, a, b]
                "
            }
            .to_string(),
        )
        .unwrap_or_else(|e| {
            e.report_to_stderr();
            panic!("spec parsing failed");
        });
        let g = Graph::new().ingest(layer).unwrap();

        // Leaf (no deps) => empty closure => the depCount-0 "leaf" shape the
        // signer's ranker gives slot ownership to.
        let leaf = *g.by_name("leaf").unwrap();
        let leaf_closure = g
            .cycle_broken_deps_of(&leaf)
            .expect("a leaf has no cycle to break");
        assert!(
            leaf_closure.is_empty(),
            "a production leaf must record ZERO resolvedDependencies (got {} — the signer's \
             leaf-owns-slot precedence would break): {:?}",
            leaf_closure.len(),
            leaf_closure
                .iter()
                .map(|r| g.get(r).unwrap().name.clone())
                .collect::<Vec<_>>()
        );

        // Rung on a breakable cycle => non-empty closure => depCount >= 1,
        // strictly outranked by the leaf above (cannot evict it).
        let a = *g.by_name("a").unwrap();
        let rung_closure = g
            .cycle_broken_deps_of(&a)
            .expect("a's cycle is breakable via b's replace_on_cycle");
        assert!(
            !rung_closure.is_empty(),
            "a CHAIN_ENFORCE rung on a cycle must record a non-empty closure"
        );
        assert!(
            rung_closure.len() > leaf_closure.len(),
            "rung closure ({}) must exceed leaf closure ({}) so depCount distinguishes them",
            rung_closure.len(),
            leaf_closure.len()
        );
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

/// Twin-vs-PRODUCTION differential test (aeneas-twin robustness leg 1).
///
/// The `formal/` trust theorems (`provenance_acyclic_enforced`,
/// `toplevel_not_recorded`, the F7/F8 witnesses) are proved over a hand-written
/// Lean model of `cycle_broken_deps_of`. The Aeneas equivalence proof aims to
/// tie that model to a Lean function machine-EXTRACTED from a dependency-free
/// Rust re-implementation ("the twin", `minimermetic/formal/aeneas-twin`). The
/// twin is only meaningful if it is FAITHFUL to the real `graph.rs` algorithm;
/// this test guards that faithfulness by running BOTH implementations on the
/// same seeded-random graphs and asserting they return equivalent verdicts.
///
/// `mod twin` below is a VERBATIM copy of `aeneas-twin/src/lib.rs`'s algorithm
/// (usize/Vec form). If the two ever drift, this test's known-witness table
/// (`known_witnesses_match`) or the random sweep will fail in CI.
///
/// SOUNDNESS OF THE COMPARISON. The two implementations use different DFS
/// disciplines (production: recursive pre-order over `build_deps`; twin:
/// iterative LIFO worklist), so the *order* in which the closure is visited
/// differs. The following projection of the verdict is nonetheless provably
/// order-INVARIANT and is what we assert on:
///   * The 3-way outcome class {Accept, Unbreakable, BreakerError}. `Accept`
///     iff no cyclic-peer-with-failing-breaker AND no cyclic-peer-without-a-
///     breaker exist; `Unbreakable` iff the former is absent but the latter
///     present; `BreakerError` iff a cyclic-peer-with-failing-breaker exists.
///     All three predicates are pure functions of graph topology, independent
///     of visitation order.
///   * On `Accept`: the recorded dependency SET (sorted).
///   * On `Unbreakable`: the failing-peer SET (both impls collect ALL such
///     peers before sorting+deduping, so it is order-invariant).
/// The *specific* breaker-error variant / peer / `via` IS order-dependent when
/// several distinct failing peers coexist (each impl early-returns the first in
/// its own order), so we assert the exact witness tuple only opportunistically:
/// when both impls happen to pick the SAME peer, their variant + breaker must
/// agree (`via` is left out — it too is order-dependent).
#[cfg(test)]
mod twin_differential {
    // ---- The twin: a verbatim copy of aeneas-twin/src/lib.rs (usize/Vec) ----
    // Keep in sync with minimermetic/formal/aeneas-twin/src/lib.rs. Doc comments
    // trimmed; algorithm bytes unchanged.
    mod twin {
        #[derive(Debug, PartialEq, Eq)]
        pub enum CycleBreakError {
            Unbreakable(Vec<usize>),
            BreakerAliasesToplevel { peer: usize },
            BreakerOnCycle { peer: usize, breaker: usize },
            BreakerReachesCycle { peer: usize, breaker: usize, via: usize },
        }

        pub struct Graph {
            pub deps: Vec<Vec<usize>>,
            pub breaker: Vec<Option<usize>>,
        }

        impl Graph {
            pub fn transitive_specs_of(&self, toplevel: usize) -> Vec<usize> {
                let n: usize = self.deps.len();
                let mut seen: Vec<bool> = Vec::new();
                let mut k: usize = 0;
                while k < n {
                    seen.push(false);
                    k += 1;
                }
                let mut reachable: Vec<usize> = Vec::new();
                let mut stack: Vec<usize> = Vec::new();
                stack.push(toplevel);
                while stack.len() != 0 {
                    let node: usize = stack[stack.len() - 1];
                    stack.pop();
                    let mut i: usize = 0;
                    while i < self.deps[node].len() {
                        let d: usize = self.deps[node][i];
                        if !seen[d] {
                            seen[d] = true;
                            reachable.push(d);
                            stack.push(d);
                        }
                        i += 1;
                    }
                }
                reachable
            }

            fn on_own_cycle(&self, node: usize) -> bool {
                let closure: Vec<usize> = self.transitive_specs_of(node);
                let mut i: usize = 0;
                while i < closure.len() {
                    if closure[i] == node {
                        return true;
                    }
                    i += 1;
                }
                false
            }

            fn breaker_cycle_witness(&self, breaker: usize) -> Option<usize> {
                if self.on_own_cycle(breaker) {
                    return Some(breaker);
                }
                let closure: Vec<usize> = self.transitive_specs_of(breaker);
                let mut i: usize = 0;
                while i < closure.len() {
                    let reached: usize = closure[i];
                    if self.on_own_cycle(reached) {
                        return Some(reached);
                    }
                    i += 1;
                }
                None
            }

            pub fn cycle_broken_deps_of(
                &self,
                toplevel: usize,
            ) -> Result<Vec<usize>, CycleBreakError> {
                let mut out: Vec<usize> = Vec::new();
                let mut unbreakable: Vec<usize> = Vec::new();

                let closure: Vec<usize> = self.transitive_specs_of(toplevel);
                let mut i: usize = 0;
                while i < closure.len() {
                    let dep: usize = closure[i];
                    i += 1;
                    if dep != toplevel {
                        let dep_closure: Vec<usize> = self.transitive_specs_of(dep);
                        let mut reaches_toplevel: bool = false;
                        let mut j: usize = 0;
                        while j < dep_closure.len() {
                            if dep_closure[j] == toplevel {
                                reaches_toplevel = true;
                            }
                            j += 1;
                        }

                        if !reaches_toplevel {
                            out.push(dep);
                        } else {
                            match self.breaker[dep] {
                                None => unbreakable.push(dep),
                                Some(breaker) => {
                                    if breaker == toplevel {
                                        return Err(CycleBreakError::BreakerAliasesToplevel {
                                            peer: dep,
                                        });
                                    }
                                    match self.breaker_cycle_witness(breaker) {
                                        Some(via) => {
                                            if via == breaker {
                                                return Err(CycleBreakError::BreakerOnCycle {
                                                    peer: dep,
                                                    breaker,
                                                });
                                            } else {
                                                return Err(
                                                    CycleBreakError::BreakerReachesCycle {
                                                        peer: dep,
                                                        breaker,
                                                        via,
                                                    },
                                                );
                                            }
                                        }
                                        None => out.push(breaker),
                                    }
                                }
                            }
                        }
                    }
                }

                if unbreakable.len() != 0 {
                    sort_dedup(&mut unbreakable);
                    return Err(CycleBreakError::Unbreakable(unbreakable));
                }
                sort_dedup(&mut out);
                Ok(out)
            }
        }

        fn sort_dedup(v: &mut Vec<usize>) {
            let n: usize = v.len();
            let mut i: usize = 0;
            while i < n {
                let mut min_idx: usize = i;
                let mut j: usize = i + 1;
                while j < n {
                    if v[j] < v[min_idx] {
                        min_idx = j;
                    }
                    j += 1;
                }
                let tmp: usize = v[i];
                v[i] = v[min_idx];
                v[min_idx] = tmp;
                i += 1;
            }
            let mut result: Vec<usize> = Vec::new();
            let mut k: usize = 0;
            while k < v.len() {
                if result.len() == 0 || result[result.len() - 1] != v[k] {
                    result.push(v[k]);
                }
                k += 1;
            }
            *v = result;
        }
    }

    // ------------------------------ Harness ------------------------------
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Deterministic splitmix64 PRNG (keeps the test dep-free + reproducible).
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }
        /// true with probability num/den.
        fn chance(&mut self, num: u64, den: u64) -> bool {
            self.next_u64() % den < num
        }
    }

    /// Build a production `Graph` isomorphic to the given usize/Vec adjacency.
    /// Node `i` <-> `refs[i]`. Returns the graph, the refs, and the reverse map.
    fn build_production(
        deps: &[Vec<usize>],
        breaker: &[Option<usize>],
    ) -> (Graph, Vec<BuildSpecRef>, HashMap<BuildSpecRef, usize>) {
        let n = deps.len();
        let mut g = Graph::new();
        let origin = Arc::new(common::SpecOrigin::Inline);
        // Phase 1: insert n empty specs so all node-refs exist before wiring.
        let mut refs = Vec::with_capacity(n);
        for i in 0..n {
            refs.push(g.insert_build(BuildSpec {
                name: format!("n{i}"),
                from: origin.clone(),
                ..Default::default()
            }));
        }
        // Phase 2: wire build_deps + replace_on_cycle via arena get_mut.
        for i in 0..n {
            let build_deps: smallvec::SmallVec<[BuildDep; 10]> =
                deps[i].iter().map(|&j| BuildDep::Build(refs[j])).collect();
            let replace_on_cycle = breaker[i].map(|j| refs[j]);
            let spec = g.builds.get_mut(refs[i].0).unwrap();
            spec.build_deps = build_deps;
            spec.replace_on_cycle = replace_on_cycle;
        }
        let reverse: HashMap<BuildSpecRef, usize> =
            refs.iter().enumerate().map(|(i, r)| (*r, i)).collect();
        (g, refs, reverse)
    }

    /// The order-invariant 3-way outcome class.
    #[derive(Debug, PartialEq, Eq)]
    enum Class {
        Accept(Vec<usize>),      // sorted recorded-dep set
        Unbreakable(Vec<usize>), // sorted failing-peer set
        BreakerError,
    }

    fn class_prod(
        r: &Result<Vec<BuildSpecRef>, CycleBreakError>,
        rev: &HashMap<BuildSpecRef, usize>,
    ) -> Class {
        match r {
            Ok(v) => {
                let mut s: Vec<usize> = v.iter().map(|b| rev[b]).collect();
                s.sort_unstable();
                Class::Accept(s)
            }
            Err(CycleBreakError::Unbreakable(v)) => {
                let mut s: Vec<usize> = v.iter().map(|b| rev[b]).collect();
                s.sort_unstable();
                Class::Unbreakable(s)
            }
            Err(_) => Class::BreakerError,
        }
    }

    fn class_twin(r: &Result<Vec<usize>, twin::CycleBreakError>) -> Class {
        match r {
            Ok(v) => {
                let mut s = v.clone();
                s.sort_unstable();
                Class::Accept(s)
            }
            Err(twin::CycleBreakError::Unbreakable(v)) => {
                let mut s = v.clone();
                s.sort_unstable();
                Class::Unbreakable(s)
            }
            Err(_) => Class::BreakerError,
        }
    }

    /// (variant-tag, peer, breaker) for opportunistic exact-witness checking.
    /// `via` is deliberately excluded (order-dependent). Returns None for the
    /// non-single-peer variants.
    fn witness_prod(
        r: &Result<Vec<BuildSpecRef>, CycleBreakError>,
        rev: &HashMap<BuildSpecRef, usize>,
    ) -> Option<(u8, usize, Option<usize>)> {
        match r {
            Err(CycleBreakError::BreakerAliasesToplevel { peer }) => Some((0, rev[peer], None)),
            Err(CycleBreakError::BreakerOnCycle { peer, breaker }) => {
                Some((1, rev[peer], Some(rev[breaker])))
            }
            Err(CycleBreakError::BreakerReachesCycle { peer, breaker, .. }) => {
                Some((2, rev[peer], Some(rev[breaker])))
            }
            _ => None,
        }
    }

    fn witness_twin(r: &Result<Vec<usize>, twin::CycleBreakError>) -> Option<(u8, usize, Option<usize>)> {
        match r {
            Err(twin::CycleBreakError::BreakerAliasesToplevel { peer }) => Some((0, *peer, None)),
            Err(twin::CycleBreakError::BreakerOnCycle { peer, breaker }) => {
                Some((1, *peer, Some(*breaker)))
            }
            Err(twin::CycleBreakError::BreakerReachesCycle { peer, breaker, .. }) => {
                Some((2, *peer, Some(*breaker)))
            }
            _ => None,
        }
    }

    /// Run one differential trial; panics with a reproducer on any divergence.
    /// Returns the outcome class so the caller can tally coverage.
    fn check_one(deps: &[Vec<usize>], breaker: &[Option<usize>], toplevel: usize) -> u8 {
        let (g, refs, rev) = build_production(deps, breaker);
        let tw = twin::Graph {
            deps: deps.to_vec(),
            breaker: breaker.to_vec(),
        };

        let prod_r = g.cycle_broken_deps_of(&refs[toplevel]);
        let twin_r = tw.cycle_broken_deps_of(toplevel);

        let cp = class_prod(&prod_r, &rev);
        let ct = class_twin(&twin_r);
        assert_eq!(
            cp, ct,
            "CLASS DIVERGENCE\n deps={deps:?}\n breaker={breaker:?}\n toplevel={toplevel}\n prod={prod_r:?}\n twin={twin_r:?}"
        );

        // Opportunistic exact-witness check when both picked the same peer.
        if let (Some(wp), Some(wt)) = (witness_prod(&prod_r, &rev), witness_twin(&twin_r)) {
            if wp.1 == wt.1 {
                assert_eq!(
                    (wp.0, wp.2),
                    (wt.0, wt.2),
                    "WITNESS DIVERGENCE (same peer {peer}, different variant/breaker)\n deps={deps:?}\n breaker={breaker:?}\n toplevel={toplevel}\n prod={prod_r:?}\n twin={twin_r:?}",
                    peer = wp.1
                );
            }
        }

        match cp {
            Class::Accept(_) => 0,
            Class::Unbreakable(_) => 1,
            Class::BreakerError => 2,
        }
    }

    /// The six hand-witness graphs mirrored from the twin's own test suite and
    /// `formal/Formal/CycleBroken.lean`. Fast, deterministic drift tripwire.
    #[test]
    fn known_witnesses_match() {
        // (deps, breaker, toplevel)
        let cases: Vec<(Vec<Vec<usize>>, Vec<Option<usize>>, usize)> = vec![
            // acyclic -> Accept([1,2])
            (vec![vec![1], vec![2], vec![]], vec![None, None, None], 0),
            // 0<->1 no breaker -> Unbreakable([1])
            (vec![vec![1], vec![0]], vec![None, None], 0),
            // breaker aliases toplevel
            (vec![vec![1], vec![0]], vec![None, Some(0)], 0),
            // breaker on its own cycle
            (
                vec![vec![1], vec![0], vec![3], vec![2]],
                vec![None, Some(2), None, None],
                0,
            ),
            // breaker off-cycle but reaches a cycle
            (
                vec![vec![1], vec![0], vec![3], vec![4], vec![3]],
                vec![None, Some(2), None, None, None],
                0,
            ),
            // cycle-free breaker leaf -> Accept([2])
            (vec![vec![1], vec![0], vec![]], vec![None, Some(2), None], 0),
        ];
        for (deps, breaker, top) in &cases {
            check_one(deps, breaker, *top);
        }
    }

    /// Seeded-random sweep: for many small graphs, assert production and twin
    /// agree. Also asserts the generator actually exercises all three outcome
    /// classes (otherwise the test would be vacuously green).
    #[test]
    fn random_graphs_agree() {
        let mut rng = Rng(0xC0FFEE_1234_5678);
        let mut tally = [0u64; 3];
        const TRIALS: usize = 40_000;
        for _ in 0..TRIALS {
            let n = 2 + rng.below(5); // 2..=6 nodes
            let mut deps = vec![Vec::new(); n];
            for i in 0..n {
                for j in 0..n {
                    // allow self-loops and both directions; ~35% edge density.
                    if i != j && rng.chance(35, 100) {
                        deps[i].push(j);
                    }
                }
            }
            let mut breaker = vec![None; n];
            for i in 0..n {
                if rng.chance(45, 100) {
                    breaker[i] = Some(rng.below(n)); // any node incl self/toplevel
                }
            }
            let toplevel = rng.below(n);
            let cls = check_one(&deps, &breaker, toplevel);
            tally[cls as usize] += 1;
        }
        eprintln!(
            "twin_differential sweep: {TRIALS} trials — Accept={} Unbreakable={} BreakerError={}",
            tally[0], tally[1], tally[2]
        );
        assert!(tally[0] > 0, "generator never produced an Accept verdict");
        assert!(tally[1] > 0, "generator never produced an Unbreakable verdict");
        assert!(tally[2] > 0, "generator never produced a BreakerError verdict");
    }
}
