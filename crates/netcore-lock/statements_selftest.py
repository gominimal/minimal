#!/usr/bin/env python3
"""Attacks the statement lock of netcore, on temporary copies of the crate.

    python3 statements_selftest.py [--crate DIR] [--verus-script PATH] [--vir FILE] [-v]

`--vir` is Verus's account of the crate (`--log vir`'s `crate.vir`), which the
second lock's attacks edit; without it, the path `VIEW.source` names.

Each attack is a way to make a proof pass without proving the claim, or to
ship code the proofs do not see. The gate (`statements.py --check`) must fail
on every one, and for the reason the entry names: a refusal (`refused`) or a
difference from the lock (`changed`). Each honest edit changes only what is
free, and the gate must pass it. A gate that nothing has tried to get past is
not known to hold.

Every entry runs on its own copy of the crate and of the gate (the scripts and
the lock), in a temporary directory beside this script that is removed
afterwards. The copy of the gate is what runs, so an edit to the gate itself
is an attack like any other.
"""

import sys

if not (sys.flags.isolated and sys.dont_write_bytecode):
    # As in statements.py: nothing beside this script or in the environment may answer an import.
    import posix

    posix.execv(sys.executable, [sys.executable, "-I", "-B"] + sys.argv)

import os
import re
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.join(os.path.dirname(HERE), "netcore")
GATE_FILES = ("statements.py", "statements_selftest.py", "STATEMENTS.lock", "view.py", "VIEW.lock",
              "controls.py", "controls.toml")
VERUS_SCRIPT = os.path.join(os.path.dirname(HERE), "ci-verus", "verus.sh")
if not os.path.isfile(VERUS_SCRIPT):
    # In the repository the lock is crates/netcore-lock and the script scripts/verus.sh.
    VERUS_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts", "verus.sh")


def option(flag):
    """The value given after `flag`, as an absolute path, taken out of the arguments; "" when absent."""
    if flag not in sys.argv[1:]:
        return ""
    at = sys.argv.index(flag, 1)
    if at + 1 >= len(sys.argv):
        sys.stderr.write(__doc__)
        sys.exit(2)
    value = os.path.abspath(sys.argv.pop(at + 1))
    sys.argv.pop(at)
    return value


VERUS_SCRIPT = option("--verus-script") or VERUS_SCRIPT


def account_path():
    """Verus's account of the placed crate: `--vir`, or else the path `VIEW.source` names."""
    given = option("--vir")
    if given:
        return given
    source = os.path.join(HERE, "VIEW.source")
    if os.path.isfile(source):
        with open(source, encoding="utf-8") as file:
            return file.read().strip()
    return ""


def pinned_count():
    """The line of the CI script that pins the verified count, as it stands."""
    with open(VERUS_SCRIPT, encoding="utf-8") as file:
        found = re.findall(r"^expect netcore \d+\n", file.read(), flags=re.M)
    return found[0] if len(found) == 1 else "expect netcore ?\n"


VIR = account_path()
COUNT = pinned_count()
LESS = "expect netcore %d\n" % (int(COUNT.split()[2]) - 1) if COUNT.split()[2].isdigit() else COUNT

# Texts several entries use.
DECIDE_ROW = "pub fn decide_row(plan: &Plan, rules: &RowRules, alias_open: bool, d: Dest) -> RowArm {\n"
ARM_ADMITS = "pub fn arm_admits(arm: RowArm) -> bool {\n"
ARM_ADMITS_BODY = "pub fn arm_admits(arm: RowArm) -> bool {\n    match arm {\n        RowArm::Arp => true,\n"
DECIDE_ENSURES = "        r == row_spec(*plan, *rules, alias_open, d),\n"
NETWORK = ("        requires wf(*self),\n        ensures r as int == spec_network(*self),\n    ))]\n"
           "    pub fn network(&self) -> u32 {\n")
FLOOR_PROOF = "            assert(addrs@.take(i as int + 1).last() == addrs@[i as int]);\n"
LEMMA_BODY = "    theorem_rb1_ordinary_name_reaches_no_box(plan, a, deny, allow, own);\n}\n"
IN_FIXED = "pub open spec fn in_fixed(a: u32) -> bool {\n    a >> 16 == 0xa9feu32 || a >> 24 == 127u32\n}\n"
V3 = "        !admits(row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port })),\n{\n"
KANI_ASSERT = "        assert!(reserved[i] != reserved[j]);\n"
KANI_HARNESS = "    #[kani::proof]\n    #[kani::unwind(8)]\n    fn kani_plan_a1() {\n"
GATEWAY = "    let gateway = dst == plan.gateway();\n"
SHIPPED_ONLY = "    #[cfg(not(any(verus_keep_ghost, kani, test)))]\n    let alias_open = true;\n"
GHOST_USE = "#[cfg(verus_keep_ghost)]\nuse vstd::prelude::*;\n\nuse crate::plan::Plan;\n"
ALIAS = "    #[cfg(verus_keep_ghost)]\n    use crate::plan::wf as row_spec;\n"
SHADOW = ("    #[cfg(verus_keep_ghost)]\n    fn row_spec(_p: Plan, _r: RowRules, _a: bool, _d: Dest) -> RowArm {\n"
          "        RowArm::Rules\n    }\n")
TESTS = "#[cfg(test)]\nmod tests {\n    use super::*;\n\n    // 100.64.0.0/24"
ARM_CONTRACT = "    ensures r == admits(arm),\n))]\n"
ADMITS_SPEC = ("pub open spec fn admits(arm: RowArm) -> bool {\n    arm == RowArm::Arp || arm == RowArm::LaneAdmit"
               " || arm == RowArm::Resolver || arm == RowArm::Rules\n}\n")

# (what is tried, file, text, replacement, "refused" or "changed" for an attack, None for an honest edit).
# The text is a string that must occur exactly once, or ("line", prefix) for the one line that starts with
# prefix, or None for a new or replaced file whose content is the replacement, or "symlink" for a link.
ATTACKS = [
    # Asked for by name.
    ("weaken an ensures on a shipped function", "src/row.rs", DECIDE_ENSURES, "        true,\n", "changed"),
    ("delete a requires", "src/plan.rs", NETWORK, NETWORK.replace("        requires wf(*self),\n", ""), "changed"),
    ("change a specification function's body", "src/row.rs", IN_FIXED, IN_FIXED.replace("127u32", "126u32"), "changed"),
    ("change a theorem's statement", "src/row.rs", V3, "        true,\n{\n", "changed"),
    ("make a predicate opaque", "src/row.rs", IN_FIXED, "#[verifier::opaque]\n" + IN_FIXED, "changed"),
    ("remove opacity", "src/frame.rs", "#[verifier::opaque]\npub open spec fn spec_be16(", "pub open spec fn spec_be16(", "changed"),
    ("assume(false) in a proof block", "src/rebind.rs", FLOOR_PROOF, "            assume(false);\n", "refused"),
    ("admit() in a lemma's body", "src/rebind.rs", LEMMA_BODY, "    admit();\n}\n", "refused"),
    ("external_body on a shipped function", "src/row.rs", DECIDE_ROW, "#[verifier::external_body]\n" + DECIDE_ROW, "refused"),
    ("external_body for Verus alone", "src/row.rs", DECIDE_ROW,
     "#[cfg_attr(verus_keep_ghost, verifier::external_body)]\n" + DECIDE_ROW, "refused"),
    ("external for Verus alone", "src/row.rs", DECIDE_ROW,
     "#[cfg_attr(verus_keep_ghost, verifier::external)]\n" + DECIDE_ROW, "refused"),
    ("external_body in the attribute style's own spelling", "src/row.rs", DECIDE_ROW,
     "#[cfg_attr(verus_keep_ghost, verus_verify(external_body))]\n" + DECIDE_ROW, "refused"),
    ("external_body in the old spelling", "src/row.rs", DECIDE_ROW, "#[verifier(external_body)]\n" + DECIDE_ROW, "refused"),
    ("external_body on a lemma", "src/row.rs", "pub proof fn theorem_v3(",
     "#[verifier::external_body]\npub proof fn theorem_v3(", "refused"),
    ("a trusted-style marker no forbidden word names", "src/row.rs", DECIDE_ROW,
     "#[cfg_attr(verus_keep_ghost, verifier::exec_allows_no_decreases_clause)]\n" + DECIDE_ROW, "refused"),
    ("a verifier attribute on a lemma that is not on the list", "src/row.rs",
     "pub proof fn theorem_v3(", "#[verifier::rlimit(infinity)]\npub proof fn theorem_v3(", "refused"),
    ("the verifier never sees the shipped body", "src/row.rs", ARM_ADMITS,
     "#[cfg(not(verus_keep_ghost))]\n" + ARM_ADMITS, "refused"),
    ("a second function of the same name behind a condition", "src/row.rs", ARM_ADMITS_BODY,
     "#[cfg(not(verus_keep_ghost))]\npub fn arm_admits(arm: RowArm) -> bool {\n    true\n}\n\n" + ARM_ADMITS_BODY, "refused"),
    ("a second function of the same name, for Kani alone", "src/row.rs", TESTS,
     "#[cfg(kani)]\npub fn arm_admits(arm: RowArm) -> bool {\n    true\n}\n\n" + TESTS, "refused"),
    ("change a Kani harness's assertion", "src/plan.rs", KANI_ASSERT, "        assert!(true);\n", "changed"),
    ("change a Kani harness's bound", "src/plan.rs", KANI_HARNESS, KANI_HARNESS.replace("unwind(8)", "unwind(1)"), "changed"),
    ("narrow a Kani harness's inputs", "src/plan.rs", "kani::assume(i < 7 && j < 7 && i != j);",
     "kani::assume(i < 1 && j < 7 && i != j);", "changed"),
    ("change a Kani shape list", "src/slab.rs", "            shape!($check, c3_6_3, 3, 6, 3);\n", "", "changed"),
    ("delete a Kani harness", "src/plan.rs", KANI_HARNESS, KANI_HARNESS.replace("    #[kani::proof]\n", ""), "changed"),
    ("move a quick Kani harness to the long lane", "src/plan.rs", KANI_HARNESS,
     '    #[cfg(feature = "kani-full")]\n' + KANI_HARNESS, "changed"),
    ("delete a Kani module by its condition", "src/plan.rs", "#[cfg(kani)]\nmod proofs {", "#[cfg(any())]\nmod proofs {", "refused"),
    ("delete the long Kani lane's feature", "Cargo.toml", "kani-full = []\n", "", "changed"),
    ("change a constant", "src/row.rs", "pub const DNS_PORT: u16 = 53;", "pub const DNS_PORT: u16 = 54;", "changed"),
    ("add a file the crate is not known to hold", "build.rs", None, "fn main() {}\n", "refused"),
    ("add a source file the root does not name", "src/twin.rs", None, "pub fn twin() {}\n", "changed"),
    ("add a cargo configuration", ".cargo/config.toml", None, "[build]\nrustflags = []\n", "refused"),
    ("replace a document by a link", "verus/controls-plan.md", "symlink", "controls-row.md", "refused"),
    ("a contract's clause behind a carriage return", "src/plan.rs", NETWORK,
     NETWORK.replace("        requires wf(*self),\n", "        // the plan\r        requires wf(*self),\n"), "refused"),
    ("code that only ships, inside what a carriage return makes a string here", "src/row.rs", GATEWAY,
     GATEWAY + "    // A note.\rlet _ = \"\n" + SHIPPED_ONLY + "    //\r\";\n", "refused"),
    ("the same, inside a real string that runs over a line end", "src/row.rs", GATEWAY,
     GATEWAY + "    let _ = \"\n" + SHIPPED_ONLY + "    \";\n", "refused"),
    ("a string that spans what looks like an attribute", "src/row.rs", DECIDE_ROW,
     "const _: &str = \"\n#[cfg_attr(verus_keep_ghost, verus_verify)]\n\";\n" + DECIDE_ROW, "refused"),
    ("an attribute's text inside a one-line string", "src/row.rs", GATEWAY,
     GATEWAY + "    let _ = \"#[cfg(not(verus_keep_ghost))]\";\n", "refused"),
    ("remove a row of the theorem index in lib.rs", "src/lib.rs", ("line", "//! | K1  |"), "", "changed"),
    ("remove an assumption row", "axioms/REGISTRY.md", ("line", "| NC1 |"), "", "changed"),
    # The template's attacks that apply to this crate's style.
    ("the premise by its library path", "src/rebind.rs", FLOOR_PROOF, "            vstd::prelude::assume_(false);\n", "refused"),
    ("admit by its library path", "src/rebind.rs", LEMMA_BODY, "    vstd::pervasive::admit();\n}\n", "refused"),
    ("the premise behind a block comment that holds //", "src/rebind.rs", FLOOR_PROOF,
     "            /* // */ assume(false);\n", "refused"),
    ("a trusted marker spelled with spaces", "src/row.rs", DECIDE_ROW,
     "#[cfg_attr(verus_keep_ghost, verifier :: external)]\n" + DECIDE_ROW, "refused"),
    ("a trusted marker split over two lines", "src/row.rs", DECIDE_ROW, "#[verifier\n::external]\n" + DECIDE_ROW, "refused"),
    ("a private module the lock does not read", "src/lib.rs", "pub mod sweep;", "pub mod sweep;\nmod twin;", "refused"),
    ("a public module added", "src/lib.rs", "pub mod sweep;", "pub mod sweep;\npub mod twin;", "changed"),
    ("ship another module than Verus checks", "src/lib.rs", "pub mod sweep;",
     '#[cfg(verus_keep_ghost)]\npub mod sweep;\n#[cfg(not(verus_keep_ghost))]\n#[path = "sweep_shipped.rs"]\npub mod sweep;', "refused"),
    ("a free test switched off by a condition", "src/row.rs", "    #[test]\n    fn only_four_arms_admit() {",
     "    #[cfg(any())]\n    #[test]\n    fn only_four_arms_admit() {", "refused"),
    ("reword an assumption", "axioms/REGISTRY.md", "| NC1 | Time is milliseconds from one clock and does not run backwards",
     "| NC1 | Time is milliseconds from one clock and may run backwards", "changed"),
    ("a module from another path", "src/lib.rs", "pub mod sweep;", '#[path = "twin.rs"]\npub mod sweep;', "refused"),
    ("the locked ghost block compiled out", "src/row.rs", "#[cfg(verus_keep_ghost)]\nverus! {\n",
     "#[cfg(verus_keep_ghost)]\n#[cfg(any())]\nverus! {\n", "refused"),
    ("a second ghost block the lock does not read", "src/row.rs", "} // verus!\n",
     "} // verus!\n\n#[cfg(verus_keep_ghost)]\nverus!{\nproof fn pad() {}\n}\n", "refused"),
    ("the ghost block's end written early, on a specification's closing line", "src/row.rs", ADMITS_SPEC,
     ADMITS_SPEC.replace("Rules\n}\n", "Rules\n} // verus!\n"), "refused"),
    ("the ghost-only condition on an ordinary statement", "src/row.rs", GATEWAY,
     "    #[cfg(verus_keep_ghost)]\n    let () = {\n        if dst == 0 {\n            return RowArm::Rules;\n        }\n    };\n"
     + GATEWAY, "refused"),
    ("a specification under the contract's name, declared inside the function", "src/row.rs",
     DECIDE_ROW, DECIDE_ROW + SHADOW, "refused"),
    ("the same, with no attribute to give it away", "src/row.rs", DECIDE_ROW,
     DECIDE_ROW + SHADOW.replace("    #[cfg(verus_keep_ghost)]\n", ""), "refused"),
    ("another name for a specification, imported inside the function", "src/row.rs", DECIDE_ROW, DECIDE_ROW + ALIAS, "refused"),
    ("the same import at the top of the file", "src/row.rs", GHOST_USE, GHOST_USE + ALIAS.replace("    ", ""), "refused"),
    ("a specification redefined inside a lemma's body", "src/rebind.rs", LEMMA_BODY,
     "    pub open spec fn floor_ok(plan: Plan, a: u32) -> bool {\n        true\n    }\n}\n", "refused"),
    ("a macro that reads the build's environment", "src/row.rs", GATEWAY,
     GATEWAY + "    if option_env!(\"OPEN\").is_some() {\n        return RowArm::Rules;\n    }\n", "refused"),
    ("the conditional macro", "src/row.rs", GATEWAY,
     GATEWAY + "    if !cfg!(verus_keep_ghost) {\n        return RowArm::Rules;\n    }\n", "refused"),
    ("an attribute that is not on the list", "src/row.rs", DECIDE_ROW, "#[track_caller]\n" + DECIDE_ROW, "refused"),
    ("everything of another module imported", "src/row.rs", GHOST_USE, GHOST_USE + "use crate::rebind::*;\n", "refused"),
    ("a function added that carries no contract", "src/row.rs", TESTS, "fn pad() -> u32 {\n    1\n}\n\n" + TESTS, "changed"),
    ("a proof block that returns from the function", "src/rebind.rs", FLOOR_PROOF, "            return Vec::new();\n", "refused"),
    ("a one-line proof block that returns from the function", "src/frame.rs",
     "    proof! { reveal(spec_be16); }\n", "    proof! { return 0; }\n", "refused"),
    ("a ghost declaration that returns from the function", "src/slab.rs",
     "            let ghost p0: int = count;\n", "            let ghost p0: int = count;\n            return 0;\n", "refused"),
    ("a loop compiled out for Verus alone, by a second attribute in its contract's list", "src/row.rs",
     "        decreases list.len() - i,\n    ))]\n    while i < list.len() {\n        if contains(list[i], a) {",
     "        decreases list.len() - i,\n    ), cfg(any()))]\n    while i < list.len() {\n        if contains(list[i], a) {", "refused"),
    ("a function hidden from Verus by a second attribute in its contract's list", "src/row.rs",
     ARM_CONTRACT, "    ensures r == admits(arm),\n), verifier::external_body)]\n", "refused"),
    ("a Kani harness narrowed behind a comment", "src/plan.rs", KANI_ASSERT,
     "        /* // */ kani::assume(i == 0);\n" + KANI_ASSERT, "refused"),
    ("a Kani assertion behind a carriage return", "src/plan.rs", KANI_ASSERT, "        //\r" + KANI_ASSERT, "refused"),
    ("an assumption row behind a carriage return", "axioms/REGISTRY.md", ("line", "| NC2 |"), "\r", "refused"),
    ("a line separator that is not a line feed", "src/row.rs", DECIDE_ROW, "// a note\u2028\n" + DECIDE_ROW, "refused"),
    ("the library built from another file", "Cargo.toml", "[dependencies]\n",
     "[lib]\npath = \"src/twin.rs\"\n\n[dependencies]\n", "changed"),
    ("an item compiled only outside tests", "src/row.rs", TESTS, "#[cfg(not(test))]\nfn twin() {}\n\n" + TESTS, "refused"),
    ("stop checking a constant", "src/row.rs", "#[cfg_attr(verus_keep_ghost, verus_verify)]\npub const DNS_PORT",
     "pub const DNS_PORT", "changed"),
    ("stop checking a function", "src/row.rs",
     "#[cfg_attr(verus_keep_ghost, verus_verify)]\n#[cfg_attr(verus_keep_ghost, verus_spec(r =>\n    ensures r == admits(arm),",
     "#[cfg_attr(verus_keep_ghost, verus_spec(r =>\n    ensures r == admits(arm),", "changed"),
    ("a control deleted", "verus/controls-row.md", ("line", "| added:P-12 |"), "", "changed"),
    ("a control rewritten to break something else, under its old name", "verus/controls-row.md",
     "| added:P-12 |  | the no-protocol theorem no longer excludes a laned row |",
     "| added:P-12 |  | a laned row is admitted |", "changed"),
    ("the gate's own list of refused forms shortened", "gate/statements.py", 'r"\\badmit\\s*\\(\\s*\\)", ', "", "changed"),
    ("an attack dropped from this selftest", "gate/statements_selftest.py",
     '    ("weaken an ensures on a shipped ' + 'function"', '    ("weaken an ensures on a shipped function_"', "changed"),
    ("the lock rewritten to hide a statement", "gate/STATEMENTS.lock",
     "  pub const DNS_PORT: u16 = 53;", "  pub const DNS_PORT: u16 = 54;", "changed"),
    # The unit checks the theorem index cites (SP1), and the verified count CI pins.
    ("weaken an assertion in a cited unit check", "src/gate.rs",
     "        assert_eq!(cfg.egress_for(f).route, Route::Unknown);\n", "        let _ = cfg.egress_for(f);\n", "changed"),
    ("weaken the other cited unit check's assertion", "src/gate.rs",
     '            assert_eq!(got, want, "outbound frame {n}");\n', '            let _ = (got, want, n);\n', "changed"),
    ("delete a cited unit check", "src/gate.rs", "    #[test]\n    fn a_configuration_short_of_a_declaration_routes_nothing() {",
     "    fn a_configuration_short_of_a_declaration_routes_nothing() {", "refused"),
    ("rename a cited unit check", "src/gate.rs", "    fn a_configuration_short_of_a_declaration_routes_nothing() {",
     "    fn a_configuration_short_routes_nothing() {", "refused"),
    ("switch a cited unit check off", "src/gate.rs", "    #[test]\n    fn plan_then_judge_decides_as_the_whole_gate_does() {",
     "    #[test]\n    #[ignore]\n    fn plan_then_judge_decides_as_the_whole_gate_does() {", "refused"),
    ("the assertions of the cited unit checks renamed away", "src/gate.rs", "    use crate::row::{RowArm, RowRules};\n",
     "    use crate::row::{RowArm, RowRules};\n    use std::stringify as assert_eq;\n", "refused"),
    ("change a helper's body that the cited unit checks call", "src/gate.rs",
     "    fn tcp(src: u32, dst: u32, dscp: u8) -> Frame {\n        Frame {\n            sent: Sent {\n                src,\n",
     "    fn tcp(src: u32, dst: u32, dscp: u8) -> Frame {\n        let src = src + 0 * u32::from(dscp);\n        Frame {\n"
     "            sent: Sent {\n                src,\n", "changed"),
    ("change a constant the helpers read", "src/gate.rs", "    const NODE: u32 = NET + 253;", "    const NODE: u32 = NET + 252;", "changed"),
    ("a type of the test module that shadows what a cited unit check names", "src/gate.rs", "    use crate::row::{RowArm, RowRules};\n",
     "    use crate::row::{RowArm, RowRules};\n\n    #[derive(Debug)]\n    enum Route {\n        Row(usize),\n        Unknown,\n    }\n", "refused"),
    ("a helper dropped from the gate's list", "gate/statements.py", '"gate_spelled", "tcp", "config")', '"gate_spelled", "tcp")', "refused"),
    ("change the pinned verified count", "ci/verus.sh", COUNT, LESS, "changed"),
    ("delete the pinned verified count", "ci/verus.sh", COUNT, "", "refused"),
    ("end the CI script before the count", "ci/verus.sh", COUNT, "exit 0\n" + COUNT, "changed"),
    ("the CI script gone", "ci/verus.sh", "symlink-gone", None, "refused"),
    ("a control's place of failure widened", "gate/controls.toml",
     'what = "making room gives up two records instead of one"\nfail_in = ["give_up_and_open"]\n',
     'what = "making room gives up two records instead of one"\nfail_in = ["give_up_and_open", "open_at_capacity"]\n',
     "changed"),
    ("a control retired without a word", "gate/controls.toml",
     'what = "making room gives up two records instead of one"\nfail_in = ["give_up_and_open"]\nstate = "live"\n',
     'what = "making room gives up two records instead of one"\nfail_in = ["give_up_and_open"]\nstate = "retired"\n',
     "changed"),
    ("the control manifest gone", "gate/controls.toml", "symlink-gone", None, "refused"),
    # This crate's own forms.
    ("a proof block without its ghost-only condition", "src/frame.rs",
     "    #[cfg(verus_keep_ghost)]\n    proof! { reveal(spec_be16); }\n", "    proof! { reveal(spec_be16); }\n", "refused"),
    ("the long Kani lane's condition on shipped code", "src/row.rs", ARM_ADMITS,
     '#[cfg(feature = "kani-full")]\n' + ARM_ADMITS, "refused"),
    ("Kani code that is not a harness module, an impl or a kani_ function", "src/row.rs", TESTS,
     "#[cfg(kani)]\nmod twin {\n}\n\n" + TESTS, "refused"),
    ("a Kani harness under another condition", "src/plan.rs", KANI_HARNESS, "    #[cfg(not(kani))]\n" + KANI_HARNESS, "refused"),
    ("a ghost import under another name", "src/row.rs", "use crate::plan::{spec_contains, spec_gateway,",
     "use crate::plan::{spec_contains as spec_gateway_, spec_gateway,", "refused"),
    ("an import of another library", "src/row.rs", GHOST_USE, GHOST_USE + "use std::cmp::Ordering;\n", "refused"),
    ("a lemma's decreases changed", "src/rebind.rs",
     "        floored(plan, s).len() <= s.len(),\n    decreases s.len(),\n{\n    if s.len() > 0 {\n        let rest",
     "        floored(plan, s).len() <= s.len(),\n    decreases s.len() + 1,\n{\n    if s.len() > 0 {\n        let rest", "changed"),
    ("a specification closed", "src/plan.rs", "pub open spec fn spec_gateway(", "pub closed spec fn spec_gateway(", "changed"),
    ("a derive added", "src/row.rs",
     "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n#[cfg_attr(verus_keep_ghost, verus_verify)]\npub struct Cidr",
     "#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]\n#[cfg_attr(verus_keep_ghost, verus_verify)]\npub struct Cidr",
     "refused"),
    ("a field changed", "src/row.rs", "    pub prefix: u8,\n}", "    pub prefix: u16,\n}", "changed"),
    ("a function made public", "src/row.rs", "fn any_proto(list: &[u8], p: u8) -> bool {",
     "pub fn any_proto(list: &[u8], p: u8) -> bool {", "changed"),
    ("a module of the crate made private", "src/lib.rs", "pub mod sweep;", "mod sweep;", "refused"),
    ("a root attribute dropped", "src/lib.rs", "#![forbid(unsafe_code)]\n", "", "changed"),
    ("a ghost result changed in a contract", "src/slab.rs",
     "            log(2, sview(*self).len() as int + 1) <= probes@ <= log(2, sview(*self).len() as int) + 1,\n",
     "            log(2, sview(*self).len() as int + 1) <= probes@ <= log(2, sview(*self).len() as int) + 2,\n", "changed"),
    ("a body put on the line of a contracted function's signature", "src/row.rs",
     "pub fn arm_admits(arm: RowArm) -> bool {\n    match arm {", "pub fn arm_admits(arm: RowArm) -> bool { match arm {", "refused"),
    ("a spinoff attribute moved onto a specification", "src/row.rs", IN_FIXED, "#[verifier::spinoff_prover]\n" + IN_FIXED, "refused"),
    ("a test module that is not the one this gate reads", "src/row.rs", "#[cfg(test)]\nmod tests {",
     "#[cfg(test)]\nmod checks {", "refused"),
    ("a lemma's body opened on its signature's line", "src/row.rs",
     "        in_fixed(dst),\n    ensures\n        !admits(row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port })),\n{\n}\n",
     "        in_fixed(dst),\n    ensures\n        !admits(row_spec(plan, rules, alias_open, Dest::V4 { dst, proto, port })), {\n}\n",
     "refused"),
    # The other direction: a proof, a body, a comment or a free test may change without the owner.
    ("change only a proof body", "src/row.rs",
     "    assert(0x6440_0000u32 <= a && a <= 0x647f_ffffu32 ==> a >> 22 == 0x191u32) by (bit_vector);\n",
     "    assert(0x6440_0000u32 <= a && a <= 0x647f_ffffu32 ==> a >> 22 == 0x191u32) by (bit_vector);\n    assert(true);\n", None),
    ("change only a lemma's body, to nothing", "src/rebind.rs", LEMMA_BODY, "}\n", None),
    ("add a proof block inside a shipped function", "src/row.rs", GATEWAY,
     GATEWAY + "    #[cfg(verus_keep_ghost)]\n    proof! {\n        assert(gateway == (dst == plan.gateway()));\n    }\n", None),
    ("change only a proof block", "src/rebind.rs", FLOOR_PROOF, FLOOR_PROOF + "            assert(i < addrs.len());\n", None),
    ("change only a ghost declaration", "src/slab.rs", "            let ghost p0: int = count;\n",
     "            let ghost p0: int = count + 0;\n", None),
    ("change only a loop invariant", "src/row.rs",
     "            forall|j: int| 0 <= j < i ==> !cidr_contains(#[trigger] list@[j], a),\n",
     "            forall|j: int| 0 <= j < i ==> !cidr_contains(#[trigger] list@[j], a) && true,\n", None),
    ("change only a shipped function's body", "src/row.rs", "    if !covered && !allowed_subnet(rules, dst) {",
     "    if !allowed_subnet(rules, dst) && !covered {", None),
    ("change only a comment", "src/row.rs", "    // A private address that passed the arm above is covered by the allowed\n",
     "    // A private address that passed the arm above is already covered by the allowed\n", None),
    ("change only a doc comment on a specification", "src/row.rs", "/// Some block of `s` contains `a`.\n",
     "/// At least one block of `s` contains `a`.\n", None),
    ("change only a comment inside a lemma's statement", "src/plan.rs",
     "        // (a) pairwise distinct, in address order, and inside the block\n",
     "        // (a) pairwise distinct, in address order, inside the block\n", None),
    ("change only a comment in a Kani harness", "src/plan.rs", "        // (c) leasable implies inside and not one of the seven\n",
     "        // (c) a leasable address is inside and is not one of the seven\n", None),
    ("change only a unit test", "src/row.rs",
     "        assert_eq!(decide_row(&plan(), &r, false, Dest::Arp), RowArm::Arp);",
     "        assert_eq!(RowArm::Arp, decide_row(&plan(), &r, false, Dest::Arp));", None),
    ("add a unit test", "src/row.rs", "    #[test]\n    fn only_four_arms_admit() {",
     "    #[test]\n    fn arp_admits() {\n        assert!(arm_admits(RowArm::Arp));\n    }\n\n    #[test]\n    fn only_four_arms_admit() {", None),
    ("change only the prose of a control document", "verus/controls-row.md",
     "Generated by controls.py --lists from", "Generated by controls.py from", None),
    ("change only the prose of the assumption registry", "axioms/REGISTRY.md", "## About the world\n", "## About the world outside\n", None),
    ("change only a test helper in a file with no cited unit checks", "src/row.rs",
     "    fn open() -> RowRules {\n        RowRules {\n            allow_protocols: None,",
     "    fn open() -> RowRules {\n        RowRules {\n            allow_protocols: None::<Vec<u8>>,", None),
    ("change only a unit check no row cites", "src/gate.rs",
     "        assert!(!g.register(NET + 1, row(NET + 1, None)));\n",
     "        assert!(!g.register(NET + 1, row(NET + 1, None)), \"the gateway\");\n", None),
    ("add another crate's count to the CI script", "ci/verus.sh", COUNT,
     COUNT + "expect boxplan 77\n", None),
    ("change only the README", "README.md", None, "replaced\n", None),
]

# Edits this gate lets through although they weaken what the crate claims or how it is checked. Each is
# a known gap, kept here so that it stays known: the selftest requires that it still passes, and says so.
GAPS = [
    ("a module's own statement of its theorems weakened (doc comments are free outside lib.rs)", "src/row.rs",
     "//!   V3  a frame to 169.254.0.0/16 or 127.0.0.0/8 is never admitted;\n",
     "//!   V3  a frame to 169.254.0.0/16 is never admitted;\n"),
    ("a control no longer run, its reason changed in the generated list alone (the list's second table is not "
     "a control table; controls.toml, which is locked, still holds the reason)", "verus/controls-flow.md",
     "| 7b/fc3 | retired | run as its adaptation flow:FC3, which carries the public row |",
     "| 7b/fc3 | retired | no longer needed |"),
    ("the crate's README rewritten (free prose)", "README.md", None, "netcore\n"),
]

# Started the plain way, as someone would by hand: the gate must isolate itself. Each module is put beside
# the gate's copy, or where the environment points, and a contract is weakened too.
ANSWERS = 'import os\nprint("statements match the lock")\nos._exit(0)\n'
PLANTS = [
    ("a module beside the gate that answers its import", "gate/difflib.py", False),
    ("a module the environment points at that answers its import", "planted/difflib.py", True),
]


def edit(root, relative, old, new):
    """Applies one edit under `root`. Returns None, or why the entry is stale."""
    path = os.path.join(root, relative)
    if old is None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as file:
            file.write(new)
        return None
    if old == "symlink-gone":
        os.remove(path)
        return None
    if old == "symlink":
        os.remove(path)
        os.symlink(new, path)
        return None
    with open(path, encoding="utf-8", newline="") as file:
        text = file.read()
    if isinstance(old, tuple):
        lines = text.split("\n")
        found = [index for index, line in enumerate(lines) if line.startswith(old[1])]
        if len(found) != 1:
            return f"{relative}: not exactly one line starts with {old[1]!r}"
        lines[found[0]] = (lines[found[0]] + new) if new else None
        text = "\n".join(line for line in lines if line is not None)
    else:
        if text.count(old) != 1:
            return f"{relative}: text not found exactly once"
        text = text.replace(old, new)
    with open(path, "w", encoding="utf-8", newline="") as file:
        file.write(text)
    return None


def vir_form(text, pattern):
    """(start, end) of the one top-level form of the account whose function path matches `pattern`."""
    found = [match.start() for match in re.finditer(r":name \(Fun :path " + pattern + r"\)", text)]
    if len(found) != 1:
        return None
    start = text.rfind("\n(@ ", 0, found[0]) + 1
    end = text.find("\n(", found[0])
    return start, len(text) if end < 0 else end + 1


def in_form(pattern, old, new):
    """An edit of the account: in the form of `pattern`, the first `old` after its name becomes `new`."""
    def apply(text):
        bounds = vir_form(text, pattern)
        if not bounds:
            return None
        form = text[bounds[0]:bounds[1]]
        at = form.find(old)
        if at < 0:
            return None
        return text[:bounds[0]] + form[:at] + new + form[at + len(old):] + text[bounds[1]:]
    return apply


def without_form(pattern):
    def apply(text):
        bounds = vir_form(text, pattern)
        return None if not bounds else text[:bounds[0]] + text[bounds[1]:]
    return apply


def with_copy(pattern, old_name, new_name):
    def apply(text):
        bounds = vir_form(text, pattern)
        return None if not bounds else text + "\n" + text[bounds[0]:bounds[1]].replace(old_name, new_name, 1)
    return apply


def spans_moved(file):
    def apply(text):
        return re.sub(r'"' + re.escape(file) + r':(\d+):(\d+): (\d+):(\d+)',
                      lambda m: f'"{file}:{int(m.group(1)) + 1}:{m.group(2)}: {int(m.group(3)) + 1}:{m.group(4)}', text)
    return apply


NETWORK_PATH = r"lib::t%plan::impl&%\d+::network"
# Edits of a copy of Verus's account (and, for the honest one, of the crate), and what `view.py --check` must
# say: "changed" (a difference from VIEW.lock), "disagrees" (the account and the text describe different
# crates), "refused", or None (it must pass).
VIEW = [
    ("a function's ensures changed in the account", in_form(NETWORK_PATH, "(BinaryOp Eq Spec)", "(BinaryOp Ne Spec)"),
     None, "changed"),
    ("a function's requirement dropped in the account",
     in_form(NETWORK_PATH, ":require (", ":require (\n  ) :was_require ("), None, "changed"),
    ("a specification's body changed in the account", in_form(r"lib::t%row::in_fixed", "(Constant Int 127)", "(Constant Int 126)"), None, "changed"),
    ("a function turned into external_body", in_form(r"lib::t%row::decide_row", ":is_external_body false",
                                                      ":is_external_body true"), None, "disagrees"),
    ("a function's termination assumed", in_form(r"lib::t%row::any_covers", ":exec_assume_termination false",
                                                  ":exec_assume_termination true"), None, "disagrees"),
    ("a specification made opaque in the account alone", in_form(r"lib::t%row::in_fixed", "(Opaqueness Revealed",
                                                                  "(Opaqueness Opaque"), None, "disagrees"),
    ("a function removed from the account", without_form(r"lib::t%row::arm_admits"), None, "disagrees"),
    ("a function added that the text does not list", with_copy(r"lib::t%row::arm_admits", "::arm_admits)", "::arm_admits_too)"),
     None, "disagrees"),
    ("a generated twin missing", without_form(r"lib::t%slab::impl&%\d+::_VERUS_VERIFIED_lower"), None, "disagrees"),
    ("a third external_body stub", in_form(r"lib::t%slab::impl&%\d+::find", ":is_external_body false",
                                           ":is_external_body true"), None, "disagrees"),
    ("a stub made callable", in_form(r"lib::t%slab::impl&%\d+::lower", "(Constant Bool false)", "(Constant Bool true)"),
     None, "disagrees"),
    ("the account cut short", lambda text: text[:len(text) // 2], None, "refused"),
    # Honest: the source moved down a line, and the account with it.
    ("spans moved, with the source", spans_moved("src/plan.rs"), ("src/plan.rs", "//! The address plan", "//\n//! The address plan"), None),
]


def view_attempt(what, change, crate_edit, expected, verbose):
    """Applies `change` to a copy of the account (and `crate_edit` to a copy of the crate), runs `view.py --check`."""
    with tempfile.TemporaryDirectory(dir=HERE, prefix=".selftest-") as scratch:
        crate, gate = os.path.join(scratch, "netcore"), os.path.join(scratch, "gate")
        shutil.copytree(CRATE, crate, symlinks=True)
        os.makedirs(gate)
        os.makedirs(os.path.join(scratch, "ci-verus"))
        shutil.copy(VERUS_SCRIPT, os.path.join(scratch, "ci-verus", "verus.sh"))
        for name in GATE_FILES:
            shutil.copy(os.path.join(HERE, name), os.path.join(gate, name))
        with open(VIR, encoding="utf-8", newline="") as file:
            text = change(file.read())
        if text is None:
            print(f"STALE      {what}: the account's text not found exactly once")
            return 1
        account = os.path.join(scratch, "crate.vir")
        with open(account, "w", encoding="utf-8", newline="") as file:
            file.write(text)
        if crate_edit:
            stale = edit(crate, *crate_edit)
            if stale:
                print(f"STALE      {what}: {stale}")
                return 1
        done = subprocess.run([sys.executable, "-I", "-B", os.path.join(gate, "view.py"), "--check", "--vir", account,
                               "--crate", crate, "--lock", os.path.join(gate, "VIEW.lock")],
                              capture_output=True, text=True, check=False)
    output = done.stdout + done.stderr
    failed = done.returncode != 0
    reason = ("refused" if output.startswith("REFUSED") else "disagrees" if "DO NOT DESCRIBE THE SAME CRATE" in output
              else "changed" if "WHAT VERUS REPORTS CHANGED" in output else "other")
    right = (not failed) if expected is None else (failed and reason == expected)
    note = "" if right or expected is None else f" (expected {expected})"
    print(f"{'ok        ' if right else 'WRONG     '} {what}: {'passed' if not failed else reason}{note}")
    if verbose or not right:
        for line in output.splitlines()[:6]:
            print(f"             {line[:160]}")
    return int(not right)


def attempt(what, edits, expected, verbose, environment=False, isolated=True):
    """Applies `edits` to a copy of the crate and of the gate, and runs the gate's copy. Returns 1 when wrong."""
    with tempfile.TemporaryDirectory(dir=HERE, prefix=".selftest-") as scratch:
        crate, gate = os.path.join(scratch, "netcore"), os.path.join(scratch, "gate")
        shutil.copytree(CRATE, crate, symlinks=True)
        os.makedirs(gate)
        os.makedirs(os.path.join(scratch, "ci"))
        shutil.copy(VERUS_SCRIPT, os.path.join(scratch, "ci", "verus.sh"))
        for name in GATE_FILES:
            shutil.copy(os.path.join(HERE, name), os.path.join(gate, name))
        for relative, old, new in edits:
            root = scratch if relative.startswith(("gate/", "planted/", "ci/")) else crate
            stale = edit(root, relative, old, new)
            if stale:
                print(f"STALE      {what}: {stale}")
                return 1
        command = [sys.executable] + (["-I", "-B"] if isolated else []) + [
            os.path.join(gate, "statements.py"), "--check", "--crate", crate, "--lock", os.path.join(gate, "STATEMENTS.lock"),
            "--verus-script", os.path.join(scratch, "ci", "verus.sh")]
        variables = dict(os.environ, **({"PYTHONPATH": os.path.join(scratch, "planted")} if environment else {}))
        done = subprocess.run(command, capture_output=True, text=True, check=False, env=variables)
    output = done.stdout + done.stderr
    failed = done.returncode != 0
    reason = "refused" if output.startswith("REFUSED") else "changed" if "THE STATEMENTS CHANGED" in output else "other"
    right = (not failed) if expected is None else (failed and reason == expected)
    shown = "passed" if not failed else reason
    note = "" if right or expected is None else f" (expected {expected})"
    print(f"{'ok        ' if right else 'WRONG     '} {what}: {shown}{note}")
    if verbose or not right:
        for line in output.splitlines()[:6]:
            print(f"             {line[:160]}")
    return int(not right)


def main():
    global CRATE
    arguments = sys.argv[1:]
    verbose = "-v" in arguments
    if "--crate" in arguments:
        CRATE = os.path.abspath(arguments[arguments.index("--crate") + 1])
    wrong = caught = passed = 0
    attacks = [entry for entry in ATTACKS if entry[4] is not None]
    honest = [entry for entry in ATTACKS if entry[4] is None]
    print("attacks (the gate must fail, for the reason named):")
    for what, relative, old, new, expected in attacks:
        result = attempt(what, [(relative, old, new)], expected, verbose)
        wrong, caught = wrong + result, caught + 1 - result
    for what, relative, by_environment in PLANTS:
        weakened = ("src/row.rs", DECIDE_ENSURES, "        true,\n")
        result = attempt(what, [(relative, None, ANSWERS), weakened], "changed", verbose,
                         environment=by_environment, isolated=False)
        wrong, caught = wrong + result, caught + 1 - result
    print("honest edits (the gate must pass):")
    for what, relative, old, new, expected in honest:
        result = attempt(what, [(relative, old, new)], None, verbose)
        wrong, passed = wrong + result, passed + 1 - result
    print("known gaps (the gate lets these through; each must still pass, so that the list stays true):")
    gaps = 0
    for what, relative, old, new in GAPS:
        result = attempt(what, [(relative, old, new)], None, verbose)
        wrong, gaps = wrong + result, gaps + 1 - result
    print("the second lock, on edited copies of Verus's account:")
    view_caught = view_passed = 0
    entries = VIEW
    if not os.path.isfile(VIR):
        print(f"WRONG      the second lock is not attacked: no account at {VIR!r} (give `--vir FILE`)")
        wrong += 1
    elif view_attempt("the account as it stands (nothing edited: this must pass, or no attack below counts)",
                      lambda text: text, None, None, verbose):
        print("WRONG      the second lock is not attacked: the unedited account does not pass")
        wrong += 1
    else:
        for what, change, crate_edit, expected in entries:
            result = view_attempt(what, change, crate_edit, expected, verbose)
            wrong += result
            if expected is None:
                view_passed += 1 - result
            else:
                view_caught += 1 - result
    view_attacks = sum(entry[3] is not None for entry in entries)
    print(f"attacks caught for the reason named: {caught} of {len(attacks) + len(PLANTS)}; "
          f"honest edits passed: {passed} of {len(honest)}; known gaps let through as listed: {gaps} of {len(GAPS)}; "
          f"second lock: {view_caught} of {view_attacks} caught, {view_passed} of {len(entries) - view_attacks} honest passed")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
