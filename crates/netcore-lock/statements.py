#!/usr/bin/env python3
"""The statement lock of netcore: what is claimed, apart from how it is proved.

    python3 statements.py --check [--crate DIR] [--lock FILE]    (the gate; exit 1 on any difference)
    python3 statements.py --write [--crate DIR] [--lock FILE]    (the owner, after reading the diff)
    --verus-script PATH    the CI script that pins the verified count (default ../../scripts/verus.sh)

The crate defaults to ../netcore beside this script's directory, the lock to
STATEMENTS.lock beside this script.

A checker only says a proof matches its statement. The cheap way to make a
failing proof pass is to change the statement: weaken an `ensures`, redefine
a specification function, narrow a Kani harness, delete an assumption row.
This script extracts every statement of the crate into one text,
`STATEMENTS.lock`, so that such a change is a visible diff in a file whose
owner is a person, and the gate fails until that file is updated on purpose.

What is locked, as text:
  * every file under the crate, by name and by how the lock holds it;
  * the manifest, and the crate root (`src/lib.rs`) whole, its doc comments
    included: the theorem index is written there;
  * every item of each source file outside the tests and the Kani code, in
    order: each import, each type and constant whole, each function's
    signature and attributes; a function that carries no contract, whole;
  * in each `verus! { ... }` block: every specification function whole, and
    every proof function's attributes and signature with its `requires`,
    `ensures` and `decreases`, but not its body;
  * every `verus_spec` contract on an executable function, with the
    function's signature; not the contracts of loops (their invariants);
  * every item under `#[cfg(kani)]`, whole: a harness has no proof body;
  * the unit checks a row of the theorem index cites (CITED_TESTS), each
    function whole; the rest of the test module is free;
  * the line `expect netcore <count>` of the CI script that runs Verus, and
    that script but for other crates' counts, by hash;
  * the rows of `axioms/REGISTRY.md`;
  * the rows of every table of a control document (`verus/*.md`; the copies
    in `public/controls/` are regenerated from these and are free) whose header names where a control must fail,
    the harness that must fail, or a control's replacement text;
And by content hash: this script and its selftest.

Free: proof bodies, `proof!`, `proof_decl!` and `proof_with!` blocks, loop
invariants, the bodies of functions with a contract, comments (but in
`src/lib.rs`), unit tests, and the documents listed as free.

The source is read twice, by lines and as tokens, and the two readings must
agree. What is not on a list is refused: an attribute, a macro, an item, a
file, a character. A line ends at a line feed and nowhere else, a string does
not run over a line end, and every compiler condition is judged a second
time by lines alone, where no string can hide it.

What this cannot do: it reads text, and what Verus checks is decided by the
compiler. The template's second lock (`view.py`, what Verus reports having
checked) is not adapted for this crate.
"""

import sys

if not (sys.flags.isolated and sys.dont_write_bytecode):
    # Before any import that a file beside this script could answer: start again in isolated mode,
    # where neither the script's directory nor the environment is searched for modules.
    import posix

    posix.execv(sys.executable, [sys.executable, "-I", "-B"] + sys.argv)

import collections
import difflib
import hashlib
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.join(os.path.dirname(HERE), "netcore")
LOCK = os.path.join(HERE, "STATEMENTS.lock")
GATES = ("statements.py", "statements_selftest.py", "view.py", "controls.py")
# The file of record for the negative controls, beside this script: locked whole, but for blank lines.
MANIFEST = "controls.toml"
# The script that runs Verus on the crate in CI, and the count it pins for this crate.
VERUS_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts", "verus.sh")
if not os.path.isfile(VERUS_SCRIPT) and os.path.isfile(os.path.join(os.path.dirname(HERE), "ci-verus", "verus.sh")):
    # A checkout that keeps the script beside the crate.
    VERUS_SCRIPT = os.path.join(os.path.dirname(HERE), "ci-verus", "verus.sh")
COUNT_LINE = re.compile(r"expect netcore [0-9]+")
OTHER_COUNT = re.compile(r"expect (?!netcore )[a-z][a-z0-9_-]* [0-9]+")
# The unit checks a row of the theorem index in `src/lib.rs` cites, by file, name and row. Each is locked
# whole; the rest of its test module is free. SP1's row says "and by example in the gate's unit checks":
# the first carries the comment "SP1 by example", the second checks SP1's last clause (a configuration
# without one declaration for each registered row routes nothing).
CITED_TESTS = {
    "src/gate.rs": [("plan_then_judge_decides_as_the_whole_gate_does", "SP1"),
                    ("a_configuration_short_of_a_declaration_routes_nothing", "SP1")],
}
# The helpers of the test module the cited unit checks call, directly or through another helper, and the
# constants they read; each locked whole. Read from the call graph; the gate checks that nothing locked uses
# an item of the module that is not locked.
CITED_HELPERS = {
    "src/gate.rs": [(name, ["the SP1 checks"]) for name in
                    ("NET", "NODE", "PUBLIC", "tables", "row", "gate", "gate_with", "gate_spelled", "tcp", "config")],
}
TEST_ATTRIBUTE = "#[test]"

# Every file under the crate, and how the lock holds it. A file that matches no line is refused.
FILES = [
    (r"Cargo\.toml", "text"),
    (r"src/[a-z]+\.rs", "source"),
    (r"axioms/REGISTRY\.md", "rows"),
    (r"verus/[A-Za-z0-9-]+\.md", "controls"),
    # Prose, designs, drafts and the fuzz crate: not compiled into netcore and not a statement. The
    # controls in `public/controls/` are regenerated from `verus/`, which is the record.
    (r"README\.md|public/README\.md|public/controls/[A-Za-z]+\.md|design/[A-Za-z0-9-]+\.md", "free"),
    (r"next/[a-z0-9-]+\.(md|rs)|fuzz/Cargo\.toml|fuzz/fuzz_targets/[a-z_]+\.rs", "free"),
]

# Beside printable ASCII and the line feed, the characters a file may hold. Source and manifest: none.
ALSO_IN_DOCUMENTS = "…′→″§−·"

# Verus's ways to accept something unproved, and ways to hide code. None may appear on a line of code.
FORBIDDEN = [
    r"\bassume\s*\(", r"\bassume_\b", r"\badmit\s*\(\s*\)", r"\badmit_\b", r"\bassume_specification\b",
    r"\bverus_builtin\b", r"\bbuiltin\s*::", r"\bexternal_body\b", r"\bexternal\b", r"\bexternal_fn_specification\b",
    r"\bexternal_type_specification\b", r"\baxiom\b", r"\bunimplemented\s*!", r"\btodo\s*!",
    r"\bcfg\s*!", r"#\s*!?\s*\[\s*path\b", r"\binclude(_str|_bytes)?\s*!", r"\bmacro_rules\s*!", r"/\*",
    r"\b(?:option_)?env\s*!", r"\bverus\s*::", r"\bunsafe\b", r"\bextern\b",
]
# `macro_rules!` is in use in the Kani code, which is locked whole; nowhere else.
FORBIDDEN_BUT_IN_KANI = {r"\bmacro_rules\s*!"}
# The paths into the Verus library in use. Any other is refused.
VSTD = re.compile(r"use vstd::prelude::\*;|use vstd::arithmetic::logarithm::log;|"
                  r"vstd::arithmetic::logarithm::lemma_log_(?:is_ordered|nonnegative)\(.*")

# The attributes in use, as written. Each is spelled twice: as tokens (a space only between two words)
# and as lines (no white space at all), and each reading compares with its own spelling.
GHOST_SRC = "#[cfg(verus_keep_ghost)]"
CHECKED_SRC = "#[cfg_attr(verus_keep_ghost, verus_verify)]"
CONTRACT = "#[cfg_attr(verus_keep_ghost,verus_spec("
TEST_SRC = "#[cfg(test)]"
KANI_SRC = "#[cfg(kani)]"
KANI_FULL_SRC = '#[cfg(feature = "kani-full")]'
OPAQUE_SRC = "#[verifier::opaque]"
SPINOFF_SRC = "#[verifier::spinoff_prover]"
DERIVE_SRC = "#[derive(Debug, Clone, Copy, PartialEq, Eq)]"
DEAD_CODE_SRC = '#[cfg_attr(not(test), expect(dead_code, reason = "used once the table is kept sorted"))]'
ROOT_SRC = [
    '#![expect(clippy::indexing_slicing, reason = "Verus proves every index in the verified functions in bounds: no panic path")]',
    '#![expect(clippy::manual_map, clippy::len_without_is_empty, clippy::collapsible_if, reason = "the kernel keeps the explicit matches, comparisons and arithmetic its proofs are written against")]',
    '#![expect(clippy::too_many_arguments, reason = "the gate\'s constructor and its DNS entry points take each part and each list by name; a struct of arguments would be one more type to specify")]',
    '#![expect(clippy::ptr_arg, reason = "`reset_rows` is specified over the vector the gate owns; a slice would need a second view in its contract")]',
    "#![forbid(unsafe_code)]",
    "#![cfg_attr(verus_keep_ghost, feature(proc_macro_hygiene))]",
    "#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]",
]
# In the Kani code, which is locked whole: the attributes it holds.
IN_KANI = re.compile(r"#\[derive\(Clone,Copy\)\]|#\[kani::proof\]|#\[kani::unwind\([0-9]+\)\]|#\[cfg\(feature=\"kani-full\"\)\]")
# Inside ghost code and contracts.
IN_GHOST_CODE = re.compile(r"#\[trigger\]|#!\[trigger .+\]")
# The macros in use in code that ships.
MACROS = {"vec", "matches"}
# The ghost blocks inside an executable function: each under the ghost-only condition.
PROOF_MACROS = {"proof", "proof_decl", "proof_with"}
# Words that start an item. None may appear inside a function: an item there is in scope for the
# function's own contract, and can stand in for the specification the contract names.
ITEM_WORDS = {"fn", "use", "mod", "impl", "struct", "enum", "union", "trait", "static", "const", "type", "extern",
              "unsafe", "macro", "macro_rules", "async"}
# A word before `!(` that is an operator's left side, not a macro's name.
NOT_A_MACRO = {"if", "while", "match", "return", "in", "else", "let", "break", "as", "mut", "ref", "move", "implies"}
# What leaves a function. A proof block exists only for Verus, so it must not decide what the function does.
LEAVES = {"return", "break", "continue", "?"}
# The words a compiler condition or a Verus marker is written with. Each occurrence must be at a known
# place of an attribute this gate has accepted: a second way of asking what the attribute lists ask.
MARKERS = {"cfg", "cfg_attr", "verus_keep_ghost", "verus_verify", "verus_spec", "verifier"}
MARKED = re.compile(r"\b(?:" + "|".join(sorted(MARKERS)) + r")\b")
# In the test module, which is free, `cfg` may name a value; a condition there is still judged.
MARKED_IN_TESTS = re.compile(r"\bcfg(?:_attr)?\s*[(!]|\b(?:verus_keep_ghost|verus_verify|verus_spec|verifier)\b")
# The same question asked of lines alone: what may follow each condition, on the next line of code.
AFTER_GHOST = re.compile(r"usevstd::prelude::\*;|usevstd::arithmetic::logarithm::log;"
                         r"|usecrate::[a-z_]+(::[a-z_]+)*(::\{[A-Za-z0-9_,]+\}|::[A-Za-z0-9_]+);"
                         r"|verus!\{|proof(_decl|_with)?!\{(.*\})?")
AFTER_TEST = "mod tests {"
AFTER_KANI = re.compile(r"mod proofs \{|impl [A-Z][A-Za-z0-9]* \{|pub\(crate\) fn kani_[a-z0-9_]+\(.*")
AFTER_OPAQUE = re.compile(r"(pub )?(open |closed )?spec fn [a-z0-9_]+\(.*")
AFTER_SPINOFF = re.compile(r"(pub )?proof fn [a-z0-9_]+\(.*")
LEAVES_A_LINE = re.compile(r"\b(?:return|break|continue)\b|\?")
GHOST_QUALIFIERS = {"open", "closed", "spec", "proof"}
STARTS_A_GHOST_ITEM = GHOST_QUALIFIERS | {"#", "pub", "fn"}
# A control document's table is a table of controls when its header names where a control must fail, the
# harness that must fail, or the replacement text a control applies.
CONTROL_HEADER = re.compile(r"fail|harness|replacement", re.IGNORECASE)
REGISTRY_ROW = re.compile(r"\| [A-Z]+[0-9]+ \|")

Token = collections.namedtuple("Token", "kind text line")
RAW_STRING = re.compile(r'[bc]?r(#*)"')
LEXEMES = [
    ("s", re.compile(r'[bc]?"(?:[^"\\]|\\.)*"', re.DOTALL)),
    ("s", re.compile(r"b?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,8}\}|[^xu])|[^\\'\n])'")),
    ("l", re.compile(r"'[A-Za-z_][A-Za-z0-9_]*")),
    ("w", re.compile(r"[A-Za-z_][A-Za-z0-9_]*")),
    ("w", re.compile(r"[0-9][0-9A-Za-z_]*(?:\.[0-9][0-9A-Za-z_]*)?")),
    ("p", re.compile(r"<==>|=~~=|==>|<==|===|!==|=~=|&&&|\|\|\||\.\.=|<<=|>>=|::|->|=>|==|!=|<=|>=|&&|\|\||\.\."
                     r"|[-+*/%^&|]=|[{}()\[\]<>,;:.#!?=+\-*/%&|^~@$]")),
]
CLOSES = {"(": ")", "[": "]", "{": "}"}


ITEMS = []


class Refused(Exception):
    """The source is not in the layout this extractor reads, or holds something refused."""


def read(relative, also=""):
    """A file's lines. A line ends at a line feed and nowhere else: read the usual way, a carriage return
    would end one here and not for the compiler."""
    with open(os.path.join(CRATE, relative), encoding="utf-8", newline="") as file:
        lines = file.read().split("\n")
    for number, line in enumerate(lines, 1):
        for char in line:
            if not (" " <= char <= "~" or char in also):
                raise Refused(f"{relative}:{number}: a character this gate does not read: {char!r}")
    return lines


def is_comment(line):
    """A line that is a `//` comment and nothing else. Block comments are refused, so such a line holds no code."""
    return line.lstrip().startswith("//")


def without_comment(line):
    """The line without a trailing `//` comment. No string in the code this reads holds `//`."""
    return line.split("//", 1)[0]


def code(lines):
    """Lines without blank lines and lines that are only a comment, each without a trailing comment."""
    return [without_comment(line).rstrip() for line in lines if line.strip() and not is_comment(line)]


def tokenize(relative, text):
    """The file as tokens: words, literals, lifetimes and punctuation, each with its line. Comments are left out."""
    out, index, line = [], 0, 1
    while index < len(text):
        char = text[index]
        if char in " \n":
            line += char == "\n"
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        found, raw = None, RAW_STRING.match(text, index)
        if raw:
            end = text.find('"' + raw.group(1), raw.end())
            if end >= 0:
                found = ("s", text[index:end + 1 + len(raw.group(1))])
        else:
            for kind, pattern in LEXEMES:
                matched = pattern.match(text, index)
                if matched:
                    found = (kind, matched.group(0))
                    break
        if not found:
            raise Refused(f"{relative}:{line}: a character this gate does not read: {char!r}")
        if "\n" in found[1]:
            # Then which lines are code would depend on where a string starts, and the two readings could differ.
            raise Refused(f"{relative}:{line}: a string that runs over a line end")
        out.append(Token(found[0], found[1], line))
        index += len(found[1])
    return out


def spelled(tokens):
    """Tokens as one string: a space only between two words, and no comma before a closing bracket."""
    out, previous = [], None
    for position, token in enumerate(tokens):
        closes_next = position + 1 < len(tokens) and tokens[position + 1].text in (")", "]")
        if token.text == "," and token.kind == "p" and closes_next:
            continue
        if previous and previous.kind == "w" and token.kind == "w":
            out.append(" ")
        out.append(token.text)
        previous = token
    return "".join(out)


def by_tokens(source):
    return spelled(tokenize("(this script)", source))


def by_lines(source):
    return re.sub(r"\s", "", source).replace(",)", ")")


GHOST, CHECKED, TEST, KANI = by_tokens(GHOST_SRC), by_tokens(CHECKED_SRC), by_tokens(TEST_SRC), by_tokens(KANI_SRC)
OPAQUE, SPINOFF, DERIVE, DEAD_CODE = by_tokens(OPAQUE_SRC), by_tokens(SPINOFF_SRC), by_tokens(DERIVE_SRC), by_tokens(DEAD_CODE_SRC)
ON_THE_ROOT = {by_tokens(form) for form in ROOT_SRC}
ON_A_TYPE = {CHECKED, DERIVE}
ON_A_FUNCTION = {CHECKED, DEAD_CODE}
LINE_FORMS = {name: by_lines(source) for name, source in [
    ("ghost", GHOST_SRC), ("checked", CHECKED_SRC), ("test", TEST_SRC), ("kani", KANI_SRC), ("full", KANI_FULL_SRC),
    ("opaque", OPAQUE_SRC), ("spinoff", SPINOFF_SRC), ("dead", DEAD_CODE_SRC)]}
ROOT_LINE_FORMS = {by_lines(form) for form in ROOT_SRC}


class Source:
    """One source file, read as tokens: its items in order, and everything in it that is refused."""

    def __init__(self, relative, lines):
        self.relative, self.lines = relative, lines
        self.tokens = tokenize(relative, "\n".join(lines))
        self.match, self.found, self.inventory, self.counts = {}, [], [], collections.Counter()
        self.proof_bodies, self.contracts, self.kani, self.tests, self.known, self.unread = [], 0, [], [], set(), []
        self.ghost, self.contract_spans, self.items, self.owner = [], [], [], None
        stack = []
        for index, token in enumerate(self.tokens):
            if token.kind != "p":
                continue
            if token.text in CLOSES:
                stack.append(index)
            elif token.text in CLOSES.values():
                if not stack or CLOSES[self.tokens[stack[-1]].text] != token.text:
                    raise Refused(f"{relative}:{token.line}: a bracket that closes nothing")
                self.match[stack.pop()] = index
        if stack:
            raise Refused(f"{relative}:{self.tokens[stack[-1]].line}: a bracket that never closes")
        try:
            self.parse(0, len(self.tokens), "file", 0, False)
        except (IndexError, KeyError):
            raise Refused(f"{relative}: the file ends in the middle of an item") from None
        tests = [range(first, last + 1) for first, last in self.tests]
        for index, token in enumerate(self.tokens):
            if any(index in span for span in tests):
                continue
            if token.kind == "s" and "//" in token.text:
                self.refuse(index, "a string that holds `//`, which the reading by lines takes for a comment")
            if any(first <= index <= last for first, last in self.unread):
                continue
            if token.kind == "w" and token.text in MARKERS and index not in self.known:
                self.refuse(index, f"`{token.text}` outside the attributes this gate knows")

    def refuse(self, index, why):
        line = self.tokens[index].line
        self.found.append(f"{self.relative}:{line}: {why}: {self.lines[line - 1].strip()}")

    def is_punct(self, index, *texts):
        return self.tokens[index].kind == "p" and self.tokens[index].text in texts

    def until(self, index, *texts):
        """The first of `texts` at this depth, from `index` on."""
        while not self.is_punct(index, *texts):
            index = self.match.get(index, index) + 1
        return index

    def attribute(self, index):
        """The index of the `]` that closes the attribute starting at `index`."""
        opening = index + 2 if self.is_punct(index + 1, "!") else index + 1
        if not self.is_punct(opening, "["):
            raise Refused(f"{self.relative}:{self.tokens[index].line}: a `#` that starts no attribute")
        return self.match[opening]

    def is_contract(self, index):
        """Whether the attribute at `index` is `#[cfg_attr(verus_keep_ghost, verus_spec(...))]` and carries nothing else:
        a second attribute in the same list would be applied for Verus alone."""
        tokens = self.tokens
        if [token.text for token in tokens[index:index + 8]] != ["#", "[", "cfg_attr", "(", "verus_keep_ghost", ",", "verus_spec", "("]:
            return False
        self.known |= {index + 2, index + 4, index + 6}
        return [token.text for token in tokens[self.match[index + 7] + 1:self.match[index + 1] + 1]] in ([")", "]"], [",", ")", "]"])

    def accept(self, index, close, attribute, *lists):
        """Whether the attribute on tokens `index` to `close` is on one of `lists`; its markers are then at known places."""
        if any(attribute in one if isinstance(one, set) else one.fullmatch(attribute) for one in lists):
            self.known |= set(range(index, close + 1))
            return True
        return False

    def is_macro(self, index):
        token = self.tokens[index]
        return (token.kind == "w" and token.text not in NOT_A_MACRO and self.is_punct(index + 1, "!")
                and self.is_punct(index + 2, "(", "[", "{"))

    def ends_its_line(self, index):
        return index + 1 >= len(self.tokens) or self.tokens[index + 1].line > self.tokens[index].line

    def record(self, depth, first, last, attributes, whole):
        """One line of the inventory for the item on tokens `first` to `last`, and its text when `whole`."""
        shown = " ".join("contract" if a.startswith(CONTRACT) else a for a in attributes)
        indent = "  " * depth
        if not whole:
            self.inventory.append(f"{indent}{spelled(self.tokens[first:last])}{'  @ ' + shown if shown else ''}")
            return
        lines = code(self.lines[self.tokens[first].line - 1:self.tokens[last].line])
        margin = len(lines[0]) - len(lines[0].lstrip())
        self.inventory.append(f"{indent}{lines[0].strip()}{'  @ ' + shown if shown else ''}")
        self.inventory.extend(f"{indent}  {line[margin:] if not line[:margin].strip() else line.strip()}" for line in lines[1:])

    def allow(self, first, attributes, places, *lists):
        for attribute in attributes:
            if not self.accept(*places[attribute], attribute, *lists):
                self.refuse(first, f"an attribute that is not on the list for this item ({attribute})")

    def item(self, kind, first, index, **more):
        """One item for the comparison with the verifier's account (`--items`)."""
        tokens = self.tokens
        self.items.append(dict(file=self.relative, line=tokens[index].line, first=tokens[first].line,
                               name=tokens[index + 1].text, kind=kind, owner=self.owner, attributes_from=self.attributes_from, **more))

    def parse(self, index, end, where, depth, checked):
        """The items on tokens `index` to `end`: of the file, of an `impl`, or of a ghost block."""
        tokens = self.tokens
        while index < end:
            attributes, places = [], {}
            self.attributes_from = tokens[index].line
            while self.is_punct(index, "#"):
                close = self.attribute(index)
                attribute = spelled(tokens[index:close + 1])
                if attribute.startswith(CONTRACT) and not self.is_contract(index):
                    self.refuse(index, "a contract's attribute that carries something else as well")
                if not attribute.startswith("#!"):
                    if attribute in places:
                        self.refuse(index, "an attribute written twice on one item")
                    attributes.append(attribute)
                    places[attribute] = (index, close)
                elif self.relative != "src/lib.rs" or where != "file" or not self.accept(index, close, attribute, ON_THE_ROOT):
                    self.refuse(index, "an attribute of a whole file or block that is not on the list")
                index = close + 1
            if index >= end:
                if attributes:
                    raise Refused(f"{self.relative}:{tokens[index - 1].line}: an attribute on nothing")
                break
            first = index
            if tokens[index].text == "pub":
                index += 1
                if self.is_punct(index, "("):
                    index = self.match[index] + 1
            qualifiers = []
            while where == "ghost" and tokens[index].text in GHOST_QUALIFIERS:
                qualifiers.append(tokens[index].text)
                index += 1
            if tokens[index].text == "const" and tokens[index + 1].text == "fn":
                index += 1
            word, name, line = tokens[index].text, tokens[index + 1].text, tokens[first].line
            contract = [a for a in attributes if a.startswith(CONTRACT)]
            others = [a for a in attributes if not a.startswith(CONTRACT)]
            if contract and (word != "fn" or where == "ghost"):
                self.refuse(first, "a contract on something that is not a function")
            if attributes == [KANI] and where == "file" and word in ("mod", "impl", "fn"):
                # Code for Kani alone: what a harness lets in and how far it unwinds is what it claims.
                opening = self.until(index + 1, "{")
                last = self.match[opening]
                self.known |= set(range(*places[KANI]))
                if not (word == "mod" and name == "proofs" or word == "impl" or word == "fn" and name.startswith("kani_")):
                    self.refuse(first, "Kani code that is not the `proofs` module, an `impl` or a `kani_` function")
                self.kani.append((tokens[places[KANI][0]].line, tokens[last].line))
                self.unread.append((places[KANI][0], last))
                self.in_kani(opening, last)
                self.inventory.append(f"{'  ' * depth}{spelled(tokens[first:opening])}  @ {KANI}  (whole, below)")
                self.counts["kani items"] += 1
            elif word == "use" and where == "file":
                last = self.until(index, ";")
                path = spelled(tokens[index + 1:last])
                self.allow(first, others, places, {GHOST})
                # A second name for an item, or two imports that could name different items under
                # Verus and under the compiler, would let a contract mean something else than it reads.
                vstd, ghost_only = path in ("vstd::prelude::*", "vstd::arithmetic::logarithm::log"), GHOST in others
                if (" as " in path or "*" in path and path != "vstd::prelude::*" or "vstd" in path and not vstd
                        or vstd and not ghost_only or not vstd and not path.startswith("crate::") or first != index):
                    self.refuse(first, "an import that renames, takes everything, or reaches another library")
                self.record(depth, first, last + 1, attributes, whole=False)
                self.counts["imports"] += 1
            elif word == "mod" and self.is_punct(index + 2, ";") and where == "file" and self.relative == "src/lib.rs":
                last = index + 2
                self.allow(first, attributes, places)
                if first == index:
                    self.refuse(first, "a module of the crate that is not public")
            elif word == "mod" and where == "file" and self.is_punct(index + 2, "{") and name == "tests" and attributes == [TEST] and first == index:
                last = self.match[index + 2]
                self.known |= set(range(*places[TEST]))
                self.tests.append((places[TEST][0], last))
                self.unread.append((places[TEST][0], last))
                self.inventory.append(f"{'  ' * depth}mod tests  (free)")
            elif word == "fn" and where == "ghost":
                opening = self.until(index + 2, "{")
                while self.match[opening] + 1 < end and tokens[self.match[opening] + 1].text not in STARTS_A_GHOST_ITEM:
                    opening = self.until(self.match[opening] + 1, "{")
                last = self.match[opening]
                if ("spec" in qualifiers) == ("proof" in qualifiers):
                    self.refuse(first, "a ghost function that is not exactly one of spec and proof")
                self.allow(first, attributes, places, {OPAQUE} if "spec" in qualifiers else {SPINOFF})
                self.inside(index + 2, opening, "a ghost function's signature")
                if "proof" in qualifiers:
                    if self.lines[tokens[opening].line - 1] != "{" or self.lines[tokens[last].line - 1] != "}":
                        self.refuse(first, "a lemma whose body does not open on a line `{` and close on a line `}`")
                    self.proof_bodies.append((tokens[opening].line, tokens[last].line))
                self.inside(opening, last, "a lemma's body" if "proof" in qualifiers else "a specification")
                self.counts["proof functions" if "proof" in qualifiers else "specification functions"] += 1
                self.item("proof" if "proof" in qualifiers else "spec", first, index, opaque=OPAQUE in attributes)
                self.counts["opaque specifications"] += OPAQUE in attributes
            elif word == "fn" and where in ("file", "impl"):
                opening = self.until(index + 2, "{", ";")
                if self.is_punct(opening, ";"):
                    raise Refused(f"{self.relative}:{line}: a function without a body")
                last = self.match[opening]
                self.allow(first, others, places, ON_A_FUNCTION)
                if len(contract) > 1:
                    self.refuse(first, "two contracts on one function")
                self.contracts += len(contract)
                # A body is free when a checker holds it to a locked statement. A function with no
                # contract has no such statement: what it does is its text, so its text is locked.
                for one in contract:
                    self.contract_spans.append((tokens[places[one][0]].line, tokens[places[one][1]].line))
                if contract and not self.ends_its_line(opening):
                    self.refuse(first, "a function with a contract whose body does not start at the end of a line")
                self.record(depth, first, opening if contract else last, attributes, whole=not contract)
                self.inside(opening, last, "a function")
                self.counts["functions with a contract" if contract else "functions without a contract, whole"] += 1
                self.item("exec", first, index, contract=bool(contract), verify=CHECKED in attributes or checked)
            elif word in ("struct", "enum") and where == "file":
                last = self.until(index + 2, "{", "(", ";")
                if not self.is_punct(last, ";"):
                    last = self.match[last] if self.is_punct(last, "{") else self.until(self.match[last], ";")
                self.allow(first, others, places, ON_A_TYPE)
                self.record(depth, first, last, attributes, whole=True)
                self.counts["types"] += 1
                self.item("type", first, index, derives=[a for a in attributes if a.startswith("#[derive(")])
            elif word == "impl" and where == "file":
                opening = self.until(index + 1, "{")
                last = self.match[opening]
                self.allow(first, others, places, {CHECKED})
                if first != index:
                    self.refuse(first, "an `impl` with a visibility")
                self.record(depth, first, opening, attributes, whole=False)
                self.owner = spelled(tokens[index + 1:opening])
                self.parse(opening + 1, last, "impl", depth + 1, CHECKED in attributes)
                self.owner = None
            elif word == "const" and where in ("file", "impl"):
                last = self.until(index + 1, ";")
                self.allow(first, others, places, {CHECKED})
                self.record(depth, first, last, attributes, whole=True)
                self.counts["constants"] += 1
                self.item("const", first, index, verify=CHECKED in attributes or checked)
            elif (word == "verus" and where == "file" and first == index and attributes == [GHOST]
                  and self.is_punct(index + 1, "!") and self.is_punct(index + 2, "{")):
                last = self.match[index + 2]
                self.known |= set(range(*places[GHOST]))
                self.inventory.append(f"{'  ' * depth}verus! {{ ... }}  (the specifications and lemmas, below)")
                self.parse(index + 3, last, "ghost", depth + 1, True)
                self.ghost.append((tokens[index].line, tokens[last].line))
                self.counts["ghost blocks"] += 1
            else:
                raise Refused(f"{self.relative}:{line}: not an item this gate reads here: {self.lines[line - 1].strip()}")
            if last >= end:
                raise Refused(f"{self.relative}:{line}: an item that runs past the end of its block")
            index = last + 1

    def test_items(self):
        """Every named item of the test module, by tokens: {name: (kind, first line, last line, attributes, words)}.
        `words` are the names the item's text uses, for the closure of what the cited unit checks call."""
        tokens, found = self.tokens, {}
        if len(self.tests) != 1:
            raise Refused(f"{self.relative}: cited unit checks, and not exactly one test module")
        start, last = self.tests[0]
        index = self.until(start, "{") + 1
        while index < last:
            if self.is_punct(index, ";"):
                index += 1
                continue
            first, attributes = index, []
            while self.is_punct(index, "#"):
                close = self.attribute(index)
                attributes.append(spelled(tokens[index:close + 1]))
                index = close + 1
            head = index + 1 if tokens[index].text == "pub" else index
            word = tokens[head].text
            if word == "const":
                end = self.until(head, ";")
            else:
                end = self.until(index, ";", "{")
                end = self.match[end] if self.is_punct(end, "{") else end
            if word in ("fn", "const", "static", "struct", "enum", "type", "trait", "macro_rules"):
                name = tokens[head + 1].text if word != "macro_rules" else tokens[head + 2].text
                if name in found:
                    self.refuse(head, f"a second item named `{name}` in a test module that holds cited unit checks")
                words = {token.text for token in tokens[head + 2:end + 1] if token.kind == "w"}
                found[name] = (word, tokens[first].line, tokens[end].line, attributes, words)
                for inner in range(head, end + 1):
                    if tokens[inner].kind == "s" and "//" in tokens[inner].text:
                        self.refuse(inner, "a string that holds `//`, in a test module that holds cited unit checks")
            index = end + 1
        return found

    def in_kani(self, opening, last):
        """The Kani code is locked whole; its attributes must still be the ones in use, and its markers in them."""
        index = opening + 1
        while index < last:
            if self.is_punct(index, "#"):
                close = self.attribute(index)
                text = spelled(self.tokens[index:close + 1])
                if not self.accept(index, close, text, IN_KANI):
                    self.refuse(index, "an attribute in the Kani code that is not on the list")
                index = close + 1
                continue
            if self.tokens[index].kind == "w" and self.tokens[index].text in MARKERS and index not in self.known:
                self.refuse(index, f"`{self.tokens[index].text}` outside the attributes this gate knows")
            index += 1

    def inside(self, opening, last, what):
        """Refuses what must not be between two brackets: of a function's body, a lemma's body or a proof block."""
        tokens, index = self.tokens, opening + 1
        shipped = what == "a function"
        while index < last:
            token = tokens[index]
            if self.is_punct(index, "#"):
                close = self.attribute(index)
                text = spelled(tokens[index:close + 1])
                if not shipped:
                    if not IN_GHOST_CODE.fullmatch(text):
                        self.refuse(index, f"an attribute inside {what} that is not a trigger")
                elif text == GHOST:
                    macro = close + 1
                    if not (tokens[macro].text in PROOF_MACROS and self.is_macro(macro) and self.is_punct(macro + 2, "{")):
                        self.refuse(index, "a ghost-only condition on something that is not a proof block")
                    else:
                        self.known |= set(range(index, close + 1))
                        for inner in range(macro + 3, self.match[macro + 2]):
                            if tokens[inner].text in LEAVES:
                                self.refuse(inner, "a proof block that leaves the function")
                        self.inside(macro + 2, self.match[macro + 2], "a proof block")
                        close = self.match[macro + 2]
                        self.counts["proof blocks in functions"] += 1
                elif text.startswith(CONTRACT):
                    if not self.is_contract(index) or tokens[close + 1].text not in ("while", "for", "loop"):
                        self.refuse(index, "a contract inside a function that is not a loop's alone")
                    else:
                        self.inside(index + 7, self.match[index + 7], "a loop's contract")
                        self.contract_spans.append((token.line, tokens[close].line))
                        self.counts["loop contracts"] += 1
                else:
                    self.refuse(index, "an attribute inside a function that is not on the list")
                index = close + 1
                continue
            if token.kind == "w" and token.text in ITEM_WORDS:
                self.refuse(index, f"an item declared inside {what}")
            elif self.is_macro(index):
                if not shipped or token.text not in MACROS:
                    self.refuse(index, f"a macro that is not on the list, inside {what}")
            index += 1


def regions(relative, lines):
    """By lines alone: the ghost blocks, the Kani code and the test module, as (first, last) lines from 1."""
    found = {"ghost": [], "kani": [], "test": []}
    index = 0
    while index < len(lines):
        line = lines[index]
        kind = {"verus! {": "ghost", LINE_FORMS["kani"]: "kani", LINE_FORMS["test"]: "test"}.get(line)
        if not kind:
            index += 1
            continue
        closing = "} // verus!" if kind == "ghost" else "}"
        first = index + 1
        while lines[index] != closing:
            index += 1
            if index == len(lines):
                raise Refused(f"{relative}:{first}: a block that does not close on a line `{closing}`")
        found[kind].append((first, index + 1))
        index += 1
    return found


def refusals(relative, lines, spans):
    """What is refused on this file's lines of code, read as lines."""
    found = []

    def refuse(number, why):
        found.append(f"{relative}:{number}: {why}: {lines[number - 1].strip()}")

    def within(kind, number):
        return any(first <= number <= last for first, last in spans[kind])

    judged = 0
    for number, line in enumerate(lines, 1):
        if is_comment(line):
            continue
        stripped = line.strip()
        previous = lines[number - 2].strip() if number > 1 else ""
        if number > judged and (MARKED_IN_TESTS if within("test", number) else MARKED).search(line):
            # A compiler condition or a Verus marker: only as a whole attribute this gate knows, before
            # what it is known to stand before. Asked of the lines alone, tests and Kani code included.
            judged, why = condition(relative, lines, number, within)
            if why:
                refuse(number, why)
        # A Kani harness narrows its inputs with `kani::assume`. That is a statement about the
        # harness, and the harness is locked whole.
        text = line.replace("kani::assume(", "kani::narrow(")
        for pattern in FORBIDDEN:
            if re.search(pattern, text) and not (pattern in FORBIDDEN_BUT_IN_KANI and within("kani", number)):
                refuse(number, "a refused form")
        if "verus_spec" in line and not re.sub(r"\s", "", line).startswith(CONTRACT):
            refuse(number, "a contract not written on one line that starts the attribute")
        if "verus!" in without_comment(line):
            before = lines[number - 3].strip() if number > 2 else ""
            if line != "verus! {" or previous != GHOST_SRC or before.startswith("#"):
                refuse(number, "a ghost block not written exactly `verus! {` under exactly `#[cfg(verus_keep_ghost)]`")
        if "vstd" in line and not VSTD.fullmatch(stripped):
            refuse(number, "a use of the Verus library by a path not on the list")
        if re.search(r"\bproof(_decl|_with)?\s*!", without_comment(line)) and previous != GHOST_SRC:
            refuse(number, "a proof block not under exactly `#[cfg(verus_keep_ghost)]` on the line above")
    return found


def condition(relative, lines, number, within):
    """Judges the attribute that starts on line `number`: (its last line, why it is refused or None)."""
    if not lines[number - 1].lstrip().startswith("#"):
        return number, "a compiler condition or a Verus marker that starts no attribute"
    attribute, last = bracketed(relative, lines, number - 1)
    text = by_lines("".join(attribute))
    after = last
    while after < len(lines) and (not lines[after].strip() or is_comment(lines[after])):
        after += 1
    following = lines[after] if after < len(lines) else ""
    in_ghost, in_kani = within("ghost", number), within("kani", number)
    if text.startswith(CONTRACT):
        if len(attribute) < 2 or attribute[-1].strip() != "))]":
            return last, "a contract's attribute that does not close on a line `))]`"
        if in_ghost or in_kani:
            return last, "a contract inside ghost or Kani code"
    elif text == LINE_FORMS["ghost"]:
        statement, end = following, after
        while statement.lstrip().startswith("use ") and not statement.rstrip().endswith(";") and end + 1 < len(lines):
            end += 1
            statement += lines[end]
        if in_ghost or in_kani or not AFTER_GHOST.fullmatch(re.sub(r"\s", "", without_comment(statement))):
            return last, "a ghost-only condition before something else than an import of ghost code, a ghost block or a proof block"
        if re.match(r"\s*proof(_decl|_with)?! \{", following):
            inner = bracketed(relative, lines, after)[0] if following.rstrip().endswith("{") else [following]
            if any(LEAVES_A_LINE.search(without_comment(one)) for one in inner):
                return last, "a proof block that leaves the function"
    elif text == LINE_FORMS["test"]:
        if following != AFTER_TEST or lines[number - 1] != TEST_SRC:
            return last, f"`{TEST_SRC}` before something else than `{AFTER_TEST}`"
    elif text == LINE_FORMS["kani"]:
        if lines[number - 1] != KANI_SRC or not AFTER_KANI.fullmatch(following):
            return last, f"`{KANI_SRC}` before something else than the Kani module, an `impl` or a `kani_` function"
    elif text == LINE_FORMS["full"]:
        if not in_kani:
            return last, "the feature of the long Kani harnesses outside the Kani code"
    elif text == LINE_FORMS["opaque"]:
        if not in_ghost or not AFTER_OPAQUE.fullmatch(following):
            return last, "`#[verifier::opaque]` on something else than a specification function in a ghost block"
    elif text == LINE_FORMS["spinoff"]:
        if not in_ghost or not AFTER_SPINOFF.fullmatch(following):
            return last, "`#[verifier::spinoff_prover]` on something else than a proof function in a ghost block"
    elif text in (LINE_FORMS["checked"], LINE_FORMS["dead"]):
        if in_ghost or in_kani:
            return last, "an attribute of shipped code inside ghost or Kani code"
    elif not (relative == "src/lib.rs" and text in ROOT_LINE_FORMS):
        return last, "a compiler condition that is not one this gate knows"
    return last, None


def ghost_blocks(relative, lines):
    """The `verus! { ... }` blocks, with each lemma's proof body left out; and the lines of those bodies."""
    out, bodies, index = [], [], 0
    while index < len(lines):
        if lines[index] != "verus! {":
            index += 1
            continue
        index += 1
        while lines[index] != "} // verus!":
            line = lines[index]
            out.append(line)
            index += 1
            if re.match(r"(pub )?proof fn ", line):
                # The statement runs to a line that is exactly `{`; the body to exactly `}`.
                while lines[index] != "{":
                    if lines[index] == "} // verus!":
                        raise Refused(f"{relative}:{index + 1}: a lemma whose body does not start on a line `{{`")
                    out.append(lines[index])
                    index += 1
                opened = index + 1
                while lines[index] != "}":
                    index += 1
                bodies.append((opened, index + 1))
                out.append("{ proof }")
                index += 1
            if index >= len(lines):
                raise Refused(f"{relative}: a ghost block that does not close on a line `}} // verus!`")
        out.append("")
        index += 1
    return code(out), bodies


def bracketed(relative, lines, start):
    """The lines of the bracketed construct starting at `start`, to the line that closes it."""
    depth, out = 0, []
    for index in range(start, len(lines)):
        out.append(lines[index])
        for char in without_comment(lines[index]):
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
        if depth == 0:
            return out, index + 1
    raise Refused(f"{relative}:{start + 1}: an attribute that never closes")


def contracts(relative, lines):
    """Each `verus_spec` contract on a function, with the function's signature; and how many there are."""
    out, index, count, spans = [], 0, 0, []
    while index < len(lines):
        if not re.sub(r"\s", "", lines[index]).startswith(CONTRACT):
            index += 1
            continue
        attribute, after = bracketed(relative, lines, index)
        spans.append((index + 1, after))
        index = after
        while lines[after].lstrip().startswith("#["):
            after = bracketed(relative, lines, after)[1]
        first = lines[after].lstrip()
        if first.startswith(("while ", "for ", "loop ")):
            continue  # a loop invariant: part of the proof
        if not re.match(r"(pub(\([a-z]+\))? )?(const )?fn ", first):
            raise Refused(f"{relative}:{after + 1}: a contract on something that is not a function or a loop")
        signature = []
        while True:
            signature.append(lines[after])
            if without_comment(lines[after]).rstrip().endswith("{"):
                break
            after += 1
        out.extend(line.strip() for line in code(attribute + signature))
        out.append("")
        count += 1
    return out, count, spans


def kani_text(spans, lines):
    """Every item for Kani alone, whole but for comments: what a harness lets in and how far it unwinds is what it claims."""
    out = []
    for first, last in spans:
        out.append(f"Kani code, whole: {lines[first].strip().rstrip(' {')}")
        out.extend("  " + line for line in code(lines[first - 1:last]))
        out.append("")
    return out


def digest(path):
    with open(path, "rb") as file:
        return hashlib.sha256(file.read()).hexdigest()


def files():
    """Every file under the crate with how the lock holds it. Refuses a file no line of FILES names."""
    out, refused = {}, []
    for directory, directories, names in os.walk(CRATE):
        for name in directories + names:
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, CRATE)
            how = [how for pattern, how in FILES if re.fullmatch(pattern, relative)]
            if os.path.islink(path):
                refused.append(f"{relative}: a symbolic link")
            elif name in names and not how:
                refused.append(f"{relative}: a file this crate is not known to hold")
            elif name in names:
                out[relative] = how[0]
    return dict(sorted(out.items())), refused


def source(relative):
    """One source file read both ways: (the lock's lines for it, what is refused in it, what was counted)."""
    lines = read(relative)
    spans = regions(relative, lines)
    refused = refusals(relative, lines, spans)
    tokens = Source(relative, lines)
    refused.extend(tokens.found)
    statements, bodies = ghost_blocks(relative, lines)
    contract_text, contract_count, contract_spans = contracts(relative, lines)
    if sorted(bodies) != sorted(tokens.proof_bodies):
        refused.append(f"{relative}: the lemmas' bodies are not the same read by lines and as tokens")
    if contract_count != tokens.contracts:
        refused.append(f"{relative}: {contract_count} contracts read by lines, {tokens.contracts} as tokens")
    if sorted(spans["kani"]) != sorted(tokens.kani):
        refused.append(f"{relative}: the Kani code is not the same read by lines and as tokens")
    if sorted(spans["test"]) != sorted((tokens.tokens[a].line, tokens.tokens[b].line) for a, b in tokens.tests) or len(spans["test"]) > 1:
        refused.append(f"{relative}: the test modules are not the same read by lines and as tokens, or more than one")
    if sorted(contract_spans) != sorted(tokens.contract_spans):
        refused.append(f"{relative}: the contracts are not on the same lines read by lines and as tokens")
    if sorted(spans["ghost"]) != sorted(tokens.ghost):
        refused.append(f"{relative}: the ghost blocks are not the same read by lines and as tokens")
    tokens.counts["contracts on functions"] = contract_count
    cited_text = []
    if relative in CITED_TESTS:
        module = tokens.test_items()
        locked = [(name, row, "test") for name, row in CITED_TESTS[relative]]
        locked += [(name, ", ".join(rows), "helper") for name, rows in CITED_HELPERS.get(relative, [])]
        names = {name for name, _, _ in locked}
        for name, row, what in locked:
            if name not in module:
                refused.append(f"{relative}: the {'unit check' if what == 'test' else 'helper'} `{name}`, which "
                               f"{row} rests on, is not in the test module")
                continue
            word, first, last, attributes, words = module[name]
            if what == "test" and (word != "fn" or attributes != [TEST_ATTRIBUTE]):
                refused.append(f"{relative}:{first}: the cited unit check `{name}` is not a function whose attributes are exactly `#[test]`")
            if what == "helper" and attributes:
                refused.append(f"{relative}:{first}: the helper `{name}` of a cited unit check carries an attribute")
            # By lines: a function opens on `    fn name(` and closes on the next line `    }`; a constant is one line.
            opens = [number for number, line in enumerate(lines, 1) if re.match(rf"    (pub(\([a-z]+\))? )?{word} {re.escape(name)}\b", line)
                     and any(a <= number <= b for a, b in spans["test"])]
            if len(opens) != 1:
                refused.append(f"{relative}: `{name}` is not found exactly once by lines")
                continue
            begin, end = opens[0], opens[0]
            while begin > 1 and lines[begin - 2].startswith("    #["):
                begin -= 1
            if word == "fn":
                while lines[end - 1] != "    }":
                    end += 1
            if (begin, end) != (first, last):
                refused.append(f"{relative}: `{name}` is not the same read by lines and as tokens")
                continue
            # What the locked text calls must itself be locked: a helper it reaches that is free could change
            # what the locked assertions test.
            for other in sorted((words & set(module)) - names - {name}):
                if module[other][0] in ("fn", "const", "static", "struct", "enum", "type", "macro_rules"):
                    refused.append(f"{relative}: `{name}`, locked, uses `{other}`, which is not locked")
            label = f"{row} cites `{name}`" if what == "test" else f"`{name}`, which {row} call"
            cited_text.append(f"{label}, whole but for comments:")
            cited_text.extend("  " + line for line in code(lines[first - 1:last]))
            tokens.counts["cited unit checks" if what == "test" else "helpers of cited unit checks"] += 1
        for first, last in spans["test"]:
            for number in range(first, last + 1):
                if re.match(r"\s*(pub(\([a-z]+\))? )?use .*\bas\b", lines[number - 1]):
                    refused.append(f"{relative}:{number}: an import that renames, in a test module that holds cited unit checks")
        refused.extend(found for found in tokens.found if found not in refused)
    ITEMS.extend(tokens.items)
    out = ["", f"==== {relative}"]
    if relative == "src/lib.rs":
        # The root decides which files are the crate, and its doc comments are the index of the theorems.
        out.append("whole, comments included:")
        out.extend("  " + line for line in lines if line.strip())
        return out, refused, tokens.counts
    out.append("items, in order:")
    out.extend("  " + line for line in tokens.inventory)
    if statements:
        out.append("")
        out.append("the specifications, and the lemmas' statements (`{ proof }` stands for a body):")
        out.extend("  " + line for line in statements)
    if contract_text:
        out.append("")
        out.append("the contracts on functions:")
        out.extend("  " + line if line else "" for line in contract_text)
    out.extend(kani_text(spans["kani"], lines))
    if cited_text:
        out.append("the unit checks the theorem index cites:")
        out.extend("  " + line for line in cited_text)
    return out, refused, tokens.counts


def table_rows(relative, header=None):
    """The rows of each table of a document whose header matches `header` (every table when None), each
    table under its header."""
    lines = read(relative, ALSO_IN_DOCUMENTS)
    out, index = [], 0
    while index + 1 < len(lines):
        top, rule = lines[index], lines[index + 1]
        if not (top.startswith("|") and re.fullmatch(r"\|[-| :]+\|", rule)):
            index += 1
            continue
        index += 2
        rows = []
        while index < len(lines) and lines[index].startswith("|"):
            rows.append(lines[index])
            index += 1
        if header is None or header.search(top):
            out.append(f"{relative}:{top}")
            out.extend("  " + row for row in rows)
    return out


def lock_text():
    """(the text of the lock, the counts of what it holds)."""
    out, counts = [], collections.Counter()
    out.append("# The statements of netcore. Generated by netcore-lock/statements.py; see that file.")
    out.append("# A change here changes what is claimed. It is made on purpose, by `--write`, and reviewed by the owner.")
    held, refused = files()
    out.append("")
    out.append("==== the crate's files (text: whole below; source: its statements below; rows and controls: their rows below; free: not locked)")
    out.extend(f"  {how:8} {relative}" for relative, how in held.items())
    out.append("")
    out.append("==== Cargo.toml (what is built), but for comments")
    out.extend("  " + line for line in read("Cargo.toml") if line.strip() and not line.lstrip().startswith("#"))
    for relative in (relative for relative, how in held.items() if how == "source"):
        try:
            text, found, found_counts = source(relative)
        except Refused as refusal:
            refused.append(str(refusal))
            continue
        out.extend(text)
        refused.extend(found)
        counts.update(found_counts)
    out.append("")
    out.append("==== axioms/REGISTRY.md (what is assumed and not proved), the rows of its tables")
    rows = table_rows("axioms/REGISTRY.md")
    out.extend(rows)
    counts["assumption rows"] = sum(line.startswith("  ") for line in rows)
    for line in rows:
        if line.startswith("  ") and not REGISTRY_ROW.match(line[2:]):
            refused.append(f"axioms/REGISTRY.md: a row without an id: {line.strip()}")
    out.append("")
    out.append("==== the control documents, the rows of each table that says where a control must fail")
    for relative in (relative for relative, how in held.items() if how == "controls"):
        try:
            found = table_rows(relative, CONTROL_HEADER)
        except Refused as refusal:
            refused.append(str(refusal))
            continue
        out.extend(found)
        counts["control rows"] += sum(line.startswith("  ") for line in found)
        counts["control tables"] += sum(not line.startswith("  ") for line in found)
    out.append("")
    out.append(f"==== {MANIFEST} (every control, what it breaks and where it must fail), whole but for blank lines")
    manifest = os.path.join(HERE, MANIFEST)
    if not os.path.isfile(manifest):
        refused.append(f"{manifest}: the control manifest is not there")
    else:
        try:
            lines = read(manifest, ALSO_IN_DOCUMENTS)
        except Refused as refusal:
            refused.append(str(refusal))
            lines = []
        out.extend("  " + line for line in lines if line.strip())
        counts["manifest controls"] = sum(line.strip() == "[[control]]" for line in lines)
    out.append("")
    out.append("==== the verified count CI pins (scripts/verus.sh, or the script `--verus-script` names)")
    if not os.path.isfile(VERUS_SCRIPT):
        refused.append(f"{VERUS_SCRIPT}: the script that pins the verified count is not there (`--verus-script PATH`)")
    else:
        try:
            script = read(VERUS_SCRIPT)
        except Refused as refusal:
            refused.append(str(refusal))
            script = []
        ours = [line for line in script if COUNT_LINE.fullmatch(line)]
        if len(ours) != 1 or any("netcore" in line and line.lstrip().startswith("expect ") and line not in ours for line in script):
            refused.append(f"{VERUS_SCRIPT}: not exactly one line `expect netcore <count>`")
        out.extend("  " + line for line in ours)
        # Whether that line is reached is decided by the rest of the script. Other crates' counts are theirs.
        rest = "\n".join(line for line in script if not OTHER_COUNT.fullmatch(line))
        out.append(f"  the script, but for the other crates' counts: {hashlib.sha256(rest.encode()).hexdigest()}")
    if refused:
        raise Refused("\n  " + "\n  ".join(refused))
    out.append("")
    out.append("==== the gates themselves (sha256; a change here is reviewed in the script's own diff)")
    out.extend(f"  {digest(os.path.join(HERE, name))}  {name}" for name in GATES)
    return "\n".join(out) + "\n", counts


def places(old, new):
    """For each changed run of lines: the section of the lock and the part of it, in order, each once."""
    def headings(lines):
        out, section, part = [], "", ""
        for line in lines:
            if line.startswith("==== "):
                section, part = line[5:], ""
            elif line and not line.startswith(" ") and not line.startswith("#"):
                part = line.split(" (")[0].rstrip(":")
            out.append(f"{section}: {part}" if part else section)
        return out
    before, after, found = headings(old), headings(new), []
    for tag, first, last, other, other_last in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        for place in before[first:last] + after[other:other_last]:
            if place not in found:
                found.append(place)
    return found


def main():
    global CRATE, LOCK, VERUS_SCRIPT
    arguments = sys.argv[1:]
    if "--verus-script" in arguments:
        at = arguments.index("--verus-script")
        if at + 1 >= len(arguments):
            sys.stderr.write(__doc__)
            return 2
        VERUS_SCRIPT = os.path.abspath(arguments.pop(at + 1))
        arguments.pop(at)
    for flag in ("--crate", "--lock"):
        if flag in arguments:
            at = arguments.index(flag)
            if at + 1 >= len(arguments):
                sys.stderr.write(__doc__)
                return 2
            value = os.path.abspath(arguments.pop(at + 1))
            arguments.pop(at)
            CRATE, LOCK = (value, LOCK) if flag == "--crate" else (CRATE, value)
    mode = arguments[0] if len(arguments) == 1 else ""
    if mode not in ("--check", "--write", "--counts", "--items"):
        sys.stderr.write(__doc__)
        return 2
    try:
        text, counts = lock_text()
    except Refused as refusal:
        print(f"REFUSED: {refusal}")
        return 1
    except UnicodeDecodeError:
        print("REFUSED: a file is not text")
        return 1
    if mode == "--items":
        import json
        json.dump(ITEMS, sys.stdout, indent=0)
        return 0
    if mode == "--counts":
        for name, count in sorted(counts.items()):
            print(f"{count:6}  {name}")
        return 0
    if mode == "--write":
        with open(LOCK, "w", encoding="utf-8", newline="") as file:
            file.write(text)
        print(f"wrote {LOCK} ({text.count(chr(10))} lines)")
        return 0
    try:
        with open(LOCK, encoding="utf-8", newline="") as file:
            locked = file.read()
    except FileNotFoundError:
        print(f"no {LOCK}: nothing is locked")
        return 1
    if locked == text:
        print(f"statements match the lock ({text.count(chr(10))} lines)")
        return 0
    old, new = locked.split("\n"), text.split("\n")
    print("\n".join(difflib.unified_diff(old, new, "STATEMENTS.lock", "the source", n=2, lineterm="")))
    print("\nwhere the statements changed (file, and the part of its section):")
    for place in places(old, new):
        print(f"  {place}")
    print("\nTHE STATEMENTS CHANGED. If the change is intended, the owner runs `--write` and reviews the diff.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
