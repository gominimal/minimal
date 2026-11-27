#!/usr/bin/env python3
"""The second lock of netcore: what the verifier itself reports having checked.

    python3 view.py --check  [--vir FILE] [--lock FILE] [--crate DIR] [--verus-script PATH]   (the gate)
    python3 view.py --write  [--vir FILE] [--lock FILE] [--crate DIR] [--verus-script PATH]   (the owner, after reading the diff)
    python3 view.py --report [--vir FILE]                               (what the account shows, in numbers)
    python3 view.py --check --alone ...                                 (the selftest: this lock without the text)

`statements.py` reads the source as text, and what Verus checks is decided by
the compiler: a name in a contract can resolve to something else than it
reads, and an attribute can be spelled in a way a text scan does not know.
This script reads Verus's own account of the crate, the file `crate.vir` that
`--log vir` writes, and holds in `VIEW.lock`:

  * every function of this crate (paths under `lib::`): its path, its kind
    (spec, proof, exec, const), its marks (external_body, an assumed
    specification, external, `requires false`, opaque, no body), how many requirements and
    guarantees it has, and a digest of its statement as Verus resolved it
    (signature, requirements, guarantees, measures, visibility, attributes;
    for a specification function or a constant, its body too), with every
    source position left out and Verus's crate-wide counters renumbered
    within the function, so that moving a line moves nothing;
  * every function of the crate Verus saw and did not check (`external_fn`);
  * every type of the crate, with a digest of its definition.

Then the two locks must describe the same crate. Every specification, lemma
and function with a contract that `statements.py --items` reads must be one
function of Verus's account at the same file and line, of the same kind, and
the reverse; what Verus checked and the text does not list must be the
`clone` a `derive(Clone)` writes; what Verus saw and did not check must be
what a derive writes or a constant. Only two functions may be marked
external_body: `slab::Slab::lower` and `slab::Slab::place`, the stubs the
attribute that gives a function a ghost result writes, each beside its
verified body `_VERUS_VERIFIED_<name>`. Each stub must also be uncallable
(`requires false`, no guarantee); a third, or a missing twin, fails.

The dump is a file, so the check is only as good as the dump: it must come
from the source the text lock describes. Producing it needs Verus, on the
machine that has it, from the crate's directory:

    verus --edition=2024 --crate-type=lib --rlimit <r> src/lib.rs --log vir --log-dir <dir>

Impl blocks have no name in Verus's account, only a number in their module
(derives count), so adding an impl or a derive renumbers the later ones.
"""

import sys

if not (sys.flags.isolated and sys.dont_write_bytecode):
    # As in statements.py: nothing beside this script or in the environment may answer an import.
    import posix

    posix.execv(sys.executable, [sys.executable, "-I", "-B"] + sys.argv)

import collections
import difflib
import hashlib
import json
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.join(os.path.dirname(HERE), "netcore")
LOCK = os.path.join(HERE, "VIEW.lock")
# The script `statements.py --items` is given as `--verus-script`; its own default when empty.
VERUS_SCRIPT = ""
# The account `--check` reads when no `--vir` is given: the path `VIEW.source` names, written with the lock.
SOURCE = os.path.join(HERE, "VIEW.source")
VIR = open(SOURCE, encoding="utf-8").read().strip() if os.path.isfile(SOURCE) else ""
PREFIX = "lib::"
# The fields of a function that are its statement, as Verus resolved it. Its body only for spec and const.
STATEMENT = [":kind", ":visibility", ":body_visibility", ":opaqueness", ":mode", ":typ_params", ":typ_bounds",
             ":params", ":outer_ret", ":inner_ret", ":require", ":ensure", ":returns", ":decrease", ":decrease_when",
             ":decrease_by", ":mask_spec", ":unwind_spec", ":item_kind", ":attrs", ":proxy"]
# Attributes Verus derives from the body, not from the statement: adding a first proof block sets it.
FROM_THE_BODY = {":uses_ghost_blocks"}
KINDS = {("Spec", "Function"): "spec", ("Proof", "Function"): "proof", ("Exec", "Function"): "exec",
         ("Spec", "Const"): "const", ("Exec", "Const"): "const"}
# Marks that say Verus takes a function's statement without checking its body.
TRUST = {":is_external_body": "external_body", ":exec_assume_termination": "assumes_termination",
         ":exec_allows_no_decreases_clause": "no_decreases_allowed", ":is_unsafe": "unsafe"}
# The functions the ghost-result attribute writes twice: a stub marked external_body under the name, and
# the verified body under `_VERUS_VERIFIED_<name>`. Exactly these, as (file, impl type, name).
TWINS = {("src/slab.rs", "Slab", "lower"), ("src/slab.rs", "Slab", "place")}
TWIN = "_VERUS_VERIFIED_"
# What each derive writes, by the name Verus reports. A checked type's `clone` is checked.
DERIVED = {"Debug": "fmt", "PartialEq": "eq", "Eq": "assert_fields_are_eq", "Clone": "clone"}
SPAN = re.compile(r'"(?:.*/)?(src/[a-z]+\.rs):(\d+):(\d+): (\d+):(\d+) \(#(\d+)\)"')
ANY_SPAN = re.compile(r'"[^"]*:\d+:\d+: \d+:\d+ \(#\d+\)"')
TOKEN = re.compile(r'[()]|"(?:[^"\\]|\\.)*"|[^\s()"]+')


class Refused(Exception):
    """Verus's account is not in the form this script reads, or disagrees with the text."""


def top_forms(text):
    """The account's top-level forms, as text, in one pass."""
    depth, start = 0, None
    for match in TOKEN.finditer(text):
        word = match.group(0)
        if word == "(":
            if depth == 0:
                start = match.start()
            depth += 1
        elif word == ")":
            depth -= 1
            if depth < 0:
                raise Refused("the account closes a bracket it did not open")
            if depth == 0:
                yield text[start:match.end()]
        elif depth == 0:
            raise Refused(f"a word outside any form in the account: {word[:60]}")
    if depth:
        raise Refused("the account ends inside a bracket")


def parse(text):
    """One form as nested lists of words and quoted strings."""
    stack = [[]]
    for match in TOKEN.finditer(text):
        word = match.group(0)
        if word == "(":
            stack.append([])
        elif word == ")":
            done = stack.pop()
            stack[-1].append(done)
        else:
            stack[-1].append(word)
    return stack[0][0]


def flat(form):
    return "(" + " ".join(flat(part) for part in form) + ")" if isinstance(form, list) else form


def field(form, name):
    try:
        return form[form.index(name) + 1]
    except (ValueError, IndexError):
        raise Refused(f"a form without `{name}`: {flat(form)[:120]}") from None


def without_spans(form):
    """The form without where in the source each part came from."""
    if not isinstance(form, list):
        return "SPAN" if ANY_SPAN.fullmatch(form) else form
    if form and form[0] in ("@", "@@") and len(form) >= 3 and ANY_SPAN.fullmatch(form[1]):
        rest = [without_spans(part) for part in form[2:]]
        return rest[0] if len(rest) == 1 else rest
    return [without_spans(part) for part in form]


def without_keys(form, keys):
    """A keyword list without the named keywords and their values."""
    out, index = [], 0
    while index < len(form):
        if isinstance(form[index], str) and form[index] in keys:
            index += 2
            continue
        out.append(form[index])
        index += 1
    return out


def digest(form):
    """A digest of the form without positions. Verus's `:id` and `RustcId` numbers count across the crate,
    so one edit renumbers every later item; here they are numbered within the form, in order."""
    numbers = {}
    text = re.sub(r"(RustcId|:id) (\d+)", lambda found: f"{found.group(1)} {numbers.setdefault(found.group(0), len(numbers))}",
                  flat(without_spans(form)))
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def place(span):
    """(file, line, whether a macro wrote the code there) of a span of this crate's source."""
    found = SPAN.fullmatch(span)
    if not found:
        raise Refused(f"a place of this crate's code that is not in its source: {span}")
    return found.group(1), int(found.group(2)), found.group(6) != "0"


def readable(path):
    """`lib::t%slab::impl&%0::lower` as `slab::impl 0::lower`."""
    return path.replace(PREFIX, "", 1).replace("t%", "").replace("impl&%", "impl ")


def is_true(attrs, key):
    return key in attrs and attrs[attrs.index(key) + 1] == "true"


def account(path):
    """Verus's account of this crate: {path: function}, [paths seen and not checked], {path: type}."""
    with open(path, encoding="utf-8", newline="") as file:
        text = file.read()
    functions, unchecked, types = {}, [], {}
    for form_text in top_forms(text):
        head = form_text[:400]
        if form_text.startswith("(external_fn"):
            name = re.match(r"\(external_fn \(Fun :path (\S+)\)\)", form_text)
            if not name:
                raise Refused(f"an `external_fn` form this script does not read: {head[:120]}")
            if name.group(1).startswith(PREFIX):
                unchecked.append(name.group(1))
            continue
        if PREFIX not in head and '"src/' not in head:
            continue
        form = parse(form_text)
        if form[0] != "@":
            continue
        body = form[2]
        if body[0] == "Function":
            name = field(field(body, ":name"), ":path")
            if not name.startswith(PREFIX):
                continue
            file, line, by_macro = place(form[1])
            mode, item_kind = field(body, ":mode"), field(body, ":item_kind")[1]
            if (mode, item_kind) not in KINDS or name in functions:
                raise Refused(f"a function in the account of a kind this script does not read, or twice: {name}")
            kind = KINDS[(mode, item_kind)]
            attrs = field(body, ":attrs")
            marks = [mark for key, mark in TRUST.items() if is_true(attrs, key)]
            if field(body, ":proxy") != "None":
                marks.append("assumed_specification")
            if kind == "spec" and field(body, ":opaqueness")[1] == "Opaque":
                marks.append("opaque")
            require = field(body, ":require")
            if any("(Constant Bool false)" in flat(without_spans(one)) and len(flat(without_spans(one))) < 60 for one in require):
                # A function no caller can meet the requirement of: the ghost-result stubs are written so.
                marks.append("requires_false")
            if field(body, ":body") == "None":
                marks.append("no_body")
            statement = [without_keys(attrs, FROM_THE_BODY) if key == ":attrs" else field(body, key) for key in STATEMENT]
            if kind in ("spec", "const"):
                statement.append(field(body, ":body"))
            ensure = field(body, ":ensure")
            functions[name] = {"file": file, "line": line, "by_macro": by_macro, "kind": kind, "marks": marks,
                               "requires": len(field(body, ":require")), "ensures": len(ensure[1]) + len(ensure[2]),
                               "digest": digest(statement)}
        elif body[0] == "Datatype":
            name = field(body, ":name")[-1]
            if name.startswith(PREFIX):
                file, line, _ = place(form[1])
                types[name] = {"file": file, "line": line, "digest": digest(body)}
    for name in unchecked:
        if name in functions and functions[name]["kind"] != "const":
            functions[name]["marks"].append("external")
    return functions, unchecked, types


def lock_text(functions, unchecked, types):
    counts = collections.Counter(entry["kind"] for entry in functions.values())
    out = ["# What Verus reports of netcore, from its `--log vir` account. Generated by netcore-lock/view.py; see that file.",
           "# A digest that changes while STATEMENTS.lock does not means a name now resolves to something else.",
           "", f"==== functions of the crate in the account ({len(functions)}: "
           + ", ".join(f"{counts[kind]} {kind}" for kind in ("spec", "proof", "exec", "const")) + ")",
           "# path, kind, marks, requirements, guarantees, digest of the statement"]
    for name in sorted(functions):
        entry = functions[name]
        marks = ",".join(entry["marks"]) or "-"
        out.append(f"  {readable(name)}  {entry['kind']}  {marks}  {entry['requires']} {entry['ensures']}  {entry['digest']}")
    out += ["", f"==== seen by Verus and not checked ({len(unchecked)})"]
    out.extend("  " + readable(name) for name in sorted(unchecked))
    out += ["", f"==== types of the crate in the account ({len(types)}): path, digest"]
    out.extend(f"  {readable(name)}  {types[name]['digest']}" for name in sorted(types))
    return "\n".join(out) + "\n"


def text_items():
    script = ["--verus-script", VERUS_SCRIPT] if VERUS_SCRIPT else []
    done = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "statements.py"), "--items", "--crate", CRATE] + script,
                          capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise Refused("statements.py does not read the source:\n" + done.stdout[:2000])
    return json.loads(done.stdout)


def derives_of(item):
    return [name for attribute in item["derives"] for name in re.findall(r"[A-Za-z]+", attribute[len("#[derive("):])]


def disagreements(functions, unchecked, types, items):
    """Where Verus's account and the text read by statements.py do not describe the same crate."""
    out = []
    at = collections.defaultdict(list)
    for item in items:
        at[(item["file"], item["line"], item["name"])].append(item)
    claimed = collections.Counter()
    twins_seen = collections.defaultdict(set)
    for name, entry in sorted(functions.items()):
        last = name.split("::")[-1]
        file, line = entry["file"], entry["line"]
        if entry["by_macro"]:
            owners = [item for item in items if item["kind"] == "type" and item["file"] == file
                      and item["attributes_from"] <= line <= item["line"] and "Clone" in derives_of(item)]
            if last != "clone" or len(owners) != 1 or entry["marks"]:
                out.append(f"Verus has {readable(name)} at {file}:{line}, written by a macro, and it is not a checked derived clone")
            else:
                claimed[(file, owners[0]["line"], owners[0]["name"], "clone")] += 1
            continue
        twin = last.startswith(TWIN)
        source_name = last[len(TWIN):] if twin else last
        there = [item for item in at.get((file, line, source_name), []) if item["kind"] != "type"]
        if len(there) != 1:
            out.append(f"Verus has {readable(name)} ({entry['kind']}) at {file}:{line}; the text lists no such item there")
            continue
        item = there[0]
        if item["kind"] != entry["kind"]:
            out.append(f"{readable(name)} at {file}:{line} is {entry['kind']} to Verus and {item['kind']} to the text")
        if (file, item.get("owner"), source_name) in TWINS and item["kind"] == "exec":
            twins_seen[(file, item.get("owner"), source_name)].add(
                "verified" if twin and not entry["marks"] else
                "stub" if not twin and entry["marks"] == ["external_body", "requires_false", "no_body"]
                and entry["ensures"] == 0 else f"other {entry['marks']}")
            claimed[(file, line, source_name, "twin" if twin else "stub")] += 1
            continue
        if twin:
            out.append(f"{readable(name)}: a generated verified body for a function that is not one of the two known twins")
        if entry["marks"] and not (entry["kind"] == "spec" and set(entry["marks"]) <= {"opaque"}):
            out.append(f"{readable(name)} at {file}:{line} is marked {','.join(entry['marks'])} by Verus")
        if entry["kind"] == "spec" and ("opaque" in entry["marks"]) != bool(item.get("opaque")):
            out.append(f"{readable(name)} at {file}:{line}: opaque to {'Verus' if 'opaque' in entry['marks'] else 'the text'} alone")
        if item["kind"] == "exec" and not item.get("contract"):
            out.append(f"{readable(name)} at {file}:{line}: checked by Verus, and held whole by the text, without a contract")
        claimed[(file, line, source_name, item["kind"])] += 1
    for key in sorted(TWINS):
        if twins_seen.get(key) != {"verified", "stub"}:
            out.append(f"the generated pair for {key[1]}::{key[2]} in {key[0]} is not one verified body and one "
                       f"external_body stub: {sorted(twins_seen.get(key, ()))}")
    for item in items:
        where = (item["file"], item["line"], item["name"])
        if item["kind"] in ("spec", "proof") or (item["kind"] == "exec" and item.get("contract")):
            want = 2 if (item["file"], item.get("owner"), item["name"]) in TWINS else 1
            got = sum(count for key, count in claimed.items() if key[:3] == where and key[3] != "clone")
            if got != want:
                out.append(f"the text lists {item['kind']} {item['name']} at {item['file']}:{item['line']}; "
                           f"Verus has it {got} times, expected {want}")
        elif item["kind"] == "const" and item.get("verify") and claimed[where + ("const",)] != 1:
            out.append(f"the text lists the checked constant {item['name']} at {item['file']}:{item['line']}; "
                       f"Verus has it {claimed[where + ('const',)]} times")
        elif item["kind"] == "type" and claimed[where + ("clone",)] != ("Clone" in derives_of(item)):
            out.append(f"the type {item['name']} at {item['file']}:{item['line']}: its derived clone is checked "
                       f"{claimed[where + ('clone',)]} times")
    # What Verus saw and did not check: what the other derives write, and the constants.
    expected = collections.Counter()
    for item in items:
        if item["kind"] == "type":
            for derive in derives_of(item):
                if derive in DERIVED and derive != "Clone":
                    expected[(item["file"], DERIVED[derive])] += 1
        elif item["kind"] == "const":
            expected[(item["file"], item["name"])] += 1
    seen = collections.Counter(("src/" + name.split("::")[1].replace("t%", "") + ".rs", name.split("::")[-1])
                               for name in unchecked)
    for key in sorted(set(expected) | set(seen)):
        if expected[key] != seen[key]:
            out.append(f"{key[0]}: `{key[1]}` is seen and not checked {seen[key]} times by Verus, and {expected[key]} by the text")
    by_text = {(item["file"], item["name"]) for item in items if item["kind"] == "type"}
    by_verus = {(entry["file"], name.split("%")[-1]) for name, entry in types.items()}
    for key in sorted(by_text ^ by_verus):
        out.append(f"the type {key[1]} in {key[0]} is in {'the text' if key in by_text else 'Verus'} alone")
    return out


def report(functions, unchecked, types):
    counts = collections.Counter(entry["kind"] for entry in functions.values())
    print(f"functions of the crate in the account: {len(functions)}: {dict(counts)}")
    macro = [name for name, entry in functions.items() if entry["by_macro"]]
    print(f"written by a macro: {len(macro)} {dict(collections.Counter(n.split('::')[-1] for n in macro))}")
    for mark in ("external_body", "requires_false", "assumed_specification", "external", "assumes_termination", "no_decreases_allowed",
                 "unsafe", "no_body", "opaque"):
        names = sorted(readable(name) for name, entry in functions.items() if mark in entry["marks"])
        print(f"marked {mark}: {len(names)}" + (f": {', '.join(names)}" if 0 < len(names) <= 12 else ""))
    kinds = collections.Counter(n.split("::")[-1] if "::impl" in n else "a constant" for n in unchecked)
    print(f"seen and not checked: {len(unchecked)} {dict(kinds)}")
    both = sorted(readable(n) for n in unchecked if n in functions)
    print(f"in both lists: {len(both)}")
    print(f"types: {len(types)}")


def main():
    global CRATE, LOCK, VIR, VERUS_SCRIPT
    arguments = sys.argv[1:]
    for flag in ("--vir", "--lock", "--crate", "--verus-script"):
        if flag in arguments:
            at = arguments.index(flag)
            if at + 1 >= len(arguments):
                sys.stderr.write(__doc__)
                return 2
            value = os.path.abspath(arguments.pop(at + 1))
            arguments.pop(at)
            if flag == "--vir":
                VIR = value
            elif flag == "--lock":
                LOCK = value
            elif flag == "--crate":
                CRATE = value
            else:
                VERUS_SCRIPT = value
    alone = "--alone" in arguments
    if alone:
        arguments.remove("--alone")
    if len(arguments) != 1 or arguments[0] not in ("--check", "--write", "--report") or (alone and arguments[0] != "--check"):
        sys.stderr.write(__doc__)
        return 2
    mode = arguments[0]
    try:
        if not os.path.isfile(VIR):
            raise Refused(f"{VIR}: no account of the crate (`--vir FILE`)")
        found = account(VIR)
        if mode == "--report":
            report(*found)
            return 0
        differing = [] if alone else disagreements(*found, text_items())
    except (Refused, ValueError, IndexError, KeyError, OSError) as refusal:
        print(f"REFUSED: {refusal}")
        return 1
    if differing:
        print("VERUS AND THE TEXT DO NOT DESCRIBE THE SAME CRATE:\n  " + "\n  ".join(differing))
        return 1
    text = lock_text(*found)
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
        print(f"what Verus reports matches the lock ({len(found[0])} functions, {len(found[2])} types)"
              + ("" if alone else ", and the text describes the same crate"))
        return 0
    print("\n".join(difflib.unified_diff(locked.split("\n"), text.split("\n"), "VIEW.lock", "the account", n=1, lineterm="")))
    print("\nWHAT VERUS REPORTS CHANGED. If the change is intended, the owner runs `--write` and reviews the diff.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
