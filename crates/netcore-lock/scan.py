"""The item scan of netcore's control generator: which function (fn / spec fn / proof fn) contains a line.

It is the scan that computed the places of the first full run of the controls, and was checked
there against Verus's own function names. Patterns HDR, IMPL, MOD, _cache; functions scan, _bisect,
items, where; nothing else. where(path, line1) -> (fn, kind, impl, span, note).
"""
import re

HDR = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?((?:(?:open|closed|broadcast|const|unsafe|async)\s+)*)'
                 r'(?:(spec|proof|exec)(?:\(checked\))?\s+)?fn\s+([A-Za-z_]\w*)')

IMPL = re.compile(r'^\s*impl\b(?:<[^>]*>)?\s*(?:[\w:<>, ]+\s+for\s+)?([A-Za-z_]\w*)')

MOD = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*\{')

def scan(text):
    """-> per-line (bracket depth at line start, brace depth at line start); and close-brace map open_line->close_line."""
    lines = text.split("\n")
    dep_all, dep_brace = [], []
    i, n, line = 0, len(text), 0
    da = db = 0
    starts = [0]
    for k, ch in enumerate(text):
        if ch == "\n": starts.append(k + 1)
    line_of = lambda pos: _bisect(starts, pos)
    stack = []                   # (char, line)
    braces = {}                  # line of an opening `{` -> line of its `}` (first `{` on a line wins)
    da_at = [None] * len(lines); db_at = [None] * len(lines)
    cur_line = 0; da_at[0] = 0; db_at[0] = 0
    while i < n:
        c = text[i]
        if c == "\n":
            cur_line += 1
            if cur_line < len(lines): da_at[cur_line] = da; db_at[cur_line] = db
            i += 1; continue
        if text.startswith("//", i):
            j = text.find("\n", i); i = n if j < 0 else j; continue
        if text.startswith("/*", i):
            depth = 1; j = i + 2
            while j < n and depth:
                if text.startswith("/*", j): depth += 1; j += 2
                elif text.startswith("*/", j): depth -= 1; j += 2
                else:
                    if text[j] == "\n":
                        cur_line += 1
                        if cur_line < len(lines): da_at[cur_line] = da; db_at[cur_line] = db
                    j += 1
            i = j; continue
        m = re.match(r'r(#*)"', text[i:i + 10]) if c == "r" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) else None
        if m:
            end = '"' + m.group(1); j = text.find(end, i + len(m.group(0)))
            j = n if j < 0 else j + len(end)
            for k in range(i, j):
                if text[k] == "\n":
                    cur_line += 1
                    if cur_line < len(lines): da_at[cur_line] = da; db_at[cur_line] = db
            i = j; continue
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\": j += 1
                elif text[j] == "\n":
                    cur_line += 1
                    if cur_line < len(lines): da_at[cur_line] = da; db_at[cur_line] = db
                j += 1
            i = j + 1; continue
        if c == "'":
            m = re.match(r"'(\\.[^']*|[^\\'])'", text[i:i + 12])
            if m: i += len(m.group(0)); continue
            i += 1; continue
        if c in "([{":
            da += 1
            if c == "{": db += 1
            stack.append((c, cur_line))
        elif c in ")]}":
            da -= 1
            if c == "}": db -= 1
            if stack:
                oc, ol = stack.pop()
                if oc == "{" and ol not in braces: braces[ol] = cur_line
        i += 1
    return lines, da_at, db_at, braces

def _bisect(a, x):
    lo, hi = 0, len(a)
    while lo < hi:
        mid = (lo + hi) // 2
        if a[mid] <= x: lo = mid + 1
        else: hi = mid
    return lo - 1

_cache = {}

def items(path):
    """-> list of (start0, header0, end0, name, kind, impl) for the fns in a file (0-based lines)."""
    if path in _cache: return _cache[path]
    text = open(path).read()
    lines, da_at, db_at, braces = scan(text)
    out, impls = [], []
    for h, l in enumerate(lines):
        mi = IMPL.match(l) or MOD.match(l)
        if mi and "{" in l and h in braces:
            impls.append((h, braces[h], mi.group(1)))
    for h, l in enumerate(lines):
        m = HDR.match(l)
        if not m or l.lstrip().startswith("//"): continue
        # the body: first line at or after h that opens a brace whose depth is the header's brace depth
        # (a contract written after the signature, `requires`/`ensures`/..., may hold struct literals with braces at
        #  the header's depth: once inside one, only a line that starts with `{` opens the body)
        b = None; in_contract = False
        for k in range(h, min(h + 400, len(lines))):
            st = lines[k].strip()
            if k > h and re.match(r"(requires|ensures|recommends|decreases|returns|opens_invariants|no_unwind)\b", st):
                in_contract = True
            if k in braces and (db_at[k] == db_at[h] or k == h):
                if not in_contract or st.startswith("{"):
                    b = k; break
            if st.endswith(";") and da_at[k] == da_at[h] and k > h and not in_contract: break
        if b is None: continue
        end = braces[b]
        s = h
        while s - 1 >= 0:
            p = lines[s - 1].strip()
            if da_at[s] is not None and da_at[s] > da_at[h] and p: s -= 1; continue
            if p.startswith("#[") or p.startswith("//") or p.startswith("#!["): s -= 1; continue
            if p and da_at[s - 1] is not None and da_at[s - 1] > da_at[h]: s -= 1; continue
            break
        kind = ((m.group(1) or "").strip() + " " + (m.group(2) or "exec")).strip()
        im = [x for x in impls if x[0] < h <= x[1]]
        imp = min(im, key=lambda x: x[1] - x[0])[2] if im else ""
        out.append((s, h, end, m.group(3), kind, imp))
    _cache[path] = out
    return out

def where(path, line1):
    it = items(path); L = line1 - 1
    inside = [x for x in it if x[0] <= L <= x[2]]
    if inside:
        x = min(inside, key=lambda x: x[2] - x[0])
        return x[3], x[4], x[5], "%d-%d" % (x[0] + 1, x[2] + 1), ""
    above = [x for x in it if x[1] <= L]
    near = max(above, key=lambda x: x[1])[3] if above else ""
    return "(outside any fn)", "", "", "", "nearest fn header above: " + near
