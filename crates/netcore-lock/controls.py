#!/usr/bin/env python3
"""The generator of netcore's negative controls. Needs Python 3.11 or later. File work only: no Verus, no
compiler. Verus runs of the copies are the lab's. Paths are relative to this file: the crate is ../netcore/src
(--crate), the headers headers/<module>.md, the results results/. See README.md.

    controls.py --check   [--crate SRC]                  the file's own rules, against the crate (default: placed)
    controls.py --cut DIR [--crate SRC] [--only ID,ID]   one changed copy per live verus control: DIR/<dir>/src
    controls.py --judge RUNDIR --cut-dir DIR --rlimit R --seed S|default [--crate SRC] [--run-id ID] [--rejudge TAG]
                                                         reads RUNDIR/<dir>/{jq.json,eq.txt}; writes results/<id>.tsv
                                                         (--rejudge keeps an existing one as <id>.before-TAG.tsv)
    controls.py --confirm RUN                            confirmed = RUN where the run's places are within fail_in
    controls.py --lists OUT [--run RUN[,RUN]] [--crate SRC]  one Markdown list per module, from the file and the results

The file: controls.toml beside this script. A control's edits are `[[control.edit]]` tables (file, text,
replacement), applied in order; every live control has at least one, and each text occurs exactly once in the
VERIFIED part of its file (before the first line-start `#[cfg(test)]` or `#[cfg(kani)]`) after the edits before it
are applied. A non-live control may have edits (the text it had) or none. A verdict is `accepted` only when the run printed its
summary with a verified count above 0 and 0 errors; no summary, a compiler error or 0 verified is `not_compiled`.
A fail_in name may be `fn`, `Impl::fn` or `module::fn` (module = the file's stem).
An rlimit-exceeded error is `cost`: recorded with its function and rlimit count, it does not count against fail_in;
a control whose only errors are cost is `not_judged`, never rejected.
The enclosing function of each observed place is computed from that control's own copy by scan.py.
"""
import sys
if sys.version_info < (3, 11):
    sys.exit('controls.py needs Python 3.11 or later.')
import hashlib, json, os, re, shutil, tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = HERE + '/controls.toml'
PLACED = os.path.normpath(os.path.join(HERE, '..', 'netcore', 'src'))  # the crate, beside this one
KEYS = {'id', 'module', 'edit', 'clause', 'what', 'fail_in', 'state', 'reason', 'confirmed', 'kind',
        'harness', 'test'}
STATES = {'live', 'accepted', 'retired', 'not_cuttable', 'compiler'}
KINDS = {'verus', 'kani', 'unit'}
HEADERS = HERE + '/headers'
MARK = re.compile(r'^#\[cfg\((?:test|kani)\)\]', re.M)


def split(t):
    m = MARK.search(t)
    return (t, '') if m is None else (t[:m.start()], t[m.start():])


def load_file():
    return tomllib.load(open(FILE, 'rb'))['control']


def edits(c):
    es = c.get('edit', [])
    ok = isinstance(es, list) and all(isinstance(e, dict) and set(e) == {'file', 'text', 'replacement'}
                                     and all(isinstance(e[k], str) for k in e) for e in es)
    return ([(e['file'], e['text'], e['replacement']) for e in es] if ok else []), ok


def dirname(cid):
    return re.sub(r'[^A-Za-z0-9._-]', '_', cid.replace(':', '__').replace('/', '--').replace("'", 'p'))


def tree_hash(src):
    h = hashlib.sha256()
    for f in sorted(os.listdir(src)):
        if f.endswith('.rs'):
            h.update(f.encode() + b'\0' + hashlib.sha256(open(src + '/' + f, 'rb').read()).digest())
    return h.hexdigest()[:16]


def apply(c, crate):
    """-> ({file: new text}, problem or None)."""
    es, ok = edits(c)
    if not ok:
        return None, 'an edit table that is not exactly file, text and replacement (all text)'
    heads = {}
    for f, t, r in es:
        if f not in heads:
            if not os.path.exists(crate + '/' + f):
                return None, '%s: no such file' % f
            heads[f] = list(split(open(crate + '/' + f).read()))
        n = heads[f][0].count(t)
        if n != 1:
            return None, '%s: the text occurs %d times in the verified part' % (f, n)
        heads[f][0] = heads[f][0].replace(t, r, 1)
    return {f: h + tl for f, (h, tl) in heads.items()}, None


def check(crate):
    cs = load_file()
    bad = []
    seen = {}
    for c in cs:
        cid = c.get('id', '?')
        unk = set(c) - KEYS
        if unk:
            bad.append('%s: unknown keys %s' % (cid, sorted(unk)))
        if 'id' not in c:
            bad.append('a table with no id')
        if cid in seen:
            bad.append('%s: id not unique' % cid)
        seen[cid] = 1
        st = c.get('state')
        if st not in STATES:
            bad.append('%s: state %r' % (cid, st))
        kind = c.get('kind', 'verus')
        if kind not in KINDS:
            bad.append('%s: kind %r' % (cid, kind))
        if kind == 'kani' and not c.get('harness'):
            bad.append('%s: kani control with no harness' % cid)
        if kind == 'unit' and not c.get('test'):
            bad.append('%s: unit control with no test' % cid)
        if st != 'live' and not c.get('reason'):
            bad.append('%s: %s with no reason' % (cid, st))
        if st == 'live':
            if kind == 'verus' and not c.get('fail_in'):
                bad.append('%s: live verus control with an empty fail_in' % cid)
            if not c.get('edit'):
                bad.append('%s: live control with no edit' % cid)
            else:
                _, why = apply(c, crate)
                if why:
                    bad.append('%s: %s' % (cid, why))
        if 'confirmed' in c and not isinstance(c['confirmed'], str):
            bad.append('%s: confirmed is not text' % cid)
    live = sum(1 for c in cs if c.get('state') == 'live')
    print('--check: %d controls, %d live; crate %s (tree %s): %s' % (len(cs), live, crate, tree_hash(crate),
                                                                 'clean' if not bad else '%d problems' % len(bad)))
    for b in bad:
        print('  ' + b)
    return not bad


def cut(out, crate, only=None):
    if not check(crate):
        sys.exit('--cut: the file does not pass --check; nothing written')
    os.makedirs(out, exist_ok=True)
    rows = []
    for c in load_file():
        if c['state'] != 'live' or c.get('kind', 'verus') != 'verus':
            continue
        if only is not None and c['id'] not in only:
            continue
        new, why = apply(c, crate)
        d = out + '/' + dirname(c['id'])
        if os.path.exists(d):
            sys.exit('--cut: %s exists; refused (nothing is overwritten)' % d)
        shutil.copytree(crate, d + '/src')
        for f, t in new.items():
            open(d + '/src/' + f, 'w').write(t)
        rows.append((c['id'], dirname(c['id'])))
    with open(out + '/copies.tsv', 'w') as w:
        w.write('# crate %s tree %s\n' % (crate, tree_hash(crate)))
        for i, d in rows:
            w.write('%s\t%s\n' % (i, d))
    print('--cut: %d copies in %s' % (len(rows), out))


def where_fn():
    sys.path.insert(0, HERE)
    import scan
    return scan.where


def judge(rundir, cutdir, crate, run_id, rejudge=None, rlimit=None, seed=None):
    where = where_fn()
    cs = {c['id']: c for c in load_file()}
    copies = [l.rstrip('\n').split('\t') for l in open(cutdir + '/copies.tsv') if not l.startswith('#')]
    head = open(cutdir + '/copies.tsv').readline()
    cut_tree = head.rsplit(' tree ', 1)[1].strip() if ' tree ' in head else '?'
    # a run names only what it was on: the crate's tree (copies.tsv's header, the cut: observed), the verifier's
    # version (every copy's own JSON: observed) and the flags the run was given (stated: Verus writes neither)
    if not rlimit or not seed:
        sys.exit('--judge: --rlimit and --seed are required: the flags the run was given (--seed default: no seed flag)')
    vers = set()
    for cid, d in copies:
        try:
            vers.add(json.load(open(rundir + '/' + d + '/jq.json'))['verus']['version'])
        except Exception:
            vers.add(None)
    if len(vers) != 1 or None in vers:
        sys.exit('--judge: the copies do not all name one verifier version: %s' % sorted(map(str, vers)))
    version = vers.pop()
    text_id = 'tree %s' % cut_tree
    header = ('# run %%s; tree %s; verifier Verus %s; flags the run was given (stated, not read from an output): '
              '--rlimit %s, %s' % (cut_tree, version, rlimit,
                                   'no seed flag (Verus\'s default seed)' if seed == 'default' else '--seed %s' % seed))
    if not run_id:
        n = [int(m.group(1)) for f in os.listdir(HERE + '/results') for m in [re.match(r'^run-(\d+)\.tsv$', f)] if m]
        run_id = 'run-%d' % (max(n, default=0) + 1)
    os.makedirs(HERE + '/results', exist_ok=True)
    outp = HERE + '/results/%s.tsv' % run_id
    if os.path.exists(outp) and rejudge:
        # a re-judge reads the same run: a kept file whose header already has this form must name the same tree,
        # verifier and flags, or the re-judge is refused
        import glob
        for old in glob.glob(HERE + '/results/%s.before-*.tsv' % run_id) + [outp]:
            h = open(old).readline().rstrip('\n')
            if '; verifier ' in h and h.split('; ', 1)[1] != (header % run_id).split('; ', 1)[1]:
                sys.exit('--judge: %s names another run: %s' % (old, h))
    if os.path.exists(outp):
        if not rejudge:
            sys.exit('--judge: %s exists; refused (--rejudge TAG keeps it as <run>.before-TAG.tsv and writes anew)' % outp)
        kept = HERE + '/results/%s.before-%s.tsv' % (run_id, rejudge)
        if os.path.exists(kept):
            sys.exit('--judge: %s exists; refused' % kept)
        os.rename(outp, kept)
    lines, fails = [], []
    for cid, d in copies:
        c = cs.get(cid)
        jq, eq = rundir + '/' + d + '/jq.json', rundir + '/' + d + '/eq.txt'
        if not os.path.exists(eq):
            lines.append((cid, 'not_run', '', '', '', '', 'no Verus output'))
            fails.append(cid)
            continue
        err = open(eq, errors='replace').read()
        vr = None
        try:
            vr = json.load(open(jq))['verification-results']
        except Exception:
            m = re.search(r'verification results:: (\d+) verified, (\d+) errors', err)
            if m:
                vr = {'verified': int(m.group(1)), 'errors': int(m.group(2))}
        compiler = re.search(r'^error\[E\d+\]', err, re.M) is not None
        places, costs = [], []
        breakdown = {}
        try:
            for m in json.load(open(jq))['times-ms']['smt']['smt-run-module-times']:
                for x in m['function-breakdown']:
                    breakdown[x['function']] = x.get('rlimit')
        except Exception:
            pass
        for msg, f, ln in re.findall(r'^(error(?:\[\w+\])?: .+)\n\s+--> src/(\w+\.rs):(\d+)', err, re.M):
            fn, kind, imp, span, note = where(cutdir + '/' + d + '/src/' + f, int(ln))
            if 'rlimit' in msg:
                # an rlimit-exceeded error is cost, not a place: recorded with its function and rlimit count
                full = 'lib::%s::%s%s' % (f[:-3], (imp + '::') if imp else '', fn)
                costs.append((f, ln, fn, imp, breakdown.get(full)))
            else:
                places.append((f, ln, fn, imp))
        if vr is None or vr['verified'] == 0 or compiler:
            verdict = 'not_compiled'
        elif vr['errors'] == 0:
            verdict = 'accepted'
        elif not places:
            verdict = 'not_judged'   # its only errors are cost
        else:
            verdict = 'rejected'
        fi = set(c.get('fail_in', [])) if c else set()
        obs = {p[2] for p in places} | {'%s::%s' % (p[3], p[2]) for p in places if p[3]}
        fns = {p[2] for p in places}
        # a place is within when fail_in names its fn as `fn`, `Impl::fn` or `module::fn` (module: the place's file stem)
        within = bool(fns) and all(fn in fi or ('%s::%s' % (p[3], fn)) in fi or ('%s::%s' % (p[0][:-3], fn)) in fi
                                   for p in places for fn in [p[2]])
        tag = verdict if verdict != 'rejected' else ('rejected_within' if within else 'rejected_elsewhere')
        if tag != 'rejected_within':
            fails.append(cid)
        note = ''
        if c and c.get('confirmed') == 'seeded':
            note = 'SEEDED fail_in, never run before: confirmed only after these places are read'
        lines.append((cid, tag, str(vr['verified']) if vr else '', str(vr['errors']) if vr else '',
                      '; '.join('%s:%s %s%s' % (f, ln, (imp + '::') if imp else '', fn) for f, ln, fn, imp in places),
                      '; '.join('%s:%s %s%s rlimit %s' % (f, ln, (imp + '::') if imp else '', fn, r) for f, ln, fn, imp, r in costs),
                      note))
    with open(outp, 'w') as w:
        w.write(header % run_id + '\n')
        w.write('id\ttext\tverdict\tverified\terrors\tplaces\tcost\tnote\n')
        for cid, v, a, b, p, k, n in lines:
            w.write('\t'.join([cid, text_id, v, a, b, p, k, n]) + '\n')
    import collections
    print('--judge: %s: %s' % (outp, dict(collections.Counter(l[1] for l in lines))))
    for cid in fails:
        l = next(x for x in lines if x[0] == cid)
        print('  %s: %s %s/%s at %s' % (cid, l[1], l[2], l[3], l[4] or '-'))
    return not fails


def confirm(run):
    """For each live control rejected within its fail_in in RUN: a control confirmed by an earlier run keeps that
    run when RUN observed exactly the functions of its fail_in (the earlier run's places, as seeded): the runs agree;
    otherwise it is confirmed by RUN. A control still `seeded` stays `seeded` (its places are read first).
    A control not rejected within fail_in is left as it is and listed."""
    import collections
    res = {}
    for l in open(HERE + '/results/%s.tsv' % run):
        if l.startswith('#') or l.startswith('id\t'):
            continue
        c = l.rstrip('\n').split('\t')
        fns = {re.sub(r'^\w+::', '', p.split(' ', 1)[1]) for p in c[5].split('; ') if ' ' in p}
        res[c[0]] = (c[2], fns)
    cs = {c['id']: c for c in load_file()}
    want, tally, left = {}, collections.Counter(), []
    for cid, c in cs.items():
        if c['state'] != 'live' or cid not in res:
            continue
        v, fns = res[cid]
        if v != 'rejected_within':
            left.append((cid, v))
            continue
        old = c.get('confirmed', 'seeded')
        if old == 'seeded':
            tally['stays seeded'] += 1
            continue
        if fns == set(c.get('fail_in', [])):
            tally['agrees with ' + old] += 1
            continue
        want[cid] = run
        tally['now ' + run] += 1
    raw = open(FILE).read().split('\n')
    out, cur = [], None
    for line in raw:
        if line == '[[control]]':
            cur = None
        m = re.match(r'^id = "(.*)"$', line)
        if m:
            cur = m.group(1).replace('\\"', '"').replace('\\\\', '\\')
        if line.startswith('confirmed = ') and cur in want:
            line = 'confirmed = "%s"' % want[cur]
        out.append(line)
    open(FILE, 'w').write('\n'.join(out))
    print('--confirm %s: %s; not within fail_in, left as they are: %d' % (run, dict(tally), len(left)))
    for cid, v in left:
        print('  %s: %s' % (cid, v))


def lists(outdir, run, crate=PLACED):
    import collections
    cs = load_file()
    res = {}
    for r1 in (run.split(',') if run else []):
        for l in open(HERE + '/results/%s.tsv' % r1):
            if l.startswith('#') or l.startswith('id\t'):
                continue
            c = l.rstrip('\n').split('\t')
            res[c[0]] = c
    crate_modules = {f[:-3] for f in os.listdir(crate) if f.endswith('.rs')}
    by = collections.defaultdict(list)
    nomod = []
    for c in cs:
        if c['module'] not in crate_modules:
            if c['state'] == 'live':
                sys.exit('--lists: refused: live control %s has module %r, not a crate module' % (c['id'], c['module']))
            nomod.append(c)
        else:
            by[c['module']].append(c)
    missing = sorted(m for m in by if not os.path.exists(HEADERS + '/%s.md' % m))
    if nomod and not os.path.exists(HEADERS + '/other.md'):
        missing.append('other (the list of non-live tables of no crate module: %d)' % len(nomod))
    if missing:
        print('--lists: refused: no header file in %s for: %s' % (HEADERS, ', '.join(
            '%s (%d tables, %d live)' % (m, len(by[m]), sum(1 for c in by[m] if c['state'] == 'live')) for m in missing)))
        sys.exit(1)
    os.makedirs(outdir, exist_ok=True)
    cell = lambda s: s.replace('|', '\\|').replace('\n', '\\n')
    for mod, rows in sorted(by.items()):
        h = HERE + '/headers/%s.md' % mod
        h = HEADERS + '/%s.md' % mod
        L = ['# Negative controls: `%s`' % mod, '', open(h).read().strip(), '',
             'Generated by controls.py --lists from controls.toml%s. Do not edit; edit the file of record.' % (
                 ' and ' + ', '.join('results/%s.tsv' % r1 for r1 in run.split(',')) if run else ''), '']
        live = [c for c in rows if c['state'] == 'live']
        other = [c for c in rows if c['state'] != 'live']
        if live:
            L += ['| Id | Clause | What is broken | Text | Replacement | Must fail in | Last run rejected it at |',
                  '|---|---|---|---|---|---|---|']
            for c in live:
                es, _ = edits(c)
                r = res.get(c['id'])
                L.append('| %s | %s | %s | %s | %s | %s | %s |' % (
                    cell(c['id']), cell(c.get('clause', '')), cell(c.get('what', '')),
                    '<br>'.join('`%s`: `%s`' % (f, cell(t)) for f, t, _ in es),
                    '<br>'.join('`%s`' % cell(x) for _, _, x in es),
                    ', '.join('`%s`' % x for x in c.get('fail_in', [])),
                    cell('%s: %s' % (r[2], r[5])) if r else 'not in the run'))
            L.append('')
        if other:
            L += ['| Id | State | Reason |', '|---|---|---|']
            for c in other:
                L.append('| %s | %s | %s |' % (cell(c['id']), c['state'], cell(c.get('reason', ''))))
            L.append('')
        open(outdir + '/controls-%s.md' % mod, 'w').write('\n'.join(L))
    if nomod:
        L = ['# Negative controls of no crate module', '', open(HEADERS + '/other.md').read().strip(), '',
             'Generated by controls.py --lists from controls.toml. Do not edit; edit the file of record.', '',
             '| Id | State | Reason |', '|---|---|---|']
        for c in sorted(nomod, key=lambda c: c['id']):
            L.append('| %s | %s | %s |' % (cell(c['id']), c['state'], cell(c.get('reason', ''))))
        open(outdir + '/other.md', 'w').write('\n'.join(L) + '\n')
    print('--lists: %d modules in %s%s' % (len(by), outdir, '; other.md: %d tables' % len(nomod) if nomod else ''))


def main(a):
    opt = lambda k, d=None: a[a.index(k) + 1] if k in a else d
    crate = opt('--crate', PLACED)
    if '--check' in a:
        sys.exit(0 if check(crate) else 1)
    if '--cut' in a:
        return cut(opt('--cut'), crate, set(opt('--only').split(',')) if '--only' in a else None)
    if '--judge' in a:
        sys.exit(0 if judge(opt('--judge'), opt('--cut-dir'), crate, opt('--run-id'), opt('--rejudge'),
                            opt('--rlimit'), opt('--seed')) else 1)
    if '--confirm' in a:
        return confirm(opt('--confirm'))
    if '--lists' in a:
        return lists(opt('--lists'), opt('--run'), crate)
    print(__doc__)


main(sys.argv[1:])
