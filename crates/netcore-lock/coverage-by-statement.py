#!/usr/bin/env python3
"""For every statement the lock holds (each function with a contract, each spec
fn, each lemma or theorem statement), how many live controls the given run rejected INSIDE it; and the list of those
with none, by module. File work only.

    coverage-by-statement.py RUN[,RUN] [--crate SRC]  reads results/RUN.tsv (several: their union) and STATEMENTS.lock; writes
                                        coverage-RUN[+RUN].tsv

The statements are read from STATEMENTS.lock's per-file sections: an `items` line ending in `contract` (a function
with a contract), and each `spec fn` / `proof fn` header of the specifications part. A place counts for a statement
when the place's file is the statement's file and its enclosing function (computed by --judge from the control's own
copy) has the statement's name. A name defined twice in one file (two impls) is counted once for both: said in the
row's note.

A second count: how many live controls CUT inside the statement (an edit's first changed line, on the placed text,
lies in it, by scan.py). A spec fn has no body of its own to fail: Verus reports a cut spec where the
spec is used, so for spec fns the first count is near zero by construction and the second is the one to read.
"""
import sys
if sys.version_info < (3, 11):
    sys.exit('coverage-by-statement.py needs Python 3.11 or later.')
import collections, os, re

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = HERE + '/STATEMENTS.lock'
runs = sys.argv[1].split(',')
run = '+'.join(runs) if len(runs) > 1 else runs[0]
PL = sys.argv[sys.argv.index('--crate') + 1] if '--crate' in sys.argv else os.path.normpath(os.path.join(HERE, '..', 'netcore', 'src'))
stm = []  # (file, name, kind)
cur, part = None, None
for line in open(LOCK):
    m = re.match(r'^==== src/(\w+\.rs)$', line.rstrip('\n'))
    if m:
        cur, part = m.group(1), 'items'
        continue
    if line.startswith('==== '):
        cur = None
        continue
    if cur is None:
        continue
    if line.startswith('the specifications'):
        part = 'specs'
        continue
    if part == 'items' and line.rstrip().endswith(' contract'):
        m = re.search(r'\bfn\s+(\w+)', line.split('  @ ')[0])
        if m:
            stm.append((cur, m.group(1), 'contract'))
    elif part == 'specs':
        m = re.match(r'^\s+(?:pub(?:\([^)]*\))?\s+)?(?:(?:open|closed|broadcast)\s+)*(spec|proof)\s+fn\s+(\w+)', line)
        if m:
            name = m.group(2)
            kind = 'spec fn' if m.group(1) == 'spec' else ('theorem' if name.startswith('theorem') else 'lemma')
            stm.append((cur, name, kind))
dup = collections.Counter((f, n) for f, n, k in stm)
hits = collections.defaultdict(set)
for l in (x for r in runs for x in open(HERE + '/results/%s.tsv' % r)):
    if l.startswith('#') or l.startswith('id\t'):
        continue
    c = l.rstrip('\n').split('\t')
    if not c[2].startswith('rejected'):
        continue
    for p in c[5].split('; '):
        m = re.match(r'^(\w+\.rs):\d+ (?:\w+::)?(\w+)$', p)
        if m:
            hits[(m.group(1), m.group(2))].add(c[0])
import ast, tomllib
sys.path.insert(0, HERE)
import scan
MARK = re.compile(r'^#\[cfg\((?:test|kani)\)\]', re.M)


def split(t):
    m = MARK.search(t)
    return (t, '') if m is None else (t[:m.start()], t[m.start():])


where = scan.where
cuts = collections.defaultdict(set)
for c in tomllib.load(open(HERE + '/controls.toml', 'rb'))['control']:
    if c['state'] != 'live':
        continue
    heads = {}
    for e in c['edit']:
        f = e['file']
        heads.setdefault(f, split(open(PL + '/' + f).read())[0])
        h = heads[f]; i = h.index(e['text'])
        a, b = e['text'], e['replacement']
        k = 0
        while k < min(len(a), len(b)) and a[k] == b[k]:
            k += 1
        ln = h[:i + k].count('\n') + 1
        cuts[(f, where(PL + '/' + f, ln)[0])].add(c['id'])
        heads[f] = h.replace(a, b, 1)
seen = set()
rows = []
for f, n, k in stm:
    if (f, n, k) in seen:
        continue
    seen.add((f, n, k))
    rows.append((f[:-3], n, k, len(hits.get((f, n), ())), len(cuts.get((f, n), ())),
                 'name defined %d times in the file' % dup[(f, n)] if dup[(f, n)] > 1 else ''))
out = HERE + '/coverage-%s.tsv' % run
with open(out, 'w') as w:
    w.write('module\tstatement\tkind\tlive controls rejected inside it\tlive controls cutting inside it\tnote\n')
    for r in rows:
        w.write('%s\t%s\t%s\t%d\t%d\t%s\n' % r)
zero = [r for r in rows if r[3] == 0 and r[4] == 0]
print('rejected inside: 0 for %d of %d; cut inside: 0 for %d' % (sum(1 for r in rows if r[3] == 0), len(rows), sum(1 for r in rows if r[4] == 0)))
print('%d statements; %d with no live control rejected inside AND none cutting inside; by kind: %s' % (len(rows), len(zero), dict(collections.Counter(r[2] for r in zero))))
by = collections.defaultdict(list)
for r in zero:
    by[r[0]].append('%s (%s)' % (r[1], r[2]))
for m in sorted(by):
    print('%s: %d: %s' % (m, len(by[m]), ', '.join(by[m])))
