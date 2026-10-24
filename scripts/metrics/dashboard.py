#!/usr/bin/env python3
"""Render the quality dashboard from a snapshot history (spec 31, QM-016).

Reads every `YYYY-MM-DD-<sha7>.json` in the history directory (the file
names sort chronologically) and writes one self-contained `index.html`:
inline SVG, a style block, no script, nothing fetched. It opens from a
file, from a static host, and in a sandbox with no network. Each chart
carries a title and is followed by a table of the values it draws, so the
numbers are reachable without the picture. A metric a snapshot did not
measure is a gap in the line, never a zero.

Usage: dashboard.py <history_dir> <out_dir>

Files that do not parse or do not validate against `schema.py` are skipped
and listed on the page. The output has no timestamp: the same history
renders the same bytes.
"""

from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema as schema_mod  # noqa: E402

NAME = re.compile(r"^(\d{4}-\d{2}-\d{2})-[0-9a-f]{7}\.json$")

# Plot geometry, in SVG user units. The right margin leaves room for an
# end label; the left for four-digit tick labels.
W, H = 720, 240
LEFT, RIGHT, TOP, BOTTOM = 56, 96, 16, 36
PLOT_W, PLOT_H = W - LEFT - RIGHT, H - TOP - BOTTOM
MAX_X_TICKS = 6
MIN_LABEL_GAP = 13  # end labels closer than this collide; the legend takes over

# Palette: the dataviz reference instance (references/palette.md). Light and
# dark are each selected steps, not a flipped copy.
CSS = """
:root {
  color-scheme: light dark;
  --page: #f9f9f7; --surface: #fcfcfb;
  --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11, 11, 11, 0.10);
  --series-1: #2a78d6; --series-2: #eb6834;
  --good: #0ca30c; --warning: #fab219; --critical: #d03b3b; --none: #898781;
}
@media (prefers-color-scheme: dark) {
  :root {
    --page: #0d0d0d; --surface: #1a1a19;
    --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255, 255, 255, 0.10);
    --series-1: #3987e5; --series-2: #d95926;
  }
}
html { background: var(--page); color: var(--ink);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
body { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.6rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 40px 0 8px; }
p.meta { color: var(--ink-2); margin: 0 0 8px; }
code { font-size: 0.92em; }
figure { margin: 0; background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; padding: 8px; }
svg { display: block; width: 100%; max-width: 720px; height: auto; }
.grid { stroke: var(--grid); stroke-width: 1; }
.axis { stroke: var(--axis); stroke-width: 1; }
.tick { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
.end-label { fill: var(--ink-2); font-size: 11px; font-variant-numeric: tabular-nums; }
.empty { fill: var(--muted); font-size: 13px; }
.line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
.dot { stroke: var(--surface); stroke-width: 2; }
.s1 .line { stroke: var(--series-1); } .s1 .dot { fill: var(--series-1); }
.s2 .line { stroke: var(--series-2); } .s2 .dot { fill: var(--series-2); }
.legend { display: flex; gap: 20px; margin: 8px 0 0; padding: 0; list-style: none;
  color: var(--ink-2); font-size: 0.9rem; }
.swatch { display: inline-block; width: 12px; height: 12px; border-radius: 50%;
  vertical-align: -1px; margin-right: 6px; }
.swatch.s1 { background: var(--series-1); } .swatch.s2 { background: var(--series-2); }
table { border-collapse: collapse; margin: 12px 0 0; font-size: 0.9rem; width: 100%; }
caption { text-align: left; color: var(--ink-2); padding: 0 0 4px; }
th, td { text-align: left; padding: 4px 10px 4px 0; border-bottom: 1px solid var(--grid);
  vertical-align: top; }
th { color: var(--ink-2); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td.gap { color: var(--muted); }
.status::before { content: ""; display: inline-block; width: 10px; height: 10px;
  border-radius: 50%; margin-right: 6px; vertical-align: -1px; background: var(--none); }
.status-pass::before { background: var(--good); }
.status-warn::before { background: var(--warning); }
.status-fail::before { background: var(--critical); }
ul.skipped li, ul.lints li { margin: 2px 0; }
"""


# --------------------------------------------------------------- reading


def get(doc: dict, path: str):
    """Walk a dotted path; None at the first missing or null step."""
    cur = doc
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur or cur[key] is None:
            return None
        cur = cur[key]
    return cur


def load_history(history: Path) -> tuple[list[tuple[str, dict]], list[tuple[str, str]]]:
    """Snapshots as (date, doc) in file-name order, and (name, reason) for every
    JSON file that was skipped."""
    snaps: list[tuple[str, dict]] = []
    skipped: list[tuple[str, str]] = []
    for path in sorted(history.glob("*.json")):
        m = NAME.match(path.name)
        if not m:
            skipped.append((path.name, "name is not YYYY-MM-DD-<sha7>.json"))
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            skipped.append((path.name, f"not JSON: {e}"))
            continue
        problems = schema_mod.validate(doc)
        if problems:
            skipped.append((path.name, "; ".join(problems[:3]) + (" ..." if len(problems) > 3 else "")))
            continue
        snaps.append((m[1], doc))
    return snaps, skipped


# --------------------------------------------------------------- formatting


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def fmt(value) -> str:
    """A number for a table cell or label: thousands-separated, two decimals
    for a float, a dash for a gap."""
    if value is None:
        return "not measured"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.2f}".rstrip("0").rstrip(".") if value != int(value) else f"{int(value):,}"
    return str(value)


def num_cell(value) -> str:
    if value is None:
        return '<td class="num gap">not measured</td>'
    return f'<td class="num">{esc(fmt(value))}</td>'


def nice_step(span: float) -> float:
    """A 1-2-5 step giving about four intervals over `span`."""
    if span <= 0:
        return 1.0
    raw = span / 4
    mag = 10 ** int(f"{raw:e}".split("e")[1])
    for mult in (1, 2, 5, 10):
        if mult * mag >= raw:
            return mult * mag
    return 10 * mag


def y_scale(values: list[float], fixed_max: float | None) -> tuple[float, list[float]]:
    """(ymax, tick values) for a domain starting at zero."""
    if fixed_max is not None:
        step = nice_step(fixed_max)
        top = fixed_max
    else:
        peak = max(values, default=0.0)
        step = nice_step(peak)
        if all(float(v).is_integer() for v in values):
            step = max(1.0, step)  # a count never gets a half tick
        top = step * max(1, -(-peak // step))  # ceil to a step; at least one step
    ticks, t = [], 0.0
    while t <= top + 1e-9:
        ticks.append(t)
        t += step
    return top, ticks


def fmt_tick(value: float) -> str:
    return f"{int(value):,}" if value == int(value) else f"{value:g}"


# --------------------------------------------------------------- charts


def line_chart(chart_id: str, title: str, dates: list[str],
               series: list[tuple[str, list]], fixed_max: float | None, unit: str) -> str:
    """One SVG: a line per series over the snapshots, gaps where a value is
    None, a marker on every measured point, the last value as an end label
    (dropped when two series' labels would collide; the legend then carries
    identity and the table the values)."""
    n = len(dates)
    xs = [LEFT + PLOT_W / 2] if n == 1 else [LEFT + i * PLOT_W / (n - 1) for i in range(n)]
    all_values = [v for _, vs in series for v in vs if v is not None]
    ymax, ticks = y_scale(all_values, fixed_max)
    bottom = TOP + PLOT_H

    def y_of(v: float) -> float:
        return bottom - (v / ymax) * PLOT_H if ymax else bottom

    out = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-labelledby="{chart_id}-title">',
           f'<title id="{chart_id}-title">{esc(title)}</title>']
    # Gridlines and y ticks; the baseline is the axis.
    for t in ticks:
        y = y_of(t)
        cls = "axis" if t == 0 else "grid"
        out.append(f'<line class="{cls}" x1="{LEFT}" y1="{y:.1f}" x2="{LEFT + PLOT_W}" y2="{y:.1f}"/>')
        out.append(f'<text class="tick" x="{LEFT - 8}" y="{y + 4:.1f}" text-anchor="end">{esc(fmt_tick(t))}</text>')
    if unit:
        out.append(f'<text class="tick" x="{LEFT - 8}" y="{TOP - 4}" text-anchor="end">{esc(unit)}</text>')
    # x ticks: at most MAX_X_TICKS dates, evenly spread by index.
    k = min(n, MAX_X_TICKS)
    idxs = sorted({round(i * (n - 1) / (k - 1)) for i in range(k)}) if k > 1 else [0]
    for i in idxs:
        out.append(f'<text class="tick" x="{xs[i]:.1f}" y="{bottom + 18}" text-anchor="middle">{esc(dates[i])}</text>')

    if not all_values:
        out.append(f'<text class="empty" x="{LEFT + PLOT_W / 2:.1f}" y="{TOP + PLOT_H / 2:.1f}" '
                   f'text-anchor="middle">not measured in any snapshot</text>')
        out.append("</svg>")
        return "\n".join(out)

    # End labels, collision-checked across series.
    ends = []
    for name, vs in series:
        last = max((i for i, v in enumerate(vs) if v is not None), default=None)
        if last is not None:
            ends.append((y_of(vs[last]), name, vs[last]))
    ys = sorted(e[0] for e in ends)
    labels_fit = all(b - a >= MIN_LABEL_GAP for a, b in zip(ys, ys[1:]))

    for s, (name, vs) in enumerate(series, start=1):
        out.append(f'<g class="s{s}">')
        # Segments of consecutive measured points; a gap breaks the path.
        seg: list[str] = []
        for i, v in enumerate(vs):
            if v is None:
                if len(seg) > 1:
                    out.append(f'<path class="line" d="M{" L".join(seg)}"/>')
                seg = []
            else:
                seg.append(f"{xs[i]:.1f} {y_of(v):.1f}")
        if len(seg) > 1:
            out.append(f'<path class="line" d="M{" L".join(seg)}"/>')
        for i, v in enumerate(vs):
            if v is not None:
                out.append(f'<circle class="dot" cx="{xs[i]:.1f}" cy="{y_of(v):.1f}" r="4"/>')
        out.append("</g>")
    if labels_fit:
        for y, name, v in ends:
            text = fmt(v) if len(series) == 1 else f"{name} {fmt(v)}"
            out.append(f'<text class="end-label" x="{LEFT + PLOT_W + 10}" y="{y + 4:.1f}">{esc(text)}</text>')
    out.append("</svg>")
    return "\n".join(out)


def series_table(title: str, dates: list[str], shas: list[str], series: list[tuple[str, list]]) -> str:
    head = "".join(f'<th class="num">{esc(name)}</th>' for name, _ in series)
    rows = []
    for i, (d, sha) in enumerate(zip(dates, shas)):
        cells = "".join(num_cell(vs[i]) for _, vs in series)
        rows.append(f"<tr><td>{esc(d)}</td><td><code>{esc(sha)}</code></td>{cells}</tr>")
    return (f"<table><caption>{esc(title)}, per snapshot</caption>"
            f"<thead><tr><th>Date</th><th>Commit</th>{head}</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")


def chart_section(chart_id: str, title: str, dates: list[str], shas: list[str],
                  series: list[tuple[str, list]], fixed_max: float | None = None, unit: str = "") -> str:
    legend = ""
    if len(series) > 1:
        items = "".join(f'<li><span class="swatch s{i}"></span>{esc(name)}</li>'
                        for i, (name, _) in enumerate(series, start=1))
        legend = f'<ul class="legend">{items}</ul>'
    return (f'<section id="{chart_id}"><h2>{esc(title)}</h2><figure>'
            f"{line_chart(chart_id, title, dates, series, fixed_max, unit)}{legend}</figure>"
            f"{series_table(title, dates, shas, series)}</section>")


# --------------------------------------------------------------- tables


def gates_table(snap: dict) -> str:
    gates = snap.get("gates") or {}
    if not gates:
        return "<p>The newest snapshot carries no gates.</p>"
    rows = []
    for name in sorted(gates):
        g = gates[name]
        if g.get("kind") == "ratchet":
            limit = g.get("baseline")
            limit_text = "no baseline" if limit is None else f"{fmt(limit)} ({g.get('baseline_sha7') or '?'})"
        else:
            limit_text = fmt(g.get("threshold"))
        result = g.get("result", "not_evaluated")
        rows.append(f"<tr><td><code>{esc(name)}</code></td><td>{esc(g.get('kind', ''))}</td>"
                    f"{num_cell(g.get('value'))}<td class=\"num\">{esc(limit_text)}</td>"
                    f'<td><span class="status status-{esc(result)}">{esc(result.replace("_", " "))}</span></td></tr>')
    return (f"<table><caption>Gates of the newest snapshot, verdict {esc(snap.get('verdict', '?'))}</caption>"
            '<thead><tr><th>Gate</th><th>Kind</th><th class="num">Value</th>'
            '<th class="num">Threshold or baseline</th><th>Result</th></tr></thead>'
            f"<tbody>{''.join(rows)}</tbody></table>")


def hotspots_table(snap: dict) -> str:
    hot = snap.get("hotspots")
    if not isinstance(hot, dict):
        reason = (snap.get("run") or {}).get("not_measured", {}).get("hotspots", "not measured")
        return f"<p>Hotspots were not measured in the newest snapshot ({esc(reason)}).</p>"
    files = hot.get("files") or []
    if not files:
        return "<p>No file scored above zero in the newest snapshot.</p>"
    notes = [f"churn over {fmt(hot.get('window_days'))} days"]
    if not hot.get("findings_included", True):
        notes.append("ranked by churn alone: no findings source")
    elif not hot.get("coverage_included", True):
        notes.append("uncovered lines not included: coverage not measured")
    rows = []
    for f in files:
        rows.append(f"<tr><td><code>{esc(f.get('path', ''))}</code></td><td>{esc(f.get('crate') or '')}</td>"
                    f"{num_cell(f.get('churn'))}{num_cell(f.get('complexity'))}{num_cell(f.get('strict'))}"
                    f"{num_cell(f.get('uncovered_lines'))}{num_cell(f.get('score'))}</tr>")
    return (f"<table><caption>Top hotspots of the newest snapshot; {esc('; '.join(notes))}</caption>"
            '<thead><tr><th>Path</th><th>Crate</th><th class="num">Churn</th><th class="num">Complexity</th>'
            '<th class="num">Strict</th><th class="num">Uncovered lines</th><th class="num">Score</th></tr></thead>'
            f"<tbody>{''.join(rows)}</tbody></table>")


def promotable_list(snap: dict) -> str:
    lints = get(snap, "workspace.strict_promotable")
    if lints is None:
        return "<p>Not available: clippy did not cover the whole workspace in the newest snapshot.</p>"
    if not lints:
        return "<p>No strict lint is at zero across the workspace.</p>"
    items = "".join(f"<li><code>{esc(l)}</code></li>" for l in lints)
    return ("<p>Strict lints at zero across the whole tree: move each into "
            "<code>[workspace.lints.clippy]</code> and out of the strict list.</p>"
            f'<ul class="lints">{items}</ul>')


# --------------------------------------------------------------- page


def render(snaps: list[tuple[str, dict]], skipped: list[tuple[str, str]]) -> str:
    parts = ['<!DOCTYPE html>', '<html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             "<title>Quality metrics</title>", f"<style>{CSS}</style></head><body>",
             "<h1>Quality metrics</h1>"]
    if not snaps:
        parts.append('<p class="meta">No valid snapshot in the history.</p>')
    else:
        dates = [d for d, _ in snaps]
        shas = [get(doc, "git.sha7") or "?" for _, doc in snaps]
        newest = snaps[-1][1]
        parts.append(f'<p class="meta">Snapshots from {esc(dates[0])} to {esc(dates[-1])}. '
                     f"Newest: {esc(dates[-1])}, commit <code>{esc(shas[-1])}</code>, "
                     f"verdict {esc(newest.get('verdict', '?'))}. "
                     "Lines break where a snapshot did not measure a metric.</p>")

        def col(path: str) -> list:
            return [get(doc, path) for _, doc in snaps]

        parts.append(chart_section("coverage", "Coverage, lines covered", dates, shas,
                                   [("lines %", col("workspace.coverage.lines.pct"))], fixed_max=100.0, unit="%"))
        parts.append(chart_section("strict", "Strict lint hits", dates, shas,
                                   [("strict total", col("workspace.clippy.strict_total"))]))
        parts.append(chart_section("complexity", "Complexity lint hits", dates, shas,
                                   [("complexity total", col("workspace.clippy.complexity_total"))]))
        parts.append(chart_section("deps", "Unused dependencies", dates, shas,
                                   [("unused total", col("workspace.deps.unused_total"))]))
        parts.append(chart_section("size", "Code size, lines of code", dates, shas,
                                   [("code", col("workspace.size.code"))]))
        parts.append(chart_section("layers", "Layer edges", dates, shas,
                                   [("exceptions", col("layers.exceptions")), ("unexcepted", col("layers.unexcepted"))]))
        parts.append(f'<section id="gates"><h2>Latest gates</h2>{gates_table(newest)}</section>')
        parts.append(f'<section id="hotspots"><h2>Top hotspots</h2>{hotspots_table(newest)}</section>')
        parts.append(f'<section id="promotable"><h2>Promotable strict lints</h2>{promotable_list(newest)}</section>')
    if skipped:
        items = "".join(f"<li><code>{esc(n)}</code>: {esc(why)}</li>" for n, why in skipped)
        parts.append(f'<section id="skipped"><h2>Skipped files</h2><ul class="skipped">{items}</ul></section>')
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: dashboard.py <history_dir> <out_dir>", file=sys.stderr)
        return 2
    history, out = Path(argv[0]), Path(argv[1])
    if not history.is_dir():
        print(f"dashboard: {history} is not a directory", file=sys.stderr)
        return 1
    snaps, skipped = load_history(history)
    for name, why in skipped:
        print(f"dashboard: skipped {name}: {why}", file=sys.stderr)
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(render(snaps, skipped), encoding="utf-8")
    print(f"dashboard: {len(snaps)} snapshots -> {out / 'index.html'}")
    return 0 if snaps else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
