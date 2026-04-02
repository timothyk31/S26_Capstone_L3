#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import html
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


def _f(x: object, default: float = 0.0) -> float:
    try:
        if x is None or str(x).strip() == "":
            return default
        return float(str(x))
    except Exception:
        return default


def _i(x: object, default: int = 0) -> int:
    try:
        if x is None or str(x).strip() == "":
            return default
        return int(float(str(x)))
    except Exception:
        return default


def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s).strip("_") or "unknown"


def _size_bucket(n: int, small_max: int, medium_max: int) -> str:
    if n <= small_max:
        return "small"
    if n <= medium_max:
        return "medium"
    return "large"


def _model_name(row: Dict[str, str], csv_path: Path) -> str:
    for key in ("remedy_model", "review_model", "qa_model", "triage_model"):
        v = (row.get(key) or "").strip()
        if v and v.lower() != "unknown":
            if "trinity" in v.lower():
                return "trinity"
            return v
    parent = csv_path.parent.name
    if "trinity" in parent.lower():
        return "trinity"
    if "20b" in parent.lower():
        return "openai/gpt-oss-20b"
    if "120b" in parent.lower():
        return "openai/gpt-oss-120b"
    return "unknown"


def _run_id(csv_path: Path) -> str:
    p = csv_path.parent.name
    if re.search(r"_\d{8}_\d{6}$", p):
        return p
    return csv_path.stem


@dataclass
class RunStats:
    model: str
    run_id: str
    size: str
    found: int
    succeeded: int
    failed: int
    pass1: int
    pass2: int
    pass3: int
    remediation_pct: float
    system: str
    avg_triage_s: float
    avg_remedy_s: float
    avg_review_s: float
    avg_qa_s: float


def load_runs(input_dirs: List[Path], small_max: int, medium_max: int) -> List[RunStats]:
    runs: List[RunStats] = []
    for root in input_dirs:
        if not root.exists():
            continue
        for csv_path in root.rglob("findings_detail_*.csv"):
            with csv_path.open("r", encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            if not rows:
                continue
            model = _model_name(rows[0], csv_path)
            found = len(rows)
            succ = sum(1 for r in rows if (r.get("final_status") or "").strip().lower() == "success")
            fail = found - succ
            pass1 = 0
            pass2 = 0
            pass3 = 0
            for r in rows:
                if (r.get("final_status") or "").strip().lower() != "success":
                    continue
                rr = _i(r.get("remediated_at_round"), 1)
                if rr == 2:
                    pass2 += 1
                elif rr == 3:
                    pass3 += 1
                else:
                    pass1 += 1
            systems = sorted({(r.get("host") or "unknown").strip() or "unknown" for r in rows})
            system = systems[0] if len(systems) == 1 else ", ".join(systems)

            def avg(col: str) -> float:
                vals = [_f(r.get(col), 0.0) for r in rows]
                vals = [v for v in vals if v > 0]
                return round(sum(vals) / len(vals), 2) if vals else 0.0

            runs.append(
                RunStats(
                    model=model,
                    run_id=_run_id(csv_path),
                    size=_size_bucket(found, small_max, medium_max),
                    found=found,
                    succeeded=succ,
                    failed=fail,
                    pass1=pass1,
                    pass2=pass2,
                    pass3=pass3,
                    remediation_pct=round((succ / found) * 100.0, 1) if found else 0.0,
                    system=system,
                    avg_triage_s=avg("triage_duration_s"),
                    avg_remedy_s=avg("remedy_duration_s"),
                    avg_review_s=avg("review_duration_s"),
                    avg_qa_s=avg("qa_duration_s"),
                )
            )
    return runs


def _style() -> str:
    return """
<style>
body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; margin:24px; color:#1f2937; }
a { color:#2563eb; text-decoration:none; }
a:hover { text-decoration:underline; }
.kpis { display:grid; grid-template-columns:repeat(4,minmax(130px,1fr)); gap:10px; margin:10px 0 16px; }
.kpi { background:#eef6ff; border:1px solid #dbeafe; border-radius:10px; padding:10px 12px; }
.k { font-size:12px; color:#6b7280; } .v { font-size:24px; font-weight:700; }
.chart-shell { display:grid; grid-template-columns:48px 1fr; gap:10px; align-items:stretch; margin:24px 0; }
.y-axis { position:relative; height:230px; font-size:12px; color:#6b7280; } .y-axis div { position:absolute; right:0; transform:translateY(50%); }
.chart-stack { display:grid; grid-template-rows:230px auto; gap:8px; }
.chart-area { position:relative; height:230px; border-left:1px solid #d1d5db; border-bottom:1px solid #d1d5db; overflow-x:auto; }
.grid-line { position:absolute; left:0; right:0; border-top:1px dashed #e5e7eb; }
.chart { position:absolute; left:0; right:0; bottom:0; display:flex; gap:22px; align-items:flex-end; padding:0 12px; min-width:max-content; }
.group { min-width:180px; text-align:center; } .group-bars { display:flex; justify-content:center; gap:10px; align-items:flex-end; height:230px; }
.mini { width:42px; height:230px; display:block; position:relative; text-decoration:none; color:inherit; }
.mini-txt { position:absolute; left:0; right:0; color:#4b5563; text-align:center; pointer-events:none; display:flex; flex-direction:column; align-items:center; line-height:1.15; white-space:nowrap; }
.mini-size { font-weight:700; font-size:11px; }
.mini-pct { font-size:10px; }
.mini-bar { position:absolute; left:0; right:0; bottom:0; height:230px; border-radius:6px 6px 0 0; display:flex; flex-direction:column-reverse; overflow:hidden; }
.seg { width:100%; }
.legend { margin:8px 0 14px; color:#4b5563; font-size:13px; display:flex; gap:14px; flex-wrap:wrap; }
.swatch { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:6px; vertical-align:middle; }
.xlabels { display:flex; gap:22px; padding-left:12px; min-width:max-content; align-items:flex-start; }
.xlabel-model { min-width:180px; width:180px; text-align:center; font-weight:600; font-size:12px; line-height:1.25; }
.runs { border:1px solid #e5e7eb; border-radius:10px; overflow:hidden; margin:12px 0; }
.run-head,.run-row { display:grid; grid-template-columns:110px 130px 110px 130px 110px 1fr; gap:8px; align-items:center; padding:10px 12px; }
.run-head { background:#f8fafc; font-weight:600; border-bottom:1px solid #e5e7eb; }
.run-row { border-top:1px solid #f1f5f9; color:#1f2937; }
.run-row:hover { background:#f8fbff; }
.run-name { font-weight:600; color:#2563eb; } .run-system { color:#4b5563; font-size:13px; }
.card { border:1px solid #e5e7eb; border-radius:10px; padding:16px; margin-bottom:16px; }
.bar-row { display:grid; grid-template-columns:150px 290px 70px; gap:8px; align-items:center; margin:5px 0; }
.bar-track { height:14px; background:#f3f4f6; border-radius:7px; overflow:hidden; }
.bar-fill { height:100%; border-radius:7px; }
</style>
"""


def _stacked_bar_html(
    pass1_pct: float,
    pass2_pct: float,
    pass3_pct: float,
    *,
    pass1_count: int,
    pass2_count: int,
    pass3_count: int,
    total_passed: int,
    total_found: int,
    total_height: int,
    size_letter: str,
    pct_total: float,
) -> str:
    h1 = max(0, int((pass1_pct / 100.0) * total_height))
    h2 = max(0, int((pass2_pct / 100.0) * total_height))
    h3 = max(0, int((pass3_pct / 100.0) * total_height))
    total_h = h1 + h2 + h3
    s1 = (pass1_count / total_passed * 100.0) if total_passed else 0.0
    s2 = (pass2_count / total_passed * 100.0) if total_passed else 0.0
    s3 = (pass3_count / total_passed * 100.0) if total_passed else 0.0
    t1 = f"pass@1: {s1:.1f}% of passed ({pass1_count}/{total_passed}), {pass1_pct:.1f}% of found ({pass1_count}/{total_found})"
    t2 = f"pass@2: {s2:.1f}% of passed ({pass2_count}/{total_passed}), {pass2_pct:.1f}% of found ({pass2_count}/{total_found})"
    t3 = f"pass@3: {s3:.1f}% of passed ({pass3_count}/{total_passed}), {pass3_pct:.1f}% of found ({pass3_count}/{total_found})"
    sz = html.escape(size_letter.strip().upper()[:1] or "?")
    pct_s = f"{pct_total:.1f}%"
    return (
        f'<div class="mini-txt" style="bottom:{total_h + 4}px">'
        f'<span class="mini-size">{sz}</span>'
        f'<span class="mini-pct">{html.escape(pct_s)}</span>'
        f"</div>"
        f'<div class="mini-bar">'
        f'<div class="seg" title="{html.escape(t1)}" style="height:{h1}px;background:#2aa65a"></div>'
        f'<div class="seg" title="{html.escape(t2)}" style="height:{h2}px;background:#66cdaa"></div>'
        f'<div class="seg" title="{html.escape(t3)}" style="height:{h3}px;background:#9be0d8"></div>'
        f"</div>"
    )


def render_root(out_dir: Path, by_model_size: Dict[Tuple[str, str], List[RunStats]]) -> None:
    models = sorted({m for (m, _s) in by_model_size.keys()})
    groups, labels = [], []
    for m in models:
        bars = []
        for size in ("small", "medium", "large"):
            runs = by_model_size.get((m, size), [])
            if not runs:
                continue
            found = sum(r.found for r in runs)
            p1 = sum(r.pass1 for r in runs)
            p2 = sum(r.pass2 for r in runs)
            p3 = sum(r.pass3 for r in runs)
            pct1 = (p1 / found * 100.0) if found else 0.0
            pct2 = (p2 / found * 100.0) if found else 0.0
            pct3 = (p3 / found * 100.0) if found else 0.0
            total_pct = pct1 + pct2 + pct3
            bar_inner = _stacked_bar_html(
                pct1,
                pct2,
                pct3,
                pass1_count=p1,
                pass2_count=p2,
                pass3_count=p3,
                total_passed=(p1 + p2 + p3),
                total_found=found,
                total_height=230,
                size_letter=size[0],
                pct_total=total_pct,
            )
            bars.append(f'<a class="mini" href="{_slug(m)}/{size}/index.html" title="{size} {total_pct:.1f}%">{bar_inner}</a>')
        groups.append(f'<div class="group"><div class="group-bars">{"".join(bars)}</div></div>')
        labels.append(f'<a class="xlabel-model" href="{_slug(m)}/index.html">{html.escape(m)}</a>')

    (out_dir / "index.html").write_text(
        f"""<!doctype html><html><head><meta charset="utf-8"/><title>Benchmark</title>{_style()}</head><body>
<h1>LLM Benchmark Overview</h1>
<p>Stacked remediation bars by size. Each bar segment shows pass@1/pass@2/pass@3 contribution to total remediation %.</p>
<div class="legend">
  <span><span class="swatch" style="background:#2aa65a"></span>pass@1</span>
  <span><span class="swatch" style="background:#66cdaa"></span>pass@2</span>
  <span><span class="swatch" style="background:#9be0d8"></span>pass@3</span>
  <span>S/M/L labels appear above each bar</span>
</div>
<div class="chart-shell"><div class="y-axis"><div style="bottom:100%">100%</div><div style="bottom:75%">75%</div><div style="bottom:50%">50%</div><div style="bottom:25%">25%</div><div style="bottom:0%">0%</div></div>
<div class="chart-stack"><div class="chart-area"><div class="grid-line" style="bottom:0%"></div><div class="grid-line" style="bottom:25%"></div><div class="grid-line" style="bottom:50%"></div><div class="grid-line" style="bottom:75%"></div><div class="grid-line" style="bottom:100%"></div><div class="chart">{"".join(groups)}</div></div><div class="xlabels">{"".join(labels)}</div></div></div>
</body></html>""",
        encoding="utf-8",
    )


def render_model_pages(out_dir: Path, runs: List[RunStats]) -> None:
    by_model_size: Dict[Tuple[str, str], List[RunStats]] = defaultdict(list)
    for r in runs:
        by_model_size[(r.model, r.size)].append(r)

    models = sorted({r.model for r in runs})
    for m in models:
        mdir = out_dir / _slug(m)
        mdir.mkdir(parents=True, exist_ok=True)

        bars, xlabels, rows = [], [], []
        for size in ("small", "medium", "large"):
            rs = by_model_size.get((m, size), [])
            if not rs:
                continue
            found = sum(r.found for r in rs)
            succ = sum(r.succeeded for r in rs)
            fail = sum(r.failed for r in rs)
            p1 = sum(r.pass1 for r in rs)
            p2 = sum(r.pass2 for r in rs)
            p3 = sum(r.pass3 for r in rs)
            pct1 = (p1 / found * 100.0) if found else 0.0
            pct2 = (p2 / found * 100.0) if found else 0.0
            pct3 = (p3 / found * 100.0) if found else 0.0
            pct = round(pct1 + pct2 + pct3, 1)
            bar_inner = _stacked_bar_html(
                pct1,
                pct2,
                pct3,
                pass1_count=p1,
                pass2_count=p2,
                pass3_count=p3,
                total_passed=(p1 + p2 + p3),
                total_found=found,
                total_height=230,
                size_letter=size[0],
                pct_total=pct,
            )
            bars.append(f'<div class="group"><div class="group-bars"><a class="mini" href="{size}/index.html" title="{size} {pct:.1f}%">{bar_inner}</a></div></div>')
            xlabels.append(
                f'<a class="xlabel-model" href="{size}/index.html">{size.title()} '
                f'(P1 {pct1:.1f}% / P2 {pct2:.1f}% / P3 {pct3:.1f}%)</a>'
            )
            rows.append(f"<tr><td>{size.title()}</td><td>{found}</td><td>{succ}</td><td>{fail}</td><td>{pct}%</td><td>{len(rs)}</td></tr>")

            sdir = mdir / size
            sdir.mkdir(parents=True, exist_ok=True)
            render_size_page(sdir, m, size, rs)

        (mdir / "index.html").write_text(
            f"""<!doctype html><html><head><meta charset="utf-8"/><title>{html.escape(m)}</title>{_style()}</head><body>
<div><a href="../index.html">All Models</a> / {html.escape(m)}</div>
<h1>{html.escape(m)} - Small vs Medium vs Large</h1>
<div class="legend">
  <span><span class="swatch" style="background:#2aa65a"></span>pass@1</span>
  <span><span class="swatch" style="background:#66cdaa"></span>pass@2</span>
  <span><span class="swatch" style="background:#9be0d8"></span>pass@3</span>
</div>
<div class="chart-shell"><div class="y-axis"><div style="bottom:100%">100%</div><div style="bottom:75%">75%</div><div style="bottom:50%">50%</div><div style="bottom:25%">25%</div><div style="bottom:0%">0%</div></div>
<div class="chart-stack"><div class="chart-area"><div class="grid-line" style="bottom:0%"></div><div class="grid-line" style="bottom:25%"></div><div class="grid-line" style="bottom:50%"></div><div class="grid-line" style="bottom:75%"></div><div class="grid-line" style="bottom:100%"></div><div class="chart">{"".join(bars)}</div></div><div class="xlabels">{"".join(xlabels)}</div></div></div>
<table style="border-collapse:collapse;width:100%;margin-top:12px"><thead><tr><th>Size</th><th>Total Found</th><th>Total Succeeded</th><th>Total Failed</th><th>Avg Remediation %</th><th>Runs</th></tr></thead><tbody>{"".join(rows)}</tbody></table>
</body></html>""",
            encoding="utf-8",
        )

    render_root(out_dir, by_model_size)


def render_size_page(size_dir: Path, model: str, size: str, runs: List[RunStats]) -> None:
    avg_pct = round(sum(r.remediation_pct for r in runs) / len(runs), 1) if runs else 0.0
    avg_found = round(sum(r.found for r in runs) / len(runs), 1) if runs else 0.0
    avg_succ = round(sum(r.succeeded for r in runs) / len(runs), 1) if runs else 0.0
    avg_fail = round(sum(r.failed for r in runs) / len(runs), 1) if runs else 0.0
    total_found = sum(r.found for r in runs)
    total_p1 = sum(r.pass1 for r in runs)
    total_p2 = sum(r.pass2 for r in runs)
    total_p3 = sum(r.pass3 for r in runs)
    p1_pct = round((total_p1 / total_found) * 100.0, 1) if total_found else 0.0
    p2_pct = round((total_p2 / total_found) * 100.0, 1) if total_found else 0.0
    p3_pct = round((total_p3 / total_found) * 100.0, 1) if total_found else 0.0

    run_rows = []
    for i, r in enumerate(sorted(runs, key=lambda x: x.run_id), start=1):
        run_slug = _slug(f"run_{i}_{r.run_id}")
        run_rows.append(
            f'<a class="run-row" href="runs/{run_slug}.html"><div class="run-name">Run {i}</div><div>{r.remediation_pct:.1f}%</div><div>{r.found}</div><div>{r.succeeded}</div><div>{r.failed}</div><div class="run-system">{html.escape(r.system)}</div></a>'
        )
        render_run_page(size_dir / "runs", model, size, f"Run {i}", run_slug, r)

    (size_dir / "index.html").write_text(
        f"""<!doctype html><html><head><meta charset="utf-8"/><title>{html.escape(model)} {size}</title>{_style()}</head><body>
<div><a href="../../index.html">All Models</a> / <a href="../index.html">{html.escape(model)}</a> / {size.title()}</div>
<h1>{html.escape(model)} - {size.title()} vulnerabilities</h1>
<div class="kpis">
<div class="kpi"><div class="k">Average Remediation % / Run</div><div class="v">{avg_pct}%</div></div>
<div class="kpi"><div class="k">Average Found / Run</div><div class="v">{avg_found}</div></div>
<div class="kpi"><div class="k">Average Succeeded / Run</div><div class="v">{avg_succ}</div></div>
<div class="kpi"><div class="k">Average Failed / Run</div><div class="v">{avg_fail}</div></div>
<div class="kpi"><div class="k">Pass@1 (of found)</div><div class="v">{p1_pct}%</div></div>
<div class="kpi"><div class="k">Pass@2 (of found)</div><div class="v">{p2_pct}%</div></div>
<div class="kpi"><div class="k">Pass@3 (of found)</div><div class="v">{p3_pct}%</div></div>
<div class="kpi"><div class="k">Total Run Count</div><div class="v">{len(runs)}</div></div>
</div>
<div class="runs"><div class="run-head"><div>Run</div><div>Remediation %</div><div>Found</div><div>Succeeded</div><div>Failed</div><div>System</div></div>{"".join(run_rows)}</div>
</body></html>""",
        encoding="utf-8",
    )


def render_run_page(run_dir: Path, model: str, size: str, run_label: str, run_slug: str, r: RunStats) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    p1_pct = round((r.pass1 / r.found) * 100.0, 1) if r.found else 0.0
    p2_pct = round((r.pass2 / r.found) * 100.0, 1) if r.found else 0.0
    p3_pct = round((r.pass3 / r.found) * 100.0, 1) if r.found else 0.0
    counts = [
        ("Total Found", r.found, "#5b8def"),
        ("Pass@1", r.pass1, "#2aa65a"),
        ("Pass@2", r.pass2, "#66cdaa"),
        ("Pass@3", r.pass3, "#9be0d8"),
        ("Total Succeeded", r.succeeded, "#15803d"),
        ("Total Failed", r.failed, "#d9534f"),
    ]
    maxv = max([v for _, v, _ in counts] + [1])
    bars = "".join(
        f'<div class="bar-row"><div>{k}</div><div class="bar-track"><div class="bar-fill" style="width:{int(v/maxv*280)}px;background:{c}"></div></div><div>{v}</div></div>'
        for k, v, c in counts
    )
    tvals = [("Triage", r.avg_triage_s, "#5b8def"), ("Remedy", r.avg_remedy_s, "#2aa65a"), ("Review", r.avg_review_s, "#8a63d2"), ("QA", r.avg_qa_s, "#f08c00")]
    maxt = max([v for _, v, _ in tvals] + [1.0])
    tbars = "".join(
        f'<div class="bar-row"><div>{k}</div><div class="bar-track"><div class="bar-fill" style="width:{int(v/maxt*280)}px;background:{c}"></div></div><div>{v:.2f}s</div></div>'
        for k, v, c in tvals
    )
    (run_dir / f"{run_slug}.html").write_text(
        f"""<!doctype html><html><head><meta charset="utf-8"/><title>{html.escape(model)} {run_label}</title>{_style()}</head><body>
<div><a href="../../../index.html">All Models</a> / <a href="../../index.html">{html.escape(model)}</a> / <a href="../index.html">{size.title()}</a> / {run_label}</div>
<h1>{html.escape(model)} - {size.title()} - {run_label}</h1>
<section class="card"><h2>{html.escape(r.system)}</h2>
<div class="kpis">
<div class="kpi"><div class="k">Remediation %</div><div class="v">{r.remediation_pct}%</div></div>
<div class="kpi"><div class="k">Total Found</div><div class="v">{r.found}</div></div>
<div class="kpi"><div class="k">Total Succeeded</div><div class="v">{r.succeeded}</div></div>
<div class="kpi"><div class="k">Pass@1 (of found)</div><div class="v">{p1_pct}%</div></div>
<div class="kpi"><div class="k">Pass@2 (of found)</div><div class="v">{p2_pct}%</div></div>
<div class="kpi"><div class="k">Pass@3 (of found)</div><div class="v">{p3_pct}%</div></div>
</div>
<h3>Outcome Counts</h3>{bars}
<h3>Average Reasoning Time per LLM Step</h3>{tbars}
</section></body></html>""",
        encoding="utf-8",
    )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input-dirs", nargs="+", default=["reports", "reports_20b"])
    p.add_argument("--output-dir", default="benchmark")
    p.add_argument("--small-max", type=int, default=40)
    p.add_argument("--medium-max", type=int, default=100)
    args = p.parse_args()

    repo = Path(__file__).resolve().parents[1]
    input_dirs = [(repo / d).resolve() for d in args.input_dirs]
    out_dir = (repo / args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    runs = load_runs(input_dirs, args.small_max, args.medium_max)
    if not runs:
        print("No findings_detail CSV files found.")
        return 1
    render_model_pages(out_dir, runs)
    models = sorted({r.model for r in runs})
    print(f"Updated benchmark for models: {', '.join(models)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

