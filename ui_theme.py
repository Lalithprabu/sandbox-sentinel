"""HTML/CSS building blocks for the Streamlit demo. All user text goes through `esc`."""

from __future__ import annotations

from html import escape

SEV_COLOR = {"critical": "#ef4444", "high": "#f97316", "medium": "#f59e0b", "low": "#38bdf8"}
DEC_COLOR = {"allow": "#22c55e", "review": "#f59e0b", "block": "#ef4444"}
DEC_ICON = {"allow": "✓", "review": "!", "block": "✕"}

CSS = """
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0e16; --panel:#111827; --panel2:#0f1522; --line:#1f2a3c; --muted:#8b98ad; --text:#e5e7eb;
  --cyan:#22d3ee; --violet:#a78bfa; --green:#22c55e; --amber:#f59e0b; --red:#ef4444;
}
html, body, [class*="css"], .stMarkdown, .stText { font-family:'Inter',system-ui,sans-serif; }
.stApp{ background:
  radial-gradient(1200px 500px at 10% -10%, rgba(34,211,238,.10), transparent 60%),
  radial-gradient(900px 500px at 100% 0%, rgba(167,139,250,.10), transparent 60%), var(--bg); }
.block-container{ padding-top:2rem; max-width:1250px; }
header[data-testid="stHeader"]{ background:transparent; }
code, pre, .mono{ font-family:'JetBrains Mono',ui-monospace,monospace !important; }

/* hero */
.hero{ border:1px solid var(--line); border-radius:20px; padding:28px 32px; margin-bottom:18px;
  background:linear-gradient(135deg, rgba(17,24,39,.92), rgba(15,21,34,.92)); position:relative; overflow:hidden; }
.hero:after{ content:""; position:absolute; inset:-1px; border-radius:20px; pointer-events:none;
  background:linear-gradient(120deg, rgba(34,211,238,.35), transparent 30%, transparent 70%, rgba(167,139,250,.35));
  -webkit-mask:linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0); -webkit-mask-composite:xor; mask-composite:exclude; padding:1px; }
.hero h1{ font-size:2.6rem; font-weight:800; margin:0 0 6px; letter-spacing:-.02em;
  background:linear-gradient(90deg,#e0f2fe,#22d3ee 40%,#a78bfa); -webkit-background-clip:text; background-clip:text; color:transparent; }
.hero p{ color:var(--muted); font-size:1.02rem; max-width:860px; margin:0 0 14px; line-height:1.55; }
.pills{ display:flex; flex-wrap:wrap; gap:8px; }
.pill{ font-size:.78rem; font-weight:600; padding:5px 11px; border-radius:999px; border:1px solid var(--line);
  background:rgba(255,255,255,.03); color:#cbd5e1; }
.pill b{ color:var(--cyan); }

/* kpis */
.kpis{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:4px 0 18px; }
@media (max-width:900px){ .kpis{ grid-template-columns:repeat(2,minmax(0,1fr)); } }
.kpi{ background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:14px 16px; }
.kpi .l{ color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.08em; font-weight:600; }
.kpi .v{ font-size:1.8rem; font-weight:800; margin-top:2px; font-variant-numeric:tabular-nums; }
.kpi .s{ color:var(--muted); font-size:.78rem; }

/* tabs */
.stTabs [data-baseweb="tab-list"]{ gap:6px; border-bottom:1px solid var(--line); }
.stTabs [data-baseweb="tab"]{ background:transparent; border-radius:10px 10px 0 0; padding:10px 16px; font-weight:600; color:var(--muted); }
.stTabs [aria-selected="true"]{ color:var(--text) !important; background:var(--panel) !important; }
.stTabs [data-baseweb="tab-highlight"]{ background:var(--cyan); }

/* buttons & inputs */
.stButton>button, .stDownloadButton>button{ border-radius:10px; font-weight:600; border:1px solid var(--line); transition:all .15s; }
.stButton>button[kind="primary"]{ background:linear-gradient(90deg,#0891b2,#7c3aed); border:0; color:white; }
.stButton>button[kind="primary"]:hover{ filter:brightness(1.12); transform:translateY(-1px); box-shadow:0 6px 20px rgba(34,211,238,.25); }
.stTextInput input, .stTextArea textarea{ font-family:'JetBrains Mono',monospace !important; font-size:.88rem; }

/* verdict */
.verdict{ border:1px solid var(--line); border-left:5px solid var(--c); border-radius:16px; padding:20px 22px; margin-top:14px;
  background:linear-gradient(90deg, color-mix(in srgb, var(--c) 12%, transparent), var(--panel) 45%); }
.vtop{ display:flex; align-items:center; gap:18px; flex-wrap:wrap; }
.vbadge{ width:54px; height:54px; border-radius:14px; display:grid; place-items:center; font-size:1.6rem; font-weight:800;
  background:color-mix(in srgb, var(--c) 18%, transparent); color:var(--c); border:1px solid color-mix(in srgb, var(--c) 45%, transparent); }
.vtitle{ font-size:1.5rem; font-weight:800; color:var(--c); letter-spacing:.02em; }
.vsub{ color:var(--muted); font-size:.88rem; }
.gauge{ flex:1; min-width:220px; }
.gauge .bar{ height:10px; border-radius:99px; background:#1f2937; overflow:hidden; }
.gauge .fill{ height:100%; border-radius:99px; background:linear-gradient(90deg,#22c55e,#f59e0b 55%,#ef4444); }
.gauge .lab{ display:flex; justify-content:space-between; color:var(--muted); font-size:.75rem; margin-top:5px; }
.finding{ display:grid; grid-template-columns:auto 1fr; gap:4px 12px; padding:12px 14px; margin-top:10px; border-radius:12px;
  background:var(--panel2); border:1px solid var(--line); }
.sev{ font-size:.68rem; font-weight:800; text-transform:uppercase; letter-spacing:.06em; padding:3px 8px; border-radius:6px; height:fit-content;
  color:var(--c); background:color-mix(in srgb, var(--c) 15%, transparent); border:1px solid color-mix(in srgb, var(--c) 40%, transparent); }
.fid{ font-weight:700; font-family:'JetBrains Mono',monospace; font-size:.88rem; }
.fdesc{ color:#cbd5e1; font-size:.88rem; grid-column:2; }
.fev{ grid-column:2; font-family:'JetBrains Mono',monospace; font-size:.78rem; color:#fca5a5; background:#0b0f18;
  padding:6px 9px; border-radius:8px; border:1px solid var(--line); overflow-x:auto; white-space:pre; }
.llm{ margin-top:12px; padding:10px 14px; border-radius:12px; border:1px dashed #334155; color:#cbd5e1; font-size:.88rem; }

/* timeline */
.tl{ position:relative; margin:8px 0 0 8px; padding-left:26px; border-left:2px solid var(--line); }
.tli{ position:relative; margin-bottom:12px; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:12px 14px;
  animation:slide .35s ease both; }
.tli:before{ content:attr(data-icon); position:absolute; left:-39px; top:12px; width:24px; height:24px; border-radius:50%;
  display:grid; place-items:center; font-size:.78rem; font-weight:800; color:#0a0e16; background:var(--c); box-shadow:0 0 0 4px var(--bg), 0 0 18px var(--c); }
.tli .h{ display:flex; justify-content:space-between; gap:10px; align-items:center; flex-wrap:wrap; }
.tli .t{ font-weight:700; }
.tli .agent{ color:var(--violet); font-family:'JetBrains Mono',monospace; font-size:.78rem; }
.tli .cmd{ margin-top:6px; font-family:'JetBrains Mono',monospace; font-size:.8rem; color:#93c5fd; background:#0b0f18;
  border:1px solid var(--line); border-radius:8px; padding:6px 9px; overflow-x:auto; white-space:pre; }
.chip{ font-size:.7rem; font-weight:800; padding:3px 9px; border-radius:999px; color:var(--c);
  background:color-mix(in srgb, var(--c) 15%, transparent); border:1px solid color-mix(in srgb, var(--c) 40%, transparent); }
.rules{ margin-top:6px; display:flex; gap:6px; flex-wrap:wrap; }
.rule{ font-family:'JetBrains Mono',monospace; font-size:.7rem; padding:2px 7px; border-radius:6px; background:#1e293b; color:#cbd5e1; }
@keyframes slide{ from{ opacity:0; transform:translateX(-8px);} to{ opacity:1; transform:none;} }

/* hash chain */
.chain{ display:flex; gap:0; overflow-x:auto; padding:8px 2px 14px; }
.blk{ flex:0 0 170px; background:var(--panel); border:1px solid var(--line); border-top:3px solid var(--c); border-radius:12px; padding:10px 12px; }
.blk.bad{ border-color:var(--red); box-shadow:0 0 0 1px var(--red), 0 0 22px rgba(239,68,68,.35); }
.blk .n{ font-size:.72rem; color:var(--muted); font-weight:700; }
.blk .k{ font-weight:700; font-size:.85rem; margin:2px 0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.blk .hh{ font-family:'JetBrains Mono',monospace; font-size:.68rem; color:var(--muted); }
.link{ flex:0 0 26px; align-self:center; text-align:center; color:#334155; font-weight:800; }
.banner{ padding:14px 18px; border-radius:12px; font-weight:600; margin:10px 0; border:1px solid; }
.banner.ok{ color:#86efac; background:rgba(34,197,94,.08); border-color:rgba(34,197,94,.35); }
.banner.bad{ color:#fca5a5; background:rgba(239,68,68,.08); border-color:rgba(239,68,68,.45); }

/* test report */
.covrow{ display:grid; grid-template-columns:160px 1fr 60px; gap:12px; align-items:center; margin:7px 0; font-size:.85rem; }
.covrow .bar{ height:8px; background:#1f2937; border-radius:99px; overflow:hidden; }
.covrow .fill{ height:100%; border-radius:99px; }
.tcase{ display:flex; justify-content:space-between; gap:10px; padding:7px 12px; border-bottom:1px solid var(--line); font-size:.84rem; }
.tcase .nm{ font-family:'JetBrains Mono',monospace; color:#cbd5e1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.panel{ background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:14px 16px; }
.sectitle{ font-weight:700; font-size:1.05rem; margin:6px 0 10px; }
.muted{ color:var(--muted); }
.credit{ position:absolute; top:16px; right:22px; font-size:.78rem; color:var(--muted); padding:4px 12px; border-radius:999px;
  border:1px solid var(--line); background:rgba(255,255,255,.03); z-index:1; }
.credit b{ background:linear-gradient(90deg,#22d3ee,#a78bfa); -webkit-background-clip:text; background-clip:text; color:transparent; }
.footer{ text-align:center; color:var(--muted); font-size:.82rem; margin:36px 0 10px; padding-top:16px; border-top:1px solid var(--line); }
.footer b{ color:#e5e7eb; }
.igrid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:8px 0 16px; }
.icard{ background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:14px 16px; }
.icard .ih{ font-weight:700; margin-bottom:4px; }
.icard .ib{ color:var(--muted); font-size:.84rem; line-height:1.45; }
.icard code{ font-size:.76rem; color:#93c5fd; }
.pc{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }
@media (max-width:800px){ .pc{ grid-template-columns:1fr; } .credit{ position:static; display:inline-block; margin-bottom:8px; } }
.pc ul{ margin:6px 0 0; padding-left:18px; }
.pc li{ margin:5px 0; font-size:.88rem; color:#cbd5e1; }
.support{ border:1px solid rgba(34,211,238,.35); background:linear-gradient(90deg, rgba(34,211,238,.08), rgba(167,139,250,.08));
  border-radius:14px; padding:16px 18px; margin-top:16px; }
.io{ background:var(--panel2); border:1px solid var(--line); border-radius:16px; padding:14px; height:100%; }
.io-t{ font-weight:800; margin-bottom:8px; }
.io-lab{ font-size:.7rem; font-weight:800; letter-spacing:.1em; color:var(--cyan); margin:10px 0 6px; }
.io-in{ display:grid; grid-template-columns:62px 1fr; gap:6px 10px; background:#0b0f18; border:1px solid var(--line); border-radius:10px; padding:10px 12px; }
.io-k{ color:var(--muted); font-size:.75rem; font-weight:700; }
.io-v{ font-family:'JetBrains Mono',monospace; font-size:.78rem; color:#93c5fd; word-break:break-word; }
.io .verdict{ margin-top:0; padding:14px; }
.io .vbadge{ width:40px; height:40px; font-size:1.2rem; }
.io .vtitle{ font-size:1.15rem; }
.io .gauge{ min-width:100%; }
.io .finding{ grid-template-columns:auto 1fr; align-items:center; }
.io .fdesc, .io .fev{ grid-column:1 / -1; }
.steps{ margin:8px 0 10px; padding-left:20px; }
.steps li{ margin:6px 0; color:#cbd5e1; font-size:.9rem; }
section[data-testid="stSidebar"]{ background:#0c111b; border-right:1px solid var(--line); }
</style>
"""


def esc(s: object) -> str:
    return escape(str(s), quote=True)


def hero(pills: list[tuple[str, str]]) -> str:
    p = "".join(f'<span class="pill"><b>{esc(a)}</b> {esc(b)}</span>' for a, b in pills)
    return f"""<div class="hero"><div class="credit">Created by <b>LalithPrabu</b></div><h1>🛡️ Sandbox Sentinel</h1>
<p>A zero-cost firewall and tamper-evident flight recorder for AI agents. In 2026, a swarm of agents escaped a test sandbox,
hacked Hugging Face and tried to delete their logs. Sentinel vets every tool call <i>before</i> it runs and keeps a hash-chained
record the agent can't quietly rewrite.</p><div class="pills">{p}</div></div>"""


def kpis(items: list[tuple[str, str, str, str]]) -> str:
    cards = "".join(
        f'<div class="kpi"><div class="l">{esc(l)}</div><div class="v" style="color:{c}">{esc(v)}</div><div class="s">{esc(s)}</div></div>'
        for l, v, s, c in items
    )
    return f'<div class="kpis">{cards}</div>'


def verdict_card(v, model: str = "") -> str:
    c = DEC_COLOR[v.decision]
    n = len(v.findings)
    sub = "No risks detected, safe to execute." if not n else f"{n} finding{'s' if n > 1 else ''} · " + ", ".join(sorted({f.category.replace('_', ' ') for f in v.findings}))
    rows = "".join(
        f'<div class="finding" style="--c:{SEV_COLOR[f.severity]}"><span class="sev">{esc(f.severity)}</span>'
        f'<span class="fid">{esc(f.rule_id)}</span><span class="fdesc">{esc(f.description)}</span>'
        f'<span class="fev">{esc(f.evidence)}</span></div>'
        for f in v.findings
    )
    llm = ""
    if v.llm_risk is not None:
        llm = f'<div class="llm">🤖 <b>{esc(model)}</b> second opinion: risk <b>{v.llm_risk}</b>/100. {esc(v.llm_reason)}</div>'
    return f"""<div class="verdict" style="--c:{c}"><div class="vtop">
<div class="vbadge">{DEC_ICON[v.decision]}</div>
<div><div class="vtitle">{v.decision.upper()}</div><div class="vsub">{esc(sub)}</div></div>
<div class="gauge"><div class="bar"><div class="fill" style="width:{max(v.score, 2)}%"></div></div>
<div class="lab"><span>risk score</span><span><b style="color:{c}">{v.score}</b> / 100</span></div></div>
</div>{rows}{llm}</div>"""


def timeline_item(i: int, label: str, action, v) -> str:
    c = DEC_COLOR[v.decision]
    cmd = action.target + (f"\n{action.payload}" if action.payload else "")
    rules = "".join(f'<span class="rule">{esc(f.rule_id)}</span>' for f in v.findings)
    return f"""<div class="tli" style="--c:{c}" data-icon="{DEC_ICON[v.decision]}">
<div class="h"><span class="t">{i}. {esc(label)}</span><span><span class="agent">{esc(action.agent_id)}</span> &nbsp;
<span class="chip">{v.decision.upper()} · {v.score}</span></span></div>
<div class="cmd">{esc(action.kind)} ▸ {esc(cmd[:400])}</div>{f'<div class="rules">{rules}</div>' if rules else ''}</div>"""


def chain(entries: list[dict], bad_seq: int | None = None, limit: int = 12) -> str:
    tail = entries[-limit:]
    parts = []
    for j, e in enumerate(tail):
        d = e["record"]["verdict"]["decision"]
        a = e["record"]["action"]
        bad = " bad" if bad_seq is not None and e["seq"] >= bad_seq else ""
        parts.append(
            f'<div class="blk{bad}" style="--c:{DEC_COLOR.get(d, "#64748b")}"><div class="n">#{e["seq"]} · {esc(e["ts"][11:19])}</div>'
            f'<div class="k">{esc(a["kind"])} · {esc(d.upper())}</div>'
            f'<div class="hh">prev {esc(e["prev_hash"][:10])}…</div><div class="hh">hash {esc(e["hash"][:10])}…</div></div>'
        )
        if j < len(tail) - 1:
            parts.append('<div class="link">⟶</div>')
    return f'<div class="chain">{"".join(parts)}</div>'


def cov_row(name: str, pct: float) -> str:
    c = "#22c55e" if pct >= 90 else "#f59e0b" if pct >= 70 else "#ef4444"
    return (f'<div class="covrow"><span class="mono">{esc(name)}</span><div class="bar"><div class="fill" '
            f'style="width:{pct:.0f}%;background:{c}"></div></div><span style="color:{c};font-weight:700">{pct:.0f}%</span></div>')


def compact(s: str) -> str:
    """Streamlit's markdown ends an HTML block at a blank line; strip them so raw HTML/CSS stays intact."""
    return "\n".join(line.strip() for line in s.splitlines() if line.strip())


CSS = compact(CSS)
