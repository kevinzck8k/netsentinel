#!/usr/bin/env python3
"""Build the NetSentinel architecture figure.

Run: python docs/make_architecture.py

One layout model emits two artifacts, so the rendered figure can never drift
from the editable source:
  docs/architecture.drawio  — editable source with embedded vector logos
  docs/architecture.svg     — rendered figure the README embeds

The canvas is deliberately kept under 1000px wide. GitHub renders README
content at roughly 900px, so anything wider gets scaled down and the labels
stop being legible.
"""
import base64
import re
from html import escape
from pathlib import Path

DOCS = Path(__file__).resolve().parent
ICONS = DOCS / "logos"

PAGE_W, PAGE_H = 962, 640

# 4x4 grid. Everything lands on a column centre so the rows read as a table.
COL_X = (30, 264, 498, 732)
COL_W = 200
CENTRE = tuple(x + COL_W / 2 for x in COL_X)
ROW1, ROW3, ROW4, AGENTS = 84, 424, 530, 286
BH = 80

F_TITLE, F_SUB, F_BOX, F_BOXSUB, F_EDGE, F_LANE = 17, 11, 13, 10, 10, 11
MARK, MARK_GAP, TITLE_H, SUB_H = 20, 6, 16, 13

BRAND = {
    "redis": "#D6382B",
    "docker": "#2496ED",
    "python": "#3776AB",
    "opentelemetry": "#425CC7",
    "sqlite": "#003B57",
    "pydantic": "#E92063",
}
PRECOLOURED = {"qdrant", "deepseek", "langchain_color"}

# Few hues, one meaning each: slate lab, teal transport, indigo reasoning
# core, grey dependency, amber output and measurement, rose failure.
PALETTE = {
    "lab": ("#EFF3F8", "#64748B"),
    "ingest": ("#E6F4F1", "#2A9D8F"),
    "agent": ("#EAECFA", "#4F5BD5"),
    "store": ("#F4F4F6", "#8E8E97"),
    "eval": ("#FDF4E7", "#D9A13B"),
    "alert": ("#FBEDED", "#C1666B"),
}
FLOW, EVID, FAIL = "#475569", "#6B7FD7", "#C1666B"
INK, MUTED = "#18181B", "#5B6472"


def _svg_source(name: str) -> str:
    svg = (ICONS / f"{name}.svg").read_text(encoding="utf-8")
    svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S).strip()
    if name not in PRECOLOURED:
        svg = re.sub(r"<svg\b", f'<svg fill="{BRAND.get(name, "#3F3F46")}"', svg,
                     count=1)
    return svg


URI = {
    n: "data:image/svg+xml;base64,"
    + base64.b64encode(_svg_source(n).encode()).decode("ascii")
    for n in "redis docker python qdrant deepseek opentelemetry "
    "langchain_color sqlite pydantic".split()
}

BOXES: dict[str, dict] = {}
ANCHORS: dict[str, dict] = {}
EDGES: list[dict] = []


def box(bid, col, y, title, sub="", kind="agent", icon=None, step=None):
    BOXES[bid] = dict(x=COL_X[col], y=y, w=COL_W, h=BH, title=title, sub=sub,
                      kind=kind, icon=icon, step=step)


def content_top(b):
    """Top of the mark+text block. Every box reserves the mark slot, so titles
    across a row share one baseline whether the mark is a logo or a step
    number."""
    total = MARK + MARK_GAP + TITLE_H + (SUB_H if b["sub"] else 0)
    return b["y"] + (b["h"] - total) / 2


def edge(eid, src, tgt, label="", style="flow", src_at=(1, 0.5),
         tgt_at=(0, 0.5), via=()):
    EDGES.append(dict(id=eid, src=src, tgt=tgt, label=label, style=style,
                      src_at=src_at, tgt_at=tgt_at, via=list(via)))


def anchor(bid, frac):
    b = BOXES.get(bid) or ANCHORS[bid]
    return b["x"] + b["w"] * frac[0], b["y"] + b["h"] * frac[1]


def route(e):
    sx, sy = anchor(e["src"], e["src_at"])
    tx, ty = anchor(e["tgt"], e["tgt_at"])
    pts = [(sx, sy)] + e["via"] + [(tx, ty)]
    if not e["via"] and sx != tx and sy != ty:
        mx = (sx + tx) / 2
        pts = [(sx, sy), (mx, sy), (mx, ty), (tx, ty)]
    return pts


# ============================================================ layout
box("lab", 0, ROW1, "Containerlab lab", "FRRouting r1-r2 eBGP", "lab",
    icon="docker")
box("rx", 1, ROW1, "Syslog receiver", "UDP :5514", "ingest", icon="python")
box("redis", 2, ROW1, "Redis Streams", "consumer group", "ingest", icon="redis")
box("dlq", 3, ROW1, "Dead-letter", "retries exhausted", "alert", icon="redis")

box("triage", 0, AGENTS, "Triage", "nine fault classes", "agent", step=1)
box("tel", 1, AGENTS, "Telemetry", "event-scoped probes", "agent", step=2)
box("rag", 2, AGENTS, "Retrieval", "lexical + vector", "agent", step=3)
box("rca", 3, AGENTS, "RCA architect", "schema-bound synthesis", "agent", step=4)

box("ckpt", 0, ROW3, "Checkpointer", "resumable graph state", "store",
    icon="sqlite")
box("tools", 1, ROW3, "Diagnostic tools", "docker exec / Netmiko", "store",
    icon="python")
box("qdrant", 2, ROW3, "Qdrant", "SOP knowledge base", "store", icon="qdrant")
box("llm", 3, ROW3, "DeepSeek", "structured output", "store", icon="deepseek")

box("report", 2, ROW4, "RCAReport", "typed contract", "eval", icon="pydantic")
box("eval", 3, ROW4, "eval_runner", "258 cases, CI gate", "eval", icon="python")

LANE = dict(x=18, y=196, w=926, h=200,
            title="LangGraph StateGraph  ·  typed shared state  ·  "
                  "OpenTelemetry spans on every transition",
            icons=("langchain_color", "opentelemetry"))
ANCHORS["lane"] = {k: LANE[k] for k in "xywh"}
_LF = lambda x: (x - LANE["x"]) / LANE["w"]  # noqa: E731

edge("e1", "lab", "rx")
edge("e2", "rx", "redis")
edge("e3", "redis", "dlq", "", "fail")
edge("e4", "redis", "triage", "", "flow", (0.5, 1), (0, 0.5),
     [(CENTRE[2], 180), (10, 180), (10, AGENTS + BH / 2)])
edge("e5", "triage", "tel")
edge("e6", "tel", "rag")
edge("e7", "rag", "rca")
edge("e8", "triage", "rag", "skip_telemetry: no device access needed", "evid",
     (0.5, 0), (0.5, 0), [(CENTRE[0], 244), (CENTRE[2], 244)])
edge("e9", "rca", "tel", "evidence gap: re-probe", "fail", (0.25, 0), (0.25, 0),
     [(COL_X[3] + 50, 266), (COL_X[1] + 50, 266)])
edge("e10", "lane", "ckpt", "", "evid", (_LF(CENTRE[0]), 1), (0.5, 0))
edge("e11", "tel", "tools", "", "evid", (0.5, 1), (0.5, 0))
edge("e12", "rag", "qdrant", "", "evid", (0.5, 1), (0.5, 0))
edge("e13", "lane", "llm", "", "evid", (_LF(CENTRE[3]), 1), (0.5, 0))
edge("e14", "rca", "report", "", "flow", (0.05, 1), (0.5, 0),
     [(COL_X[3] + 10, 408), (715, 408), (715, 513), (CENTRE[2], 513)])
edge("e15", "report", "eval")

TITLE = ("NetSentinel — evidence-grounded multi-agent root-cause analysis "
         "for telco networks")
SUBTITLE = ("Every agent is restricted to the evidence it can actually obtain. "
            "Solid arrows carry the incident, dashed arrows fetch evidence, "
            "red marks a retry or failure path.")
FOOTER_HEAD = "258 labeled incidents · DeepSeek · 1,016 model calls"
FOOTER = [
    "Multi-agent 97.7%  vs  regex taxonomy 89.5%",
    "Free-text operator notes: 96.3%  vs  0% for regex",
    "Scored on seven weighted fields; CI gate at 70%",
]


# ============================================================ drawio emitter
def emit_drawio() -> str:
    cells: list[str] = []
    add = cells.append

    label = (f'<span style="font-size:{F_TITLE}px;font-weight:600">{TITLE}'
             f'</span><div style="font-size:{F_SUB}px;color:{MUTED};'
             f'margin-top:4px">{SUBTITLE}</div>')
    add(f'<mxCell id="title" value="{escape(label)}" style="text;html=1;'
        f'whiteSpace=wrap;align=left;verticalAlign=top;fontFamily=Helvetica;" '
        f'vertex="1" parent="1"><mxGeometry x="30" y="16" width="910" '
        f'height="52" as="geometry" /></mxCell>')

    add(f'<mxCell id="lane" value="" style="rounded=1;arcSize=4;html=1;'
        f'fillColor=none;strokeColor=#CBD5E1;strokeWidth=1.25;dashed=1;'
        f'dashPattern=8 5;" vertex="1" parent="1">'
        f'<mxGeometry x="{LANE["x"]}" y="{LANE["y"]}" width="{LANE["w"]}" '
        f'height="{LANE["h"]}" as="geometry" /></mxCell>')
    for i, name in enumerate(LANE["icons"]):
        add(f'<mxCell id="lane_ic{i}" style="shape=image;imageAspect=1;'
            f'aspect=fixed;html=1;image={URI[name]};" vertex="1" parent="1">'
            f'<mxGeometry x="{LANE["x"] + 14 + i * 24}" y="{LANE["y"] + 8}" '
            f'width="19" height="19" as="geometry" /></mxCell>')
    add(f'<mxCell id="lane_t" value="{escape(LANE["title"])}" style="text;'
        f'html=1;align=left;verticalAlign=middle;fontSize={F_LANE};fontStyle=1;'
        f'fontFamily=Helvetica;fontColor=#475569;" vertex="1" parent="1">'
        f'<mxGeometry x="{LANE["x"] + 66}" y="{LANE["y"] + 8}" width="640" '
        f'height="19" as="geometry" /></mxCell>')

    for bid, b in BOXES.items():
        fill, stroke = PALETTE[b["kind"]]
        lbl = f'<b>{escape(b["title"])}</b>'
        if b["sub"]:
            lbl += (f'<div style="font-size:{F_BOXSUB}px;color:{MUTED};'
                    f'margin-top:2px">{escape(b["sub"])}</div>')
        add(f'<mxCell id="{bid}" value="{escape(lbl)}" style="rounded=1;'
            f'arcSize=12;whiteSpace=wrap;html=1;fillColor={fill};'
            f'strokeColor={stroke};strokeWidth=1.25;verticalAlign=middle;'
            f'align=center;spacingTop={MARK + MARK_GAP};fontSize={F_BOX};'
            f'fontFamily=Helvetica;fontColor={INK};" vertex="1" parent="1">'
            f'<mxGeometry x="{b["x"]}" y="{b["y"]}" width="{b["w"]}" '
            f'height="{b["h"]}" as="geometry" /></mxCell>')
        mx, my = b["x"] + b["w"] / 2 - MARK / 2, content_top(b)
        if b["icon"]:
            add(f'<mxCell id="{bid}_ic" style="shape=image;imageAspect=1;'
                f'aspect=fixed;html=1;image={URI[b["icon"]]};" vertex="1" '
                f'parent="1"><mxGeometry x="{mx}" y="{my}" width="{MARK}" '
                f'height="{MARK}" as="geometry" /></mxCell>')
        elif b["step"]:
            add(f'<mxCell id="{bid}_st" value="{b["step"]}" style="ellipse;'
                f'html=1;fillColor={stroke};strokeColor=none;fontSize=11;'
                f'fontStyle=1;fontColor=#FFFFFF;fontFamily=Helvetica;'
                f'verticalAlign=middle;align=center;" vertex="1" parent="1">'
                f'<mxGeometry x="{mx}" y="{my}" width="{MARK}" '
                f'height="{MARK}" as="geometry" /></mxCell>')

    colours = {"flow": FLOW, "evid": EVID, "fail": FAIL}
    for e in EDGES:
        st = (f"edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;jettySize=auto;"
              f"orthogonalLoop=1;strokeColor={colours[e['style']]};"
              f"strokeWidth=1.4;fontSize={F_EDGE};fontFamily=Helvetica;"
              f"fontColor=#334155;labelBackgroundColor=#FFFFFF;"
              f"endArrow=blockThin;endFill=1;"
              f"exitX={e['src_at'][0]};exitY={e['src_at'][1]};exitDx=0;exitDy=0;"
              f"entryX={e['tgt_at'][0]};entryY={e['tgt_at'][1]};entryDx=0;"
              f"entryDy=0;")
        if e["style"] != "flow":
            st += "dashed=1;dashPattern=5 4;"
        geo = '<mxGeometry relative="1" as="geometry">'
        if e["via"]:
            geo += ('<Array as="points">' + "".join(
                f'<mxPoint x="{x}" y="{y}" />' for x, y in e["via"]) + "</Array>")
        geo += "</mxGeometry>"
        add(f'<mxCell id="{e["id"]}" value="{escape(e["label"])}" style="{st}" '
            f'edge="1" parent="1" source="{e["src"]}" target="{e["tgt"]}">'
            f"{geo}</mxCell>")

    foot = (f'<b>{escape(FOOTER_HEAD)}</b><div style="margin-top:4px;'
            f'line-height:1.5">'
            + "<br/>".join(escape(line) for line in FOOTER) + "</div>")
    add(f'<mxCell id="footer" value="{escape(foot)}" style="text;html=1;'
        f'whiteSpace=wrap;align=left;verticalAlign=top;fontSize={F_BOXSUB};'
        f'fontFamily=Helvetica;fontColor=#334155;" vertex="1" parent="1">'
        f'<mxGeometry x="{COL_X[0]}" y="{ROW4}" width="440" height="80" '
        f'as="geometry" /></mxCell>')

    return ('<mxfile host="app.diagrams.net" version="24.7.17" type="device">\n'
            '  <diagram id="netsentinel-arch" name="NetSentinel architecture">\n'
            f'    <mxGraphModel dx="1000" dy="700" grid="0" gridSize="10" '
            f'guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" '
            f'pageScale="1" pageWidth="{PAGE_W}" pageHeight="{PAGE_H}" math="0" '
            f'shadow="0">\n      <root>\n        <mxCell id="0" />\n'
            '        <mxCell id="1" parent="0" />\n'
            + "\n".join(f"        {c}" for c in cells)
            + "\n      </root>\n    </mxGraphModel>\n  </diagram>\n</mxfile>\n")


# ============================================================ svg emitter
def emit_svg() -> str:
    o: list[str] = []
    o.append(f'<svg xmlns="http://www.w3.org/2000/svg" '
             f'xmlns:xlink="http://www.w3.org/1999/xlink" width="{PAGE_W}" '
             f'height="{PAGE_H}" viewBox="0 0 {PAGE_W} {PAGE_H}" '
             f'font-family="Helvetica, Arial, sans-serif">')
    o.append('<rect width="100%" height="100%" fill="#FFFFFF"/>')
    for name, col in (("flow", FLOW), ("evid", EVID), ("fail", FAIL)):
        o.append(f'<marker id="a_{name}" viewBox="0 0 10 10" refX="9" refY="5" '
                 f'markerWidth="6.5" markerHeight="6.5" '
                 f'orient="auto-start-reverse">'
                 f'<path d="M0,1.5 L10,5 L0,8.5 z" fill="{col}"/></marker>')

    o.append(f'<text x="30" y="36" font-size="{F_TITLE}" font-weight="600" '
             f'fill="{INK}">{escape(TITLE)}</text>')
    o.append(f'<text x="30" y="57" font-size="{F_SUB}" fill="{MUTED}">'
             f'{escape(SUBTITLE)}</text>')

    o.append(f'<rect x="{LANE["x"]}" y="{LANE["y"]}" width="{LANE["w"]}" '
             f'height="{LANE["h"]}" rx="5" fill="none" stroke="#CBD5E1" '
             f'stroke-width="1.25" stroke-dasharray="8 5"/>')
    for i, name in enumerate(LANE["icons"]):
        o.append(f'<image x="{LANE["x"] + 14 + i * 24}" y="{LANE["y"] + 8}" '
                 f'width="19" height="19" xlink:href="{URI[name]}"/>')
    o.append(f'<text x="{LANE["x"] + 66}" y="{LANE["y"] + 22}" '
             f'font-size="{F_LANE}" font-weight="600" fill="#475569">'
             f'{escape(LANE["title"])}</text>')

    colours = {"flow": FLOW, "evid": EVID, "fail": FAIL}
    for e in EDGES:
        pts = route(e)
        d = " ".join(f"{'M' if i == 0 else 'L'}{x},{y}"
                     for i, (x, y) in enumerate(pts))
        dash = ' stroke-dasharray="5 4"' if e["style"] != "flow" else ""
        o.append(f'<path d="{d}" fill="none" stroke="{colours[e["style"]]}" '
                 f'stroke-width="1.4"{dash} '
                 f'marker-end="url(#a_{e["style"]})"/>')
        if e["label"]:
            i = len(pts) // 2
            mid = (((pts[i - 1][0] + pts[i][0]) / 2,
                    (pts[i - 1][1] + pts[i][1]) / 2) if len(pts) % 2 == 0
                   else pts[i])
            tw = len(e["label"]) * 5.0 + 10
            o.append(f'<rect x="{mid[0] - tw / 2:.1f}" y="{mid[1] - 8:.1f}" '
                     f'width="{tw:.1f}" height="16" fill="#FFFFFF"/>')
            o.append(f'<text x="{mid[0]:.1f}" y="{mid[1] + 3.5:.1f}" '
                     f'font-size="{F_EDGE}" fill="#334155" '
                     f'text-anchor="middle">{escape(e["label"])}</text>')

    for bid, b in BOXES.items():
        fill, stroke = PALETTE[b["kind"]]
        o.append(f'<rect x="{b["x"]}" y="{b["y"]}" width="{b["w"]}" '
                 f'height="{b["h"]}" rx="7" fill="{fill}" stroke="{stroke}" '
                 f'stroke-width="1.25"/>')
        cx, top = b["x"] + b["w"] / 2, content_top(b)
        if b["icon"]:
            o.append(f'<image x="{cx - MARK / 2}" y="{top}" width="{MARK}" '
                     f'height="{MARK}" xlink:href="{URI[b["icon"]]}"/>')
        elif b["step"]:
            o.append(f'<circle cx="{cx}" cy="{top + MARK / 2}" '
                     f'r="{MARK / 2}" fill="{stroke}"/>')
            o.append(f'<text x="{cx}" y="{top + MARK / 2 + 4:.1f}" '
                     f'font-size="11" font-weight="700" fill="#FFFFFF" '
                     f'text-anchor="middle">{b["step"]}</text>')
        top += MARK + MARK_GAP
        o.append(f'<text x="{cx}" y="{top + 12:.1f}" font-size="{F_BOX}" '
                 f'font-weight="700" fill="{INK}" text-anchor="middle">'
                 f'{escape(b["title"])}</text>')
        if b["sub"]:
            o.append(f'<text x="{cx}" y="{top + 27:.1f}" '
                     f'font-size="{F_BOXSUB}" fill="{MUTED}" '
                     f'text-anchor="middle">{escape(b["sub"])}</text>')

    o.append(f'<text x="{COL_X[0]}" y="{ROW4 + 14}" font-size="{F_SUB}" '
             f'font-weight="700" fill="{INK}">{escape(FOOTER_HEAD)}</text>')
    for i, line in enumerate(FOOTER):
        o.append(f'<text x="{COL_X[0]}" y="{ROW4 + 36 + i * 16}" '
                 f'font-size="{F_BOXSUB}" fill="#334155">{escape(line)}</text>')

    o.append("</svg>")
    return "\n".join(o)


(DOCS / "architecture.drawio").write_text(emit_drawio(), encoding="utf-8")
(DOCS / "architecture.svg").write_text(emit_svg(), encoding="utf-8")
print("drawio:", (DOCS / "architecture.drawio").stat().st_size, "bytes")
print("svg   :", (DOCS / "architecture.svg").stat().st_size, "bytes")
print(f"canvas: {PAGE_W}x{PAGE_H}  boxes: {len(BOXES)}  edges: {len(EDGES)}")
