"""Export findings to JSON, HTML and DOCX. Stdlib only — the .docx is a minimal OOXML
package assembled with zipfile, so no external dependency is added."""
from __future__ import annotations

import json
import zipfile
from collections import Counter
from xml.sax.saxutils import escape

from .catalog import meta_for
from .report import _SEVERITY_ORDER, _severity

_SEVERITIES = ("critical", "high", "medium", "low")
_SEV_COLOR = {"critical": "#7b1fa2", "high": "#d32f2f", "medium": "#f57c00",
              "low": "#388e3c", "info": "#616161"}


def _model(store):
    findings = list(store.read_findings())
    confirmed = sorted((f for f in findings if f.get("status") == "confirmed"),
                       key=lambda f: _SEVERITY_ORDER.get(_severity(f), 5))
    by_status = Counter(f.get("status") for f in findings)
    by_sev = Counter(_severity(f) for f in confirmed)
    return {
        "target": store.dir.name,
        "mode": store.state.get("mode"),
        "objective": store.state.get("objective"),
        "summary": {
            "confirmed": by_status.get("confirmed", 0),
            "unconfirmed": by_status.get("unconfirmed", 0),
            "false_positive": by_status.get("false-positive", 0),
            "by_severity": {s: by_sev[s] for s in _SEVERITIES if by_sev.get(s)},
        },
        "findings": [_finding_view(f) for f in confirmed],
    }


def _finding_view(f):
    meta = meta_for(f.get("class")) or {}
    return {"severity": _severity(f), "class": f.get("class"), "endpoint": f.get("endpoint"),
            "cwe": meta.get("cwe"), "owasp": meta.get("owasp"), "method": f.get("method"),
            "parameter": f.get("parameter"), "payload": f.get("payload"),
            "proof": f.get("proof"), "evidence": f.get("evidence", {})}


def _write(store, name, text):
    path = store.dir / "reports" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return str(path)


def write_json(store):
    return _write(store, "report.json", json.dumps(_model(store), indent=2) + "\n")


def write_html(store):
    m = _model(store)
    sev = ", ".join(f"{k}: {v}" for k, v in m["summary"]["by_severity"].items()) or "none"
    rows = "".join(
        f'<li>{_badge(x["severity"])} <b>{escape(str(x["class"]))}</b> '
        f'&mdash; <code>{escape(str(x["endpoint"]))}</code></li>'
        for x in m["findings"]) or "<li>No confirmed findings.</li>"
    cards = "".join(_html_card(x) for x in m["findings"])
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Security Assessment - {escape(str(m['target']))}</title>
<style>body{{font:15px/1.6 system-ui,-apple-system,sans-serif;max-width:820px;margin:40px auto;
padding:0 16px;color:#1a1a1a}}h1{{font-size:24px}}h2{{border-bottom:1px solid #ddd;
padding-bottom:4px;margin-top:32px}}.sev{{color:#fff;padding:1px 7px;border-radius:4px;
font-size:12px;font-weight:700}}.card{{border:1px solid #e0e0e0;border-radius:8px;
padding:4px 16px;margin:12px 0}}code{{background:#f4f4f4;padding:1px 4px;border-radius:3px}}
ul{{padding-left:18px}}.meta{{color:#555;font-size:13px}}</style></head><body>
<h1>Security Assessment Report &mdash; {escape(str(m['target']))}</h1>
<p class="meta">Mode: {escape(str(m['mode']))} &middot; Objective: {escape(str(m['objective']))}</p>
<h2>Executive Summary</h2>
<p>Confirmed: <b>{m['summary']['confirmed']}</b> &middot; Unconfirmed: {m['summary']['unconfirmed']}
&middot; False positives: {m['summary']['false_positive']}</p>
<p class="meta">By severity (confirmed): {escape(sev)}</p>
<ul>{rows}</ul>
<h2>Findings</h2>
{cards or '<p>No confirmed findings.</p>'}
</body></html>"""
    return _write(store, "report.html", html)


def _badge(severity):
    color = _SEV_COLOR.get(severity, "#616161")
    return f'<span class="sev" style="background:{color}">{escape(severity.upper())}</span>'


def _html_card(x):
    ev = x["evidence"] or {}
    files = ", ".join(ev.get("files", [])) or "none"
    return (f'<div class="card"><h3>{_badge(x["severity"])} {escape(str(x["class"]))} '
            f'&mdash; <code>{escape(str(x["endpoint"]))}</code></h3>'
            f'<p class="meta">{escape(str(x["cwe"]))} | {escape(str(x["owasp"]))}</p>'
            f'<p><b>Payload:</b> <code>{escape(str(x["payload"]))}</code></p>'
            f'<p><b>Proof:</b> {escape(str(x["proof"]))}</p>'
            f'<p class="meta"><b>Evidence:</b> {escape(str(ev.get("dir")))} '
            f'({escape(files)})</p></div>')


_CONTENT_TYPES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                  '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-'
                  'package.relationships+xml"/><Default Extension="xml" ContentType='
                  '"application/xml"/><Override PartName="/word/document.xml" ContentType='
                  '"application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                  '.main+xml"/></Types>')
_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
         '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006'
         '/relationships/officeDocument" Target="word/document.xml"/></Relationships>')


def _para(text, bold=False, size=None):
    rpr = ""
    if bold or size:
        rpr = "<w:rPr>" + ("<w:b/>" if bold else "") + \
              (f'<w:sz w:val="{size}"/>' if size else "") + "</w:rPr>"
    return (f'<w:p><w:r>{rpr}<w:t xml:space="preserve">{escape(str(text))}</w:t></w:r></w:p>')


def write_docx(store):
    m = _model(store)
    body = [_para(f"Security Assessment Report - {m['target']}", bold=True, size=36),
            _para(f"Mode: {m['mode']}  |  Objective: {m['objective']}"),
            _para("Executive Summary", bold=True, size=28),
            _para(f"Confirmed: {m['summary']['confirmed']}  |  Unconfirmed: "
                  f"{m['summary']['unconfirmed']}  |  False positives: "
                  f"{m['summary']['false_positive']}"),
            _para("By severity (confirmed): "
                  + (", ".join(f"{k}: {v}" for k, v in m["summary"]["by_severity"].items())
                     or "none")),
            _para("Findings", bold=True, size=28)]
    for x in m["findings"]:
        ev = x["evidence"] or {}
        body += [
            _para(f"[{x['severity'].upper()}] {x['class']} - {x['endpoint']}", bold=True, size=26),
            _para(f"Classification: {x['cwe']} | {x['owasp']}"),
            _para(f"Method/Parameter: {x['method']} / {x['parameter']}"),
            _para(f"Payload: {x['payload']}"),
            _para(f"Proof: {x['proof']}"),
            _para(f"Evidence: {ev.get('dir')} ({', '.join(ev.get('files', [])) or 'none'})"),
        ]
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/'
                '2006/main"><w:body>' + "".join(body) + "<w:sectPr/></w:body></w:document>")
    path = store.dir / "reports" / "report.docx"
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", document)
    return str(path)


def write_exports(store):
    return {"json": write_json(store), "html": write_html(store), "docx": write_docx(store)}
