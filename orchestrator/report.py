"""Renders confirmed findings into REPORT.md."""
from __future__ import annotations

from .catalog import meta_for

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}


def _severity(f) -> str:
    meta = meta_for(f.get("class")) or {}
    return (f.get("severity") or meta.get("severity") or "info").lower()


def write_report(store) -> dict:
    confirmed = sorted(
        (f for f in store.read_findings() if f.get("status") == "confirmed"),
        key=lambda f: _SEVERITY_ORDER.get(_severity(f), 5),
    )
    lines = [
        f"# Security Assessment Report - {store.dir.name}", "",
        f"- Mode: {store.state.get('mode')}",
        f"- Objective: {store.state.get('objective')}", "",
        "## Executive Summary",
        f"- Confirmed findings: {len(confirmed)}", "",
        "## Findings",
    ]
    if not confirmed:
        lines.append("No confirmed findings.")
    for f in confirmed:
        evidence = f.get("evidence", {})
        meta = meta_for(f.get("class")) or {}
        lines += [
            "",
            f"### [{_severity(f).upper()}] {f.get('class')} - {f.get('endpoint')}",
            f"- Classification: {meta.get('cwe', 'n/a')} | {meta.get('owasp', 'n/a')}",
            f"- Method/Parameter: {f.get('method')} / {f.get('parameter')}",
            f"- Payload: {f.get('payload')}",
            f"- Proof: {f.get('proof')}",
            f"- Evidence: {evidence.get('dir')} "
            f"({', '.join(evidence.get('files', [])) or 'none'})",
        ]
        if f.get("explanation"):
            lines.append(f"- Impact & remediation: {f['explanation']}")

    report_file = store.dir / "reports" / "REPORT.md"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text("\n".join(lines) + "\n")
    return {"report_file": str(report_file), "confirmed": len(confirmed)}
