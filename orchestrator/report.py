"""Renders confirmed findings into REPORT.md."""
from __future__ import annotations

from collections import Counter

from .catalog import meta_for

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
_SEVERITIES = ("critical", "high", "medium", "low")


def _severity(f) -> str:
    meta = meta_for(f.get("class")) or {}
    return (f.get("severity") or meta.get("severity") or "info").lower()


def write_report(store) -> dict:
    findings = list(store.read_findings())
    confirmed = sorted(
        (f for f in findings if f.get("status") == "confirmed"),
        key=lambda f: _SEVERITY_ORDER.get(_severity(f), 5),
    )
    by_status = Counter(f.get("status") for f in findings)
    by_sev = Counter(_severity(f) for f in confirmed)
    sev_line = ", ".join(f"{s}: {by_sev[s]}" for s in _SEVERITIES if by_sev.get(s)) or "none"

    lines = [
        f"# Security Assessment Report - {store.dir.name}", "",
        f"- Target: {store.dir.name}",
        f"- Mode: {store.state.get('mode')}",
        f"- Objective: {store.state.get('objective')}", "",
        "## Executive Summary", "",
        f"- Confirmed: {by_status.get('confirmed', 0)} | "
        f"Unconfirmed: {by_status.get('unconfirmed', 0)} | "
        f"False positives: {by_status.get('false-positive', 0)}",
        f"- By severity (confirmed): {sev_line}", "",
    ]
    if confirmed:
        lines.append("Confirmed findings:")
        lines += [f"- [{_severity(f).upper()}] {f.get('class')} - {f.get('endpoint')}"
                  for f in confirmed]
        lines.append("")
    lines.append("## Findings")
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
