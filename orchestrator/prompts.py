"""Pure prompt builders for the LLM executors. Each embeds a 'PHASE: ...' marker so a
test (or a human) can tell which phase a prompt belongs to."""
from __future__ import annotations

import json
from pathlib import Path

HEADER = (
    "You are an agent in the Hackbot harness for AUTHORIZED security testing.\n"
    "Obey CLAUDE.md. Stay strictly inside the in-scope hosts; never touch anything else.\n"
    "Use curl or tools/http.sh for HTTP and capture raw request/response as evidence.\n"
    "Work from the repository root. Write every output file exactly where instructed."
)


def build_recon_prompt(target_dir, urls, objective) -> str:
    t = Path(target_dir)
    return "\n\n".join([
        "PHASE: RECON",
        HEADER,
        "FOLLOW THESE FILES:\n"
        "- CLAUDE.md\n- agents/recon/AGENT.md\n- agents/recon/skills/recon.md\n"
        "- contracts/coordinator-to-recon.md, contracts/recon-to-coordinator.md,\n"
        "  contracts/hypothesis.schema.md",
        f"TARGET: {t.name}",
        f"IN-SCOPE HOSTS (only these; never touch any other host): {', '.join(urls)}",
        f"OBJECTIVE: {objective}",
        "WRITE OUTPUTS (JSON):\n"
        f"- {t}/recon/tech.json\n- {t}/recon/surface.json\n- {t}/recon/js.json\n"
        f"- {t}/recon/hypotheses.json   (array, each item per hypothesis.schema.md)",
        f"When finished, write ONLY the integer count of HTTP requests you made to "
        f"{t}/recon/.requests",
        "Produce hypotheses only. Do NOT claim any vulnerability is confirmed. "
        "If the host is unreachable, write an empty array to hypotheses.json and stop.",
    ])


def build_hunt_prompt(target_dir, hyp, urls, skill) -> str:
    t = Path(target_dir)
    fid = "F-" + str(hyp["id"]).split("-", 1)[-1]
    return "\n\n".join([
        "PHASE: HUNT",
        HEADER,
        "FOLLOW THESE FILES:\n"
        "- CLAUDE.md\n- agents/vuln-hunter/AGENT.md\n"
        f"- agents/vuln-hunter/skills/{skill}/{skill}.md\n"
        "- contracts/coordinator-to-vuln-hunter.md, contracts/vuln-hunter-to-coordinator.md,\n"
        "  contracts/finding.schema.md",
        f"TARGET: {t.name}",
        f"IN-SCOPE HOSTS (only these): {', '.join(urls)}",
        "HYPOTHESIS TO TEST:\n" + json.dumps(hyp, indent=2),
        f"WRITE the finding to {t}/findings/{fid}.json per finding.schema.md.",
        f"SAVE raw evidence files under {t}/findings/evidence/{fid}/ "
        "(e.g. request-a.http, response-a.http, request-b.http, response-b.http).\n"
        "A status of 'confirmed' REQUIRES those evidence files to exist on disk.",
        f"When finished, write ONLY the integer request count to "
        f"{t}/findings/.requests_{fid}",
        "Send one harmless proof only (no destructive/DoS payloads). "
        "Classify as confirmed | unconfirmed | false-positive.",
    ])


def build_report_prompt(target_dir, confirmed_findings) -> str:
    t = Path(target_dir)
    refs = [f.get("id") for f in confirmed_findings]
    return "\n\n".join([
        "PHASE: REPORT",
        HEADER,
        "FOLLOW THESE FILES:\n- CLAUDE.md\n- agents/reporter/AGENT.md\n"
        "- contracts/coordinator-to-reporter.md, contracts/reporter-to-coordinator.md",
        f"TARGET: {t.name}",
        f"CONFIRMED FINDINGS TO INCLUDE (read each from {t}/findings/): {refs}",
        f"WRITE the report to {t}/reports/REPORT.md.",
        "Use ONLY data present in the finding files and their evidence. Quote evidence "
        "verbatim. Never invent requests, responses, or impact. Order by severity.",
    ])
