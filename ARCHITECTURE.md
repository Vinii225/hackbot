# Architecture

Hackbot is a Coordinator-driven loop for **authorized** web security testing. It separates
*what to do next* (a deterministic state machine) from *how a phase is carried out* (a
pluggable executor), so the same engagement logic runs offline against a scenario, live via
deterministic checkers, or through an LLM coding agent.

## The loop

`orchestrator/core.py` holds the Coordinator. `run_engagement(target_dir, executors, ...)`:

1. Loads the on-disk `StateStore` and the target's **scope** (`scope.md`). A missing or
   placeholder scope terminates the run before any request is made.
2. Repeatedly calls `decide(store)`, which returns the next phase:
   - **recon** — until recon has produced hypotheses.
   - **hunt** — the next prioritized hypothesis whose skill is available and untested.
   - **report** — once there is at least one confirmed finding.
   - **done** — nothing left to do (or no attack surface found).
3. Dispatches that phase to the executor, persists state, and enforces limits
   (`max_iterations`, `max_requests`, `max_runtime_seconds`, a no-progress guard, and an
   operator stop).

```
USER ──▶ COORDINATOR ──▶ RECON ──▶ VULN-HUNTER ──▶ REPORTER
             ▲              │            │              │
             └──────────────┴── hypotheses, findings, state ──┘
```

## Executors (the Strategy seam)

Every executor implements the same three methods — `recon(store, urls, objective)`,
`hunt(store, hyp, urls)`, `report(store)` — so the Coordinator never branches on which one
is in use:

- **`SimulationExecutors`** (`agents.py`) — replays a JSON scenario. Fully offline,
  deterministic, no network or model. Used by most tests and the `--executor sim` CLI.
- **`DynamicExecutors`** (`scanner.py`) — crawls the target, generates hypotheses
  (`recon.py`) and runs the registered **checkers** against real HTTP. Deterministic, no LLM.
- **`LLMExecutors`** (`llm.py`) — drives the Markdown agent playbooks through an LLM coding
  agent (e.g. the Claude CLI). This is what makes real requests in a `coop`/`auto` run.
- **`TriagedExecutors`** (`triage.py`) — an optional decorator that adds an LLM triage layer
  (prioritize + explain) on top of any executor, degrading to deterministic-only when no
  backend is available.

## Checkers and the catalog

Each vulnerability class is one **checker** in `orchestrator/checks.py`, registered with
`@register("CLASS", ...aliases)` so the hunter dispatches by hypothesis class with no
hardcoded branch (Open/Closed). A checker returns a `CheckResult` with a status:

- **confirmed** — reproduced against the target with evidence saved to disk.
- **false-positive** — the safe variant of the surface; explicitly *not* a finding.
- **unconfirmed** — a hypothesis that could not be proven.

`catalog.py` carries per-class metadata (title, CWE, OWASP, severity, remediation).
`tests/test_consistency.py` fails CI if any class lacks a checker, metadata, a skill
playbook, or an example-config entry — so a class is only "supported" when wired end-to-end
(see `CONTRIBUTING.md`).

## Recon and skill gating

`recon.py` turns a crawl into hypotheses using parameter/path hint sets (one per class). A
hypothesis is only hunted when its class is in the target's `allowed_skills` **and** a skill
directory exists (`_skill_available`); `focus` orders which classes are tried first.

## State and reporting

`StateStore` persists everything under `targets/<target>/state/` (config, state, tested
hypotheses) and `targets/<target>/findings/` (one `F-*.json` per result). The reporter
(`report.py` + `export.py`) renders confirmed findings — with an executive summary, a
per-class **coverage** appendix, and the authorized **scope** — to `REPORT.md`,
`report.json`, `report.html` and `report.docx`.

## Scope safety (non-negotiable)

- No run proceeds without a real in-scope host in `scope.md`.
- Checkers probe only the authorized target, never follow redirects out of scope, and keep
  probes non-destructive (one proof is enough; emulated metadata, no real secrets).
- Standard library only — no third-party dependencies.
