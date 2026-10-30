# Hackbot

An AI-orchestrated harness for **authorized** web application security testing, built on a
Coordinator pattern. Designed for PortSwigger Web Security Academy labs and other targets
you are explicitly authorized to test.

> ⚠️ **Authorized use only.** Every run is bounded by `targets/<target>/scope.md`. The
> system never expands scope on its own. See [`CLAUDE.md`](CLAUDE.md).

## MVP focus

- **IDOR / Broken Access Control** — `agents/vuln-hunter/skills/idor/idor.md`
- **Command Injection** — `agents/vuln-hunter/skills/cmdi/cmdi.md`

New vulnerability classes are added as new skills without redesigning the system.

## Architecture

```
USER → COORDINATOR → RECON → COORDINATOR → VULN-HUNTER → COORDINATOR → REPORTER → REPORT.md
```

| Agent | File | Role |
|-------|------|------|
| Coordinator | [`COORDINATOR.md`](COORDINATOR.md) | Plan, route, track state, decide, terminate. |
| Recon | [`agents/recon/AGENT.md`](agents/recon/AGENT.md) | Map attack surface → **hypotheses**. |
| Vuln-Hunter | [`agents/vuln-hunter/AGENT.md`](agents/vuln-hunter/AGENT.md) | Test a hypothesis with a skill → classified **finding** + evidence. |
| Reporter | [`agents/reporter/AGENT.md`](agents/reporter/AGENT.md) | Confirmed findings → `REPORT.md`. |

A **hypothesis** is a guess. A **confirmed finding** requires captured evidence. These are
never blurred. See [`contracts/`](contracts/) for every inter-agent message schema.

## Directory layout

```
hackbot/
├── CLAUDE.md               # global rules (scope, state, evidence)
├── COORDINATOR.md          # orchestrator agent
├── agents/
│   ├── recon/              AGENT.md + skills/recon.md
│   ├── vuln-hunter/        AGENT.md + skills/idor/idor.md, skills/cmdi/cmdi.md
│   └── reporter/           AGENT.md
├── contracts/              # JSON message schemas between agents
├── commands/               # /hackbot-coop and /hackbot-auto definitions
├── targets/
│   └── target-example/     scope.md, state/, recon/, findings/, reports/
└── tools/                  # http.sh (raw evidence capture), state.py (state helper)
```

## State (filesystem is the source of truth)

Nothing important lives only in chat. Each engagement persists under
`targets/<target>/`: `state/config.json` (limits), `state/state.json` (status/counters),
`state/plan.md`, `state/tested.json` (dedupe ledger), `recon/`, `findings/` (+ `evidence/`),
`reports/`.

## How to run

1. Create a target dir (copy `targets/target-example`) and fill in `scope.md`
   with your authorized host(s) and limits.
2. From a Claude Code session in this repo, invoke a mode:

   ```
   /hackbot-coop target-example "Find IDOR and command injection in the lab"
   ```
   or, after validating the target once:
   ```
   /hackbot-auto target-example "Find IDOR and command injection in the lab"
   ```

- **`/hackbot-coop`** — pauses for your approval at each phase boundary (see
  [`commands/hackbot-coop.md`](commands/hackbot-coop.md)).
- **`/hackbot-auto`** — runs autonomously within the limits in `config.json`, never
  expanding scope (see [`commands/hackbot-auto.md`](commands/hackbot-auto.md)).

The agent prompts are plain Markdown, so the same workflow can be driven by any agent
runner that can read files and run `curl` — not just Claude Code.

## Tools

- `tools/http.sh` — curl wrapper that saves raw request/response + timing as evidence.
- `tools/state.py` — stdlib-only helper: show/set state, bump counters, enforce limits,
  and record/query the tested ledger for dedupe.

## Roadmap (future skills, not in MVP)

XSS · SSRF · SQL Injection · JWT · CORS · SSTI · GraphQL · XXE · CSRF — each added as a new
`agents/vuln-hunter/skills/<class>/<class>.md` plus a Coordinator routing rule.
