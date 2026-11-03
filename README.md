# Hackbot

An AI-orchestrated harness for **authorized** web application security testing, built on a
Coordinator pattern. Designed for PortSwigger Web Security Academy labs and other targets
you are explicitly authorized to test.

> **Authorized use only.** Every run is bounded by `targets/<target>/scope.md`. The
> system never expands scope on its own. See [`CLAUDE.md`](CLAUDE.md).

## MVP focus

- **IDOR / Broken Access Control** — `agents/vuln-hunter/skills/idor/idor.md`
- **Command Injection** — `agents/vuln-hunter/skills/cmdi/cmdi.md`
- **Path Traversal** — `agents/vuln-hunter/skills/path-traversal/path-traversal.md`
- **Reflected XSS** — `agents/vuln-hunter/skills/xss/xss.md`
- **Broken Access Control** (unauthenticated privileged access) — `agents/vuln-hunter/skills/access-control/access-control.md`
- **SQL Injection** (error / boolean / time-based) — `agents/vuln-hunter/skills/sqli/sqli.md`

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
│   ├── vuln-hunter/        AGENT.md + skills/{idor,cmdi,path-traversal,xss,access-control,sqli}/*.md
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

## Programmatic runner (code-driven loop)

`orchestrator/` is a real Python implementation of the Coordinator loop. The loop,
state, limit enforcement and termination are actual code (not model instructions);
the recon/exploitation work is delegated to a pluggable `Executors` object.

```
# Offline, deterministic (no network, no model) — used by the tests and for demos:
python -m orchestrator targets/target-example --executor sim --sim examples/scenario.json

# Real run: drive the Markdown agents via an LLM coding agent (hits the target):
python -m orchestrator targets/target-example --executor llm --mode coop

# Inspect the prompts the llm executor would send, without calling any model:
python -m orchestrator targets/target-example --print-prompts
```

- `--executor sim` with `--sim <scenario.json>` replays a scenario with
  `SimulationExecutors` (`orchestrator/agents.py`) — fully offline and deterministic.
- `--executor llm` uses `orchestrator/llm.py:LLMExecutors`, which builds a prompt per
  phase (`orchestrator/prompts.py`) and invokes a coding agent — the Claude Code CLI by
  default (`claude -p`; override with env `HACKBOT_LLM_CMD`). The agent follows the
  `AGENT.md` / skill / contract files and writes the same on-disk artifacts, so the loop
  and all its limits apply unchanged. The `invoke` callable is injectable, so the whole
  pipeline is testable with a fake model offline.

Loop safety: the loop stops on any of `max_iterations`, `max_requests`,
`max_runtime_seconds`, a no-progress guard, missing/ambiguous scope, operator stop,
or objective-complete. A `confirmed` finding whose evidence files are missing on disk is
automatically downgraded to `unconfirmed`.

Run the tests (stdlib only):

```
python -m unittest discover -s tests -v
```

### Checkers + end-to-end proof

Each vulnerability class is a deterministic (no-LLM) checker registered in
`orchestrator/checks.py` (`check_idor`, `check_cmdi`, `check_path_traversal`), driving the
corresponding `*.md` procedure over real HTTP via the session/evidence client in
`tools/httpx.py`. The `tests/test_e2e_*.py` suites boot an intentionally-vulnerable local
fixture (`tests/fixtures/mock_lab.py`) and assert each class is confirmed from real
captured evidence — and that safe endpoints are reported as false positives, not vulns.

For a real PortSwigger lab, see `targets/portswigger-idor/RUNBOOK.md`.

### Autonomous recon

`orchestrator/scanner.py:DynamicExecutors` is the point-and-go set: given only a base URL
(and optional credentials), recon uses the bounded, in-scope crawler (`tools/crawler.py`)
to discover endpoints, params, forms, same-origin JS and object ids, then
`orchestrator/recon.py` turns those into hypotheses (object id -> IDOR; command-ish param
-> CMDI; file-ish param -> path traversal). Hunt looks up the registered checker for each
hypothesis class, so adding a skill never touches the dispatcher. `tests/test_recon.py`
proves it discovers the surface and confirms the vulns without being handed any endpoint.

## Tools

- `tools/http.sh` — curl wrapper that saves raw request/response + timing as evidence.
- `tools/state.py` — stdlib-only helper: show/set state, bump counters, enforce limits,
  and record/query the tested ledger for dedupe.

## Optional LLM triage layer (bring your own backend)

The deterministic engine runs with no LLM. Triage is an *optional* decision layer that
reads what the engine already produced and helps prioritize hypotheses and explain
findings — a couple of small calls per scan, so it is cheap on any backend. If no backend
is available, or a call fails, the pipeline runs unchanged.

Pick a backend with `--triage` (or `HACKBOT_LLM`), default `none`:

```
python -m orchestrator targets/x --executor sim --sim examples/scenario.json --triage auto
```

| `--triage` | Backend | Notes |
|------------|---------|-------|
| `claude`   | `claude -p` CLI | uses your existing Claude subscription; override `HACKBOT_CLAUDE_CMD` |
| `ollama`   | `http://localhost:11434` | free & local; `ollama serve` + `ollama pull <model>`; set `HACKBOT_OLLAMA_MODEL` |
| `openai`   | any OpenAI-compatible API | set `OPENAI_BASE_URL`, `OPENAI_API_KEY`, model via `HACKBOT_OPENAI_MODEL` — covers OpenAI, Groq, OpenRouter, LM Studio, … |
| `auto`     | first available | tries claude → ollama → openai |
| `none`     | disabled (default) | deterministic only, zero cost |

See `orchestrator/triage.py`. The LLM is a decision layer only — it never sends requests
to the target.

## Roadmap (future skills, not in MVP)

SSRF · JWT · CORS · SSTI · GraphQL · XXE · CSRF — each added as a new
`agents/vuln-hunter/skills/<class>/<class>.md` plus a Coordinator routing rule.
