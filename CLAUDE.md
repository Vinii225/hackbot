# Hackbot — Global Instructions

This repository is an **AI-orchestrated web application security testing harness**.
It is designed for **authorized** testing only: PortSwigger Web Security Academy labs,
controlled lab environments, and targets the operator has explicit permission to test.

Read this file before acting. It applies to every agent (Coordinator, Recon,
Vuln-Hunter, Reporter) and every skill.

---

## 1. Authorization & Scope (hard rules)

1. **Never test anything outside the declared scope.** The scope for an engagement
   lives in `targets/<target>/scope.md`. If it is missing, ambiguous, or empty, **stop
   and ask the operator** — do not guess.
2. **Never autonomously expand scope.** Discovered external domains, IPs, subdomains,
   third-party services, or links are *not* in scope just because they were found.
   They may only be tested after the operator adds them to `scope.md`.
3. If a target is clearly not a lab/authorized environment and the operator cannot
   produce authorization, refuse to proceed.
4. Respect the per-engagement limits in `targets/<target>/state/config.json`
   (max iterations, max requests, max runtime, allowed agents/skills/tools).
5. Prefer non-destructive tests. Do not run denial-of-service, data-destruction,
   or mass-exploitation actions. One proof-of-concept request is enough to confirm.

## 2. Architecture (Coordinator pattern)

```
USER → COORDINATOR → RECON → COORDINATOR → VULN-HUNTER → COORDINATOR → REPORTER → REPORT.md
```

- **Coordinator** (`COORDINATOR.md`): orchestrates. Plans, routes, tracks state,
  decides next step and termination. Does not perform recon or exploitation itself.
- **Recon** (`agents/recon/AGENT.md`): maps attack surface, produces *hypotheses*.
  Never confirms a vulnerability.
- **Vuln-Hunter** (`agents/vuln-hunter/AGENT.md`): loads a skill, tests a hypothesis,
  classifies the result (`confirmed` / `unconfirmed` / `false-positive`) with evidence.
- **Reporter** (`agents/reporter/AGENT.md`): turns confirmed findings into a report.
  Never tests, never invents evidence, never upgrades a hypothesis.

## 3. Hypothesis vs. Finding (never blur these)

- A **hypothesis** is a *guess* that something might be vulnerable. Recon produces these.
- A **confirmed finding** requires **captured evidence** (request + response + before/after).
  Only Vuln-Hunter can promote a hypothesis to a confirmed finding, and only with evidence.
- The Reporter may only report `confirmed` findings. It must never treat a hypothesis as a vuln.

See `contracts/` for the exact schemas of every message passed between agents.

## 4. State lives on the filesystem, not in chat memory

All durable information is written under `targets/<target>/`:

| Path | Purpose |
|------|---------|
| `scope.md` | Authorized scope, credentials, limits (human-authored) |
| `state/config.json` | Engagement config & limits |
| `state/state.json` | Current status, mode, iteration counter, plan pointer |
| `state/plan.md` | Human-readable plan |
| `state/tested.json` | Dedupe ledger: endpoints/hypotheses already tested |
| `recon/` | Recon outputs (attack surface, JS findings, hypotheses) |
| `findings/` | One file per finding (hypothesis or confirmed) |
| `reports/` | Generated reports |

Before any action, an agent **reads the relevant state files**. After any action, it
**writes results back**. Never rely only on the LLM conversation for anything important.

## 5. Agent loop (Ralph-style)

```
THINK → PLAN → ACT → OBSERVE → VALIDATE → UPDATE STATE → REPLAN → REPEAT
```

Stop the loop when ANY termination condition is met (see `COORDINATOR.md` §Termination).

## 6. Duplicate-work avoidance

Before executing an action, check `state/tested.json`:
- endpoint already tested with this technique? → skip unless there is a new, justified reason.
- hypothesis already exists? → do not recreate it.
- evidence already captured? → reuse it.

## 7. Evidence rules

- Evidence is captured, not described. Save raw request + raw response.
- Never fabricate requests, responses, parameters, or results.
- If you cannot capture evidence, the finding stays `unconfirmed`.

## 8. Modes

- `/hackbot-coop` — human-in-the-loop. Pause at each phase boundary for operator review.
- `/hackbot-auto` — autonomous within configured limits. Still never expands scope.

See `commands/hackbot-coop.md` and `commands/hackbot-auto.md`.

## 9. Tools

Light helper scripts live in `tools/`. HTTP is done with `curl` by default to keep
evidence raw and reproducible. No heavy dependencies are required for the MVP.
