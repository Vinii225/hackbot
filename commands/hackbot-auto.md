# /hackbot-auto — Autonomous mode

Run the Coordinator loop **without per-step approval**, within the configured limits.
Use only after a target has been validated in `/hackbot-coop` at least once.

## Usage
```
/hackbot-auto <target> "<objective>"
# example:
/hackbot-auto target-example "Find IDOR and command injection in the lab"
```

## Behavior

Act as the Coordinator (`COORDINATOR.md`). Run THINK→PLAN→ACT→OBSERVE→VALIDATE→UPDATE→
REPLAN→REPEAT continuously, delegating to agents, until a termination condition fires.

No pause between phases — BUT every one of these limits from `state/config.json` is hard
enforced, and the loop stops the instant any is exceeded:

- `max_iterations`
- `max_requests`
- `max_runtime_seconds`
- `allowed_agents`
- `allowed_skills`
- `allowed_tools`
- `scope` (hosts in `scope.md` only)

## Steps

1. Read `CLAUDE.md`, `COORDINATOR.md`.
2. Read `targets/<target>/scope.md`. If missing/ambiguous → STOP and ask (never guess).
3. Read `state/config.json`; set `state.json.mode: "auto"`. Start timers/counters.
4. Enter the loop:
   - Before each ACT: check `tested.json` (dedupe) and ALL limits.
   - Delegate via `contracts/`. Validate every result. Persist everything.
   - Bump `iteration`, add `requests_used`, update `state.json` after each step.
5. Terminate on any condition in `COORDINATOR.md §Termination`; write final state + reason.
6. Generate a report if ≥1 confirmed finding.

## Hard guardrails (autonomous mode never relaxes these)
- **Never expand scope.** Out-of-scope hosts are off-limits regardless of objective.
- **Never run destructive/DoS/mass actions.** One harmless PoC per hypothesis.
- **Stop, don't guess**, if scope is missing/ambiguous or the system can't safely continue.
- A `confirmed` finding still requires evidence on disk; no evidence → `unconfirmed`.
