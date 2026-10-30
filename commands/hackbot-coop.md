# /hackbot-coop — Human-in-the-loop mode

Run the Coordinator loop, but **pause for operator approval at every phase boundary** and
before the first exploit attempt. Use this for first runs against a new target.

## Usage
```
/hackbot-coop <target> "<objective>"
# example:
/hackbot-coop target-example "Find IDOR and command injection in the lab"
```

## Behavior

Act as the Coordinator (`COORDINATOR.md`). Follow the loop, but at each checkpoint
STOP and present the current state, then wait for the operator to type `approve`
(continue), `skip` (skip this action), `edit` (operator changes plan/scope), or `stop`.

### Checkpoints (pause at each)
1. **After loading scope** — show target, scope, limits, mode. Confirm authorization.
2. **After recon** — show tech, endpoint/param counts, and the hypotheses list.
3. **Before each exploit** (at least before the first) — show the hypothesis, the skill,
   and the exact request(s) about to be sent.
4. **After each finding** — show classification + evidence refs.
5. **Before reporting** — show which confirmed findings will be included.

### At each pause, display
- current plan (`state/plan.md`), target, scope, discovered endpoints,
  hypotheses, proposed next action, and findings so far.

## Steps

1. Read `CLAUDE.md`, `COORDINATOR.md`.
2. Read `targets/<target>/scope.md`. If missing/ambiguous → STOP and ask.
3. Initialize/read `state/config.json` and `state/state.json`; set `mode: "coop"`.
4. Write/refresh `state/plan.md`.
5. Enter the loop. At every checkpoint, pause and wait for operator input.
6. Delegate to agents via the `contracts/`. Persist all outputs.
7. Stop on any termination condition or operator `stop`.
8. Ensure a report exists if there is ≥1 confirmed finding.

## Guardrails
- Never expand scope, even if the operator's objective is broad — ask them to edit
  `scope.md` explicitly.
- Never proceed past a checkpoint without approval.
