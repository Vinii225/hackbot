# Skill: Command Injection (OS Command Injection)

Operational playbook. Confirm whether user input reaches an OS command interpreter.
Non-destructive: prove execution with a **harmless, unique marker** (e.g. `whoami`,
a unique echo, or a timing delay). Never run destructive or persistence commands.

## Trigger conditions
IF a hypothesis has class `CMDI`
AND a parameter plausibly feeds an OS command (ping/host/dns lookup, filename, stock
   check, PDF/image conversion, email/feedback host, backup, log path, etc.).

## Required inputs
- `endpoint`, `method`, the `parameter` to inject.
- A valid baseline request (so you can compare behavior).

## Procedure
THEN send a clean baseline request and record normal response + timing.
→ save `request-a.http` / `response-a.http`.
THEN try inline command separators around a **unique, harmless** command, e.g.:
  `; echo HB_<rand>` · `| echo HB_<rand>` · `& echo HB_<rand>` · `$(echo HB_<rand>)` ·
  `` `echo HB_<rand>` `` · newline-prefixed variants · and quote-breakouts
  (`'`, `"`) if the value looks quoted.
→ save `request-b.http` / `response-b.http`.
THEN if output is not reflected, test **blind** execution:
  - time-based: `; sleep 10` (or `& ping -c 10 127.0.0.1 &`) and compare response time
    to baseline (and to a `sleep 0` control).
  - out-of-band only if `scope.md` explicitly authorizes an OOB collector in scope.
THEN use a unique random token per attempt so reflected output cannot be confused with
existing page content.

## Decision rules
- The unique marker appears in the response where only command output could place it
  → candidate confirmation (reflected).
- Response time tracks the injected delay (delay present vs. control absent), repeatably
  → candidate confirmation (blind/time-based).

## Confirmation criteria (ALL must hold)
- Reflected: the exact unique marker (`HB_<rand>` / `whoami` output) appears in the
  response and is absent from the baseline. OR
- Time-based: injected `sleep N` reliably adds ~N seconds vs. a `sleep 0` control,
  reproduced at least twice.
- Evidence captured: baseline + injected request/response (and timings for blind).

## False-positive criteria (ANY)
- The marker is reflected because the app simply echoes input (same string also appears
  when sent without any command separators) → not execution.
- Timing differences are within normal jitter / not reproducible with a control.
- The response is a generic error with no sign of command execution.

## Evidence requirements
- `request-a.http`, `response-a.http` (baseline).
- `request-b.http`, `response-b.http` (injection).
- For blind: record the timings (baseline, control `sleep 0`, injected `sleep N`).

## Output
- Finding JSON (`contracts/finding.schema.md`) with:
  `class: "CMDI"`, `status: confirmed|unconfirmed|false-positive`,
  `endpoint`, `method`, `parameter`, the confirming payload, the unique marker/timing,
  and `evidence` file refs.
