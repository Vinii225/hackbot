# Skill: Prototype Pollution

Operational playbook. Confirm whether a JSON-merge endpoint honors a `__proto__` key,
landing attacker data on the object prototype. Non-destructive: one benign marker under
`__proto__`; never pollute keys that change app behavior.

## Trigger conditions
IF a hypothesis has class `PROTO-POLLUTION` AND an endpoint merges client JSON (merge,
config, settings, patch).

## Procedure
1. POST `{"__proto__": {"hbflag": "<marker>"}}`.

## Confirmation criteria
- The marker is reflected back as part of the merged object — `__proto__` polluted it.

## False-positive criteria
- The `__proto__` key is stripped/ignored (marker absent).

## Evidence requirements
- `proto-merge.*` showing the request and the polluted (or clean) result.

## Output
- Finding JSON with `class: "PROTO-POLLUTION"`, `status`, `endpoint`, `method`, and
  `evidence`.
