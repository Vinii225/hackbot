# Skill: Mass Assignment

Operational playbook. Confirm whether an update endpoint binds a privileged field from the
request body that a client should not control. Non-destructive: set one benign marker plus
the privileged field; read whether it was bound.

## Trigger conditions
IF a hypothesis has class `MASS-ASSIGNMENT` AND an endpoint updates an object (profile,
account, user, register).

## Procedure
1. POST the normal field(s) plus an unexpected privileged field, e.g. `role=admin`.

## Confirmation criteria
- The response reflects the privileged field as set (e.g. `role` became `admin`).

## False-positive criteria
- The privileged field is ignored (role stays the default).

## Evidence requirements
- `inject-role.*` showing the privileged field accepted.

## Output
- Finding JSON with `class: "MASS-ASSIGNMENT"`, `status`, `endpoint`, `method`,
  the confirming `payload`, and `evidence` file refs.
