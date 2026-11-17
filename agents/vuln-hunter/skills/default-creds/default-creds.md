# Skill: Default Credentials

Operational playbook. Confirm whether an administrative login accepts a common vendor-default
username/password pair. Non-destructive: a short, fixed list of well-known defaults; never a
password brute-force or spray beyond that list.

## Trigger conditions
IF a hypothesis has class `DEFAULT-CREDS` AND an endpoint is an admin/privileged login.

## Procedure
1. Submit each well-known default pair (admin:admin, admin:password, root:root, ...).

## Confirmation criteria
- Any default pair authenticates successfully.

## False-positive criteria
- No default pair is accepted.

## Evidence requirements
- `try-<user>-<pass>.*` for the attempts, including the accepted one.

## Output
- Finding JSON with `class: "DEFAULT-CREDS"`, `status`, `endpoint`, the accepted `payload`, `evidence`.
