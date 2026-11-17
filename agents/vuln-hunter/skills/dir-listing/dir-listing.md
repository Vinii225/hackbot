# Skill: Directory Listing Enabled

Operational playbook. Confirm whether a directory path returns an auto-generated index of
its files. Fully passive: one GET; read only the response.

## Trigger conditions
IF a hypothesis has class `DIR-LISTING`
AND a path looks like a directory (trailing slash, or files/uploads/assets/backup/static).

## Required inputs
- `endpoint`, `method` (GET).

## Procedure
1. GET the directory path. → `listing.*`

## Confirmation criteria
- A 200 HTML response containing an index marker (`Index of /`, `Directory listing for`) —
  the directory contents are enumerable.

## False-positive criteria
- The path returns 401/403/404 — no listing is exposed.

## Evidence requirements
- `listing.*` showing the index (or the denial).

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "DIR-LISTING"`, `status`,
  `endpoint`, `method`, and `evidence` file refs.
