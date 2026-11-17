# Skill: LDAP Injection

Operational playbook. Confirm whether user input is concatenated into an LDAP filter, so
metacharacters change the query logic. Non-destructive: read-only filter probes; never
modify directory entries.

## Trigger conditions
IF a hypothesis has class `LDAPI` AND an endpoint is backed by an LDAP directory lookup.

## Procedure
1. Send a benign value that matches nothing (control).
2. Send a filter-injection payload, e.g. `*)(uid=*))(|(uid=*`.

## Confirmation criteria
- The injection returns records the benign lookup did not (the filter logic was altered).

## False-positive criteria
- The metacharacters are escaped — no extra records are returned.

## Evidence requirements
- `control.*` and `inject-ldap.*`, plus the record delta.

## Output
- Finding JSON with `class: "LDAPI"`, `status`, `endpoint`, `method`, `parameter`,
  the confirming `payload`, and `evidence` file refs.
