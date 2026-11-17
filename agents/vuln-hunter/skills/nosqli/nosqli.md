# Skill: NoSQL Injection

Operational playbook. Confirm whether a JSON login/query endpoint accepts a query operator
object (e.g. `{"$ne": ...}`) where a string is expected, altering the query. Non-destructive:
one operator probe; never run operators that enumerate or dump data.

## Trigger conditions
IF a hypothesis has class `NOSQLI` AND an endpoint takes a JSON body backed by a document store.

## Procedure
1. POST normal JSON with a wrong string password (control).
2. POST the same with the password replaced by `{"$ne": "<wrong>"}`.

## Confirmation criteria
- The operator request authenticates (or returns data) where the control was rejected.

## False-positive criteria
- The operator is coerced to a literal — same rejection as the control.

## Evidence requirements
- `control.*` and `inject-operator.*`.

## Output
- Finding JSON with `class: "NOSQLI"`, `status`, `endpoint`, `method`, the `payload`, `evidence`.
