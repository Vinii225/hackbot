# Skill: XPath Injection

Operational playbook. Confirm whether user input is concatenated into an XPath query, so a
quote breakout changes the query logic. Non-destructive: read-only boolean probes.

## Trigger conditions
IF a hypothesis has class `XPATHI` AND an endpoint searches an XML/XPath-backed store.

## Procedure
1. Send a benign value that matches nothing (control).
2. Send a quote-breakout payload, e.g. `' or '1'='1`.

## Confirmation criteria
- The breakout returns records the benign query did not (the predicate was altered).

## False-positive criteria
- Quotes are stripped/escaped — no extra records.

## Evidence requirements
- `control.*` and `inject-xpath.*`, plus the record delta.

## Output
- Finding JSON with `class: "XPATHI"`, `status`, `endpoint`, `method`, `parameter`, `payload`.
