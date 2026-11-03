# Skill: SQL Injection

Operational playbook. Confirm whether a parameter is concatenated into a SQL query.
Non-destructive: probe with read-only payloads (a quote, a boolean, a short sleep);
never UNION-dump data, modify rows, or stack destructive statements to "prove" it.

## Trigger conditions
IF a hypothesis has class `SQLI`
AND a parameter plausibly reaches a database (filter, search, sort, id, lookup).

## Required inputs
- `endpoint`, `method`, the `parameter`. Optional `benign` seed value (default `1`).

## Procedure (stop at the first that confirms)
1. **Error-based** — send `<benign>'`. A database error in the response (and not in the
   benign control) means the quote broke the query. → `error-probe.*`
2. **Boolean-based** — send `<benign>' OR '1'='1` and `<benign>' AND '1'='2`. If the
   always-true response carries more data than the always-false one, input alters the
   query logic. → `boolean-true.*`, `boolean-false.*`
3. **Time-based blind** — send `<benign>' OR pg_sleep(N)--` twice. If the response is
   delayed ~N s versus the control, reproducibly, the injection executes. → `time-inject.*`

## Confirmation criteria (ANY one)
- A DB error appears for the quote probe but not the benign control.
- Always-true returns strictly more than always-false.
- The sleep payload delays the response ~N s, reproduced twice.

## False-positive criteria
- The quote causes no error AND the boolean payloads return identical results — the input
  is parameterized/escaped and treated as data.

## Evidence requirements
- `control.*`, plus the probe responses for whichever technique was used.
- Record the exact payload and the observed signal (error text, row delta, or timing).

## Safety
- Read-only confirmation only. Do NOT run UNION data extraction, `OR 1=1` against
  UPDATE/DELETE, or stacked queries. One reproducible signal is enough.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "SQLI"`, `status`, `endpoint`,
  `method`, `parameter`, the confirming `payload`, and `evidence` file refs.
