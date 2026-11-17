# Skill: Verbose Error / Information Disclosure

Operational playbook. Confirm whether malformed input makes the server return a stack trace
or framework error that discloses internals (paths, versions, code). Non-destructive: one
malformed value; read only the error response.

## Trigger conditions
IF a hypothesis has class `INFO-DISCLOSURE`
AND a parameter plausibly triggers a server-side error (numeric/compute/paging params).

## Required inputs
- `endpoint`, `method`, the `parameter`.

## Procedure
1. Send a benign value (control) and then a malformed value (junk/wrong type).
   → `control.*`, `malformed.*`

## Confirmation criteria
- The malformed response matches a stack-trace / framework-error signature (Traceback,
  `File "...", line N`, a Java `Exception`, a PHP `Fatal error ... on line N`) that the
  control does not.

## False-positive criteria
- The malformed input returns a generic 4xx error with no server internals.

## Evidence requirements
- `control.*` and `malformed.*`, plus the leaked error excerpt.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "INFO-DISCLOSURE"`, `status`,
  `endpoint`, `method`, `parameter`, and `evidence` file refs.
