# Skill: Server-Side Includes (SSI) Injection

Operational playbook. Confirm whether an SSI directive in user input is executed by the
server. Non-destructive: a benign `echo` directive only; never `#exec cmd` with a real
command beyond echoing a marker.

## Trigger conditions
IF a hypothesis has class `SSI` AND a page renders user input through an includes parser.

## Procedure
1. Submit `<!--#exec cmd="echo <marker>"-->`.

## Confirmation criteria
- The marker appears in the response AND the directive text was consumed (executed).

## False-positive criteria
- The directive is reflected as inert, escaped text (not executed).

## Evidence requirements
- `inject-ssi.*` showing the rendered output.

## Output
- Finding JSON with `class: "SSI"`, `status`, `endpoint`, `method`, `parameter`, `payload`.
