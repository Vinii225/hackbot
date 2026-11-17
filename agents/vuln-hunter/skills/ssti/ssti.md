# Skill: Server-Side Template Injection (SSTI)

Operational playbook. Confirm whether a parameter is embedded into a server-side template
that evaluates it as an expression. Non-destructive: probe only with a self-contained math
expression; never read files, call engine builtins, or chain to RCE to "prove" it.

## Trigger conditions
IF a hypothesis has class `SSTI`
AND a parameter is plausibly rendered by a template engine (name, greeting, subject,
title, message, body, preview, content, template).

## Required inputs
- `endpoint`, `method`, the `parameter`.

## Procedure
1. Pick two random three-digit integers `a`, `b` and compute `product = a*b` locally.
2. Send a literal control (a plain token with no template syntax). → `control-literal.*`
3. Send the same arithmetic wrapped in each common engine's delimiters, stopping at the
   first that evaluates: `{{a*b}}` (Jinja2/Twig), `${a*b}` (FreeMarker/EL),
   `#{a*b}` (Thymeleaf), `<%= a*b %>` (ERB/EJS). → `inject-ssti.*`

## Confirmation criteria
- The response to an injection contains `product` (the computed value), and the literal
  control does not. The expression was evaluated server-side.

## False-positive criteria
- The operands come back but `product` does not — the payload was reflected literally or
  HTML-encoded, not evaluated. (Output encoding can still hide XSS while the template
  evaluates; absence of `product` means no evaluation.)

## Evidence requirements
- `control-literal.*` and the confirming `inject-ssti.*`.
- Record the exact payload, the engine delimiters that worked, and the observed `product`.

## Safety
- Arithmetic proof only. Do NOT escalate to config/file reads, sandbox escapes, or command
  execution. One reproducible evaluated expression is enough.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "SSTI"`, `status`, `endpoint`,
  `method`, `parameter`, the confirming `payload`, and `evidence` file refs.
