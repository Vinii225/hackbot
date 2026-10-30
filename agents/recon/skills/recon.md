# Skill: Recon

Operational playbook for mapping an authorized target's attack surface.
Stay inside `scope.md`. Count every HTTP request toward `limits.max_requests`.

## Inputs required
- `target`, in-scope base URL(s), optional `credentials`, `focus` list, `limits`.

## Procedure

### 1. Fingerprint the stack
IF given an in-scope base URL
THEN fetch the root and a few known pages with headers:
`curl -s -i -D - <url> -o /dev/null`
THEN record: `Server`, `X-Powered-By`, `Set-Cookie` (names/flags), CSP and other
security headers, framework hints in HTML/cookies, visible CMS/API markers.
THEN write `recon/tech.json`.

### 2. Map the application
THEN enumerate linked pages/forms from the HTML you fetched (do not brute force unless
`scope.md` allows it).
THEN for each page record: path, HTTP methods seen, parameters (query/body), forms
(action + fields), redirects, and any **object identifiers** (numeric/UUID ids in URLs,
hidden fields, JSON).
THEN if `credentials` are provided, authenticate and repeat as an authenticated user,
noting which functionality requires auth.
THEN write `recon/surface.json`.

### 3. Analyze JavaScript
THEN fetch each in-scope JS file referenced by the pages.
THEN extract: endpoint strings, API routes, parameter names, `fetch`/`XHR` calls,
GraphQL operations, interesting function names, object-id patterns, and any client-side
security checks (role flags, `isAdmin`, hidden toggles).
THEN write `recon/js.json`.

### 4. Form hypotheses
THEN for each suspicious surface, create a hypothesis:
- client-controlled object id → `IDOR`
- parameter whose value could reach a shell/OS command (ping, dns, filename, export,
  format conversion, feedback-to-email host) → `CMDI`
- (other classes → record as hypothesis even if no skill exists yet)
THEN give each a `confidence` (`low|medium|high`) and a concrete `reason`.
THEN write `recon/hypotheses.json` (array).

## Decision rules
- Only record what you observed. No invented endpoints/params.
- A hypothesis is a guess, never a confirmation. Use neutral language.
- If the base URL is unreachable or out of scope → stop and report to Coordinator.

## Evidence requirements
- Save raw response headers/bodies you relied on under `recon/raw/` when useful, and
  reference them from the JSON via `evidence_refs`.

## Output (contract: recon-to-coordinator.md)
- `recon/tech.json`, `recon/surface.json`, `recon/js.json`, `recon/hypotheses.json`
- Return summary: counts of endpoints, params, JS files, and hypotheses by class.
