# Runbook — PortSwigger IDOR lab (coop)

Step-by-step for the first real end-to-end run. Use **coop** mode so you approve each
request before it is sent.

## 1. Prereqs
- A started PortSwigger "Insecure direct object references" lab (or any access-control
  lab) — copy its URL from the lab page.
- The Claude Code CLI available on PATH (the default llm executor shells out to `claude`).

## 2. Fill scope
Edit `scope.md`:
- tick the authorization box,
- paste your lab URL under **In scope** (replace `REPLACE-ME`),
- keep `wiener / peter` unless the lab differs.

## 3. Dry-check the prompts (optional, no cost)
```
python -m orchestrator targets/portswigger-idor --print-prompts
```
Confirms the scope URL and task look right before any model call.

## 4. Run in coop
Via the Markdown workflow (recommended for the first run):
```
/hackbot-coop portswigger-idor "Find and confirm IDOR in the lab"
```
or via the programmatic runner with the LLM executor:
```
python -m orchestrator targets/portswigger-idor --executor llm --mode coop \
  --objective "Find and confirm IDOR in the lab"
```
Approve each phase: recon → review hypotheses → approve the IDOR test → review the finding
→ approve reporting.

## 5. Fast path (deterministic, no LLM)
If the lab's shape matches `/api/user/{id}`-style access (many do), you can confirm it
with the deterministic executor instead of the LLM — same code path proven in
`tests/test_e2e_idor.py`. Adapt the endpoint/accounts to the lab and drive
`orchestrator.http_exec.HttpIdorExecutors` (see that test for the exact call).

## 6. Output
- Confirmed finding: `findings/F-001.json`
- Raw evidence: `findings/evidence/F-001/` (baseline + cross-user request/response)
- Report: `reports/REPORT.md`

## Notes / expectations
- This is the first live exercise of the **LLM** executor; watch the recon/hunt steps and
  be ready to correct the endpoint it targets. The deterministic IDOR path (step 5) is
  already validated end-to-end against a local fixture.
- Stays strictly in `scope.md`. If the lab URL is still the placeholder, the loop stops
  immediately (by design).
