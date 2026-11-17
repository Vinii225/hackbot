# Contributing

Hackbot is an orchestrated harness for **authorized** web security testing only. Every
change keeps the test suite green under `-W error::DeprecationWarning` and respects scope
safety (checks never leave the authorized target; probes are non-destructive).

## Run the tests

```
python -m unittest discover -s tests
# CI also runs it warning-clean:
python -W error::DeprecationWarning -m unittest discover -s tests
```

## Adding a vulnerability class

A class is only "supported" when it is wired end-to-end. `tests/test_consistency.py`
enforces this, so complete every step:

1. **Checker** — add `check_<name>` in `orchestrator/checks.py`, decorated with
   `@register("CLASS", ...aliases)`. Return a `CheckResult` with status
   `confirmed` / `false-positive` / `unconfirmed`, a severity and evidence files.
2. **Catalog** — add a `CLASS_META` entry (title, cwe, owasp, severity) and a
   `REMEDIATION` entry in `orchestrator/catalog.py`; add any lowercase/alias names.
3. **Recon hints** — add a hint set and a generation loop in `orchestrator/recon.py`
   so the class is discovered autonomously.
4. **Fixtures** — add a **vulnerable** and a **safe** endpoint to
   `tests/fixtures/mock_lab.py`, plus a discovery link/form in `INDEX_HTML`.
5. **Skill playbook** — `agents/vuln-hunter/skills/<class-lower>/<class-lower>.md`.
6. **Config** — enable `<class-lower>` in `targets/target-example/state/config.json`
   (`allowed_skills` and `focus`).
7. **Test** — `tests/test_<name>.py` with: checker confirms on the vulnerable endpoint,
   reports false-positive on the safe endpoint, and the class is found autonomously.

### Invariants to preserve

- A **confirmed** finding needs real evidence from the emulated target; a safe endpoint
  must come back **false-positive**, never confirmed.
- New fixture endpoints must not add confirmed findings to unrelated class runs
  (return JSON where an HTML reflection would create a false XSS, keep parameters off the
  shared hint sets unless intended, etc.).
- No third-party dependencies — standard library only.

## Commits

Small, focused PRs based on `main`. Keep CI green.
