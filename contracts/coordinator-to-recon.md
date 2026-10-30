# Contract: Coordinator → Recon

```json
{
  "to": "recon",
  "target": "target-example",
  "objective": "Map attack surface and produce hypotheses focused on IDOR and CMDI.",
  "scope_summary": "In scope: https://LAB.web-security-academy.net (host only).",
  "credentials": [
    { "role": "user", "username": "wiener", "password": "peter" }
  ],
  "focus": ["idor", "cmdi"],
  "limits": { "max_requests": 200 },
  "state_paths": {
    "recon_dir": "targets/target-example/recon/",
    "state": "targets/target-example/state/state.json"
  }
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `target` | yes | Target directory name under `targets/`. |
| `objective` | yes | Plain objective for the recon pass. |
| `scope_summary` | yes | Copied from `scope.md`; the only hosts allowed. |
| `credentials` | no | Only if authorized recon is requested. |
| `focus` | no | Bias hypotheses toward these classes. |
| `limits` | yes | At least `max_requests`. |
| `state_paths` | yes | Where to write outputs. |

Recon must not act outside `scope_summary`.
