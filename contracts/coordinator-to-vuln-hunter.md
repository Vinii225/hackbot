# Contract: Coordinator → Vuln-Hunter

```json
{
  "to": "vuln-hunter",
  "target": "target-example",
  "skill": "idor | cmdi",
  "hypothesis": {
    "id": "H-001",
    "endpoint": "/api/user/{id}",
    "method": "GET",
    "parameter": "id",
    "class": "IDOR",
    "confidence": "medium",
    "reason": "Client-controlled numeric id"
  },
  "scope_summary": "In scope: https://LAB.web-security-academy.net (host only).",
  "credentials": [
    { "role": "user", "username": "wiener", "password": "peter" },
    { "role": "victim", "object_hint": "carlos" }
  ],
  "limits": { "max_requests": 50 },
  "state_paths": {
    "findings_dir": "targets/target-example/findings/",
    "tested": "targets/target-example/state/tested.json"
  }
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `skill` | yes | Must match an existing skill directory. |
| `hypothesis` | yes | A single object from `hypotheses.json`. |
| `scope_summary` | yes | Hosts the hunter may touch. |
| `credentials` | no | Accounts/object hints for the test. |
| `limits` | yes | Per-task request budget. |
| `state_paths` | yes | Where to write the finding + ledger. |

If `skill` has no matching skill file, Vuln-Hunter returns `unconfirmed`
(`reason: "no skill for class"`).
