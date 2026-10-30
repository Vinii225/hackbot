# Contract: Vuln-Hunter → Coordinator

```json
{
  "from": "vuln-hunter",
  "target": "target-example",
  "hypothesis_id": "H-001",
  "skill": "idor",
  "result": {
    "finding_file": "targets/target-example/findings/F-001.json",
    "status": "confirmed | unconfirmed | false-positive",
    "severity": "high",
    "evidence_dir": "targets/target-example/findings/evidence/F-001/",
    "evidence_present": true
  },
  "tested_tuple": { "endpoint": "/api/user/2", "method": "GET", "technique": "idor-id-swap" },
  "requests_used": 4,
  "notes": "wiener session read carlos's account via id swap."
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `finding_file` | yes | Must exist and conform to `finding.schema.md`. |
| `status` | yes | One of the three classes. |
| `evidence_present` | yes | Must be `true` whenever `status: confirmed`. |
| `tested_tuple` | yes | Written to `tested.json` for dedupe. |
| `requests_used` | yes | Added to the engagement counter. |

Coordinator rejects `status: "confirmed"` with `evidence_present: false` and records the
finding as `unconfirmed` instead.
