# Schema: Finding

Produced by Vuln-Hunter. One file per finding: `findings/F-<id>.json`.

```json
{
  "id": "F-001",
  "hypothesis_id": "H-001",
  "class": "IDOR",
  "status": "confirmed | unconfirmed | false-positive",
  "endpoint": "/api/user/2",
  "method": "GET",
  "parameter": "id",
  "severity": "critical | high | medium | low | info",
  "payload": "id=2 (other user's object)",
  "proof": "Response B contained user carlos's email, returned to user wiener's session.",
  "evidence": {
    "dir": "findings/evidence/F-001/",
    "files": ["request-a.http", "response-a.http", "request-b.http", "response-b.http"],
    "timings": null
  },
  "false_positive_reason": null,
  "tested_at": "2026-10-30T18:00:00Z",
  "requests_used": 4
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | `F-NNN`. |
| `hypothesis_id` | yes | Links back to the hypothesis. |
| `class` | yes | Vuln class. |
| `status` | yes | `confirmed` requires non-empty `evidence.files` on disk. |
| `severity` | yes when confirmed | Reporter uses this to order findings. |
| `payload` | yes when confirmed | The confirming payload / id swap. |
| `proof` | yes when confirmed | One line naming the evidence that proves it. |
| `evidence` | yes when confirmed | Files must actually exist under `evidence.dir`. |
| `false_positive_reason` | yes when `false-positive` | Which FP criterion matched. |
| `timings` | for blind CMDI | baseline / control / injected seconds. |

**Hard rule:** `status: "confirmed"` is INVALID unless the listed evidence files exist on
disk. The Coordinator rejects a confirmed finding with no evidence and forces it back to
`unconfirmed`.
