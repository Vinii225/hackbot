# Schema: Hypothesis

A guess produced by Recon. NOT a vulnerability. Stored in `recon/hypotheses.json` (array).

```json
{
  "id": "H-001",
  "endpoint": "/api/user/{id}",
  "method": "GET",
  "parameter": "id",
  "hypothesis": "IDOR",
  "class": "IDOR",
  "confidence": "low | medium | high",
  "reason": "Human-readable justification grounded in observed recon data.",
  "evidence_refs": ["recon/surface.json#/endpoints/3", "recon/raw/me.http"],
  "status": "open | routed | tested"
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | Unique, `H-NNN`. |
| `endpoint` | yes | Path, may contain `{placeholder}`. |
| `method` | yes | HTTP method. |
| `parameter` | no | The suspicious parameter, if any. |
| `hypothesis` / `class` | yes | Vuln class, e.g. `IDOR`, `CMDI`, `XSS`… |
| `confidence` | yes | `low` / `medium` / `high`. |
| `reason` | yes | Must cite concrete observed data. |
| `evidence_refs` | no | Pointers to recon artifacts. |
| `status` | yes | Lifecycle; Coordinator updates it. |

Rules:
- Neutral language only. Never "vulnerable", always "possible/candidate".
- `class` must be set so the Coordinator can select a skill.
