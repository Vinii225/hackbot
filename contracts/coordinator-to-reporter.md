# Contract: Coordinator → Reporter

```json
{
  "to": "reporter",
  "target": "target-example",
  "findings": [
    "targets/target-example/findings/F-001.json",
    "targets/target-example/findings/F-002.json"
  ],
  "include_open_hypotheses": true,
  "state_paths": {
    "reports_dir": "targets/target-example/reports/"
  }
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `findings` | yes | Files to consider. Reporter includes only `status: confirmed`. |
| `include_open_hypotheses` | no | If true, add a clearly-labeled appendix of unconfirmed items. |
| `state_paths` | yes | Where to write `REPORT.md`. |

The Reporter must drop any finding whose evidence files do not exist, even if the JSON
says `confirmed`.
