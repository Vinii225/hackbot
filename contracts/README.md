# Agent Output Contracts

Agents communicate through **structured messages**, never arbitrary prose. Every message
is JSON (for machine state) described here. The Coordinator validates each message against
its contract before acting on it.

Message flow:

```
Coordinator → Recon        coordinator-to-recon.md
Recon       → Coordinator  recon-to-coordinator.md
Coordinator → Vuln-Hunter  coordinator-to-vuln-hunter.md
Vuln-Hunter → Coordinator  vuln-hunter-to-coordinator.md
Coordinator → Reporter     coordinator-to-reporter.md
Reporter    → Coordinator  reporter-to-coordinator.md
```

Shared object schemas:
- `hypothesis.schema.md` — what Recon emits, what Vuln-Hunter consumes.
- `finding.schema.md` — what Vuln-Hunter emits, what Reporter consumes.

Golden rule: a **hypothesis** (`hypothesis.schema.md`) is a guess; a **confirmed finding**
(`finding.schema.md` with `status: "confirmed"`) requires captured evidence. The two are
never interchangeable.
