# Skill: Insecure Deserialization

Operational playbook. Confirm whether a serialized object supplied by the client is trusted,
so a forged type/role field escalates privileges. Non-destructive: forge one benign type
marker; never craft gadget chains or code-execution payloads.

## Trigger conditions
IF a hypothesis has class `DESERIAL` AND an endpoint accepts a serialized object (base64/JSON).

## Procedure
1. Send a benign serialized object (control).
2. Send the same object with a privileged type forged (e.g. `__class__: AdminSession`).

## Confirmation criteria
- The forged type is honored (privileged response) where the control was not.

## False-positive criteria
- The type field is ignored; authority is resolved server-side.

## Evidence requirements
- `control.*` and `inject-object.*`.

## Output
- Finding JSON with `class: "DESERIAL"`, `status`, `endpoint`, `method`, `parameter`, `payload`.
