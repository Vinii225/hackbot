# Skill: GraphQL Introspection Exposure

Operational playbook. Confirm whether a GraphQL endpoint answers an introspection query,
disclosing its full schema. Non-destructive: one read-only introspection query; never run
mutations or batched abuse.

## Trigger conditions
IF a hypothesis has class `GRAPHQL`
AND an endpoint looks like a GraphQL API (graphql, graphiql, gql).

## Required inputs
- `endpoint`, `method` (POST).

## Procedure
1. POST a minimal introspection query, e.g. `{__schema{queryType{name} types{name}}}`.
   → `introspection.*`

## Confirmation criteria
- A 200 response whose body contains `__schema` — the schema is disclosed to anyone.

## False-positive criteria
- Introspection is disabled or rejected (error mentioning introspection, or 400/403).

## Evidence requirements
- `introspection.*` showing the query and the returned schema (or the rejection).

## Safety
- Introspection is read-only. Do NOT enumerate or call mutations; schema disclosure is the
  finding.

## Output
- Finding JSON (`contracts/finding.schema.md`) with `class: "GRAPHQL"`, `status`,
  `endpoint`, `method`, and `evidence` file refs.
