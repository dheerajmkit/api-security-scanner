# api-security-scanner

Audits OpenAPI specifications (JSON) for common API security gaps:
endpoints with no authentication, sensitive fields in responses,
plaintext servers, and missing rate limiting. Day 2 adds live
endpoint probing to verify auth is actually enforced.

This is a **personal portfolio project** exploring API security
analysis and security automation. It is a learning exercise, not a
production tool, and it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py samples/petstore-openapi.json
```

Exit codes: `2` = usage error or unreadable spec, `1` = at least one
high finding, `0` = no high findings.

## Day-1 scope

- OpenAPI 3.x JSON loading (paths, operations, servers, schemas).
- Checks: unauthenticated operations, sensitive response fields
  (passwords, SSNs, card numbers, tokens), plaintext server URLs,
  missing 429 rate-limit responses, missing operationIds.
- Text and JSON (`--json`) findings reports with severity counts.
