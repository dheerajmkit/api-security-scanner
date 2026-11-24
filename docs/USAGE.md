# Usage

## Auditing a spec

```bash
python3 run.py spec.json
python3 run.py spec.json --json   # machine-readable output
```

Exit code `1` means at least one HIGH finding; `0` means none;
`2` means the file could not be read or parsed.

## Live probing

```bash
python3 run.py spec.json --probe https://api.acme.example/v1
```

Operations that declare no security are requested without
credentials. A 200 proves the endpoint is public; 401/403 confirms
auth is enforced. Path parameters are replaced with `1`.
Unreachable endpoints are reported as notes on stderr, not findings.

## Findings

| Check | Severity | Meaning |
|---|---|---|
| no-auth-required | HIGH | operation declares no security |
| sensitive-data-exposed | HIGH | response schema contains a sensitive field |
| plaintext-server | HIGH | server URL is plaintext HTTP |
| endpoint-public | HIGH | endpoint returns 200 without auth |
| no-rate-limit | MEDIUM | operation defines no 429 response |
| missing-operation-id | LOW | operation has no operationId |

Sensitive field names: password, passwd, ssn, social_security,
credit_card, card_number, cvv, api_key, secret, token, private_key.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```
