"""Security checks over OpenAPI specifications."""

METHODS = ("get", "put", "post", "delete", "options", "head", "patch",
           "trace")

SENSITIVE_FIELDS = ("password", "passwd", "ssn", "social_security",
                    "credit_card", "card_number", "cvv", "api_key",
                    "secret", "token", "private_key")


def _sensitive_fields(schema, seen=None):
    """Yield sensitive property names found anywhere in a schema."""
    if not isinstance(schema, dict):
        return
    props = schema.get("properties") or {}
    for name, subschema in props.items():
        if any(marker in name.lower() for marker in SENSITIVE_FIELDS):
            yield name
        yield from _sensitive_fields(subschema)
    for key in ("items", "additionalProperties"):
        if key in schema:
            yield from _sensitive_fields(schema[key])
    for subs in schema.get("allOf") or []:
        yield from _sensitive_fields(subs)


def _operation_security(spec, operation):
    if "security" in operation:
        return operation["security"]
    return spec.get("security")


def check_operation(spec, path, method, operation):
    """Return findings for one operation."""
    label = f"{method.upper()} {path}"
    findings = []
    security = _operation_security(spec, operation)
    if not security:
        findings.append({
            "check": "no-auth-required", "severity": "HIGH",
            "object": label,
            "message": f"{label} requires no authentication",
        })
    if not operation.get("operationId"):
        findings.append({
            "check": "missing-operation-id", "severity": "LOW",
            "object": label,
            "message": f"{label} has no operationId",
        })
    responses = operation.get("responses") or {}
    if "429" not in responses:
        findings.append({
            "check": "no-rate-limit", "severity": "MEDIUM", "object": label,
            "message": f"{label} defines no 429 rate-limit response",
        })
    for status, response in responses.items():
        content = (response or {}).get("content") or {}
        for media in content.values():
            schema = (media or {}).get("schema") or {}
            for field in sorted(set(_sensitive_fields(schema))):
                findings.append({
                    "check": "sensitive-data-exposed", "severity": "HIGH",
                    "object": label,
                    "message": f"{label} returns sensitive field '{field}' "
                               f"(HTTP {status})",
                })
    return findings


def check_spec(spec):
    """Return all findings for an OpenAPI spec."""
    findings = []
    for server in spec.get("servers") or []:
        url = server.get("url", "")
        if url.startswith("http://"):
            findings.append({
                "check": "plaintext-server", "severity": "HIGH",
                "object": url,
                "message": f"server URL {url} is plaintext HTTP",
            })
    for path, item in (spec.get("paths") or {}).items():
        for method, operation in item.items():
            if method.lower() in METHODS and isinstance(operation, dict):
                findings.extend(
                    check_operation(spec, path, method, operation))
    return findings
