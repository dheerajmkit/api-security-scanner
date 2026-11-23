"""Live endpoint probing: verify auth is actually enforced.

For each operation that declares no security, request the endpoint
without credentials. A 200 means the endpoint is genuinely public;
401/403 means auth is enforced. Anything else is inconclusive and
produces no finding. Network failures are reported, not hidden.
"""

import re
import urllib.request
import urllib.error

from .checks import METHODS, _operation_security


def _concrete_path(path):
    return re.sub(r"\{[^}]+\}", "1", path)


def probe_endpoint(base_url, path, timeout=10):
    """GET one endpoint without auth; return the HTTP status or None."""
    url = base_url.rstrip("/") + _concrete_path(path)
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError, ValueError):
        return None


def probe_spec(spec, base_url, timeout=10):
    """Probe unauthenticated operations; return findings + errors."""
    findings = []
    errors = []
    for path, item in (spec.get("paths") or {}).items():
        for method, operation in item.items():
            if method.lower() not in METHODS or not isinstance(operation, dict):
                continue
            if _operation_security(spec, operation):
                continue
            status = probe_endpoint(base_url, path, timeout=timeout)
            label = f"{method.upper()} {path}"
            if status is None:
                errors.append(f"{label}: unreachable")
            elif status == 200:
                findings.append({
                    "check": "endpoint-public", "severity": "HIGH",
                    "object": label,
                    "message": f"{label} returns 200 without authentication",
                })
            elif status in (401, 403):
                pass  # Auth enforced — the spec is accurate.
    return findings, errors
