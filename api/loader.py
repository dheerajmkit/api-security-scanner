"""Load OpenAPI specifications (JSON)."""

import json


def load_spec(path):
    """Load an OpenAPI JSON file; return the spec dict."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "paths" not in data:
        raise ValueError("spec must be an OpenAPI object with a paths map")
    return data
