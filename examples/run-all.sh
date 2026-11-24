#!/bin/sh
# Audit the sample spec, then run the tests.
set -e
cd "$(dirname "$0")/.."
python3 run.py samples/petstore-openapi.json || true
python3 -m unittest discover -s tests -v
