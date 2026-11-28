"""Lossless evidence JSON, preserving all fields and integer precision."""
import json
def encoded(value):
    # No application response uses this evidence-only representation.
    return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
