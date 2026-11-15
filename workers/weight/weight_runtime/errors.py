"""Typed errors and strict JSON primitives shared by both transports."""
import hashlib
import json
import math
import re


class WeightError(Exception):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code, self.message, self.details = code, message, details or {}

    def as_dict(self):
        return {"code": self.code, "message": self.message, "details": self.details}


def need(condition, code, message, **details):
    if not condition:
        raise WeightError(code, message, details)


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "INVALID_JSON", "Duplicate JSON key", key=key)
        result[key] = value
    return result


def _constant(value):
    raise WeightError("NONFINITE", "Non-finite JSON number", {"value": value})


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        _constant(value)
    return result


def loads(value):
    try:
        return json.loads(value, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except (ValueError, UnicodeError) as exc:
        raise WeightError("INVALID_JSON", str(exc)) from exc


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def number(value, name):
    need(type(value) in (int, float) and math.isfinite(value), "NONFINITE", "Expected finite number", field=name)
    return float(value)


def integer(value, name, low=0, high=2**63 - 1):
    need(type(value) is int and low <= value <= high, "INVALID_ARGUMENT", "Integer outside allowed range", field=name, minimum=low, maximum=high)
    return value


def identifier(value, name="id"):
    need(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value), "INVALID_ARGUMENT", "Invalid identifier", field=name)
    return value


def checksum(value, name="sha256"):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "INVALID_ARGUMENT", "Expected SHA256 hex digest", field=name)
    return value
