"""Frozen publication inputs; no application or filesystem effects."""
from pathlib import Path
from evidence_common import decode
def cases():return decode((Path(__file__).resolve().parents[1]/"DOMAIN.json").read_bytes())["cases"]
def group(name):
    result=[q for q in cases()if q["group"]==name]
    if not result:raise ValueError("undeclared fixed publication domain")
    return result
