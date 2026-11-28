# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Frozen original input objects; no expected responses or execution results."""
from pathlib import Path
import copy
from common import canonical,decode,require
ROOT=Path(__file__).resolve().parents[1]
def expanded(value):
    if isinstance(value,dict):
        if set(value)=={"$u64"}:
            result=int(value["$u64"])
            require(0<=result<1<<64,"frozen u64 input")
            return result
        if set(value)=={"$repeat"}:
            text,count=value["$repeat"]
            require(type(text)is str and type(count)is int and 0<=count<=2_000_000,"frozen repeat input")
            return text*count
        return {key:expanded(item)for key,item in value.items()}
    if isinstance(value,list):return [expanded(item)for item in value]
    return value
def groups(folder):
    result=copy.deepcopy(decode((ROOT/"DOMAIN.json").read_bytes())["groups"])
    seen=set()
    for group in result:
        if group["config"]is not None:
            group["config"]["state_dir"]=str(Path(folder).absolute()/group["name"]/"state")
        for row in group["cases"]:
            require(row["case_id"]not in seen,"duplicate frozen input identity");seen.add(row["case_id"])
            row["raw_json"]=canonical(expanded(row.pop("params"))).decode().rstrip("\n")
    return result
def encoded(group):return canonical(group)
