#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Normalize only a direct result's independently checked seven-field stat."""
from pathlib import Path
import json,stat
from common import require,sha
from wire_versions import BODY_KEYS,version
def body(raw,parameters,case,final_files,reader):
    require(type(raw) is bytes,"complete direct result bytes")
    value=json.loads(raw)
    require(type(value) is dict and set(value)==BODY_KEYS,"whole direct publication result")
    require(set(parameters)=={"path","mode","content","expected_sha256"}
        and parameters["mode"]=="create" and parameters["expected_sha256"]=="absent",
        "the complete unchanged direct lifecycle parameters")
    require(value["path"]==parameters["path"],"result belongs to admitted direct input")
    relative=Path(parameters["path"]).relative_to(case["root"]).as_posix()
    found=[r for r in final_files if r["path"]==relative]
    require(len(found)==1 and found[0]["kind"]=="file","one actual resulting file")
    row=found[0];s=row["stat"];data=reader.get(row["data"])
    require(stat.S_ISREG(s["mode"]) and s["nlink"]==1 and data==parameters["content"].encode()
        and len(data)==s["size"]==value["bytes"] and sha(data)==value["sha256"],"all published file bytes")
    require(value["mode"]=="create" and value["published"] is True and value["was_new_file"] is True
        and value["same_path_atomic_publication"] is True
        and value["external_writers_transactionally_excluded"] is False,"complete publication flags")
    exact=version(s);require(value["version"]==exact and type(value["version"]) is str,
        "all seven returned version fields equal actual stat")
    needle=b'"version":"'+exact.encode("ascii")+b'"'
    require(raw.count(needle)==1,"one exact complete JSON version token")
    normalized=raw.replace(needle,b'"version":"<actual-seven-field-stat>"',1)
    return normalized,dict(path=relative,version=exact,actual_stat={k:s[k] for k in
        ("dev","ino","size","mtime_ns","ctime_ns")},whole_result_sha256=sha(raw),
        normalized_sha256=sha(normalized),whole_file_sha256=sha(data))
