#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact source inverse and complete input-only domain; no implementations execute."""
from pathlib import Path
import ast,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"));sys.path.insert(0,str(ROOT))
from common import canonical,decode,pin,require,source_evidence,sha
import check_source
def check():
    source=source_evidence(ROOT)
    original=decode((ROOT/"RETAINED_RECOVERY_SOURCE_MANIFEST.json").read_bytes())
    require(pin(ROOT/"RETAINED_RECOVERY_SOURCE_MANIFEST.json")==dict(bytes=8947,
        sha256="c825ab0f81fbc39b3620884570933c312b52249e5bcadf663ece0e104b9fb32a"),
        "exact original source recovery manifest")
    for row in original["files"]:
        path=ROOT/row["path"]
        require(pin(path)=={k:row[k] for k in ("bytes","sha256")},"unchanged original source "+row["path"])
    transforms=decode((ROOT/"TRANSFORMS.json").read_bytes())
    require(transforms["retained_source"]=="24ae71cb3c017269d3c82d44b4ba5476fee17045"
        and set(transforms["transforms"])=={"recipe/capture_native.py","recipe/read_current.py"},
        "only two derived original source files")
    proofs={}
    for name,row in transforms["transforms"].items():
        before=(ROOT/row["before"]).read_text();after=(ROOT/name).read_text();value=before
        require(pin(ROOT/row["before"])=={k:row["before_pin"][k] for k in ("bytes","sha256")}
            and pin(ROOT/name)=={k:row["after_pin"][k] for k in ("bytes","sha256")},"exact source transform pins")
        for old,new in row["edits"]:
            require(value.count(old)==1,"one exact before source seam");value=value.replace(old,new)
        require(value==after,"whole derived source text and complete inverse")
        old_tree=ast.parse(before);new_tree=ast.parse(after)
        old_functions={n.name:ast.dump(n,include_attributes=False) for n in old_tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        new_functions={n.name:ast.dump(n,include_attributes=False) for n in new_tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        changed=[n for n in old_functions if old_functions[n]!=new_functions[n]]
        require(set(old_functions)==set(new_functions)
            and changed==(["execute"] if name.endswith("capture_native.py") else ["read"]),
            "all other actual functions and full case loops retain original AST")
        proofs[name]=dict(before=row["before_pin"],after=row["after_pin"],changed_functions=changed)
    original_check=check_source.check()
    for path in sorted(ROOT.rglob("*.py")):compile(path.read_bytes(),str(path),"exec")
    result=dict(status="CURRENT124_ORDINARY_COMPLETE_SOURCE_PASS",source=source,transforms=proofs,
        original_input_check=original_check,native_executed=False,rust_executed=False,
        ordinary_native_cases=686,retained_original_cases=686)
    return result
if __name__=="__main__":print(json.dumps(check(),sort_keys=True))
