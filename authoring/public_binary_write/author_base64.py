#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Derive current strict padding from the retained HIA codec and real CPython."""
from pathlib import Path
import argparse
import copy
import json
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "hepta", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    sys.path.insert(0, str(root / "authoring/public_publication_v1"))
    import source_support as support
    api = support.tools(args.hepta.resolve(strict=True))
    original = (root / "runtime_support/binary_write/source/parent/dependency/native/binary_base64_decode.hepta").read_bytes()
    before = api[3](original).as_dict()
    old = {f["name"]:f for f in before["functions"]}
    support.require(len(old) == 19 and list(old) == ["f"+str(i) for i in range(19)], "complete original codec layout differs")
    names = {"entry":"f0", "load":"f1", "put":"f2", "utf8":"f3", "value":"f4",
             "decode":"f5", "error":"f10", "retained_error":"f19"}
    seed = copy.deepcopy(before)
    retained = copy.deepcopy(old["f10"])
    retained["name"] = "f19"
    seed["functions"].append(retained)
    message = b"Excess padding not allowed"
    pseudo = (root / "authoring/public_binary_write/base64_current.pseudo").read_text()
    pseudo += "\ndef excess_padding(o:mutbuf,at:u64) -> u64:\n"
    pseudo += "".join(f"    store(o,at+{i},{byte})\n" for i,byte in enumerate(message))
    pseudo += f"    return at+{len(message)}\n"
    raw, names, proof = support.compile_delta(api, api[4](seed).encode(), names, pseudo,
        {"RESULT":3544386040927240776}, before["module"])
    after = api[3](raw).as_dict()
    current = {f["name"]:f for f in after["functions"]}
    for name in old:
        if name not in {"f5", "f10"}:
            support.require(old[name] == current[name], "retained codec function changed: " + name)
    retained = copy.deepcopy(current["f19"]); retained["name"] = "f10"
    support.require(retained == old["f10"], "complete old error formatter inverse differs")
    inverse = copy.deepcopy(after)
    inverse["functions"] = [old[f["name"]] if f["name"] in {"f5", "f10"} else f
                            for f in inverse["functions"] if f["name"] in old]
    support.require(api[4](inverse).encode() == original, "whole original codec inverse differs")
    proof.update(schema="hepta.runtime.public-binary-write.current-base64.v1", aliases=names,
                 baseline=support.identity(original), changed_functions=["f5", "f10"],
                 retained_original_functions=17, complete_original_entry_retained=True,
                 whole_original_inverse=True, reference_profile="CPython 3.14.10 strict base64 string",
                 reference_url="https://github.com/python/cpython/blob/v3.14.10/Modules/binascii.c",
                 runtime_python_required=False, filesystem_effect_order_changed=False,
                 actual_reference_compared=False, public_binary_write_registered=False)
    output = args.output.absolute(); output.mkdir(parents=True, exist_ok=False)
    (output / "public_binary_base64_decode.hepta").write_bytes(raw)
    (output / "public_binary_base64_decode_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps(dict(source=support.identity(raw), functions=len(after["functions"])), sort_keys=True))


if __name__ == "__main__":
    main()
