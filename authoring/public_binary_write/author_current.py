#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Preserve the actual current CPython open/NUL literal in both write owners."""
from pathlib import Path
import argparse
import copy
import json
import sys

sys.dont_write_bytecode = True
OLD = b"embedded null byte"
CURRENT = b"open: embedded null character in path"


def literal(name, raw):
    lines = [f"def {name}(w:mutbuf,at:u64) -> u64:"]
    lines += [f"    store(w,at+{index},{value})" for index, value in enumerate(raw)]
    lines += [f"    return at+{len(raw)}"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "hepta", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    source = root / "runtime_support/binary_write/source/parent"
    sys.path.insert(0, str(root / "authoring/public_publication_v1"))
    import source_support as support
    api = support.tools(args.hepta.resolve(strict=True))
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    owners = [("binary_parent_owner", "native", "literal_null"),
              ("binary_write_body", "dependency/native", "literal_embedded")]
    results = {}
    for name, folder, alias in owners:
        original = (source / folder / (name + ".hepta")).read_bytes()
        composition = json.loads((source / folder / (name + "_composition.json")).read_bytes())
        aliases = composition["aliases"]
        before = api[3](original).as_dict()
        recreated, _, _ = support.compile_delta(api, original, aliases, literal(alias, OLD), {}, before["module"])
        support.require(recreated == original, "whole original literal source reproduction differs: " + name)
        raw, names, proof = support.compile_delta(api, original, aliases, literal(alias, CURRENT), {}, before["module"])
        after = api[3](raw).as_dict()
        old_functions = {f["name"]: f for f in before["functions"]}
        changed = [f["name"] for f in after["functions"] if f != old_functions.get(f["name"])]
        support.require(changed == [aliases[alias]], "nonliteral application logic changed: " + name)
        inverse = copy.deepcopy(after)
        inverse["functions"] = [old_functions[f["name"]] if f["name"] in changed else f
                                for f in inverse["functions"]]
        support.require(api[4](inverse).encode() == original, "whole original source inverse differs: " + name)
        proof.update(schema="hepta.runtime.public-binary-write.current-open-error.v1",
                     aliases=names, baseline=support.identity(original),
                     old_message=OLD.decode(), current_message=CURRENT.decode(),
                     changed_functions=changed, retained_functions=len(before["functions"]) - 1,
                     whole_original_reproduced=True, whole_body_inverse=True,
                     reference_profile="Actual CPython 3.14.10 Linux os.open path converter",
                     effect_order_changed=False, public_binary_write_registered=False)
        (output / ("public_" + name + ".hepta")).write_bytes(raw)
        (output / ("public_" + name + "_composition.json")).write_bytes(support.ENCODE(proof))
        results[name] = {"source": support.identity(raw), "changed_functions": changed,
                         "retained_functions": len(before["functions"]) - 1}
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main()
