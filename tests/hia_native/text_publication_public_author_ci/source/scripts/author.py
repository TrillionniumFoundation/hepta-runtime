#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Generate a route/catalog increment over one fixed shared WAIT predecessor."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_support as support
import inherited_catalog
import frontend_author
import catalog_author
from callable_common import syntax, require, encoded, decode, pin

def run(source, hepta, output):
    source = source.resolve(strict=True)
    hepta = hepta.resolve(strict=True)
    require(not output.exists(), "fresh author destination required")
    output.mkdir(parents=True)
    source_identity = syntax(source)
    inputs = decode((source / "INPUTS.json").read_bytes())
    baseline = {}
    for name, expected in inputs["base_files"].items():
        path = source / "baseline" / name
        raw = path.read_bytes()
        require(pin(path) == {k: expected[k] for k in ("bytes", "sha256")},
                "complete author predecessor differs: " + name)
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                == expected["git_blob"], "predecessor Git object differs")
        baseline[name] = raw
    binding = decode(baseline["native/runtime_mcp_sources.json"])
    require(binding["sources"]["native/runtime_mcp.hepta"]
            == support.identity(baseline["native/runtime_mcp.hepta"]), "WAIT frontend source binding differs")
    for name, raw in baseline.items():
        if name != "native/runtime_mcp_sources.json":
            require(binding["sources"][name] == support.identity(raw), "fixed graph source binding differs: " + name)
    for asset_name in ("authoring/public_extract/catalog_assets/ASSETS.json",
                       "authoring/public_mixed_opener/catalog_assets/ASSETS.json"):
        asset = decode(baseline[asset_name])
        root = str(Path(asset_name).parent) + "/"
        for path, expected in asset["files"].items():
            if root + path in baseline:
                require(support.identity(baseline[root + path]) == expected, "actual native asset differs")
    readonly = decode(baseline["authoring/public_extract/catalog_assets/READONLY.json"])
    require(readonly["status"] == "PASS" and readonly["before"] == readonly["after"]
            and len(readonly["probes"]) == 12 and all(x["denied"] for x in readonly["probes"]),
            "retained full native metadata admission differs")
    require(readonly["native_executions"] == readonly["rust_executions"] == readonly["reader_writes"] == 0,
            "retained metadata custody changed")
    api = support.tools(hepta)
    front, front_proof = frontend_author.generate(api, baseline, support,
        (source / "scripts/frontend.pseudo").read_text())
    catalog, catalog_proof = catalog_author.generate(api, baseline, support, inherited_catalog)
    combined = {**front, **catalog}
    require(len(combined) == 6, "generated output inventory differs")
    for name, raw in sorted(combined.items()):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    result = dict(status="PUBLICATION_ROUTE_AND_CATALOG_SOURCE_ONLY_PASS",
        source=source_identity, baseline_commit=inputs["baseline_commit"],
        baseline_binding=inputs["base_files"]["native/runtime_mcp_sources.json"],
        generated={name: support.identity(raw) for name, raw in combined.items()},
        frontend=front_proof, catalog=catalog_proof, engine_edited=False,
        shared_wait_semantics_qualified=False, native_executed=False, rust_executed=False,
        public_qualified=False, full_async=False, installed=False)
    (output / "AUTHOR.json").write_bytes(encoded(result))
    print(json.dumps(result, sort_keys=True))
    return result

def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "hepta", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    run(args.source, args.hepta, args.output)
if __name__ == "__main__":
    main()
