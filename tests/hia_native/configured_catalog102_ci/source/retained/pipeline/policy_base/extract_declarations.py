"""Export only actual raw Tool declarations and original classification lists.

Expected handler outputs are deliberately excluded from this author input.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
PROFILES = ("disabled", *(str(i) for i in range(8)))
ALLOWED = ("raw_tool_wires", "runtime_tool_names", "weight_tool_names", "hia_tool_names")

def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()

def extract(evidence: Path, destination: Path):
    selected = None
    records = {}
    for profile in PROFILES:
        relative = f"processes/profile-{profile}.stdout"
        raw = (evidence / relative).read_bytes()
        observation = json.loads(raw)
        assert observation["target_commit"] == TARGET
        current = {key: observation[key] for key in ALLOWED}
        if selected is None:
            selected = current
        assert current == selected, "declarations differ between original configurations"
        records[relative] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    tools = [json.loads(wire) for wire in selected["raw_tool_wires"]]
    names = [tool["name"] for tool in tools]
    assert len(names) == 136 and names == sorted(set(names))
    assert all(isinstance(tool["inputSchema"], dict) for tool in tools)
    for key in ALLOWED[1:]:
        values = selected[key]
        assert len(values) == len(set(values)) and all(name in names for name in values)
    asset = {"schema": "hepta.runtime.catalog-declarations.v1", "target_commit": TARGET, **selected}
    raw_input = ("[" + ",".join(selected["raw_tool_wires"]) + "]").encode()
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "declarations.json").write_bytes(encode(asset))
    (destination / "catalog-input.json").write_bytes(raw_input)
    return {"schema": "hepta.runtime.catalog-declarations-extraction.v1", "target_commit": TARGET,
        "observations": records, "exported_fields": list(ALLOWED), "tools": len(names),
        "input_bytes": len(raw_input), "input_sha256": hashlib.sha256(raw_input).hexdigest(),
        "asset_sha256": hashlib.sha256(encode(asset)).hexdigest(),
        "expected_handler_outputs_exported": False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    receipt = extract(args.evidence, args.destination)
    args.receipt.write_bytes(encode(receipt))
    print(json.dumps(receipt, sort_keys=True))

if __name__ == "__main__":
    main()
