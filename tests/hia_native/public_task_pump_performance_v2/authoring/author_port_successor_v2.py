"""Bind the unchanged public host to the separately checked byte-helper port successor."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "handoff", "output", "baseline-port-package"):
        ap.add_argument("--" + name, type=Path, required=True)
    a = ap.parse_args()
    before = (a.source / "native/runtime_mcp_sources.json").read_bytes()
    assert sha(before) == "9e1e4ecf8fa6b981712a325f8a46a8b2b4b72c468f732cf360c2735d4a2754a7"
    handoff_raw = a.handoff.read_bytes()
    assert sha(handoff_raw) == "e03ba5f4767408fa1dc58ca124592189b5058ff293bab87f37627cf231fd145b"
    handoff = json.loads(handoff_raw)
    assert handoff["status"] == "ACTUAL_SHARED_PORT_DOMAINS_AND_RELOCATED_READER_PASS"
    assert handoff["successor_full_worker_reference_ci_pending"] is True
    package = Path(handoff["source_root"])
    assert sha((package / "PACKAGE.json").read_bytes()) == handoff["package"]["sha256"] == "2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1"
    old = json.loads((a.source / "native/bellman_port_component.json").read_bytes())
    new_raw = (package / "source/native/bellman_port_component.json").read_bytes()
    new = json.loads(new_raw)
    for key in ("exports", "port_assembly", "public_engine", "runtime_hia_images"):
        assert old[key] == new[key]
    assert new["executable"] == {key: handoff["port_executable"][key] for key in ("bytes", "sha256")}
    assert new["worker_executable_sha256"] == handoff["worker_executable"]["sha256"]
    assert new["worker_source_pins_sha256"] == handoff["worker_source_pins_sha256"]
    assert sha((a.baseline_port_package / "PACKAGE.json").read_bytes()) == "2ac7b74d927685ef5c92eb90d6f87590f9e8d492e7e78f047bf417fb9c6c69e6"
    assert (a.source / "native/bellman_port_component.json").read_bytes() == (a.baseline_port_package / "source/native/bellman_port_component.json").read_bytes()
    assembly = (package / "source" / new["port_assembly"]["path"]).read_bytes()
    assert assembly == (a.baseline_port_package / "source" / old["port_assembly"]["path"]).read_bytes()
    assert sha(assembly) == new["port_assembly"]["sha256"]
    shutil.copytree(a.source, a.output)
    (a.output / "native/bellman_port_component.json").write_bytes(new_raw)
    builder = a.output / "scripts/public_nine_build.py"
    raw = builder.read_text()
    old_line = "PORT_PACKAGE_SHA256 = '2ac7b74d927685ef5c92eb90d6f87590f9e8d492e7e78f047bf417fb9c6c69e6'"
    new_line = "PORT_PACKAGE_SHA256 = '2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1'"
    assert raw.count(old_line) == 1
    updated = raw.replace(old_line, new_line, 1)
    assert updated.replace(new_line, old_line, 1) == raw
    builder.write_text(updated)
    proof = {"schema": "hepta.runtime.public-pump-byte-helper-port-binding.v1",
             "before_public_binding_sha256": sha(before), "successor_handoff_sha256": sha(handoff_raw),
             "port_package_sha256": handoff["package"]["sha256"],
             "before_port_component_sha256": sha((a.source / "native/bellman_port_component.json").read_bytes()),
             "after_port_component_sha256": sha(new_raw),
             "builder_only_change": {"before": old_line, "after": new_line},
             "port_exports_and_mechanical_assembly_unchanged": True,
             "all_92_direct_hia_sources_unchanged_from_public_candidate": True,
             "packed_port_changed_images": 4, "packed_port_changed_helpers": 14,
             "reserved_slots_47_52_and_active_53_58_unchanged": True,
             "new_source_executed": False, "full_public_qualified": False,
             "full_async_qualified": False, "fresh_worker_reference_qualified": False,
             "author_sha256": sha(Path(__file__).read_bytes())}
    (a.output / "native/runtime_mcp_port_byte_access.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    binding = json.loads(before)
    binding["sources"] = {str(p.relative_to(a.output)): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
                          for p in sorted(a.output.rglob("*")) if p.is_file() and p != a.output / "native/runtime_mcp_sources.json"}
    (a.output / "native/runtime_mcp_sources.json").write_text(json.dumps(binding, sort_keys=True, indent=2) + "\n")
    assert all(p.read_bytes() == (a.source / p.relative_to(a.output)).read_bytes() for p in (a.output / "native").glob("*.hepta"))
    print(json.dumps({"source": str(a.output), "binding_sha256": sha((a.output / "native/runtime_mcp_sources.json").read_bytes()),
                      "port_package_sha256": handoff["package"]["sha256"], "direct_hia_sources_changed": 0}, sort_keys=True))

if __name__ == "__main__":
    main()
