"""Verify actual serial authority artifacts, complete captures and Rust replay.

This module supplies no runtime authority and executes no semantic fallback.
Captured observations remain distinct from mandatory new qualification.
"""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import gzip
import hashlib
import json
import re
import struct
import tomllib

from hia_native_build import HEPTA_COMMIT
from hia_native_authority_layout import validate_authority_layout
from hia_native_entropy_qualification import completion, digest, inspect_elf, native_receipt, object_at, read

FOLDER = "caller-authority-rust-oracle"
SPECS = (
    ("caller-authority", "native/caller_authority.hepta", 1, 456, 8 << 20, 8 << 20, 16 << 20),
    ("operation-record", "native/operation_record.hepta", 1, 28, 8 << 20, 2 << 20, 3 << 20),
    ("operation-kdf", "native/operation_kdf.hepta", 0, 0, 8 << 20, 128, 2048),
    ("binary-codec", "native/binary_codec.hepta", 0, 0, 8 << 20, 128, 1184),
    ("operation-aead", "native/operation_aead.hepta", 0, 0, 8 << 20, 1048640, 512),
    ("operation-nonce", "native/operation_nonce.hepta", 0, 0, 164, 64, 1576960),
    ("operation-scope", "native/operation_scope.hepta", 1, 166, 8 << 20, 2 << 20, 3 << 20),
    ("system-entropy", "native/entropy_policy.hepta", 4, 0, 24, 128, 1024),
    ("authority-loader", "native/authority_loader.hepta", 8, 0, 131095, 4096, 262144),
)
ORIGINAL_PINS = {
    "src/main.rs": "c7d92845ca693e192a878a340d7532accdef99ebe77fdb6853d2fba269b0020e",
    "src/mcp/runtime/caller_scope.rs": "8013904df0fbe9e0aa5a44bf4e1c77a6ea9a273de06fe365078f81fd40a4254c",
    "src/mcp/runtime/caller_scope_tests.rs": "77ccf054de81a644a3dc1245fffd7ce840853137205f33d93ab7c023088af950",
    "src/mcp/runtime/operation_crypto.rs": "a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633",
    "src/mcp/runtime/search_jobs.rs": "d24a8e03a636cc0ed570fed36ea4d4505c285ddc3e963053c2496f683c127537",
    "Cargo.lock": "7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43",
    "Cargo.toml": "377e7dca547f0ff0d832fb28cf01862a6d84b4b6ed42c8b36dae9075cbbbb78f",
}
PROFILE_SHA = "927cb5e16d8c3fcb9f4d61dc00c4aa48ae09592fec8e28cb2ba3deb4b0950b92"
PACKER_SHA = "c54c54f664944b7a243d8e8e3d10e2ba623ab7e8e4f4189962542722617969d0"
PROVENANCE_SHA = "9683325f1ab64d1e675ab12b967959944d579fcc28a4a18bde0c602317a354e1"
PROBE_PACKER_SHA = "feb13a0ecefdf07abbcff1016270bdbaaf7b4d9e0bde9440a8129c56f3659fda"
VECTOR_SHA = "98e5da67f5b463bc57a0706f6f3c06fe49254603d8ecd455dfb0c8c259551e38"
ORACLE_SOURCES = (
    "tests/hia_native/oracle_caller_authority.rs", "tests/hia_native/authority_oracle/Cargo.toml",
    "tests/hia_native/authority_oracle/Cargo.lock", "tests/hia_native/authority_oracle/build.rs",
    "tests/hia_native/authority_oracle/original_access.rs", "tests/hia_native/authority_oracle/crypto_access.rs",
)
CONTROLLER_SOURCES = ("test_caller_authority.py", "authority_native_harness.py")
KERNEL_SOURCES = ("test_authority_loader_kernel.py", "authority_loader_supervisor.py")
TRANSPORT_SOURCES = ("test_authority_transport.py", "authority_backend_supervisor.py",
                     "authority_loader_supervisor.py", "authority_native_harness.py", "authority_wire_vectors.json.gz")
PACKER_SOURCES = ("native/authority_packer.hepta", "native/authority_profile.json", "native/authority_packer_provenance.json",
                  "scripts/hia_native_authority_build.py", "scripts/hia_native_authority_layout.py",
                  "tests/hia_native/test_authority_packer.py", "tests/hia_native/authority_native_harness.py")
CONTROLLER_COUNTS = {"native_entries": [333, 0, 18, 95, 0, 15, 77, 84, 164], "native_public_requests": 112,
    "native_lifecycle_calls": 23, "native_contexts": 20, "synthetic_entropy_contexts": 20,
    "synthetic_ack_controls": 1, "fixture_os_effects": 133, "trusted_extension_fixture_transfers": 2,
    "original_rust_replays": 0}
KERNEL_COUNTS = {"processes": 110, "token_processes": 103, "owner_processes": 7,
    "kernel_supervised_processes": 26, "controlled_fault_processes": 23,
    "injected_errno_completions": 18, "injected_zero_completions": 2, "actual_fixture_mutations": 5,
    "original_owner_calls": 0, "native_owner_calls": 110}
TRANSPORT_COUNTS = {"processes": 48, "frames_sent": 144, "responses": 143, "original_wire_comparisons": 78,
    "known_private_binding_comparisons": 11, "kernel_supervised_processes": 17,
    "kernel_fault_processes": 14, "new_original_rust_calls": 0}
PACKER_COUNTS = {"native_packer_calls": 30, "valid_native_packs": 1, "capacity_refusals": 2,
    "profile_refusals": 16, "image_pin_refusals": 11, "cached_build_checks": 8, "cached_build_refusals": 6,
    "arbitrary_checkout_processes": 2, "arbitrary_checkout_native_requests": 1}
EVIDENCE_COUNTS = {"accepted_evidence_objects": 8, "mutation_refusals": 37,
    "rehashed_loaded_image_refusals": 2, "new_native_calls": 0, "new_original_calls": 0}
EVIDENCE_SOURCES = ("scripts/hia_native_authority_qualification.py", "tests/hia_native/test_authority_evidence.py",
                   "tests/hia_native/authority_receipt_fixture.json.gz", "tests/hia_native/authority_native_harness.py")
SUITES = (
    ("test_caller_authority.py", "HIA_AUTHORITY_TEST_REPORT", "controller.json", 8, CONTROLLER_COUNTS),
    ("test_authority_loader_kernel.py", "HIA_AUTHORITY_KERNEL_CORPUS_DIR", "kernel/kernel-report.json", 5, KERNEL_COUNTS),
    ("test_authority_transport.py", "HIA_AUTHORITY_TRANSPORT_CORPUS_DIR", "transport/transport-report.json", 6, TRANSPORT_COUNTS),
    ("test_authority_packer.py", "HIA_AUTHORITY_PACKER_REPORT", "packer.json", 4, PACKER_COUNTS),
    ("test_authority_evidence.py", "HIA_AUTHORITY_EVIDENCE_REPORT", "evidence.json", 7, EVIDENCE_COUNTS),
)


def require(condition, message):
    if not condition:
        raise ValueError("authority evidence: " + message)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def same(actual, expected, message):
    require(json_bytes(actual) == json_bytes(expected), message)


def sha(path):
    return digest(read(path))


def hex_digest(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def integer(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def hex_bytes(value, maximum=8 << 20):
    require(type(value) is str and len(value) % 2 == 0 and len(value) <= maximum * 2
            and re.fullmatch("[0-9a-f]*", value) is not None, "noncanonical or oversized hex bytes")
    return bytes.fromhex(value)


def source_pins(root):
    paths = {row[1] for row in SPECS} | set(ORIGINAL_PINS) | set(ORACLE_SOURCES) | set(PACKER_SOURCES)
    paths.update({"scripts/hia_native_authority_qualification.py", "scripts/hia_native_authority_probe_build.py",
                  "scripts/hia_native_entropy_qualification.py", "scripts/hia_native_build.py",
                  "scripts/hia_native_loader.py", "tests/hia_native/authority_loader_probe_packer.hepta",
                  "tests/hia_native/scope_entropy_fixture.hepta", "rustfmt.toml"})
    paths.update("tests/hia_native/" + name for name in (*CONTROLLER_SOURCES, *KERNEL_SOURCES, *TRANSPORT_SOURCES))
    paths.update(EVIDENCE_SOURCES)
    result = {name: sha(root / name) for name in sorted(paths)}
    require(all(result[name] == expected for name, expected in ORIGINAL_PINS.items()), "original owner baseline differs")
    return result


def suite_report(root, report, *, schema, tests, counts, sources):
    completion(report, tests)
    require(report.get("schema") == schema and report.get("counts_match") is True,
            "suite schema or strict completion differs")
    same(report.get("counts"), counts, "suite count coverage differs")
    same(report.get("expected_counts"), counts, "suite expected count declaration differs")
    same(report.get("sources"), {name: sha(root / name) for name in sources}, "suite source identity differs")


def test_sources(root, names):
    return {name: sha(root / "tests/hia_native" / name) for name in names}


def _record_file(artifacts, path, base):
    artifacts[path.relative_to(base).as_posix()] = sha(path)


def compilation_context(build_root, compiler_sha256):
    bootstrap = object_at(build_root / "bootstrap/bootstrap.json")
    require(bootstrap.get("schema") == "hepta.runtime.native-bootstrap.v1"
            and bootstrap.get("qualification") == "development_fixed_point"
            and bootstrap.get("generation_sha256") == compiler_sha256,
            "compiler bootstrap identity or qualification differs")
    dependency = bootstrap.get("dependency")
    require(type(dependency) is dict and dependency.get("commit") == HEPTA_COMMIT,
            "compiler dependency commit differs")
    for label in ("B1", "B2", "B3"):
        require(sha(build_root / ("bootstrap/" + label + ".image.bin")) == compiler_sha256,
                "compiler fixed point image differs")
    return read(build_root / "bootstrap/B3.image.bin"), dependency


def _compiled(root, build_root, source_name, name, source, image, compiler, dependency, artifacts):
    folder = build_root / "modules" / name
    manifest = object_at(folder / "manifest.json")
    expected = {"schema": "hepta.runtime.native-module.v1", "name": name,
        "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1", "target": "linux-x86_64",
        "compiler_commit": HEPTA_COMMIT, "compiler_sha256": digest(compiler),
        "source": name + ".hepta", "source_sha256": digest(source), "image": "module.image.bin",
        "image_sha256": digest(image), "input_capacity": 8 << 20, "output_capacity": 8 << 20,
        "workspace_capacity": 32 << 20, "qualification": "development_fixed_point", "standalone": None}
    same(manifest, expected, "actual compiled module manifest differs")
    require(source == read(root / source_name) == read(folder / (name + ".hepta"))
            and read(folder / "module.input.bin") == source and read(folder / "module.image.bin") == image,
            "compiled source/input/image bytes differ")
    receipt = object_at(folder / "module.receipt.json")
    native_receipt(receipt, image=compiler, source=source, output=read(folder / "module.output.bin"), produced=image)
    require(receipt.get("produced_sha256") == digest(image) and receipt.get("produced_bytes") == len(image),
            "compiler product receipt differs")
    same(object_at(folder / "build.json"), {"compile_receipt": receipt,
        "compiler_dependency": dependency, "whole_runtime_replaced": False}, "compiler build receipt differs")
    for item in ("manifest.json", name + ".hepta", "module.input.bin", "module.output.bin",
                 "module.image.bin", "module.receipt.json", "build.json"):
        _record_file(artifacts, folder / item, build_root)


def composition_artifacts(root, build_root, manifest, compiler_sha256):
    compiler, dependency = compilation_context(build_root, compiler_sha256)
    metadata = object_at(manifest)
    require(manifest.parent.parent == build_root / "composition", "composition escaped its retained build")
    expected = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64",
        "transport": "newline-hex-typed-header-qualification", "compiler_commit": HEPTA_COMMIT,
        "compiler_sha256": compiler_sha256, "executable": "native-authority.elf",
        "runtime_python_required": False, "runtime_libc_required": False, "whole_runtime_replaced": False}
    same({key: metadata.get(key) for key in expected}, expected, "composition contract differs")
    profile = object_at(root / "native/authority_profile.json")
    provenance = object_at(root / "native/authority_packer_provenance.json")
    require(sha(root / "native/authority_profile.json") == PROFILE_SHA
            and sha(root / "native/authority_packer_provenance.json") == PROVENANCE_SHA
            and sha(root / "native/authority_packer.hepta") == PACKER_SHA
            and profile.get("compiler_commit") == HEPTA_COMMIT
            and profile.get("compiler_sha256") == compiler_sha256, "fixed native profile or compiler differs")
    table = [{"id": i, "name": name, "source_sha256": sha(root / source), "flags": flags, "call_mask": mask,
              "input_capacity": inp, "output_capacity": out, "workspace_capacity": work}
             for i, (name, source, flags, mask, inp, out, work) in enumerate(SPECS)]
    same(metadata.get("profile"), table, "nine-image capabilities differ")
    require(type(metadata.get("members")) is list and len(metadata["members"]) == 9,
            "packed member count differs")
    rows = [("packer", "native/authority_packer.hepta", metadata.get("packer"))]
    rows += [(f"module_{i:02d}", spec[1], metadata["members"][i]) for i, spec in enumerate(SPECS)]
    frame = bytearray(b"HIABND01" + struct.pack("<3Q", 9, 0, 0))
    artifacts, images = {}, []
    for position, (stem, source_name, row) in enumerate(rows):
        require(type(row) is dict and row.get("manifest") == stem + ".json", "packed member path differs")
        path = manifest.parent / (stem + ".json")
        child = object_at(path)
        source, image = read(manifest.parent / (stem + ".hepta")), read(manifest.parent / (stem + ".image.bin"))
        require(sha(path) == row.get("manifest_sha256") and source == read(root / source_name)
                and digest(source) == row.get("source_sha256") == child.get("source_sha256")
                and digest(image) == row.get("image_sha256") == child.get("image_sha256"),
                "packed actual source/image bytes differ")
        contract = {"schema": "hepta.runtime.native-module.v1", "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1",
            "target": "linux-x86_64", "compiler_commit": HEPTA_COMMIT, "compiler_sha256": compiler_sha256,
            "source": stem + ".hepta", "image": stem + ".image.bin", "input_capacity": 8 << 20,
            "output_capacity": 8 << 20, "workspace_capacity": 32 << 20, "standalone": None}
        same({key: child.get(key) for key in contract}, contract, "copied module ABI differs")
        _compiled(root, build_root, source_name, "composition-" + digest(source)[:24],
                  source, image, compiler, dependency, artifacts)
        for name in (stem + ".json", stem + ".hepta", stem + ".image.bin"):
            _record_file(artifacts, manifest.parent / name, build_root)
        if position:
            item = table[position - 1]
            same(profile["members"][position - 1], {**item, "source": source_name,
                "image_sha256": digest(image), "image_bytes": len(image)}, "fixed image pin differs")
            images.append(image)
            frame.extend(struct.pack("<8Q", len(image), item["input_capacity"], item["output_capacity"],
                                     item["workspace_capacity"], item["flags"], item["call_mask"], 0, 0))
            frame.extend(bytes.fromhex(digest(source) + digest(image)) + image)
    executable = read(manifest.parent / "native-authority.elf")
    layout = validate_authority_layout(executable, frame, profile, provenance)
    key = digest((json.dumps({"compiler": compiler_sha256, "members": table, "packer": PACKER_SHA},
                             indent=2, sort_keys=True) + "\n").encode())
    require(metadata.get("key") == key == manifest.parent.name and metadata.get("frame_sha256") == digest(frame)
            and metadata.get("frame_bytes") == len(frame) and metadata.get("executable_sha256") == digest(executable),
            "packing frame/key/executable identity differs")
    same(metadata.get("inspection"), inspect_elf(executable), "static executable inspection differs")
    same(metadata.get("packing"), {"owner": "HIA", "input_unchanged": True, "buffer_canaries_unchanged": True,
         "packer_image_sha256": metadata["packer"]["image_sha256"]}, "packing ownership differs")
    if "layout" in metadata:
        same(metadata["layout"], layout, "recorded exact embedded layout differs")
    for name in ("manifest.json", "native-authority.elf"):
        _record_file(artifacts, manifest.parent / name, build_root)
    return {"status": "PASS", "manifest_sha256": sha(manifest), "executable_sha256": digest(executable),
        "compiler_image_sha256": compiler_sha256, "compiler_commit": HEPTA_COMMIT,
        "source_sha256": table[0]["source_sha256"], "image_sha256": digest(images[0]),
        "loader_source_sha256": table[8]["source_sha256"], "loader_image_sha256": digest(images[8]),
        "profile_sha256": PROFILE_SHA, "packer_sha256": PACKER_SHA, "profile": table,
        "embedded_layout": layout, "artifact_sha256": artifacts}


def probe_artifacts(root, build_root, manifest, compiler_sha256):
    compiler, dependency = compilation_context(build_root, compiler_sha256)
    metadata = object_at(manifest)
    require(manifest.parent.parent == build_root / "authority-loader-probe", "loader fixture escaped its build")
    expected = {"schema": "hepta.runtime.authority-loader-probe.v1", "target": "linux-x86_64",
        "transport": "trusted-startup-argv-u32-fixture-result", "compiler_sha256": compiler_sha256,
        "compiler_commit": HEPTA_COMMIT, "executable": "authority-loader-probe.elf",
        "policy_manifest": "policy.json", "packer_manifest": "packer.json", "maximum_startup_bytes": 131095,
        "maximum_result_bytes": 4096, "workspace_bytes": 262144, "runtime_python_required": False,
        "runtime_libc_required": False, "qualification_fixture": True, "publishes_owned_fixture_bytes": True,
        "registered_mcp_tool": False, "production_activated": False, "whole_runtime_replaced": False}
    same({key: metadata.get(key) for key in expected}, expected, "loader fixture contract differs")
    sources = {"policy": "native/authority_loader.hepta", "packer": "tests/hia_native/authority_loader_probe_packer.hepta"}
    require(sha(root / sources["packer"]) == PROBE_PACKER_SHA, "loader fixture packer differs")
    artifacts, images = {}, {}
    for kind, source_name in sources.items():
        source = read(root / source_name)
        child = object_at(manifest.parent / (kind + ".json"))
        image = read(manifest.parent / (kind + ".image.bin"))
        require(read(manifest.parent / (kind + ".hepta")) == source
                and metadata.get(kind + "_manifest_sha256") == sha(manifest.parent / (kind + ".json"))
                and metadata.get(kind + "_source_sha256") == child.get("source_sha256") == digest(source)
                and metadata.get(kind + "_image_sha256") == child.get("image_sha256") == digest(image),
                "loader fixture actual source/image differs")
        contract = {"source": kind + ".hepta", "image": kind + ".image.bin", "compiler_commit": HEPTA_COMMIT,
                    "compiler_sha256": compiler_sha256, "input_capacity": 8 << 20,
                    "output_capacity": 8 << 20, "workspace_capacity": 32 << 20, "standalone": None}
        same({key: child.get(key) for key in contract}, contract, "loader fixture child ABI differs")
        _compiled(root, build_root, source_name, "authority-loader-" + kind + "-" + digest(source)[:16],
                  source, image, compiler, dependency, artifacts)
        for name in (kind + ".json", kind + ".hepta", kind + ".image.bin"):
            _record_file(artifacts, manifest.parent / name, build_root)
        images[kind] = image
    require(manifest.parent.name == digest(read(root / sources["policy"]) + read(root / sources["packer"])),
            "loader fixture directory key differs")
    executable = read(manifest.parent / expected["executable"])
    require(metadata.get("executable_sha256") == digest(executable), "loader fixture ELF hash differs")
    same(metadata.get("inspection"), inspect_elf(executable), "loader fixture static ELF differs")
    frame = b"HIALODP1" + struct.pack("<Q", len(images["policy"])) + images["policy"]
    require(read(manifest.parent / "pack.input.bin") == frame, "loader fixture pack input differs")
    native_receipt(metadata["pack_receipt"], image=images["packer"], source=frame,
                   output=read(manifest.parent / "pack.output.bin"), produced=executable)
    same(object_at(manifest.parent / "pack.receipt.json"), metadata["pack_receipt"], "packing receipts disagree")
    for name in ("manifest.json", expected["executable"], "pack.input.bin", "pack.output.bin", "pack.receipt.json"):
        _record_file(artifacts, manifest.parent / name, build_root)
    return {"status": "PASS", "manifest_sha256": sha(manifest), "executable_sha256": digest(executable),
        "loader_source_sha256": metadata["policy_source_sha256"], "loader_image_sha256": digest(images["policy"]),
        "packer_source_sha256": metadata["packer_source_sha256"], "packer_image_sha256": digest(images["packer"]),
        "artifact_sha256": artifacts, "qualification_fixture": True}


def direct_loaded_evidence(root, observation, *, authority=None, scope=None, scope_sha256=None):
    require(type(observation) is dict and observation.get('schema') == 'hepta.runtime.authority.loaded-fixture.v1'
            and observation.get('authority_profile_sha256') == PROFILE_SHA and observation.get('fixture_entropy') is True
            and hex_digest(observation.get('fixture_scope_manifest_sha256')), 'direct native fixture identity is missing')
    require(sha(root / 'native/authority_profile.json') == PROFILE_SHA, 'current authority profile differs')
    profile = object_at(root / 'native/authority_profile.json')
    rows = observation.get('members')
    require(type(rows) is list and len(rows) == 9, 'direct native image inventory differs')
    keys = ('id', 'name', 'source_sha256', 'flags', 'call_mask', 'input_capacity', 'output_capacity', 'workspace_capacity')
    expected = [{key: row[key] for key in keys} for row in profile['members']]
    expected[7] = {'id': 7, 'name': 'scope-entropy-fixture', 'flags': 0, 'call_mask': 0,
        'input_capacity': 48, 'output_capacity': 128, 'workspace_capacity': 128,
        'source_sha256': 'cf33465aa3e26fde3e7c28d092f566000d2e0e01eb824cfbc4bf8f9325b23675'}
    require(sha(root / 'tests/hia_native/scope_entropy_fixture.hepta') == expected[7]['source_sha256'],
            'direct native entropy fixture source differs')
    for index, row in enumerate(rows):
        require(type(row) is dict and set(row) == {'id', 'manifest_sha256', 'source_sha256', 'image_sha256', 'image_bytes',
                'compiler_commit', 'compiler_sha256', 'effective_profile'}, 'direct native image observation fields differ')
        same(row['effective_profile'], expected[index], 'direct native effective buffer/call profile differs')
        image_sha = 'e7fd77ba95a5f8ad13de09e1e06455437002b8305b5533b4f9ba9d7a97ed632d' if index == 7 else profile['members'][index]['image_sha256']
        require(type(row['id']) is int and row['id'] == index and row['source_sha256'] == expected[index]['source_sha256']
                and row['image_sha256'] == image_sha and integer(row['image_bytes'], 1, 1 << 20)
                and row['compiler_commit'] == HEPTA_COMMIT and row['compiler_sha256'] == profile['compiler_sha256']
                and hex_digest(row['manifest_sha256']), 'direct native source/image/compiler differs')
        if index != 7:
            require(row['image_bytes'] == profile['members'][index]['image_bytes'], 'direct native image length differs')
        else:
            require(row['image_bytes'] == 22396, 'direct native fixture image length differs')
        if authority is not None and index in (0, 8):
            require(row['manifest_sha256'] == authority['members'][index]['manifest_sha256'],
                    'direct root/loader manifest differs from the qualified executable owner')
        if scope is not None and 1 <= index <= 7:
            wanted = scope['members'][index]
            same({key: row[key] for key in ('source_sha256', 'image_sha256', 'manifest_sha256')},
                 {key: wanted[key] for key in ('source_sha256', 'image_sha256', 'manifest_sha256')},
                 'direct fixture leaf differs from the independently qualified fixture scope')
    if scope_sha256 is not None:
        require(observation['fixture_scope_manifest_sha256'] == scope_sha256,
                'direct native calls used a different fixture scope manifest')
    return observation


def controller_evidence(root, directory):
    metadata = object_at(directory / "native-corpus.json")
    packed = read(directory / "authority_cases.jsonl.gz")
    require(0 < len(packed) <= 1 << 20, "controller gzip is outside its declared bound")
    raw = gzip.decompress(packed)
    expected = {"schema": "hepta.runtime.caller-authority.native-corpus.v1", "rows": 122,
        "adapter_only_rows": 2, "source_sha256": sha(root / "native/caller_authority.hepta"),
        "raw_bytes": 16804536, "raw_sha256": "0fb2139e283d23c148a257c0967f93bc064a2ed2e3d8130455243ea7adf9886f",
        "gzip_bytes": len(packed), "gzip_sha256": digest(packed),
        "output_sha256": "36b5d9939cd3dc6de512115d4819caec68c3604d72e1067d2d20f2ae825b8ba8",
        "original_rust_replay_status": "PENDING"}
    same({k: metadata.get(k) for k in expected}, expected, "controller corpus domain or claim differs")
    require(len(raw) == expected["raw_bytes"] and digest(raw) == expected["raw_sha256"],
            "complete controller input corpus differs")
    report = metadata.get("native_report")
    suite_report(root / "tests/hia_native", report, schema="hepta.runtime.caller-authority.native-tests.v1",
                 tests=8, counts=CONTROLLER_COUNTS, sources=CONTROLLER_SOURCES)
    require(report.get("synthetic_entropy_fixture") is True and report.get("production_http_transport") is False
            and type(report.get("rust_corpus_rows")) is int and report["rust_corpus_rows"] == 122,
            "controller fixture or comparison claim differs")
    loaded = direct_loaded_evidence(root, report.get("loaded_artifacts"))
    controls = [{"context": 2, "reason": "test_capacity_refusal_keeps_bound_owner_and_bad_ack_retires",
                 "selected_before_startup": True},
                {"context": 3, "reason": "test_capacity_refusal_keeps_bound_owner_and_bad_ack_retires",
                 "selected_before_startup": True},
                {"context": 18, "reason": "test_serialized_fields_cannot_create_or_reload_authority",
                 "selected_before_startup": True}]
    same(metadata.get("predetermined_control_contexts"), controls, "native-only contexts were not predeclared")
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) == 122 and all(type(row) is dict for row in rows), "controller rows differ")
    counts = Counter(row.get("operation") for row in rows)
    same(dict(counts), {"start": 17, "request": 100, "replace_verified_extension": 1,
                       "restore_verified_extension": 1, "shutdown": 2, "reconnect": 1},
         "controller complete lifecycle domain differs")
    require(sum(row.get("adapter_only") is True for row in rows) == 2
            and all(row.get("context") not in (2, 3, 18) for row in rows),
            "native-only rows leaked into the original domain")
    output = bytearray()
    for row in rows:
        require(integer(row.get("code"), 0, 0xffffffff), "controller code is not exact u32")
        value = hex_bytes(row.get("output_hex"))
        output.extend(struct.pack("<IQ", row["code"], len(value)) + value)
    require(digest(output) == expected["output_sha256"], "controller complete result bytes differ")
    return {"status": "PASS", "gzip_bytes": len(packed), "gzip_sha256": digest(packed),
        "raw_bytes": len(raw), "raw_sha256": digest(raw), "output_sha256": digest(output),
        "rows": 122, "adapter_only_rows": 2, "counts": CONTROLLER_COUNTS,
        "native_entries": sum(CONTROLLER_COUNTS["native_entries"]), "native_contexts": 20,
        "original_domain_rows": 120, "private_adapter_control_rows": 2,
        "predetermined_native_only_contexts": controls, "synthetic_entropy_fixture": True,
        "loaded_artifacts": loaded, "new_original_rust_calls": 0,
        "files": {name: sha(directory / name) for name in ("native-corpus.json", "authority_cases.jsonl.gz")}}


def logical_loader_trace(case):
    events = []
    for row in case["trace"]["events"]:
        item = {key: row[key] for key in ("action", "effect", "flags", "errno") if key in row}
        if item == {"action": "read", "effect": "kernel_continue"} and events and events[-1] == item:
            continue
        events.append(item)
    return {"case": case["case"], "kind": case["kind"], "mode": case["supervisor"], "events": events}


def kernel_evidence(root, directory, executable_sha256, *, original=False):
    report = object_at(directory / "kernel-report.json")
    expected_counts = dict(KERNEL_COUNTS)
    if original:
        expected_counts.update(original_owner_calls=110, native_owner_calls=0)
    suite_report(root / "tests/hia_native", report, schema="hepta.runtime.authority-loader.kernel-tests.v1",
                 tests=5, counts=expected_counts, sources=KERNEL_SOURCES)
    backend = "unchanged-original-rust" if original else "native-hia-probe"
    require(report.get("backend") == backend and report.get("normal_random_bytes_compared") is False
            and report.get("whole_runtime_replaced") is False, "kernel backend or claim differs")
    raw = read(directory / "kernel-cases.json")
    require(report.get("cases_sha256") == digest(raw) and report.get("cases_bytes") == len(raw),
            "kernel complete case receipt differs")
    cases = json.loads(raw)
    require(type(cases) is list and len(cases) == 110, "kernel process domain differs")
    fields = ("ordinal", "case", "kind", "fixture", "closed_stderr", "supervisor", "code",
              "output_bytes", "output_hex", "normal_random_bytes_compared")
    domain = [{key: row.get(key) for key in fields} for row in cases]
    domain_sha = digest(json_bytes(domain))
    require(domain_sha == "4533209b16df607da959caa67c430e8fa6a389f052543b6ac427cabf450c0dc2",
            "kernel input/result domain differs")
    counts = Counter({key: 0 for key in expected_counts})
    traces, files, logical = set(), {name: sha(directory / name) for name in
                                    ("kernel-report.json", "kernel-cases.json")}, []
    effects = {"kernel_continue", "injected_errno", "injected_zero_read", "owned_fixture_rewrite",
               "owned_fixture_chmod", "owned_fixture_hardlink", "owned_fixture_replace_path",
               "owned_fixture_replace_after_stat"}
    actions = {"open_token": {257}, "open_owner": {257}, "stat_before": {5, 262, 332},
               "stat_after": {5, 262, 332}, "geteuid": {107}, "read": {0}, "close": {3}}
    for ordinal, case in enumerate(cases, 1):
        require(case["ordinal"] == ordinal and integer(case["code"], 0, 0xffffffff)
                and case["kind"] in ("token", "owner") and type(case["closed_stderr"]) is bool
                and integer(case["output_bytes"], 0, 4096) and hex_digest(case.get("stdout_sha256")),
                "kernel case result fields differ")
        counts.update(processes=1)
        counts[case["kind"] + "_processes"] += 1
        if case["kind"] == "token":
            output = hex_bytes(case["output_hex"], 4096)
            require(len(output) == case["output_bytes"] and
                    digest(struct.pack("<I", case["code"]) + output) == case["stdout_sha256"],
                    "kernel exact returned bytes differ")
        elif case["output_bytes"]:
            require(case["output_bytes"] == 32 and case["code"] == 32
                    and case["output_hex"] is None and case["normal_random_bytes_compared"] is False,
                    "normal random owner bytes must remain unpaired")
        else:
            require(case["output_hex"] is None and case["normal_random_bytes_compared"] is False
                    and digest(struct.pack("<I", case["code"])) == case["stdout_sha256"],
                    "owner refusal status bytes differ")
        require((case["code"] <= 4096 and case["output_bytes"] == case["code"])
                or (case["code"] >= 0xffff0000 and case["output_bytes"] == 0), "kernel refusal published bytes")
        trace = case.get("trace")
        if case["supervisor"] is None:
            require(trace is None, "unsupervised kernel case contains a trace")
            continue
        require(type(trace) is dict and set(trace) == {"schema", "kind", "mode", "events", "executable_sha256",
                "executable_unchanged", "exit_code", "fault_fired", "secondary_fault_fired", "owned_process_reaped"},
                "kernel raw trace fields differ")
        require(trace["schema"] == "hepta.runtime.authority-loader.kernel-trace.v1"
                and trace["kind"] == case["kind"] and trace["mode"] == case["supervisor"]
                and trace["executable_sha256"] == executable_sha256 and trace["executable_unchanged"] is True
                and trace["owned_process_reaped"] is True and type(trace["exit_code"]) is int
                and trace["exit_code"] == 0 and trace["fault_fired"] is (case["supervisor"] != "observe")
                and trace["secondary_fault_fired"] is (case["supervisor"] in ("read_and_close_error", "stat_and_close_error")),
                "kernel owned process, fault or exit identity differs")
        counts.update(kernel_supervised_processes=1, controlled_fault_processes=int(trace["fault_fired"]))
        filename = f"trace-{ordinal:03d}.json"
        same(object_at(directory / filename), trace, "raw and embedded kernel traces differ")
        traces.add(filename)
        files[filename] = sha(directory / filename)
        require(type(trace["events"]) is list and trace["events"], "kernel effects are missing")
        limit, previous_offset = (4098 if case["kind"] == "token" else 32), 0
        for event in trace["events"]:
            require(type(event) is dict and event.get("action") in actions
                    and type(event.get("syscall")) is int and event["syscall"] in actions[event["action"]]
                    and event.get("effect") in effects, "kernel action/syscall/effect differs")
            if not original and event["action"].startswith("stat_"):
                require(event["syscall"] == 5, "native metadata syscall differs")
            if event["action"].startswith("open_"):
                require(event.get("flags") == (0xa0800 if case["kind"] == "token" else 0x80000),
                        "private open flags differ")
            elif event["action"] != "geteuid":
                offset = event.get("descriptor_offset_before")
                require(integer(offset, previous_offset, limit), "descriptor offset is not bounded and monotonic")
                previous_offset = offset
            if event["action"] == "read":
                require(integer(event.get("requested_bytes"), 1, limit - event["descriptor_offset_before"]),
                        "read exceeds its remaining bound")
            if event["effect"] == "injected_errno":
                require(integer(event.get("errno"), 1, 4095), "invalid injected errno")
                counts["injected_errno_completions"] += 1
            elif event["effect"] == "injected_zero_read":
                require(event["action"] == "read", "zero-read effect has another operation")
                counts["injected_zero_completions"] += 1
            elif event["effect"].startswith("owned_fixture_"):
                counts["actual_fixture_mutations"] += 1
        if case["case"] == "bounded-take-4098":
            require(trace["events"][-1].get("action") == "close"
                    and trace["events"][-1].get("descriptor_offset_before") == 4098,
                    "bounded take did not consume exactly its original maximum")
        logical.append(logical_loader_trace(case))
    require({path.name for path in directory.glob("trace-*.json")} == traces, "raw kernel trace inventory differs")
    counts["original_owner_calls" if original else "native_owner_calls"] = len(cases)
    same(dict(counts), expected_counts, "kernel counts do not reconstruct from the complete process domain")
    logical_sha = digest(json_bytes(logical))
    require(logical_sha == "a2ffc04416fcadc5615f4c77875c162a1f0718c2e15776511555bc6325d92781",
            "logical kernel effects, retry/error order or fixed-device custody differs")
    return {"status": "PASS", "backend": backend, "counts": expected_counts,
        "domain_sha256": domain_sha, "logical_trace_sha256": logical_sha,
        "normalized_trace_pairs": len(logical), "executable_sha256": executable_sha256,
        "files": files, "normal_random_bytes_compared": False}



def _header_frame(row):
    headers = row.get("headers")
    require(type(headers) is list and integer(row.get("request_op"), 0, 2), "wire request domain differs")
    payload = hex_bytes(row.get("payload_hex"))
    raw = bytearray(b"HRAUTR01" + struct.pack("<3Q", row["request_op"], len(headers), len(payload)))
    for pair in headers:
        require(type(pair) is list and len(pair) == 2, "wire header pair differs")
        name, value = (hex_bytes(item) for item in pair)
        raw.extend(struct.pack("<2Q", len(name), len(value)) + name + value)
    raw.extend(payload)
    return bytes(raw).hex().encode()


def wire_vectors(root, controller_directory):
    raw = read(root / "tests/hia_native/authority_wire_vectors.json.gz")
    require(digest(raw) == VECTOR_SHA, "retained wire vector bytes differ")
    vectors = json.loads(gzip.decompress(raw))
    require(vectors.get("schema") == "hepta.runtime.authority.wire-vectors.v1"
            and type(vectors.get("contexts")) is list
            and [row.get("source_context") for row in vectors["contexts"]] == [1, 4, 17, 20],
            "wire selection differs")
    rows = [json.loads(line) for line in gzip.decompress(read(controller_directory / "authority_cases.jsonl.gz")).splitlines()]
    expected = {}
    for context in vectors["contexts"]:
        number = context["source_context"]
        selected = [row for row in rows if row.get("context") == number]
        require(len(selected) >= 2 and selected[0].get("operation") == "start"
                and all(row.get("operation") in ("request", "shutdown") for row in selected[1:]),
                "wire vector selected lifecycle differs")
        same(context["startup"], selected[0], "wire startup differs from the complete actual corpus")
        same(context["requests"], [row for row in selected[1:] if row["operation"] == "request"],
             "wire requests differ from the complete actual corpus")
        requests = b"\n".join(_header_frame(row) for row in context["requests"]) + b"\n"
        responses = b"".join((struct.pack("<I", row["code"]) + hex_bytes(row["output_hex"])).hex().encode() + b"\n"
                             for row in context["requests"])
        expected["original-context-" + str(number)] = {"input_sha256": digest(requests), "input_bytes": len(requests),
            "output_sha256": digest(responses), "output_bytes": len(responses),
            "frames_sent": len(context["requests"]), "responses": len(context["requests"])}
    binding = vectors.get("credential_binding_vector")
    require(binding in rows and binding.get("context") == 16 and binding.get("operation") == "request"
            and binding.get("request_op") == 2 and binding.get("code") == 0
            and len(hex_bytes(binding.get("output_hex"))) == 64, "wire credential binding is not an actual complete-corpus row")
    require(sum(row["frames_sent"] for row in expected.values()) == 78, "wire original comparison count differs")
    return vectors, expected


def transport_evidence(root, directory, executable_sha256, controller_directory):
    report = object_at(directory / "transport-report.json")
    suite_report(root / "tests/hia_native", report, schema="hepta.runtime.authority-transport.tests.v1",
                 tests=6, counts=TRANSPORT_COUNTS, sources=TRANSPORT_SOURCES)
    require(report.get("production_http_transport") is False and report.get("new_rust_replay_claimed") is False
            and report.get("whole_runtime_replaced") is False, "transport scope or new-Rust claim differs")
    cases = json.loads(read(directory / "transport-cases.json"))
    require(type(cases) is list and len(cases) == 48, "transport process domain differs")
    domain_fields = ("case", "frames_sent", "responses", "exit_code", "supervisor", "closed_stderr")
    domain = [{name: row.get(name, False if name == "closed_stderr" else None) for name in domain_fields}
              for row in cases]
    domain_sha = digest(json_bytes(domain))
    require(domain_sha == "4481a644431f118afdd324d0bf267c45eb95698c88d893d78a99a6d66784f82d",
            "transport complete request/exit domain differs")
    _, expected_wire = wire_vectors(root, controller_directory)
    counts = Counter({key: 0 for key in TRANSPORT_COUNTS})
    traces, normalized, names = set(), [], set()
    files = {name: sha(directory / name) for name in ("transport-report.json", "transport-cases.json")}
    calls = {"token_open": 257, "token_stat": 5, "effective_uid": 107, "token_read": 0, "token_close": 3,
             "owner_open": 257, "owner_read": 0, "owner_close": 3, "entropy_probe": 318, "entropy_fill": 318,
             "entropy_random_open": 257, "entropy_poll": 7, "entropy_random_close": 3,
             "entropy_urandom_open": 257, "entropy_urandom_read": 0, "entropy_urandom_close": 3}
    for ordinal, case in enumerate(cases, 1):
        label = case.get("case")
        require(type(label) is str and label not in names, "duplicate transport process")
        names.add(label)
        require(integer(case.get("frames_sent"), 0, 100) and integer(case.get("responses"), 0, case["frames_sent"])
                and type(case.get("exit_code")) is int and case["exit_code"] in (0, 2, 64)
                and hex_digest(case.get("input_sha256")) and hex_digest(case.get("output_sha256")),
                "transport exact process receipt differs")
        if label == "frozen-private-credential":
            require(case.get("ordinary_frames_cannot_change_lifecycle") is True,
                    "ordinary-frame authority isolation was not observed")
            counts["known_private_binding_comparisons"] += 2
        else:
            require(integer(case.get("input_bytes"), 0, 32 << 20)
                    and integer(case.get("output_bytes"), 0, 8 << 20)
                    and type(case.get("closed_stderr")) is bool, "transport byte receipt differs")
        if label in expected_wire:
            same({key: case.get(key) for key in expected_wire[label]}, expected_wire[label],
                 "actual ELF wire input/result differs from the original-domain corpus")
            counts["original_wire_comparisons"] += case["responses"]
        if label == "http-token-fd-two":
            counts["known_private_binding_comparisons"] += 1
        counts.update(processes=1, frames_sent=case["frames_sent"], responses=case["responses"])
        trace = case.get("trace")
        if case.get("supervisor") is None:
            require(trace is None, "unsupervised transport has a synthetic trace")
            continue
        mode = case["supervisor"]
        require(type(trace) is dict and set(trace) == {"schema", "mode", "events", "executable_sha256",
                "executable_unchanged", "exit_code", "fault_fired", "native_cleanup", "owned_process_reaped"},
                "transport raw trace fields differ")
        require(trace["schema"] == "hepta.runtime.authority-backend.kernel-trace.v1"
                and trace["mode"] == mode and trace["executable_sha256"] == executable_sha256
                and trace["executable_unchanged"] is True and trace["owned_process_reaped"] is True
                and type(trace["exit_code"]) is int and trace["exit_code"] == case["exit_code"]
                and trace["fault_fired"] is (mode != "observe"), "transport effect/provenance/cleanup differs")
        same(trace["native_cleanup"], {"module_count": 9, "private_workspaces_zero": True,
            "transport_input_output_zero": True, "private_descriptor_slots_retired": True,
            "inspected_bytes": 41689784, "exit_code": case["exit_code"]}, "actual private-state erasure differs")
        filename = f"trace-{ordinal:03d}.json"
        same(object_at(directory / filename), trace, "retained raw transport trace differs")
        traces.add(filename)
        files[filename] = sha(directory / filename)
        counts["kernel_supervised_processes"] += 1
        counts["kernel_fault_processes"] += mode != "observe"
        if label.startswith("kernel-2-"):
            counts["known_private_binding_comparisons"] += 1
        require(type(trace["events"]) is list and trace["events"], "transport kernel effects are absent")
        for event in trace["events"]:
            require(type(event) is dict and event.get("action") in calls
                    and type(event.get("syscall")) is int and event["syscall"] == calls[event["action"]]
                    and event.get("effect") in ("kernel_continue", "injected_errno"),
                    "transport action/effect/syscall domain differs")
            if event["effect"] == "injected_errno":
                require(integer(event.get("errno"), 1, 4095), "transport injected errno differs")
        normalized.append({"case": label, "mode": mode,
            "events": [{key: value for key, value in event.items() if key != "syscall"} for event in trace["events"]]})
    require({path.name for path in directory.glob("trace-*.json")} == traces, "transport raw trace inventory differs")
    same(dict(counts), TRANSPORT_COUNTS, "transport counts do not reconstruct from actual complete cases")
    normalized_sha = digest(json_bytes(normalized))
    require(normalized_sha == "c8c56d016cfdae65a97e76bf10c8ae881a736cb9921bef03be1705835bee2fd1",
            "transport syscall ordering, entropy independence or cleanup effects differ")
    return {"status": "PASS", "counts": TRANSPORT_COUNTS, "domain_sha256": domain_sha,
        "normalized_trace_sha256": normalized_sha, "actual_private_cleanup_processes": len(traces),
        "cleanup_bytes_per_process": 41689784, "executable_sha256": executable_sha256, "files": files,
        "production_http_transport": False, "new_original_rust_calls": 0}


def packer_evidence(root, path, artifact):
    report = object_at(path)
    suite_report(root, report, schema="hepta.runtime.authority-packer.tests.v1",
                 tests=4, counts=PACKER_COUNTS, sources=PACKER_SOURCES)
    require(report.get("compiler_commit") == HEPTA_COMMIT
            and report.get("compiler_sha256") == artifact["compiler_image_sha256"]
            and report.get("manifest_sha256") == artifact["manifest_sha256"]
            and report.get("executable_sha256") == artifact["executable_sha256"]
            and report.get("profile_sha256") == PROFILE_SHA
            and report.get("whole_runtime_replaced") is False, "packer suite actual artifact identity differs")
    return {"status": "PASS", "counts": PACKER_COUNTS, "report_sha256": sha(path),
            "manifest_sha256": artifact["manifest_sha256"], "executable_sha256": artifact["executable_sha256"]}


def _retained_path(output, relative):
    require(type(relative) is str and relative and not Path(relative).is_absolute()
            and ".." not in Path(relative).parts and Path(relative).as_posix() == relative,
            "artifact path escapes the retained result")
    path = output / relative
    require(path.absolute() == path.resolve(), "artifact path is aliased")
    return path


def _completed_suite(root, output, report, completed_test_summary, name, expected, retained):
    check, summary = completed_test_summary(output, report, name)
    same(summary, retained, "completed suite stdout differs from its retained receipt")
    completion(summary, expected)
    require(check.get("command", [None])[1:] == ["-I", "-B", str(root / "tests/hia_native" / name)],
            "completed suite command used another source or injected arguments")
    stderr = read(output / (name + ".stderr")).decode("utf-8")
    require(len(re.findall(r"\.\.\. ok\n", stderr)) == expected
            and re.search(r"\nRan " + str(expected) + r" tests in [0-9.]+s\n\nOK\n\Z", stderr) is not None,
            "actual unittest completion differs from its declared receipt")
    return {"stdout_sha256": check["stdout_sha256"], "stderr_sha256": check["stderr_sha256"]}



def evidence(root, output, report, completed_test_summary):
    """Reconstruct this component's current qualification; never start a process."""
    require(report.get("compiler_commit") == HEPTA_COMMIT
            and hex_digest(report.get("compiler_image_sha256")), "aggregate compiler pin differs")
    pins = source_pins(root)
    owner = report["modules"]["caller_authority"]
    require(owner.get("builder") == "authority_composition"
            and owner.get("source") == "native/caller_authority.hepta", "aggregate native owner differs")
    manifest = _retained_path(output, owner.get("manifest"))
    probe_manifest = _retained_path(output, owner.get("probe_manifest"))
    require(sha(manifest) == owner.get("sha256") and sha(probe_manifest) == owner.get("probe_sha256"),
            "aggregate authority/probe manifest identity differs")
    build_root = output / "build"
    artifact = composition_artifacts(root, build_root, manifest, report["compiler_image_sha256"])
    probe = probe_artifacts(root, build_root, probe_manifest, report["compiler_image_sha256"])
    require(artifact["loader_image_sha256"] == probe["loader_image_sha256"]
            and artifact["loader_source_sha256"] == probe["loader_source_sha256"], "probe used another loader")
    metadata = object_at(manifest)
    scope_manifest = None
    dependencies = {}
    for index, key, member in ((1, "operation_record", 1), (2, "operation_kdf", None),
                               (3, "binary_codec", None), (4, "operation_aead", None),
                               (5, "operation_nonce", None), (6, "operation_scope", 6),
                               (7, "system_entropy", "policy")):
        entry = report["modules"][key]
        path = _retained_path(output, entry.get("manifest"))
        require(sha(path) == entry.get("sha256"), "independently qualified dependency manifest differs")
        parent = object_at(path)
        if member is None:
            child, child_path = parent, path
        elif member == "policy":
            require(parent.get("policy_manifest") == "policy.json", "entropy dependency path differs")
            child_path = path.parent / "policy.json"
            require(parent.get("policy_manifest_sha256") == sha(child_path), "entropy dependency child differs")
            child = object_at(child_path)
        else:
            require(parent["members"][member]["manifest"] == f"module_{member:02d}.json",
                    "composed dependency member path differs")
            child_path = path.parent / f"module_{member:02d}.json"
            require(parent["members"][member]["manifest_sha256"] == sha(child_path), "composed dependency child differs")
            child = object_at(child_path)
        require(child.get("compiler_commit") == HEPTA_COMMIT
                and child.get("compiler_sha256") == report["compiler_image_sha256"]
                and child.get("source_sha256") == metadata["members"][index]["source_sha256"]
                and child.get("image_sha256") == metadata["members"][index]["image_sha256"],
                "packed owner differs from the independently qualified original component")
        for field in ("source", "image"):
            require(type(child.get(field)) is str and Path(child[field]).name == child[field],
                    "dependency source/image escaped its retained directory")
        require(sha(child_path.parent / child["source"]) == child["source_sha256"]
                and sha(child_path.parent / child["image"]) == child["image_sha256"],
                "independent dependency actual source/image differs")
        dependencies[key] = {"manifest": entry["manifest"], "manifest_sha256": entry["sha256"],
                             "source_sha256": child["source_sha256"], "image_sha256": child["image_sha256"]}
        if key == "operation_scope":
            scope_manifest = path
    folder = output / FOLDER
    controller = controller_evidence(root, folder / "controller")
    direct_loaded_evidence(root, controller["loaded_artifacts"], authority=metadata,
                           scope=object_at(scope_manifest), scope_sha256=sha(scope_manifest))
    same(object_at(folder / "controller.json"), object_at(folder / "controller/native-corpus.json")["native_report"],
         "retained controller completion differs from its complete native corpus")
    kernel = kernel_evidence(root, folder / "kernel", probe["executable_sha256"])
    transport = transport_evidence(root, folder / "transport", artifact["executable_sha256"], folder / "controller")
    packed = packer_evidence(root, folder / "packer.json", artifact)
    controls = object_at(folder / "evidence.json")
    suite_report(root, controls, schema="hepta.runtime.authority-evidence.tests.v1",
                 tests=7, counts=EVIDENCE_COUNTS, sources=EVIDENCE_SOURCES)
    require(controls.get("manifest_sha256") == artifact["manifest_sha256"]
            and controls.get("probe_manifest_sha256") == probe["manifest_sha256"]
            and controls.get("whole_runtime_replaced") is False, "evidence controls used another native artifact")
    checks, corpus_files = {}, {}
    for name, _, relative, tests, _ in SUITES:
        retained = object_at(folder / relative)
        checks[name] = _completed_suite(root, output, report, completed_test_summary, name, tests, retained)
    for prefix, observation in (("controller", controller), ("kernel", kernel), ("transport", transport)):
        for name, expected in observation["files"].items():
            relative = FOLDER + "/" + prefix + "/" + name
            require(sha(output / relative) == expected, "retained authority corpus changed")
            corpus_files[relative] = expected
    for name in ("controller.json", "packer.json", "evidence.json"):
        corpus_files[FOLDER + "/" + name] = sha(folder / name)
    result = {"status": "PASS", "schema": "hepta.runtime.authority.qualification-evidence.v1",
        "source_sha256": pins, "artifact": artifact, "probe": probe, "dependencies": dependencies,
        "controller": controller, "kernel": kernel, "transport": transport, "packer": packed,
        "evidence_controls": {"counts": EVIDENCE_COUNTS, "report_sha256": sha(folder / "evidence.json")},
        "completed_suites": checks, "corpus_sha256": corpus_files,
        "native_entries_in_fixture_controller": 786, "actual_native_kernel_processes": 110,
        "actual_native_transport_processes": 48, "actual_native_transport_frames": 144,
        "original_rust_replay_status": "PENDING", "new_original_rust_calls": 0,
        "concurrent_http_qualified": False, "production_activated": False,
        "old_stack_removal_qualified": False, "whole_runtime_replaced": False}
    require(source_pins(root) == pins, "source changed while checking authority evidence")
    return result


ORIGINAL_CONTROLLER = {"actual_router_dispatch_calls": 28, "adapter_only_rows": 2,
    "native_cases_added_by_replay": 0, "original_load_http_auth_calls": 11, "original_middleware_executed": True,
    "original_new_owner_id_calls": 15, "original_resolve_calls": 27, "original_resolve_operation_crypto_calls": 11,
    "original_stdio_with_fixture_calls": 16,
    "output_sha256": "36b5d9939cd3dc6de512115d4819caec68c3604d72e1067d2d20f2ae825b8ba8",
    "reconnects": 1, "requests": 100, "rows": 122, "shutdowns": 2, "starts": 17,
    "status": "PASS", "synthetic_entropy_fills": 52, "whole_runtime_replaced": False}


def original_source_bytes(root):
    for name, expected in ORIGINAL_PINS.items():
        require(sha(root / name) == expected, "original source baseline changed: " + name)
    caller = read(root / "src/mcp/runtime/caller_scope.rs").decode()
    crypto = read(root / "src/mcp/runtime/operation_crypto.rs").decode()
    main = read(root / "src/main.rs").decode()
    search = read(root / "src/mcp/runtime/search_jobs.rs").decode()
    begin = main.index("#[derive(Clone)]\nstruct HttpAuth {")
    auth = main[begin:main.index("/// Run the MCP server over HTTP", begin)]
    begin = search.index("pub fn new_owner_id() -> Result<String> {")
    owner = search[begin:search.index("\nfn instance()", begin)]
    recipe = root / "tests/hia_native/authority_oracle"
    access = read(recipe / "original_access.rs").decode()
    crypto_access = read(recipe / "crypto_access.rs").decode()
    generated = (f"#[allow(dead_code)]\nmod mcp {{\npub mod runtime {{\npub mod operation_crypto {{\n{crypto}\n{crypto_access}\n}}\n"
        f"pub mod caller_scope {{\n{caller}\n{access}\n}}\npub mod owner_reference {{\nuse anyhow::{{Context, Result}};\n"
        f"use std::io::Read;\n{owner}\n}}\n}}\n}}\n{auth}")
    result = {"original_authority_reference.rs": generated.encode(),
              "original_auth_segment.rs": auth.encode(), "original_owner_segment.rs": owner.encode()}
    expected = {"original_authority_reference.rs": "15762a8bfb72c9ee20325815692362429bde22d95e4354a7415d4684e2301633",
                "original_auth_segment.rs": "2a0f8fc0fbcb0e5e37bcffd3eb1c013f1dfbe7163348d0c9ef56d9eeb49927f2",
                "original_owner_segment.rs": "af2789170462478e2d1a0d85955af6287c7ce0ae00ca6735b99ace0886d347cb"}
    same({name: digest(raw) for name, raw in result.items()}, expected, "generated original owner or private access shim differs")
    return result


def oracle_dependencies(root):
    recipe = root / "tests/hia_native/authority_oracle"
    require(sha(recipe / "Cargo.lock") == "f2c592c32404a24beac2e63c5358b93899a3b194532e6b6ac4bedc0a1af747d7",
            "original oracle locked graph differs")
    packages = tomllib.loads(read(recipe / "Cargo.lock").decode())["package"]
    baseline = {(row["name"], row["version"]): row for row in
                tomllib.loads(read(root / "Cargo.lock").decode())["package"]}
    require(len(packages) == 133 and len({(row["name"], row["version"]) for row in packages}) == 133,
            "oracle locked package count or uniqueness differs")
    result = []
    for row in packages:
        if "source" not in row:
            require(row["name"] == "hia-caller-authority-reference", "unexpected local oracle dependency")
            continue
        match = baseline.get((row["name"], row["version"]))
        require(match is not None and row["source"] == match.get("source")
                and row.get("checksum") == match.get("checksum") and hex_digest(row.get("checksum")),
                "original oracle registry version/checksum differs from the baseline")
        result.append({key: row[key] for key in ("name", "version", "source", "checksum")})
    return {"locked_package_count": 133, "registry_package_count": len(result), "registry_packages": result,
            "all_registry_versions_and_checksums_match_baseline": True,
            "complete_lockfiles_identical": False, "test_recipe_has_reduced_feature_closure": True,
            "cargo_lock_sha256": sha(recipe / "Cargo.lock")}


def compare_original(root, output, report, rustc, *, record_check, completed_test_summary,
                     qualification_env, cargo):
    """Run the actual locked original owner; captured observations cannot replace this."""
    import os
    import sys
    before = evidence(root, output, report, completed_test_summary)
    if "caller_authority_evidence" in report:
        same(report["caller_authority_evidence"], before, "native authority evidence changed before Rust replay")
    folder = output / FOLDER
    target = folder / "rust-target"
    require(not target.exists() and not (folder / "original-kernel").exists()
            and not (folder / "rust-comparison.json").exists(), "actual original replay output already exists")
    dependency = oracle_dependencies(root)
    original = original_source_bytes(root)
    recipe = root / "tests/hia_native/authority_oracle/Cargo.toml"
    environment = qualification_env()
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR"):
        environment.pop(key, None)
    environment.update(HIA_REFERENCE_RUNTIME=str(root), RUSTC=str(rustc), CARGO_TARGET_DIR=str(target))
    record_check(output, report, name="caller-authority-rust-format",
        command=[str(cargo), "fmt", "--manifest-path", str(recipe), "--check"], env=environment, timeout=30)
    record_check(output, report, name="caller-authority-rust-compile",
        command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(recipe),
                 "--target-dir", str(target)], env=environment, timeout=180)
    products = list((target / "release/build").glob("hia-caller-authority-reference-*/out/original_authority_reference.rs"))
    require(len(products) == 1, "original generated source inventory differs")
    for name, expected in original.items():
        require(read(products[0].parent / name) == expected, "compiled original owner bytes differ")
    binary = target / "release/hia-caller-authority-reference"
    binary_sha = sha(binary)
    raw = gzip.decompress(read(folder / "controller/authority_cases.jsonl.gz"))
    result = record_check(output, report, name="caller-authority-rust-compare",
        command=[str(binary)], env=environment, input_bytes=raw, timeout=120)
    require(not result.stderr, "original controller replay emitted diagnostics")
    actual = json.loads(result.stdout)
    same(actual, ORIGINAL_CONTROLLER, "actual original controller lifecycle/header/binding results differ")
    environment.update(HIA_AUTHORITY_REFERENCE_BINARY=str(binary), HIA_AUTHORITY_REFERENCE_SHA256=binary_sha,
        HIA_AUTHORITY_PROBE_MANIFEST=str(_retained_path(output, report["modules"]["caller_authority"]["probe_manifest"])),
        HIA_AUTHORITY_KERNEL_CORPUS_DIR=str(folder / "original-kernel"))
    record_check(output, report, name="caller-authority-rust-kernel",
        command=[sys.executable, "-I", "-B", str(root / "tests/hia_native/test_authority_loader_kernel.py")],
        env=environment, timeout=120)
    check, observed = completed_test_summary(output, report, "caller-authority-rust-kernel")
    same(observed, object_at(folder / "original-kernel/kernel-report.json"), "actual original kernel stdout differs")
    original_kernel = kernel_evidence(root, folder / "original-kernel", binary_sha, original=True)
    for key in ("domain_sha256", "logical_trace_sha256", "normalized_trace_pairs"):
        same(original_kernel[key], before["kernel"][key], "actual original/native complete kernel domain differs")
    require(sha(binary) == binary_sha, "original executable changed during replay")
    same(evidence(root, output, report, completed_test_summary), before, "native qualification changed during original replay")
    result = {"schema": "hepta.runtime.authority.actual-rust-comparison.v1", "status": "PASS",
        "original_controller": actual, "kernel": original_kernel, "original_kernel_calls": 110,
        "generated_original_sha256": {name: digest(raw) for name, raw in original.items()},
        "original_sources": ORIGINAL_PINS, "oracle_sources": {name: sha(root / name) for name in ORACLE_SOURCES},
        "dependencies": dependency, "binary_sha256": binary_sha, "binary_bytes": len(read(binary)),
        "native_evidence_sha256": digest(json_bytes(before)), "native_cases_added_by_replay": 0,
        "captured_observation_used_as_execution": False, "normal_random_bytes_compared": False,
        "production_activated": False, "concurrent_http_qualified": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("xb") as stream:
        stream.write(json_bytes(result))
    return result



def _capture_process(directory, name, timeout):
    receipt = object_at(directory / (name + ".receipt.json"))
    require(receipt.get("exit_code") == 0 and type(receipt.get("exit_code")) is int
            and receipt.get("timed_out") is False and receipt.get("timeout_seconds") == timeout
            and type(receipt.get("elapsed_seconds")) in (int, float)
            and 0 <= receipt["elapsed_seconds"] < timeout,
            "captured original process did not complete within its declared budget")
    command = receipt.get("command")
    require(type(command) is list and command and all(type(part) is str and part for part in command),
            "captured process command is absent")
    streams = {}
    for kind in ("stdout", "stderr"):
        raw = read(directory / (name + "." + kind))
        require(receipt.get(kind + "_sha256") == digest(raw) and receipt.get(kind + "_bytes") == len(raw),
                "captured process retained raw stream differs")
        streams[kind] = raw
    return receipt, streams


def captured_original_evidence(root, directory, controller_directory, artifact, probe):
    """Verify the immutable v4 observation, explicitly without a new execution."""
    inventory = object_at(directory / "retained-files.json")
    require(len(inventory) == 103 and set(inventory) | {"retained-files.json"} ==
            {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()},
            "captured original raw-file closure differs")
    files = {"retained-files.json": sha(directory / "retained-files.json")}
    for relative, observation in inventory.items():
        path = _retained_path(directory, relative)
        data = read(path)
        same(observation, {"bytes": len(data), "sha256": digest(data)}, "captured raw member bytes differ")
        files[relative] = digest(data)
    comparison = object_at(directory / "authority-comparison.json")
    require(comparison.get("schema") == "hepta.runtime.authority.original-comparison.v1"
            and comparison.get("status") == "PASS" and comparison.get("source_unchanged") is True
            and comparison.get("random_owner_bytes_compared") is False
            and comparison.get("whole_runtime_replaced") is False
            and type(comparison.get("matched_kernel_cases")) is int and comparison["matched_kernel_cases"] == 110
            and type(comparison.get("normalized_logical_trace_pairs")) is int
            and comparison["normalized_logical_trace_pairs"] == 26, "captured original comparison scope differs")
    source_map = object_at(directory / "source-map.json")
    require(sha(directory / "source-map.json") == comparison.get("source_map_sha256")
            == "c2e146d9a5e2bd91f1f84b85980a219a9d1da9ede3da17b36c338f2746025492",
            "captured exact source map differs")
    names = {row[1] for row in SPECS} | set(ORACLE_SOURCES)
    names.update({"native/authority_packer.hepta", "native/authority_profile.json",
        "native/authority_packer_provenance.json", "scripts/hia_native_loader.py", "rustfmt.toml",
        "tests/hia_native/authority_loader_probe_packer.hepta", "tests/hia_native/scope_entropy_fixture.hepta"})
    names.update("tests/hia_native/" + name for name in (*CONTROLLER_SOURCES, *KERNEL_SOURCES, *TRANSPORT_SOURCES))
    for name in names:
        require(source_map.get("candidate/" + name) == sha(root / name),
                "captured observation used another current HIA/test/oracle source: " + name)
    for name in ORIGINAL_PINS:
        if name == "src/mcp/runtime/caller_scope_tests.rs":
            require(sha(root / name) == ORIGINAL_PINS[name], "original source test pin differs")
            continue
        require(source_map.get("runtime/" + name) == sha(root / name) == ORIGINAL_PINS[name],
                "captured original runtime source differs")
    controller = controller_evidence(root, controller_directory)
    for name in ("authority_cases.jsonl.gz", "native-corpus.json"):
        require(source_map.get("controller-corpus/" + name) == sha(controller_directory / name),
                "captured original input differs from the complete native result corpus")
    scope = object_at(directory / "fixture-scope-manifest.json")
    require(sha(directory / "fixture-scope-manifest.json") == source_map.get("fixture-scope-manifest.json"),
            "captured independently selected fixture scope differs")
    loaded = direct_loaded_evidence(root, comparison.get("direct_native_loaded_artifacts"),
                                     scope=scope, scope_sha256=sha(directory / "fixture-scope-manifest.json"))
    same(loaded, controller["loaded_artifacts"], "captured original comparison used another direct native closure")
    for index in (0, 8):
        require(source_map.get(f"authority-elf/module_{index:02d}.json") == loaded["members"][index]["manifest_sha256"],
                "captured direct native root/loader manifest differs")
    profile = object_at(root / "native/authority_profile.json")
    for index, member in enumerate(profile["members"]):
        require(source_map.get(f"authority-elf/module_{index:02d}.hepta") == member["source_sha256"]
                and source_map.get(f"authority-elf/module_{index:02d}.image.bin") == member["image_sha256"],
                "captured actual packed image/source differs from the fixed nine-image profile")
    require(source_map.get("authority-elf/native-authority.elf") == artifact["executable_sha256"]
            and source_map.get("probe/authority-loader-probe.elf") == probe["executable_sha256"]
            and source_map.get("probe/policy.image.bin") == artifact["loader_image_sha256"] == probe["loader_image_sha256"],
            "captured actual ELF or private-loader image differs")
    generated = original_source_bytes(root)
    for name, expected in generated.items():
        require(read(directory / "generated" / name) == expected, "captured generated original bytes differ")
    dependency = oracle_dependencies(root)
    build = object_at(directory / "original-build.json")
    same(build, comparison.get("original_build"), "captured build reports disagree")
    expected_build = {"status": "PASS", "binary_bytes": 4223696,
        "binary_sha256": "b157e78536ee099c2bf9a684009227a637df5e11d940278af7ddaf881fcdbfa8",
        "cargo_lock_sha256": dependency["cargo_lock_sha256"], "locked_package_count": 133,
        "all_registry_versions_and_checksums_match_baseline": True, "test_recipe_has_reduced_feature_closure": True,
        "generated_source_byte_exact": True, "generated_module_sha256": digest(generated["original_authority_reference.rs"]),
        "exact_original_main_auth_segment_sha256": digest(generated["original_auth_segment.rs"]),
        "exact_original_owner_segment_sha256": digest(generated["original_owner_segment.rs"]),
        "complete_original_caller_module_sha256": ORIGINAL_PINS["src/mcp/runtime/caller_scope.rs"],
        "complete_original_crypto_module_sha256": ORIGINAL_PINS["src/mcp/runtime/operation_crypto.rs"]}
    same({key: build.get(key) for key in expected_build}, expected_build, "captured unchanged Rust build identity differs")
    processes = {}
    streams = {}
    for name, timeout in (("rustc-version", 20), ("rustfmt-check", 30), ("cargo-build", 600),
                           ("original-controller-replay", 120), ("native-kernel-replay", 120),
                           ("original-kernel-replay", 120), ("native-authority-transport", 120)):
        processes[name], streams[name] = _capture_process(directory, name, timeout)
    require(streams["rustc-version"]["stdout"].decode() == build.get("compiler")
            and not streams["rustc-version"]["stderr"]
            and processes["rustc-version"]["command"][1:] == ["--version", "--verbose"],
            "captured actual compiler/version stream differs")
    command = processes["cargo-build"]["command"]
    require(command[1:5] == ["build", "--locked", "--release", "--manifest-path"] and len(command) == 6
            and command[-1].endswith("/candidate/tests/hia_native/authority_oracle/Cargo.toml"),
            "captured original locked compilation recipe differs")
    require(processes["rustfmt-check"]["command"][1:3] == ["fmt", "--manifest-path"]
            and processes["rustfmt-check"]["command"][-1] == "--check"
            and processes["rustfmt-check"]["command"][-2] == command[-1]
            and not streams["rustfmt-check"]["stdout"] and not streams["rustfmt-check"]["stderr"]
            and not streams["cargo-build"]["stdout"], "captured formatting or compiler output differs")
    same(processes["cargo-build"], build.get("cargo_receipt"), "captured Cargo receipt differs")
    same(processes["rustfmt-check"], build.get("rustfmt_receipt"), "captured rustfmt receipt differs")
    require(len(processes["original-controller-replay"]["command"]) == 1
            and processes["original-controller-replay"]["command"][0].endswith("/target/release/hia-caller-authority-reference")
            and not streams["original-controller-replay"]["stderr"], "captured controller did not invoke the original binary")
    actual_controller = json.loads(streams["original-controller-replay"]["stdout"])
    same(actual_controller, ORIGINAL_CONTROLLER, "captured actual original controller results differ")
    same(actual_controller, comparison.get("original_controller"), "captured original controller reports disagree")
    same(processes["original-controller-replay"], comparison.get("controller_receipt"),
         "captured original controller process receipt differs")
    native_kernel = kernel_evidence(root, directory / "native-kernel", probe["executable_sha256"])
    original_kernel = kernel_evidence(root, directory / "original-kernel", build["binary_sha256"], original=True)
    for key in ("domain_sha256", "logical_trace_sha256", "normalized_trace_pairs"):
        same(native_kernel[key], original_kernel[key], "captured real native/original kernel domains differ")
    for label, subdir in (("native", "native-kernel"), ("original", "original-kernel")):
        process = processes[label + "-kernel-replay"]
        command = process["command"]
        require(command[1:3] == ["-I", "-B"] and len(command) == 4
                and command[-1].endswith("/candidate/tests/hia_native/test_authority_loader_kernel.py"),
                "captured kernel process used another executable suite")
        summary = json.loads(streams[label + "-kernel-replay"]["stdout"])
        same(summary, object_at(directory / subdir / "kernel-report.json"), "captured kernel stdout differs")
        same(comparison["kernel_results"][label], {"receipt": process, "report": summary},
             "captured kernel comparison does not bind its actual suite")
    transport = transport_evidence(root, directory / "authority-transport", artifact["executable_sha256"], controller_directory)
    process = processes["native-authority-transport"]
    require(process["command"][1:3] == ["-I", "-B"] and len(process["command"]) == 4
            and process["command"][-1].endswith("/candidate/tests/hia_native/test_authority_transport.py"),
            "captured real transport used another suite")
    summary = json.loads(streams["native-authority-transport"]["stdout"])
    same(summary, object_at(directory / "authority-transport/transport-report.json"), "captured transport stdout differs")
    same(summary, comparison.get("native_transport"), "captured transport comparison differs")
    same(process, comparison.get("native_transport_receipt"), "captured transport process receipt differs")
    return {"status": "PASS", "schema": "hepta.runtime.authority.captured-original-evidence.v1",
        "capture_only": True, "new_executions": 0, "files": files, "raw_file_count": len(files),
        "source_map_sha256": sha(directory / "source-map.json"), "original_controller": actual_controller,
        "binary_sha256": build["binary_sha256"], "binary_bytes": build["binary_bytes"],
        "generated_original_sha256": {name: digest(raw) for name, raw in generated.items()},
        "dependencies": dependency, "kernel_domain_sha256": native_kernel["domain_sha256"],
        "logical_trace_sha256": native_kernel["logical_trace_sha256"], "matched_kernel_cases": 110,
        "normalized_logical_trace_pairs": 26, "original_kernel_calls": 110,
        "transport_counts": transport["counts"], "raw_process_receipts": len(processes),
        "normal_random_bytes_compared": False, "whole_runtime_replaced": False}
