"""Validate private-scope composition and its disjoint reference/control histories."""
from __future__ import annotations

from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import struct

from hia_native_build import HEPTA_COMMIT, json_bytes
from check_hia_native_inventory import RUNTIME_BASE_COMMIT
from hia_native_entropy_qualification import digest, exact_counts, inspect_elf, native_receipt, object_at, read

FOLDER = "operation-scope-rust-oracle"
CORPUS_FILES = ("native-corpus.json", "scope_cases.jsonl.gz", "scope_fault_sessions.jsonl.gz",
                "scope_capacity_controls.jsonl.gz")
COUNTS = {
    "actual_elf_fatal_contract_controls": 1, "actual_elf_processes": 4, "actual_elf_requests": 27,
    "actual_elf_responses": 26, "authentication_reference_refusals": 16, "binding_reference_cases": 36,
    "capacity_refusals": 3, "child_contract_refusals": 24, "direct_requests_5": 16384,
    "direct_requests_6": 588, "direct_requests_7": 49, "direct_sessions": 49,
    "duplicate_nonce_reference_cases": 3, "entropy_failure_reference_cases": 1,
    "exact_capacity_successes": 104, "fault_session_prefix_rows_excluded": 47,
    "fault_sessions_excluded_from_rust": 25, "invalid_binding_input_reference_cases": 36,
    "invalid_token_reference_cases": 166, "malformed_frame_refusals": 109,
    "native_entries_1": 683, "native_entries_2": 215, "native_entries_3": 230,
    "native_entries_4": 127, "native_entries_5": 16510, "native_entries_6": 1099, "native_entries_7": 147,
    "nonce_budget_reference_refusals": 1, "nonce_budget_setup_reservations": 16384,
    "open_reference_cases": 55, "post_reservation_refusal_controls": 2, "preflight_reference_refusals": 4,
    "seal_reference_cases": 57, "stdio_failure_reference_cases": 4,
    "stdio_success_reference_cases": 4, "verified_constructor_reference_cases": 6,
}
ORACLE_COUNTS = {
    "rust_oracle_cases": 16944, "sessions": 24, "refusal_cases": 344, "original_domain_rows": 16807,
    "adapter_only_rows": 137, "original_verified_constructors": 179, "original_stdio_constructors": 9,
    "original_request_bindings": 25, "original_idempotency_bindings": 23, "original_policy_bindings": 24,
    "original_seals": 64, "original_opens": 73, "original_clones": 4, "original_releases": 22,
    "original_last_releases": 18, "original_nonce_setup_reservations": 16384,
    "original_binding_constructors": 16384, "original_entropy_fixture_fills": 92,
    "original_entropy_fixture_requested_bytes": 1704, "fixture_control_rows": 24,
    "original_owner_calls": 33191, "native_cases_added_by_replay": 0,
}
SPECS = (
    ("scope-hex-fixture", "tests/hia_native/scope_hex_transport.hepta", 1, 192, 8 << 20, 8 << 20, 16 << 20),
    ("operation-record", "native/operation_record.hepta", 1, 28, 8 << 20, 2 << 20, 3 << 20),
    ("operation-kdf", "native/operation_kdf.hepta", 0, 0, 8 << 20, 128, 2048),
    ("binary-codec", "native/binary_codec.hepta", 0, 0, 8 << 20, 32, 1184),
    ("operation-aead", "native/operation_aead.hepta", 0, 0, 8 << 20, 1048640, 512),
    ("operation-nonce", "native/operation_nonce.hepta", 0, 0, 164, 64, 1576960),
    ("operation-scope", "native/operation_scope.hepta", 1, 166, 8 << 20, 2 << 20, 3 << 20),
    ("scope-entropy-fixture", "tests/hia_native/scope_entropy_fixture.hepta", 0, 0, 48, 128, 128),
)
PACKER_SOURCE_SHA256 = "4367179d1c4776853d5c9542db6582b24be2c59c76ac8d1c347d6373cb297d5a"
PACKER_PREFIX_SHA256 = "db41d6cf9664e59dcd216e2d0c7df398fc945c8df0a7e73b6137c97dfbf73273"


def embedded_images(executable: bytes, profile: list[dict], images: list[bytes]) -> dict:
    """Bind the complete frozen adapter, pointed-to table and every image byte.

    The source-owned 4367179d packer has an 8,752-byte fixed ELF/adapter prefix.
    Only its two total-size words vary with this profile; its RIP-relative
    metadata displacement, all adapter code and alignment bytes are fixed.
    """
    metadata_at, pointer_at, work_start = 8752, 228, 16859136
    if len(executable) < metadata_at + 64 + len(profile) * 128 or len(images) != len(profile):
        raise ValueError("scope embedded native table is incomplete")
    prefix = bytearray(executable[:metadata_at])
    prefix[96:112] = bytes(16)
    if (digest(prefix) != PACKER_PREFIX_SHA256 or executable[pointer_at - 3:pointer_at] != b"\x4c\x8d\x2d"
            or pointer_at + 4 + struct.unpack_from("<i", executable, pointer_at)[0] != metadata_at):
        raise ValueError("scope embedded adapter or metadata pointer differs from the frozen HIA packer")
    code, memory = metadata_at + 64 + len(profile) * 128, work_start
    offsets = []
    for index, (p, image) in enumerate(zip(profile, images)):
        desc = metadata_at + 64 + index * 128
        expected = (code, len(image), p["input_capacity"], p["output_capacity"], memory,
                    p["workspace_capacity"], p["flags"], p["call_mask"])
        end = code + len(image)
        following = (end + 15) & ~15
        if (struct.unpack_from("<8Q", executable, desc) != expected
                or executable[desc + 64:desc + 96] != bytes.fromhex(p["source_sha256"])
                or executable[desc + 96:desc + 128] != bytes.fromhex(digest(image))
                or executable[code:end] != image or executable[end:following] != bytes(following - end)):
            raise ValueError("scope embedded descriptor, hash, image or padding differs")
        offsets.append({"id": index, "image_offset": code, "image_bytes": len(image), "workspace_offset": memory})
        code = following
        memory += ((p["workspace_capacity"] + 4095) & ~4095) + 4096
    expected_header = (int.from_bytes(b"HIAMOD01", "little"), len(profile), 0, memory, 128, work_start, 0, 0)
    if struct.unpack_from("<8Q", executable, metadata_at) != expected_header or code != len(executable):
        raise ValueError("scope embedded native table extent or private memory layout differs")
    return {"prefix_sha256": PACKER_PREFIX_SHA256, "metadata_offset": metadata_at,
            "metadata_pointer_displacement_offset": pointer_at, "private_memory_bytes": memory,
            "images": offsets, "all_embedded_image_bytes_match": True}


def sha(path: Path) -> str:
    return digest(read(path))


def composition_evidence(root: Path, output: Path, report: dict) -> dict:
    owner = report["modules"]["operation_scope"]
    relative = Path(owner["manifest"])
    if (owner.get("builder") != "scope_composition" or owner.get("source") != "native/operation_scope.hepta"
            or relative.is_absolute() or ".." in relative.parts or relative.parts[:2] != ("build", "composition")):
        raise ValueError("scope composition registry or manifest path differs")
    manifest = output / relative
    metadata = object_at(manifest)
    expected = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64",
                "transport": "newline-json", "compiler_commit": HEPTA_COMMIT,
                "compiler_sha256": report["compiler_image_sha256"], "executable": "native-local-read.elf",
                "runtime_python_required": False, "runtime_libc_required": False, "whole_runtime_replaced": False}
    if sha(manifest) != owner.get("sha256") or any(
            type(metadata.get(key)) is not type(value) or metadata[key] != value for key, value in expected.items()):
        raise ValueError("scope composition manifest identity differs")
    profile = [{"id": index, "name": name, "source_sha256": sha(root / source), "flags": flags,
                "call_mask": mask, "input_capacity": inp, "output_capacity": out, "workspace_capacity": work}
               for index, (name, source, flags, mask, inp, out, work) in enumerate(SPECS)]
    if json_bytes(metadata.get("profile")) != json_bytes(profile) or len(metadata.get("members", [])) != 8:
        raise ValueError("scope fixed eight-image authority table differs")
    provenance = object_at(root / "native/operation_scope_composition.json")
    dependencies = {"native/" + name + "_composition.json" for name in (
        "operation_record", "operation_kdf", "binary_codec", "operation_aead", "operation_nonce")}
    if (provenance.get("schema") != "hepta.runtime.operation-scope-composition.v1"
            or provenance.get("source_sha256") != profile[6]["source_sha256"]
            or provenance.get("members") != [dict(row, source=spec[1]) for row, spec in zip(profile, SPECS)]
            or provenance.get("compiler_commit") != HEPTA_COMMIT
            or provenance.get("compiler_sha256") != report["compiler_image_sha256"]
            or provenance.get("packer_source_sha256") != sha(root / "native/composition_packer.hepta")
            or provenance.get("packer_source_sha256") != PACKER_SOURCE_SHA256
            or provenance.get("dependency_provenance") != {name: sha(root / name) for name in sorted(dependencies)}
            or provenance.get("entropy") != "trusted deterministic test child, not SystemEntropy"
            or provenance.get("production_activated") is not False
            or provenance.get("complete_concurrent_scope_parity") is not False
            or provenance.get("public_key_output") is not False
            or provenance.get("original_runtime_commit") != RUNTIME_BASE_COMMIT
            or provenance.get("original_source") != "src/mcp/runtime/operation_crypto.rs"
            or provenance.get("original_source_sha256") != sha(root / "src/mcp/runtime/operation_crypto.rs")):
        raise ValueError("scope source/dependency/authority provenance differs")
    rows = [("packer", "native/composition_packer.hepta", metadata["packer"])]
    rows += [(f"module_{index:02d}", spec[1], metadata["members"][index]) for index, spec in enumerate(SPECS)]
    artifacts = {relative.as_posix(): sha(manifest)}
    compiler = read(output / "build/bootstrap/B3.image.bin")
    if digest(compiler) != report["compiler_image_sha256"]:
        raise ValueError("scope compiler image changed")
    frame = bytearray(b"HIABND01" + struct.pack("<3Q", 8, 0, 0))
    native_images = []
    scope = {}
    for position, (stem, source_name, row) in enumerate(rows):
        if row.get("manifest") != stem + ".json":
            raise ValueError("scope child manifest path differs")
        path = manifest.parent / row["manifest"]
        child = object_at(path)
        source, image = read(manifest.parent / (stem + ".hepta")), read(manifest.parent / (stem + ".image.bin"))
        contract = {"schema": "hepta.runtime.native-module.v1", "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1",
                    "target": "linux-x86_64", "compiler_commit": HEPTA_COMMIT,
                    "compiler_sha256": report["compiler_image_sha256"], "source": stem + ".hepta",
                    "image": stem + ".image.bin", "input_capacity": 8 << 20, "output_capacity": 8 << 20,
                    "workspace_capacity": 32 << 20, "standalone": None}
        if (sha(path) != row.get("manifest_sha256") or source != read(root / source_name)
                or digest(source) != row.get("source_sha256") or digest(source) != child.get("source_sha256")
                or digest(image) != row.get("image_sha256") or digest(image) != child.get("image_sha256")
                or not 0 < len(image) <= 1 << 20
                or any(type(child.get(key)) is not type(value) or child[key] != value for key, value in contract.items())):
            raise ValueError("scope packed source/image/compiler identity differs")
        compiled = output / "build/modules" / ("composition-" + digest(source)[:24])
        receipt = object_at(compiled / "module.receipt.json")
        native_receipt(receipt, image=compiler, source=source, output=read(compiled / "module.output.bin"), produced=image)
        built = object_at(compiled / "build.json")
        if (read(compiled / "module.input.bin") != source or read(compiled / "module.image.bin") != image
                or receipt.get("produced_sha256") != digest(image) or receipt.get("produced_bytes") != len(image)
                or built.get("compile_receipt") != receipt
                or built.get("compiler_dependency") != object_at(output / "build/bootstrap/bootstrap.json").get("dependency")):
            raise ValueError("scope native compilation receipt differs")
        for name in (stem + ".json", stem + ".hepta", stem + ".image.bin"):
            artifacts[(manifest.parent / name).relative_to(output).as_posix()] = sha(manifest.parent / name)
        for name in ("module.receipt.json", "module.input.bin", "module.output.bin", "module.image.bin", "build.json"):
            artifacts[(compiled / name).relative_to(output).as_posix()] = sha(compiled / name)
        if position == 7:
            scope = child
        if position in (2, 3, 4, 5, 6):
            key = {2: "operation_record", 3: "operation_kdf", 4: "binary_codec", 5: "operation_aead", 6: "operation_nonce"}[position]
            tested_owner = report["modules"][key]
            tested_relative = Path(tested_owner["manifest"])
            if tested_relative.is_absolute() or ".." in tested_relative.parts:
                raise ValueError("scope tested dependency escaped the retained result")
            tested_path = output / tested_relative
            tested = object_at(tested_path)
            if sha(tested_path) != tested_owner["sha256"]:
                raise ValueError("scope tested dependency manifest changed")
            if key == "operation_record":
                tested = tested["members"][1]
            if any(child.get(field) != tested.get(field) for field in ("source_sha256", "image_sha256")):
                raise ValueError("scope packed leaf differs from its independently tested owner")
        if position:
            native_images.append(image)
            p = profile[position - 1]
            frame.extend(struct.pack("<8Q", len(image), p["input_capacity"], p["output_capacity"], p["workspace_capacity"],
                                     p["flags"], p["call_mask"], 0, 0))
            frame.extend(bytes.fromhex(digest(source)) + bytes.fromhex(digest(image)) + image)
    key = digest(json_bytes({"compiler": report["compiler_image_sha256"], "members": profile,
                             "packer": sha(root / "native/composition_packer.hepta")}))
    executable = read(manifest.parent / "native-local-read.elf")
    layout = embedded_images(executable, profile, native_images)
    if (metadata.get("key") != key or metadata.get("frame_sha256") != digest(frame)
            or metadata.get("frame_bytes") != len(frame) or len(frame) > 8 << 20
            or metadata.get("executable_sha256") != digest(executable)
            or metadata.get("inspection") != inspect_elf(executable)
            or metadata.get("packing") != {"owner": "HIA", "input_unchanged": True,
                "buffer_canaries_unchanged": True, "packer_image_sha256": metadata["packer"]["image_sha256"]}):
        raise ValueError("scope packed frame or static executable differs")
    artifacts[(manifest.parent / "native-local-read.elf").relative_to(output).as_posix()] = digest(executable)
    return {"status": "PASS", "manifest_sha256": sha(manifest), "source_sha256": scope["source_sha256"],
            "image_sha256": scope["image_sha256"], "executable_sha256": digest(executable),
            "frame_sha256": digest(frame), "profile": profile, "members": metadata["members"],
            "packer": metadata["packer"], "artifact_sha256": artifacts, "embedded_layout": layout,
            "entropy_provider": "trusted deterministic fixture", "real_os_entropy_connected": False}


def captured_rows(folder: Path, entry: dict, *, name: str, count: int, raw_bytes: int,
                   raw_sha256: str, controls: bool = False) -> list[dict]:
    if (entry.get("file") != name or type(entry.get("native_rows" if controls else "cases")) is not int
            or entry["native_rows" if controls else "cases"] != count
            or type(entry.get("raw_bytes")) is not int or entry["raw_bytes"] != raw_bytes
            or entry.get("raw_sha256") != raw_sha256):
        raise ValueError("scope retained corpus contract differs: " + name)
    packed = read(folder / name)
    if digest(packed) != entry.get("gzip_sha256") or (controls and entry.get("gzip_bytes") != len(packed)):
        raise ValueError("scope retained compressed corpus changed: " + name)
    raw = gzip.decompress(packed)
    if len(raw) != raw_bytes or digest(raw) != raw_sha256 or not raw.endswith(b"\n"):
        raise ValueError("scope retained complete history bytes differ: " + name)
    lines = raw.splitlines()
    if len(lines) != count:
        raise ValueError("scope retained history row count differs")
    return [json.loads(line) for line in lines]


def check_row(row: dict, *, control: bool) -> None:
    fields = {"session", "target", "input_hex", "code", "output_hex", "scope_state",
              "scope_references", "entropy_calls", "nonce_count"}
    if control:
        fields |= {"native_ordinal", "output_capacity", "export_requested", "injected_fault_reason", "child_events"}
    if not isinstance(row, dict) or set(row) != fields:
        raise ValueError("scope retained row fields differ")
    for name in ("session", "target", "code", "scope_state", "scope_references", "entropy_calls", "nonce_count"):
        if type(row[name]) is not int or not 0 <= row[name] < 1 << 64:
            raise ValueError("scope retained row integer differs")
    if (not 1 <= row["session"] <= 49 or row["target"] not in (5, 6, 7)
            or not 0 <= row["code"] <= 0xffffffff or row["scope_state"] not in (0, 2, 3, 4)
            or row["nonce_count"] > 16384 or (row["scope_state"] != 2 and row["scope_references"] != 0)):
        raise ValueError("scope retained state or status domain differs")
    request, value = bytes.fromhex(row["input_hex"]), bytes.fromhex(row["output_hex"])
    if (request.hex() != row["input_hex"] or value.hex() != row["output_hex"]
            or len(request) > SPECS[row["target"]][4]
            or (row["code"] < 0xffff0000 and (row["code"] != len(value) or len(value) > SPECS[row["target"]][5]))
            or (row["code"] >= 0xffff0000 and value)):
        raise ValueError("scope captured frame/output length differs")
    if not control:
        return
    if (type(row["native_ordinal"]) is not int or not 0 <= row["native_ordinal"] < 17021
            or type(row["output_capacity"]) is not int or not 0 <= row["output_capacity"] <= SPECS[row["target"]][5]
            or type(row["export_requested"]) is not bool
            or not isinstance(row["child_events"], list)
            or (row["injected_fault_reason"] is not None and not isinstance(row["injected_fault_reason"], str))):
        raise ValueError("scope retained control admission differs")
    mutated = False
    for event in row["child_events"]:
        fields = {"caller", "phase", "target", "input_bytes", "output_capacity", "code"}
        if not isinstance(event, dict) or set(event) not in (fields, fields | {"fixture_completion_words"}):
            raise ValueError("scope retained child-event fields differ")
        if any(type(event[key]) is not int or not 0 <= event[key] < 1 << 64 for key in fields):
            raise ValueError("scope retained child event has an invalid scalar")
        authority = {1: {2, 3, 4}, 6: {1, 2, 5, 7}}
        if (event["target"] not in authority.get(event["caller"], set())
                or event["input_bytes"] > SPECS[event["target"]][4]
                or event["output_capacity"] > SPECS[event["target"]][5]
                or event["code"] > 0xffffffff):
            raise ValueError("scope retained child authority or buffer span differs")
        if "fixture_completion_words" in event:
            words = event["fixture_completion_words"]
            if not isinstance(words, list) or len(words) != 14 or any(type(v) is not int or not 0 <= v < 1 << 64 for v in words):
                raise ValueError("scope fault control lost its actual completion words")
            mutated = True
    if mutated != (row["injected_fault_reason"] is not None):
        raise ValueError("scope named fault lost its mutated child completion")


def domain_evidence(metadata: dict, rows: list[dict], faults: list[dict], capacities: list[dict]) -> dict:
    for row in rows:
        check_row(row, control=False)
    for row in (*faults, *capacities):
        check_row(row, control=True)
    control = metadata["native_controls"]
    if (control.get("selection_policy") != "entire session selected when a named child-result fault is installed, before observing the result"
            or type(control.get("total_direct_native_rows")) is not int or control["total_direct_native_rows"] != 17021
            or len(rows) + len(faults) + len(capacities) != 17021):
        raise ValueError("scope disjoint native/reference accounting differs")
    reasons = {phase + 3: f"phase {phase}: replace the child result length" for phase in range(1, 11)}
    reasons.update({index + 14: f"phase 4: corrupt call-footer word at byte {offset}"
                    for index, offset in enumerate((0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 88, 96, 104))})
    reasons.update({27: "phase 4: child result has nonzero bits above u32",
                    29: "phase 8: replace record seal completion after nonce reservation"})
    sessions = {row["session"] for row in rows}
    if (sessions & reasons.keys() or sessions | reasons.keys() != set(range(1, 50))
            or {row["session"] for row in faults} != reasons.keys()
            or any(row["session"] in reasons or row["code"] != 0xfffffffe
                   or row["export_requested"] is not False or row["injected_fault_reason"] is not None for row in capacities)):
        raise ValueError("scope fault/capacity/reference session domains overlap or omit history")
    ledger, prefix = [], 0
    for session, reason in sorted(reasons.items()):
        history = [row for row in faults if row["session"] == session]
        injected = [index for index, row in enumerate(history) if row["injected_fault_reason"] is not None]
        if (len(injected) != 1 or history[injected[0]]["injected_fault_reason"] != reason
                or history[injected[0]]["export_requested"] is not False
                or any(row["export_requested"] is not True for row in history[:injected[0]])
                or [row["native_ordinal"] for row in history]
                != list(range(history[0]["native_ordinal"], history[-1]["native_ordinal"] + 1))):
            raise ValueError("scope named fault history is incomplete or selected after its result")
        prefix += injected[0]
        ledger.append({"session": session, "reason": reason, "native_rows": len(history), "injected_rows": 1,
                       "first_native_ordinal": history[0]["native_ordinal"],
                       "last_native_ordinal": history[-1]["native_ordinal"]})
    if control.get("excluded_sessions") != ledger or prefix != 47:
        raise ValueError("scope exclusion ledger differs from the retained full histories")
    controls = {row["native_ordinal"]: row for row in (*faults, *capacities)}
    if len(controls) != len(faults) + len(capacities):
        raise ValueError("scope control native ordinals overlap")
    replay = iter(rows)
    target_counts, all_sessions = Counter(), set()
    previous_session = 0
    for ordinal in range(17021):
        row = controls.get(ordinal)
        if row is None:
            row = next(replay, None)
        if row is None or row["session"] < previous_session:
            raise ValueError("scope reconstructed direct history is missing or reordered")
        if row["session"] != previous_session:
            if (row["target"] != 7 or row["code"] != 0 or row["scope_state"] != 0
                    or row["scope_references"] != 0 or row["entropy_calls"] != 0 or row["nonce_count"] != 0):
                raise ValueError("scope reconstructed session does not start fresh")
            previous_session = row["session"]
            all_sessions.add(previous_session)
        target_counts[row["target"]] += 1
    if next(replay, None) is not None or all_sessions != set(range(1, 50)) or dict(target_counts) != {5: 16384, 6: 588, 7: 49}:
        raise ValueError("scope direct request/session reconstruction differs")
    output_hash = hashlib.sha256()
    for row in rows:
        output_hash.update(f"{row['code']}:{row['output_hex']}\n".encode())
    if (output_hash.hexdigest() != metadata.get("native_output_sha256")
            or output_hash.hexdigest() != "6ffb0f8a65797307edea097fd5479e7635351dc5a5f98bd6b0d5773bd9984cde"
            or sum(row["code"] >= 0xffff0000 for row in rows) != 344
            or Counter(row["target"] for row in rows) != {5: 16384, 6: 536, 7: 24}):
        raise ValueError("scope replay result bytes or exact native request domains differ")
    return {"total_direct_native_rows": 17021, "reference_rows": 16944, "reference_sessions": 24,
            "fault_history_rows": 74, "fault_sessions": 25, "fault_prefix_rows": 47,
            "capacity_rows": 3, "native_scope_requests": 588, "nonce_preparation_rows": 16384,
            "native_fixture_controls": 49, "native_output_sha256": output_hash.hexdigest(),
            "exclusion_ledger": ledger, "native_cases_added_by_replay": 0,
            "fault_histories_passed_to_original": False, "capacity_controls_passed_to_original": False}


def test_coverage(summary: dict, stderr: str) -> None:
    if set(summary) != {"native_scope_counts"}:
        raise ValueError("scope completed native summary differs")
    exact_counts(summary["native_scope_counts"], COUNTS)
    if stderr.count("\nRan 12 tests in ") != 1 or not stderr.endswith("\nOK\n"):
        raise ValueError("scope requires all twelve test groups without skips or expected failures")


def scope_evidence(root: Path, output: Path, report: dict, summary_fn) -> dict:
    check, summary = summary_fn(output, report, "test_operation_scope.py")
    test_coverage(summary, read(output / "test_operation_scope.py.stderr").decode())
    composition = composition_evidence(root, output, report)
    folder = output / FOLDER
    metadata = object_at(folder / "native-corpus.json")
    reference_names = ("oracle_operation_scope.rs", "scope_oracle/Cargo.toml", "scope_oracle/Cargo.lock",
                       "scope_oracle/build.rs", "scope_oracle/original_access.rs")
    oracle_sources = {name: sha(root / "tests/hia_native" / name) for name in reference_names}
    expected = {"schema": "hepta.runtime.native-operation-scope-corpus.v1", "counts": COUNTS,
                "source_sha256": composition["source_sha256"], "image_sha256": composition["image_sha256"],
                "manifest_sha256": composition["manifest_sha256"],
                "composition_sha256": sha(root / "native/operation_scope_composition.json"),
                "builder_sha256": sha(root / "scripts/hia_native_scope_build.py"),
                "test_sha256": sha(root / "tests/hia_native/test_operation_scope.py"),
                "original_source_sha256": sha(root / "src/mcp/runtime/operation_crypto.rs"),
                "oracle_sources_sha256": oracle_sources,
                "python_reference": {"distribution": "cryptography", "version": "50.0.0"}}
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ValueError("scope corpus original/native/oracle source identity differs")
    rows = captured_rows(folder, metadata["corpus"], name="scope_cases.jsonl.gz", count=16944,
                         raw_bytes=48268172, raw_sha256="eb707ea2b886d4bd75474ecc5d909fcbd009d6ef544097969059a35d2c88e715")
    faults = captured_rows(folder, metadata["native_controls"]["fault_histories"], controls=True,
                           name="scope_fault_sessions.jsonl.gz", count=74, raw_bytes=45349,
                           raw_sha256="4092c61778bc20ed542a2a107749df07d5d621fe2e8e0cbef849f256f38ae776")
    capacities = captured_rows(folder, metadata["native_controls"]["capacity_controls"], controls=True,
                               name="scope_capacity_controls.jsonl.gz", count=3, raw_bytes=3019,
                               raw_sha256="4ba8dac7d0a4afb80ef44a4346e9077b138b10615f264b4e6e16dd40334a1b03")
    domains = domain_evidence(metadata, rows, faults, capacities)
    return {"status": "PASS", "test_groups": 12, "counts": COUNTS, "composition": composition,
            "domains": domains, "corpus_metadata_sha256": sha(folder / "native-corpus.json"),
            "input_sha256": metadata["corpus"]["raw_sha256"],
            "native_output_sha256": metadata["native_output_sha256"],
            "oracle_sources_sha256": oracle_sources, "original_source_sha256": metadata["original_source_sha256"],
            "test_stdout_sha256": check["stdout_sha256"], "test_stderr_sha256": check["stderr_sha256"],
            "retained_inputs": {name: sha(folder / name) for name in CORPUS_FILES},
            "real_os_entropy_connected": False, "concurrent_shared_capability_qualified": False,
            "production_activated": False, "whole_runtime_replaced": False}
