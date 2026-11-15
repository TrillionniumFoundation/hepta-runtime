"""Admit complete workdir process evidence without executing a semantic owner."""
from pathlib import Path
import argparse
import hashlib
import json
import math
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_workdir_service_build as native

SOURCE_INDEX = "native/workdir_qualification_sources.json"
SOURCE_INDEX_SHA256 = "1fd708aab5a483e8c088e4aba8d09806216a9b0d62dc0487f12ee0e33e65800f"
sha = lambda raw: hashlib.sha256(raw).hexdigest()
require = native.require
FLAGS = ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified")
BOOTSTRAP_SHA256 = "0819e5dedf13bfc4d4e56d6426a81a0ea2efe564aa1b9ac54b86ea69a5be94f3"


def obj(path):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate evidence JSON key")
            result[key] = value
        return result
    value = json.loads(Path(path).read_bytes(), object_pairs_hook=unique)
    require(type(value) is dict, "evidence must be an object")
    return value


def record(raw):
    return dict(bytes=len(raw), sha256=sha(raw))


def duration(value, limit=180):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value < limit,
            "actual process duration differs")


def scopes(value):
    require(all(value.get(key) is False for key in FLAGS), "workdir production/removal scope overclaimed")


def source_inventory(root=ROOT):
    root = Path(root).resolve(strict=True)
    raw = native.file(root, SOURCE_INDEX).read_bytes()
    require(sha(raw) == SOURCE_INDEX_SHA256, "workdir qualification input index differs")
    index = json.loads(raw)
    require(index["schema"] == "hepta.workdir.qualification-sources.v1" and len(index["files"]) == 80,
            "workdir executed input domain differs")
    result = {}
    for name, expected in index["files"].items():
        actual = record(native.file(root, name).read_bytes())
        require(actual == expected, "workdir executed source changed: " + name)
        result[name] = actual
    result[SOURCE_INDEX] = record(raw)
    own = "scripts/hia_native_workdir_qualification.py"
    require(native.file(root, own).read_bytes() == Path(__file__).read_bytes(),
            "selected workdir evidence driver differs")
    result[own] = record(native.file(root, own).read_bytes())
    return result


def frames(raw):
    at = 0
    while at < len(raw):
        require(len(raw) - at >= 8, "truncated complete response prefix")
        count = struct.unpack_from("<Q", raw, at)[0]
        at += 8
        require(0 < count <= len(raw) - at, "truncated complete response body")
        yield raw[at:at + count]
        at += count
    require(at == len(raw), "complete response trailing bytes")


def response(raw, variant):
    rows = []
    for frame in frames(raw):
        if variant == "native":
            require(len(frame) >= 96 and frame[:8] == b"HMWDOB01", "native public envelope differs")
            cn, latch, sn = struct.unpack_from("<3Q", frame, 8)
            require(latch <= 1 and len(frame) == 32 + cn + sn, "native public envelope spans differ")
            call, state = frame[32:32 + cn], frame[32 + cn:]
            require(len(call) >= 32 and call[:8] == b"HMWDCS01"
                    and len(state) >= 32 and state[:8] == b"HRSWR001", "native result/state differs")
            tag, reserved, n = struct.unpack_from("<3Q", call, 8)
            require(tag <= 2 and reserved == 0 and len(call) == 32 + n
                    and struct.unpack_from("<3Q", state, 8) == (1, 0, len(state) - 32),
                    "native result/state spans differ")
            current, text = state[32:], call[32:]
        else:
            require(len(frame) >= 56 and frame[:8] == b"HMWDRS01", "original result differs")
            tag, latch, cn, tn, nn, reserved = struct.unpack_from("<6Q", frame, 8)
            require(tag <= 2 and latch <= 1 and reserved == 0 and len(frame) == 56 + cn + tn + nn,
                    "original result/state spans differ")
            current, text = frame[56:56 + cn], frame[56 + cn:56 + cn + tn]
            frame[56 + cn + tn:].decode()
        text.decode()
        rows.append((tag, latch, current, text))
    return rows


def process_streams(directory, item, variant, expected_sha):
    require(item.get("variant") == variant and type(item.get("pid")) is int and item["pid"] > 0
            and item.get("exit_code") == 0 and item.get("timed_out") is False
            and item.get("timeout_seconds") == 30 and item.get("executable_sha256") == expected_sha,
            "actual public process completion differs")
    duration(item["elapsed_seconds"], 30)
    result = {}
    for name in ("input", "stdout", "stderr", "snapshot"):
        raw = native.file(directory, variant + "." + name).read_bytes()
        require(record(raw) == item["streams"][name], "full public process stream differs")
        result[name] = raw
    require(result["stderr"] == b"" if variant == "native"
            else sha(result["stderr"]) == BOOTSTRAP_SHA256, "actual public process stderr differs")
    return result


def inspect_parameters(directory, cases, bundle):
    directory, cases = Path(directory), Path(cases)
    report = obj(directory / "result.json")
    scopes(report); duration(report["elapsed_seconds"])
    require(report.get("schema") == "hepta.workdir.params-native.v1" and report.get("status") == "PASS"
            and report.get("native_cases") == 680 and report.get("native_entries") == 1416
            and report.get("native_value_calls") == 700 and len(report.get("controls", [])) == 18
            and report.get("original_input_sha256") == sha(cases.read_bytes()), "complete workdir parameter domain differs")
    members = {row["name"]: row for row in bundle["members"]}
    for label, name in (("owner", "params"), ("value", "value")):
        item = report["modules"][label]
        require(item["source_sha256"] == members[name]["source_sha256"]
                and item["image_sha256"] == members[name]["image_sha256"], "actual parameter image differs")
    raw = native.file(directory, "native.bin").read_bytes()
    require(sha(raw) == report["output_sha256"]
            == "df40f1d6085de08d8d7b5a40ef87575b3baeb551d90030fa7ec46c051773870e",
            "complete native parameter output differs")
    original = obj(cases)["cases"]
    outputs = list(frames(raw))
    require(len(original) == len(outputs) == len(report["cases"]) == 680, "parameter rows missing")
    for ordinal, (expected, output, row) in enumerate(zip(original, outputs, report["cases"], strict=True)):
        require(len(output) >= 48 and output[:8] == b"HMWDPR01", "parameter response envelope differs")
        tag, present, reset, path_n, text_n = struct.unpack_from("<5Q", output, 8)
        require(tag <= 1 and present <= 1 and reset <= 2 and len(output) == 48 + path_n + text_n,
                "parameter response spans differ")
        observed = expected["observed"]
        wanted_tag = 0 if observed["code"] == 0 else 1
        text = observed["normalized"] if wanted_tag == 0 else observed["result"]
        require(tag == wanted_tag and output[48 + path_n:] == text.encode()
                and row["ordinal"] == ordinal and row["label"] == expected["label"]
                and row["input_sha256"] == sha(expected["parameters"].encode())
                and row["output_sha256"] == sha(output) and row["original_text_sha256"] == sha(text.encode()),
                "native parameter output differs from actual original")
        if tag == 0:
            value = json.loads(text)
            path = value["path"]
            require(present == int(path is not None)
                    and output[48:48 + path_n] == (path.encode() if path is not None else b"")
                    and reset == (0 if value["reset"] is None else 2 if value["reset"] else 1),
                    "native typed parameter projection differs")
        else:
            require(present == reset == path_n == 0, "failed parameters exposed a typed value")
    labels = ["short", "magic", "reserved", "trailing", "invalid-json", "depth-128", "oversized"]
    labels += ["action-word-" + str(x) for x in (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 88)]
    require([row["label"] for row in report["controls"]] == labels, "parameter refusal domain changed")
    for row in report["controls"]:
        require(row["actual_code"] == (0xfffffffe if row["label"] == "oversized" else 0xffffffff)
                and row["output_unchanged"] is True, "parameter refusal behavior differs")
        if row["label"].startswith("action-word-"):
            require(row["recovery"] is True, "parameter state did not recover")
    return report


def inspect_caller(directory, bundle):
    report = obj(Path(directory) / "result.json")
    scopes(report); duration(report["elapsed_seconds"])
    require(report.get("schema") == "hepta.workdir.caller-controls.v1" and report.get("status") == "PASS"
            and report.get("installed_policy_and_os_results_are_explicit_fixtures") is True
            and report.get("original_method_comparison_in_separate_recipe") is True
            and (report.get("control_count"), report.get("actual_caller_entries"),
                 report.get("actual_parameter_entries"), report.get("actual_value_calls")) == (193, 1995, 408, 407),
            "workdir explicit caller controls differ")
    members = {row["name"]: row for row in bundle["members"]}
    require(set(report["modules"]) == {"caller", "params", "context", "client", "state", "value", "path"},
            "workdir caller-control module domain differs")
    for name, value in report["modules"].items():
        require(value == {key: members[name][key] for key in ("source_sha256", "image_sha256")},
                "workdir caller-control native image differs")
    expected = []
    for phase in range(1, 12):
        for offset in range(0, 96, 8):
            expected.append(dict(kind="forged-action", phase=phase, offset=offset,
                output_unchanged=True, existing_state_unchanged=True, recovery=True))
        expected.append(dict(kind="forged-child-magic", phase=phase,
            output_unchanged=True, existing_state_unchanged=True, recovery=True))
    for label in [*("short-" + str(x) for x in range(40)), "magic", "trailing", "reserved",
                  "metadata-flag", "parameter-limit", "metadata-limit", "startup-replacement"]:
        expected.append(dict(kind="private-frame", label=label, output_unchanged=True,
            trusted_mode_unchanged=True, existing_state_unchanged=True, recovery=True))
    expected += [dict(kind="typed-parameter-before-metadata-and-latch", actual_child_order=[1]),
        dict(kind="reset-bypasses-path-and-configuration", actual_child_order=[1, 2, 3, 3]),
        dict(kind="absent-configuration-bypasses-preflight", actual_child_order=[1, 2, 3, 4, 5, 7, 8, 3])]
    require(report["controls"] == expected and len(expected) == 193, "caller continuation/control inventory differs")
    return report


def inspect_regex(directory, source_root, bundle, manifest_sha, original_sha=None):
    directory = Path(directory)
    report = obj(directory / "result.json")
    scopes(report); duration(report["elapsed_seconds"])
    expected = dict(native_processes=18, native_requests=36, native_startup_refusals=6,
        original_processes=18 if original_sha else 0, original_requests=36 if original_sha else 0,
        original_startup_refusals=6 if original_sha else 0)
    require(report["status"] == "PASS" and report["schema"] == "hepta.workdir.installed-regex-comparison.v1"
            and report["actual_original"] is bool(original_sha)
            and report["public_sdk_routing_qualified"] is False and report["remote_execution_qualified"] is False
            and report["manifest_sha256"] == manifest_sha and report["native_sha256"] == native.ELF
            and report["expected_counts"] == expected and all(report.get(k) == v for k, v in expected.items())
            and report["source_sha256"] == sha(native.file(source_root, "tests/hia_native/test_workdir_service_regex.py").read_bytes()),
            "workdir installed regex domain differs")
    valid = ("literal", "character-class", "unicode-property", "anchored-wrapper-alternation",
             "size-bound-accepted", "ordered-multiple")
    labels = [name + "-mode-" + str(mode) for name in valid for mode in (0, 1)]
    labels += ["syntax", "unicode-size", "size-bound-refused", "invalid-byte",
               "regex-before-later-action", "earlier-action-before-regex"]
    variants = ("native", "original") if original_sha else ("native",)
    require([(row["label"], row["process"]["variant"]) for row in report["cases"]]
            == [(name, variant) for name in labels for variant in variants], "regex scenario order differs")
    pairs = {}
    for row in report["cases"]:
        label, process = row["label"], row["process"]
        variant = process["variant"]
        success = labels.index(label) < 12
        require(type(process.get("pid")) is int and process["pid"] > 0 and process["timed_out"] is False
                and process["reaped"] is True and process["timeout_seconds"] == 30
                and process["exit_code"] == (0 if success else 78)
                and process["executable_sha256"] == (native.ELF if variant == "native" else original_sha),
                "actual regex process completion differs")
        duration(process["elapsed_seconds"], 30)
        stored = obj(directory / label / (variant + ".process.json"))
        require(stored == process, "retained regex process differs")
        streams = {}
        for name in ("input", "stdout", "stderr", "snapshot"):
            raw = native.file(directory / label, variant + "." + name).read_bytes()
            require(record(raw) == process[name], "complete regex process stream differs")
            streams[name] = raw
        require(streams["snapshot"] == (b"HMWINIT1" + struct.pack("<3Q", row["mode"], 0, 0)
                if variant == "native" else b""), "trusted regex connection snapshot differs")
        if success:
            decoded = response(streams["stdout"], variant)
            require(len(decoded) == 3 and len(list(frames(streams["input"]))) == 3,
                    "regex workdir response/request missing")
            events = [dict(label=name, tag=tag, latch=latch, current_hex=current.hex(), text_hex=text.hex())
                for name, (tag, latch, current, text) in zip(("set-sub", "reset", "set-other"), decoded, strict=True)]
            require(process["events"] == events and all(row["tag"] == 0 and row["latch"] == 1 for row in events),
                    "actual installed-regex workdir state differs")
            require(streams["stderr"] == b"" if variant == "native" else sha(streams["stderr"]) == BOOTSTRAP_SHA256,
                    "actual regex process stderr differs")
        else:
            require(streams["input"] == streams["stdout"] == b"" and process["events"] == []
                    and streams["stderr"] == bytes.fromhex(row["error_hex"]) + b"\n", "regex startup refusal differs")
        pairs[(label, variant)] = process["events"]
    if original_sha:
        require(all(pairs[(name, "native")] == pairs[(name, "original")] for name in labels),
                "native and actual original regex workdir states differ")
    return report


def public_groups():
    result = [("complete-typed-public", 680)]
    result += [("paths-" + policy + "-" + str(mode), 59) for mode in (0, 1) for policy in ("absent", "allowed", "denied")]
    result += [("unicode-trim-absent", 116), ("unicode-trim-allowed", 116)]
    contexts = ("metadata", "legacy", "current-empty", "current-invalid", "current-experimental-null",
                "relative", "missing", "file", "spelling")
    result += [("context-" + policy + "-" + str(mode) + "-" + name, 4) for mode in (0, 1)
        for policy in ("absent", "allowed", "denied") for name in contexts]
    result += [(name, 6) for name in ("relative-empty", "relative-dot", "relative-sub", "raw-root")]
    result += [("environment-" + name, 2) for name in ("absent", "empty", "invalid-utf8")]
    return result + [("remote-policy-refusals", 6), ("complete-parameter-domain", 15),
                     ("simultaneous-full-domains-0", 2), ("simultaneous-full-domains-1", 2)]


def inspect_public(directory, original_sha, manifest_sha):
    directory = Path(directory)
    report = obj(directory / "result.json")
    scopes(report); duration(report["elapsed_seconds"])
    require(report["status"] == "PASS" and report["schema"] == "hepta.workdir.public-original-comparison.v1"
            and report["native_executable_sha256"] == native.ELF
            and report["original_executable_sha256"] == original_sha
            and report["native_manifest_sha256"] == manifest_sha
            and report["actual_native_processes"] == report["actual_original_processes"] == 74
            and report["actual_native_requests"] == report["actual_original_requests"] == 1537
            and report["exact_response_bytes_and_raw_session_state"] is True
            and report["actual_filesystem"] is True and report["actual_original_public_method"] is True
            and report["actual_original_rmcp_context"] is True and report["remote_execution_qualified"] is False,
            "full public workdir original domain differs")
    require([(row["label"], row["count"]) for row in report["groups"]] == public_groups()
            and len(report["processes"]) == 148, "public workdir complete group inventory differs")
    for index, group in enumerate(report["groups"]):
        require(group["directory"] == f"{index:04d}-" + group["label"], "public group directory differs")
        folder = directory / group["directory"]
        pair = {}
        for offset, variant in enumerate(("native", "original")):
            process = obj(folder / (variant + ".json"))
            require(process == report["processes"][index * 2 + offset], "public process record omitted or replaced")
            streams = process_streams(folder, process, variant, native.ELF if variant == "native" else original_sha)
            rows = response(streams["stdout"], variant)
            requests = list(frames(streams["input"]))
            require(len(rows) == len(requests) == group["count"], "public request/result missing")
            pair[variant] = (rows, requests, streams["snapshot"])
        require(pair["native"][0] == pair["original"][0], "actual public outputs/raw session state differ")
        snapshot = pair["native"][2]
        require(len(snapshot) >= 32 and snapshot[:8] == b"HMWINIT1" and pair["original"][2] == b"",
                "public connection snapshot differs")
        mode, present, legacy_n = struct.unpack_from("<3Q", snapshot, 8)
        require(mode == group["mode"] and present <= 1 and len(snapshot) == 32 + legacy_n, "public trusted mode differs")
        for case, observed, left, right in zip(group["cases"], pair["native"][0], pair["native"][1], pair["original"][1], strict=True):
            require(len(left) >= 40 and left[:8] == b"HMWDCR01" and len(right) >= 64 and right[:8] == b"HMWDRQ01",
                    "public actual request envelope differs")
            pn, mp, mn, zero = struct.unpack_from("<4Q", left, 8)
            command, rm, rp, rmn, rln, rpn, rz = struct.unpack_from("<7Q", right, 8)
            require(mp <= 1 and zero == rz == 0 and len(left) == 40 + pn + mn
                    and len(right) == 64 + rmn + rln + rpn and command == 1 and rm == mode and rp == present
                    and rln == legacy_n and rpn == pn and right[64 + rmn:64 + rmn + rln] == snapshot[32:]
                    and right[64 + rmn + rln:] == left[40:40 + pn]
                    and right[64:64 + rmn] == (left[40 + pn:] if mp else b"{}"),
                    "public actual native/original request inputs differ")
            tag, latch, current, text = observed
            require(case["parameters_bytes"] == pn and case["parameters_sha256"] == sha(left[40:40 + pn])
                    and case["metadata_sha256"] == sha(left[40 + pn:])
                    and case["tag"] == tag and case["latch"] == latch
                    and case["current_bytes"] == len(current) and case["current_sha256"] == sha(current)
                    and case["text_bytes"] == len(text) and case["text_sha256"] == sha(text)
                    and case["full_bytes_equal"] is True, "public summary differs from complete process bytes")
    return report


def outer_check(directory, check, expected_name):
    require(check.get("name") == expected_name and type(check.get("pid")) is int and check["pid"] > 0
            and check.get("exit_code") == 0 and check.get("timed_out") is False and check.get("reaped") is True
            and check.get("timeout_seconds") == 180, "outer workdir process did not complete")
    duration(check["elapsed_seconds"])
    result = {}
    for channel in ("stdout", "stderr"):
        raw = native.file(directory, expected_name + "." + channel).read_bytes()
        require(len(raw) == check[channel + "_bytes"] and sha(raw) == check[channel + "_sha256"],
                "completed workdir process log differs")
        result[channel] = raw
    return result


def inspect_original(directory, source_root, bundle, manifest_sha):
    directory, source_root = Path(directory), Path(source_root)
    report = obj(directory / "result.json")
    scopes(report); duration(report["elapsed_seconds"])
    require(report["schema"] == "hepta.workdir.fresh-original-comparison.v1" and report["status"] == "PASS"
            and report["source_unchanged"] is True and report["rust_version"].startswith("rustc 1.95.0 ")
            and report["locked_registry_dependencies"] == 100 and report["sdk_installed_files_verified"] == 175
            and len(report["sdk_files"]) == 175 and report["sdk_crate_sha256"]
                == "5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898"
            and report["native_manifest_sha256"] == manifest_sha and report["native_executable_sha256"] == native.ELF
            and report["rust_runtime_fallback"] is False and report["remote_effects_are_unreachable_fences"] is True
            and report["remote_execution_qualified"] is False, "actual original build completion differs")
    reference = source_root / "tests/hia_native/workdir_oracle"
    identity = obj(reference / "source-identity.json")
    require(sha((reference / "source-identity.json").read_bytes()) == report["original_source_identity_sha256"]
            and report["original_project_files"] == identity["files"], "original compiled source identity differs")
    for name, expected in identity["files"].items():
        require(record(native.file(reference, name).read_bytes()) == expected
                and record(native.file(directory / "project", name).read_bytes()) == expected,
                "retained original compiler input differs")
    for name, digest in report["source_sha256"].items():
        require(sha(native.file(source_root, name).read_bytes()) == digest, "original comparison driver changed")
    binary_sha = report["original_executable_sha256"]
    require(sha(native.file(directory, "target/release/hia-workdir-reference").read_bytes()) == binary_sha,
            "actual original executable changed")
    names = ("rust-version", "format-check", "build", "original-probe", "fresh-parameter-join", "complete-public", "installed-regex")
    require([c["name"] for c in report["checks"]] == list(names), "actual Rust recipe process omitted")
    logs = {name: outer_check(directory, check, name) for name, check in zip(names, report["checks"], strict=True)}
    require(logs["rust-version"]["stdout"].decode() == report["rust_version"]
            and logs["format-check"]["stdout"] == logs["format-check"]["stderr"] == b""
            and all(word in report["checks"][2]["command"] for word in ("build", "--release", "--locked", "--offline", "hia-workdir-reference")),
            "actual locked Rust invocation differs")
    parameters = inspect_parameters(directory / "parameters", directory / "probe-v1/parameters.json", bundle)
    public = inspect_public(directory / "public", binary_sha, manifest_sha)
    regex = inspect_regex(directory / "regex", source_root, bundle, manifest_sha, binary_sha)
    for name, stored, field, omit in (("fresh-parameter-join", parameters, "parameters", {"cases", "controls", "modules"}),
            ("complete-public", public, "public", {"groups", "processes"}),
            ("installed-regex", regex, "regex", {"cases"})):
        expected = {k: v for k, v in stored.items() if k not in omit}
        require(json.loads(logs[name]["stdout"]) == report[field] == expected and logs[name]["stderr"] == b"",
                "actual original replay stdout differs")
    probe = obj(directory / "probe-v1/result.json")
    require(probe == report["probe"] == json.loads(logs["original-probe"]["stdout"])
            and probe["status"] == "PASS" and probe["typed_cases"] == 680
            and probe["public_cases"] == 15 and probe["priority_cases"] == 3
            and probe["accepted"] == 36 and probe["rejected"] == 644
            and probe["original_binary_sha256"] == binary_sha, "fresh original probe domain differs")
    for process, name, count in zip(probe["processes"], ("parameters", "public", "latch-priority"), (680, 15, 3), strict=True):
        require(process["name"] == name and process["exit_code"] == 0 and process["actual_original_process"] is True,
                "original probe process incomplete")
        for key, suffix in (("input", "input.bin"), ("stdout", "stdout"), ("stderr", "stderr")):
            raw = native.file(directory / "probe-v1", name + "." + suffix).read_bytes()
            require(len(raw) == process[key + "_bytes"] and sha(raw) == process[key + "_sha256"],
                    "actual original probe stream changed")
            if key in ("input", "stdout"):
                require(len(list(frames(raw))) == count, "actual original probe rows missing")
        case_file = obj(directory / "probe-v1" / (name + ".json"))
        require(case_file["process"] == process and len(case_file["cases"]) == count,
                "original retained probe differs")
        observed = response(native.file(directory / "probe-v1", name + ".stdout").read_bytes(), "original")
        for case, (tag, latch, current, text) in zip(case_file["cases"], observed, strict=True):
            require(case["observed"]["code"] == tag and case["observed"]["latch"] == latch
                    and bytes.fromhex(case["observed"]["current_hex"]) == current
                    and case["observed"]["result"].encode() == text,
                    "retained original observation differs from actual process output")
    return report


def admit_private(directory, hepta, build_root, *, source_root=ROOT):
    directory, source_root = Path(directory).resolve(strict=True), Path(source_root).resolve(strict=True)
    source_before = source_inventory(source_root)
    report = obj(directory / "result.json")
    scopes(report); duration(report["elapsed_seconds"], 600)
    require(report["schema"] == "hepta.workdir.portable-qualification.v1" and report["status"] == "PASS"
            and report["source_unchanged"] is True and report["source_files"] == 80
            and report["remote_execution_qualified"] is False and report["fresh_full_cold_gate"] is False,
            "actual portable workdir phase incomplete")
    names = ("native-build", "native-parameters", "native-caller-controls", "native-installed-regex", "workdir-rust-compare")
    require([c["name"] for c in report["checks"]] == list(names), "portable process inventory differs")
    logs = {name: outer_check(directory, check, name) for name, check in zip(names, report["checks"], strict=True)}
    require(all(log["stderr"] == b"" for log in logs.values()), "portable phase emitted an error")
    manifest_path = Path(report["build"]["manifest"])
    require(manifest_path.resolve(strict=True).is_relative_to(Path(build_root).resolve(strict=True)),
            "portable manifest escaped the selected build root")
    bundle = native.verify_bundle(manifest_path, hepta, build_root, source_root=source_root)
    manifest_sha = sha(manifest_path.read_bytes())
    require(json.loads(logs["native-build"]["stdout"]) == report["build"]
            and report["build"]["elf_sha256"] == native.ELF, "actual native build stdout differs")
    parameters = inspect_parameters(directory / "native-parameters", source_root / "tests/hia_native/workdir_parameter_cases.json", bundle)
    caller = inspect_caller(directory / "native-caller-controls", bundle)
    regex = inspect_regex(directory / "native-installed-regex", source_root, bundle, manifest_sha)
    original = inspect_original(directory / "original", source_root, bundle, manifest_sha)
    for name, stored, field, omit in (("native-parameters", parameters, "parameters", {"cases", "controls", "modules"}),
            ("native-caller-controls", caller, "caller", {"controls", "modules"}),
            ("native-installed-regex", regex, "regex", {"cases"}),
            ("workdir-rust-compare", original, "original", {"checks", "sdk_files", "original_project_files"})):
        expected = {k: v for k, v in stored.items() if k not in omit}
        require(json.loads(logs[name]["stdout"]) == report[field] == expected, "portable actual stdout differs")
    require(source_inventory(source_root) == source_before, "workdir source changed during evidence admission")
    return dict(schema="hepta.workdir.complete-evidence.v1", status="PASS", source_inventory=source_before,
        manifest_sha256=manifest_sha, native_executable_sha256=native.ELF,
        actual_native_suites=3, actual_original_recipe_checks=7, typed_parameter_cases=680,
        explicit_caller_controls=193, public_requests_per_side=1537, public_processes_per_side=74,
        original_regex_requests_per_side=36, original_regex_processes_per_side=18,
        native_calls_added_by_evidence_admission=0, production_activated=False,
        whole_runtime_replaced=False, old_stack_removal_qualified=False, remote_execution_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", required=True, type=Path)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--build-root", required=True, type=Path)
    parser.add_argument("--source-root", default=ROOT, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = admit_private(args.qualification, args.hepta, args.build_root, source_root=args.source_root)
    with args.output.open("xb") as stream:
        stream.write((json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
    print(json.dumps({k: v for k, v in result.items() if k != "source_inventory"}, sort_keys=True))


if __name__ == "__main__":
    main()
