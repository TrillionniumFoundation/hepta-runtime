"""Damage actual retained evidence, require refusal, restore and fully re-admit."""
from pathlib import Path
import argparse
import hashlib
import json
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_workdir_qualification as qualify

sha = lambda raw: hashlib.sha256(raw).hexdigest()


def change_json(raw, operation):
    value = json.loads(raw)
    operation(value)
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def flip(raw):
    assert raw
    return bytes([raw[0] ^ 1]) + raw[1:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qualification", "hepta", "build-root", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--inactive-workspace", action="store_true", required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = args.qualification.resolve(strict=True)
    phase = qualify.obj(root / "result.json")
    manifest = Path(phase["build"]["manifest"])
    bundle = qualify.obj(manifest)
    members = {row["name"]: row for row in bundle["members"]}
    first = "0000-complete-typed-public"
    json_change = lambda operation: lambda raw: change_json(raw, operation)
    tests = [
        ("empty-completed-stdout", root / "native-caller-controls.stdout", lambda raw: b""),
        ("outer-failure", root / "result.json", json_change(lambda v: v["checks"][1].update(exit_code=1))),
        ("outer-not-reaped", root / "result.json", json_change(lambda v: v["checks"][2].update(reaped=False))),
        ("executed-observer-source", ROOT / "tests/hia_native/test_workdir_params.py", lambda raw: raw + b"\n"),
        ("parameter-complete-output", root / "native-parameters/native.bin", flip),
        ("caller-fixture-misclassified", root / "native-caller-controls/result.json",
            json_change(lambda v: v.update(installed_policy_and_os_results_are_explicit_fixtures=False))),
        ("caller-control-omitted", root / "native-caller-controls/result.json",
            json_change(lambda v: v["controls"].pop())),
        ("regex-complete-output", root / "native-installed-regex/literal-mode-0/native.stdout", flip),
        ("regex-observation-forged", root / "native-installed-regex/result.json",
            json_change(lambda v: v["cases"][0]["process"]["events"][0].update(latch=0))),
        ("original-public-output", root / "original/public" / first / "original.stdout", flip),
        ("original-request-input", root / "original/public" / first / "original.input", flip),
        ("original-group-omitted", root / "original/public/result.json", json_change(lambda v: v["groups"].pop())),
        ("original-build-failure", root / "original/result.json", json_change(lambda v: v["checks"][2].update(exit_code=101))),
        ("original-executable", root / "original/target/release/hia-workdir-reference", flip),
        ("original-compiled-source", root / "original/project/owner/oracle_workdir.rs", lambda raw: raw + b"\n"),
        ("fresh-parameter-observation", root / "original/probe-v1/parameters.json",
            json_change(lambda v: v["cases"][0]["observed"].update(result="forged original response"))),
        ("compiled-native-image", manifest.parent / members["caller"]["manifest"].replace("manifest.json", "module.image.bin"), flip),
        ("actual-pack-receipt", manifest.parent / "service-pack.receipt.json", json_change(lambda v: v.update(core_u32=1))),
        ("whole-runtime-overclaim", root / "result.json", json_change(lambda v: v.update(whole_runtime_replaced=True))),
        ("complete-sdk-inventory-omitted", root / "original/result.json", json_change(lambda v: v["sdk_files"].pop(next(iter(v["sdk_files"]))))),
    ]
    report = dict(schema="hepta.workdir.evidence-controls.v1", status="FAIL", accepted=[], refused=[],
        expected_refusals=[name for name, _, _ in tests], semantic_executions_added=0,
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)
    started = time.monotonic()
    def save():
        (args.output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    def admit(label):
        result = qualify.admit_private(root, args.hepta, args.build_root)
        report["accepted"].append(dict(label=label, status=result["status"],
            manifest_sha256=result["manifest_sha256"], source_inventory_sha256=sha(json.dumps(result["source_inventory"], sort_keys=True).encode())))
        save()
        return result
    try:
        baseline = admit("baseline")
        for label, path, mutate in tests:
            original = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
            changed = mutate(original)
            assert changed != original
            reason = None
            try:
                path.chmod(mode | 0o200)
                path.write_bytes(changed)
                try:
                    qualify.admit_private(root, args.hepta, args.build_root)
                except (ValueError, AssertionError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
                    reason = str(error)
                assert reason is not None, "damaged workdir evidence was admitted: " + label
                report["refused"].append(dict(label=label, path=str(path),
                    original_sha256=sha(original), damaged_sha256=sha(changed), reason=reason))
            finally:
                path.chmod(mode | 0o200)
                path.write_bytes(original)
                path.chmod(mode)
            assert path.read_bytes() == original and stat.S_IMODE(path.stat().st_mode) == mode
            assert admit("restored-" + label) == baseline
        assert len(report["refused"]) == 20 and len(report["accepted"]) == 21
        report.update(status="PASS", restored_all_bytes_and_modes=True, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k not in ("accepted", "refused")}, sort_keys=True))


if __name__ == "__main__":
    main()
