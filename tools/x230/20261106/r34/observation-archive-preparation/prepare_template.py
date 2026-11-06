#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create an unsealed R34 collector from the reviewed original R33 source.

Static source transformation only. No collector, archived program or original
auditor is imported or executed. This helper uses fixed local input files.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
REFERENCE = BASE / "r33-observation-archive/sealed-01/archive_r33_observation.py"
REFERENCE_SHA = "d9aedf45f00d9e7a525de89d348aca7081be4df480b747b4464d4fdc0fb313ce"
Q_ARCHIVE_SHA = "488f38422ffca19dc28ecc986fda5218cff090fe8a906053a217eee8e741cb1b"
CI_ARCHIVE_SHA = "9431da8651cfa3e43fe83a1ec3de3f2f85165e20316f2fd8142bacba004abd73"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def replace_once(source, old, new):
    assert source.count(old) == 1, old[:100]
    return source.replace(old, new, 1)


def main():
    raw = REFERENCE.read_bytes()
    assert sha(raw) == REFERENCE_SHA
    original = raw.decode()
    tree = ast.parse(original)
    assignments = {n.targets[0].id: n for n in tree.body if isinstance(n, ast.Assign)
                   and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
    old_pins = ast.literal_eval(assignments["PINNED"].value)
    dynamic = {name.replace("r33", "r34") for name in old_pins
               if name.startswith("campaign-01/") or name in {
                   "campaign-inputs-01.json", "observation-holder-native-01.json",
                   "observation-holder-read-01.json", "observation-postflight-01.json"}
               or name.startswith("external/r16/r33-cancel-recovery-01/")}
    remove = {"lifecycle-materialization-native-01.json", "lifecycle-materialization-read-01.json"}
    static = {name.replace("r33", "r34"): value for name, value in old_pins.items()
              if name.replace("r33", "r34") not in dynamic and name not in remove}
    local_origins = {}

    def local(name, path):
        body = path.read_bytes()
        static[name] = sha(body)
        local_origins[name] = {"local_path": str(path), "bytes": len(body), "sha256": sha(body)}

    generated = BASE / "r34-observation-template-01/generated"
    for path in sorted(generated.iterdir()):
        if path.is_file():
            local("tools-01/" + path.name, path)
    qualified = BASE / "r34-qualified-originals-01"
    for name, local_name in {
        "preparation.json": "preparation.json", "qualification-01/report.json": "report.json",
        "qualification-01/source-map.json": "source-map.json",
        "qualification-01/isolated-tests/summary.json": "isolated-summary.json",
        "qualification-terminal-status-01.json": "qualification-terminal-status-01.json",
    }.items():
        local(name, qualified / local_name)
    local("campaign-inputs-01.example.json", BASE / "r34-observation-template-01/campaign-inputs-01.example.json")
    # The installer materializes this example; the local unmaterialized template
    # has different bytes. These are root's already observed exact remote pins.
    static["lifecycle-inputs-01.example.json"] = "edcfc2eeb7c8937aabfae70b5606111ea209250759e4c0a02f55ce6e7183f27b"
    static["parent-tools-install-01.json"] = "b783a85e4b41e5202305b7739e63eace75c71d4ea65f14fcbe7d05e5ceef30a2"
    source = original.replace("R33", "R34").replace("r33", "r34")
    source = replace_once(source, "REFERENCE_SHA = '296d84668c1703361cb3dfe6b3a8b0849aed561d125f4a39988a44cda21fd7dc'",
                          "REFERENCE_SHA = '" + REFERENCE_SHA + "'")
    source = replace_once(source, "QUALIFICATION_ARCHIVE_SHA = 'fa8a1bfcfe46b96aa59021c7f9ff20695fcc84b224c4ed0be811eda02c550c2f'",
                          "QUALIFICATION_ARCHIVE_SHA = '" + Q_ARCHIVE_SHA + "'")
    source = replace_once(source, "CI_ARCHIVE_SHA = 'bf993f6e81d4f50930c35e7ddf73d229a0264733a1718b34699852e038948210'",
                          "CI_ARCHIVE_SHA = '" + CI_ARCHIVE_SHA + "'")
    source = replace_once(source, "HOLDER_JOB = '1a1aecd302a-fc05-6294'\nLIFECYCLE_MATERIALIZATION_JOB = '1a1aed5c50a-fc05-6301'\nSEALED = True",
                          "ACTUAL = None\nHOLDER_JOB = ACTUAL['holder_job_id'] if ACTUAL is not None else None\nSEALED = ACTUAL is not None")
    source = replace_once(source,
        "NAMESPACE_PATHS = ('lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01')",
        "NAMESPACE_PATHS = ('lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01',\n"
        "                   'lifecycle-materialization-native-01.json', 'lifecycle-materialization-read-01.json')")
    start = source.index("PINNED = ")
    end = source.index("REQUIRED = tuple(PINNED)", start) + len("REQUIRED = tuple(PINNED)")
    source = source[:start] + (
        "STATIC_PINS = " + pprint.pformat(dict(sorted(static.items())), sort_dicts=True, width=120) + "\n"
        "DYNAMIC_REQUIRED = " + pprint.pformat(tuple(sorted(dynamic)), width=120) + "\n"
        "PINNED = {**STATIC_PINS, **(ACTUAL['sha256'] if ACTUAL is not None else {})}\n"
        "REQUIRED = tuple(sorted(set(STATIC_PINS) | set(DYNAMIC_REQUIRED)))"
    ) + source[end:]
    # Both actual reads and verify refuse before touching any input while unsealed.
    guard = "    need(SEALED, 'unsealed R34 collector: actual original receipts are missing')\n"
    for signature in ("def collect():\n", "def summary(kind, data, namespace):\n", "def verify_archive(path, expected_sha):\n"):
        source = replace_once(source, signature, signature + guard)
    source = replace_once(source,
        "    need(SEALED and LIFECYCLE_MATERIALIZATION_JOB is not None\n         and all(isinstance(value, str) and len(value) == 64 for value in PINNED.values()),",
        "    need(SEALED and HOLDER_JOB is not None and set(DYNAMIC_REQUIRED) <= set(PINNED)\n         and all(isinstance(value, str) and len(value) == 64 for value in PINNED.values()),")
    source = replace_once(source,
        "        ('lifecycle-materialization-01', 'lifecycle-materialization', LIFECYCLE_MATERIALIZATION_JOB),\n", "")
    source = replace_once(source,
        "        if label.startswith('observation'):\n            lines = [json.loads(line) for line in stream['stdout']['text'].splitlines() if line]\n            receipt['holder_completion'] = lines[-1] if lines else None\n        else:\n            receipt['stderr_text'] = stream['stderr']['text']\n            receipt['original_gate_message_present'] = 'normal observation campaign did not close and pass' in stream['stderr']['text']\n",
        "        lines = [json.loads(line) for line in stream['stdout']['text'].splitlines() if line]\n        receipt['holder_completion'] = lines[-1] if lines else None\n")
    source = replace_once(source, "    monitor_audit = read('campaign-01/compiler-monitor.audit.json')\n",
        "    monitor_audit = read('campaign-01/compiler-monitor.audit.json')\n"
        "    postflight = read('observation-postflight-01.json')\n"
        "    need(postflight.get('schema') == 'hepta-r34-rejected-observation-owner-postflight/v1'\n"
        "         and postflight.get('original_observation_job_id') == HOLDER_JOB\n"
        "         and postflight.get('normal_lifecycle_started') is False\n"
        "         and postflight.get('lifecycle_materialization_started') is False\n"
        "         and postflight.get('candidate_adopted') is False, 'original postflight must retain unrun lifecycle state')\n")
    source = replace_once(source, "    if monitor.get('sample_count') != len(monitor.get('samples', [])):\n",
        "    if any(namespace.values()):\n"
        "        errors.append('normal lifecycle/materialization paths exist despite the original unrun postflight')\n"
        "    if set(postflight.get('normal_lifecycle_paths_absent', [])) != set(NAMESPACE_PATHS[:3]):\n"
        "        errors.append('original postflight lifecycle absence inventory differs')\n"
        "    if postflight.get('observation_gate_passed') != gates['observation_gate_passed']:\n"
        "        errors.append('original postflight and observation gate differ')\n"
        "    if monitor.get('sample_count') != len(monitor.get('samples', [])):\n")
    old = """        'normal_lifecycle': {'materialization_job_id': LIFECYCLE_MATERIALIZATION_JOB,
            'materialization_native_state': native_receipts['lifecycle-materialization-01']['state'],
            'materialization_native_exit_code': native_receipts['lifecycle-materialization-01']['exit_code'],
            'blocked_by_original_observation_gate': not gate_passed and native_receipts['lifecycle-materialization-01']['original_gate_message_present'],
            'output_presence_observed_during_collection': namespace,
            'performance_ABBA_established': False, 'saturation_established': False},"""
    new = """        'normal_lifecycle': {'materialization_job_id': None,
            'materialization_native_state': None, 'materialization_native_exit_code': None,
            'materialization_started': False, 'normal_lifecycle_started': False,
            'state': 'not_run_after_original_observation_rejection',
            'original_postflight': {'bytes': len(data['observation-postflight-01.json']),
                                   'sha256': sha(data['observation-postflight-01.json'])},
            'output_presence_observed_during_collection': namespace,
            'performance_ABBA_established': False, 'saturation_established': False},"""
    source = replace_once(source, old, new)
    ast.parse(source)
    changed_tree = ast.parse(source)
    before = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    after = {n.name: n for n in changed_tree.body if isinstance(n, ast.FunctionDef)}
    stable = ("need", "sha", "encoded", "stamp", "terminal", "streams_from_reads", "member_path", "source_path", "main")
    checks = {}
    for name in stable:
        a = ast.get_source_segment(original, before[name]).replace("R33", "R34").replace("r33", "r34")
        b = ast.get_source_segment(source, after[name])
        checks[name] = a == b
        assert checks[name], name
    for name in ("collect", "verify_archive"):
        a = ast.get_source_segment(original, before[name]).replace("R33", "R34").replace("r33", "r34")
        b = ast.get_source_segment(source, after[name]).replace(guard, "", 1)
        checks[name + "_except_unsealed_guard"] = a == b
        assert checks[name + "_except_unsealed_guard"], name
    reference_path = HERE / "reference-archive-r33-observation.py"
    collector_path = HERE / "archive_r34_observation.unsealed.py"
    create(reference_path, raw)
    create(collector_path, source.encode())
    preparation = {"schema": "hepta-r34-observation-archive-template/v1", "sealed": False,
        "reference": {"path": str(reference_path), "bytes": len(raw), "sha256": sha(raw)},
        "collector": {"path": str(collector_path), "bytes": len(source.encode()), "sha256": sha(source.encode())},
        "static_pin_count": len(static), "dynamic_required_count": len(dynamic),
        "known_local_originals": local_origins, "checks": checks,
        "original_materialized_lifecycle_example_sha256": static["lifecycle-inputs-01.example.json"],
        "original_parent_install_receipt_sha256": static["parent-tools-install-01.json"],
        "normal_lifecycle_materializer_required_or_executed": False,
        "normal_lifecycle_executed": False, "collector_or_original_auditors_executed": False,
        "future_actual_holder_postflight_and_output_pins": None,
        "limits": {"selected_bytes": 64 * 1024 * 1024, "file_bytes": 8 * 1024 * 1024,
                   "manifest_bytes": 2 * 1024 * 1024, "files": 8192}}
    create(HERE / "preparation.json", encoded(preparation))
    print(json.dumps(preparation, sort_keys=True))


if __name__ == "__main__":
    main()
