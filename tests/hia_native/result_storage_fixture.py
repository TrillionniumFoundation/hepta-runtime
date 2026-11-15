# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Admit complete retained reference streams without executing original code.

The separate original recipes compile locked Rust sources and replay the same
complete requests. Loading these fixtures always records zero original process
executions; their historical receipts are not current qualification receipts.
"""
from pathlib import Path
import gzip
import hashlib
import json
import lzma

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
FIXTURES = Path(__file__).resolve().parent / "fixtures/result_storage_reference"
DOMAIN_CASES = {"safe_dto": 5591, "retention": 6315, "storage_json": 4221, "record_validation": 9361}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def pack(path, raw):
    compressed = gzip.compress(raw, compresslevel=6, mtime=0)
    Path(path).write_bytes(compressed)
    return dict(bytes=len(raw), sha256=SHA(raw), compressed_bytes=len(compressed),
        compressed_sha256=SHA(compressed))


def manifest():
    raw = (FIXTURES / "manifest.json").read_bytes()
    value = json.loads(raw)
    assert value["schema"] == "hepta.result-storage.retained-reference.v1"
    assert value["actual_original_executions"] == 0
    assert value["observation_kind"] == "retained-original-fixture"
    assert set(value["domains"]) == set(DOMAIN_CASES)
    return raw, value


def member(domain, name):
    raw, inventory = manifest()
    row = inventory["domains"][domain]["files"][name]
    assert row["file"] == domain + "/" + name + ".xz"
    path = FIXTURES / row["file"]
    assert path.is_file() and not path.is_symlink()
    compressed = path.read_bytes()
    assert row["compressed"] == dict(bytes=len(compressed), sha256=SHA(compressed))
    data = lzma.decompress(compressed)
    assert (len(data), SHA(data)) == (row["bytes"], row["sha256"])
    return data, row, SHA(raw), inventory["domains"][domain]["original_job_id"]


def retained_bytes(domain, prefix, wire, output, name, *, suffix="jsonl", startup_refusal=False):
    """Match the entire regenerated input and retain complete input/output bytes."""
    stem = (prefix + "/" if prefix else "") + name
    infix = "." + suffix if suffix else ""
    expected, input_row, inventory_sha, original_job = member(domain, stem + ".stdin" + infix)
    assert wire == expected, ("complete retained original input differs", domain, stem)
    stdout, stdout_row, _, _ = member(domain, stem + ".stdout" + infix)
    stderr_name = stem + (".stderr.log" if suffix else ".stderr")
    stderr, stderr_row, _, _ = member(domain, stderr_name)
    historical, _, _, _ = member(domain, stem + ".process.json")
    old = json.loads(historical)
    assert old["stdin_bytes"] == len(wire) and old["stdin_sha256"] == SHA(wire)
    assert old["stdout_bytes"] == len(stdout) and old["stdout_sha256"] == SHA(stdout)
    assert old["stderr_bytes"] == len(stderr) and old["stderr_sha256"] == SHA(stderr)
    assert old["timed_out"] is False and old["reaped"] is True
    if startup_refusal:
        assert old["exit_code"] != 0 and not stdout and not wire
        assert b"runtime config must declare at least one host" in stderr
    else:
        assert old["exit_code"] == 0 and not stderr
        assert len(stdout.splitlines()) == len(wire.splitlines())
    output = Path(output)
    directory = output / (name + ".retained")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = dict(schema="hepta.result-storage.retained-input.v1", domain=domain, profile=prefix,
        name=name, observation_kind="retained-original-fixture", actual_original_executions=0,
        original_observation_job=original_job, fixture_manifest_sha256=inventory_sha,
        historical_receipt_sha256=SHA(historical), input_source=input_row,
        output_source=stdout_row, error_source=stderr_row, cases=len(wire.splitlines()),
        startup_refusal=startup_refusal,
        input=pack(directory / "requests.bin.gz", wire),
        stdout=pack(directory / "stdout.bin.gz", stdout),
        stderr=pack(directory / "stderr.bin.gz", stderr))
    (directory / "receipt.json").write_bytes(encoded(receipt) + b"\n")
    return stdout, receipt


def retained_json(domain, profile, rows, output, name, *, startup_refusal=False):
    wire = b"".join(encoded(row) + b"\n" for row in rows)
    stdout, receipt = retained_bytes(domain, profile, wire, output, name,
        startup_refusal=startup_refusal)
    if startup_refusal:
        return None, receipt
    parsed = [json.loads(line) for line in stdout.splitlines()]
    assert len(parsed) == len(rows)
    return parsed, receipt


def configurations(domain):
    """Return raw administrator profiles with their historical path removed.

    Each fresh runner supplies its own owned state directory. Only that absolute
    test fixture path is replaceable; every actual configuration field stays
    byte-equivalent after JSON decoding and is checked before process startup.
    """
    _, inventory = manifest()
    result = {}
    for name in inventory["domains"][domain]["files"]:
        if name.endswith("/config.json"):
            profile = name.rsplit("/", 1)[0]
            raw, _, _, _ = member(domain, name)
            value = json.loads(raw)
            assert set(value) == {"state_dir", "hosts"}
            assert isinstance(value["state_dir"], str) and value["state_dir"].startswith("/")
            result[profile] = value["hosts"]
    result["uninstalled"] = None
    assert set(result) == {"uninstalled", "empty", "mixed", "hosts-256", "hosts-257"}
    return result
