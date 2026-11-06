#!/usr/bin/env python3
"""Build the create-only D1 archive03 source and seven new metadata inputs.

This program only reads exact local originals, hashes/compares AST/source and
writes new preparation files. It never imports or executes a collector, test,
auditor, compiler or host API.
"""
import ast
import hashlib
import json
from pathlib import Path

LOCAL = Path("/tmp/hepta-runtime-recovery-20261106")
OUT = LOCAL / "d1-archive-preparation-03"
REMOTE = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
BASE = LOCAL / "d1-archive-preparation-02"
OLD = {
    "01": {
        "local": LOCAL / "d1-qualification-archive-sealed-01/archive_d1_qualification.py",
        "path": str(REMOTE / "archive_d1_qualification_01.py"),
        "bytes": 55645,
        "sha256": "e8d151daf83577367432d0913e0783ca2cce9bd62fdb8e8e3e156823b1baa444",
        "git_blob": "0a9c96080f43aee5c1aeb2b327b3f36f47a346b0",
    },
    "02": {
        "local": LOCAL / "d1-qualification-archive-sealed-02/archive_d1_qualification.py",
        "path": str(REMOTE / "archive_d1_qualification_02.py"),
        "bytes": 58076,
        "sha256": "67e681a58af261c11d5de8d470ff25a0d43abf2a84613ebb0303c6df7d97944c",
        "git_blob": "7e46ad1ca5f3846e7a501f5bdb2c3c02d308dae8",
    },
}


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def assignment(source, name, value):
    tree = ast.parse(source)
    matches = [node for node in tree.body if isinstance(node, ast.Assign)
               and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id == name]
    assert len(matches) == 1
    lines = source.splitlines(True)
    node = matches[0]
    return "".join(lines[:node.lineno - 1]) + name + " = " + repr(value) + "\n" + "".join(lines[node.end_lineno:])


def function_sources(source):
    lines = source.splitlines(True)
    return {node.name: "".join(lines[node.lineno - 1:node.end_lineno])
            for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}


def main():
    assert not OUT.exists()
    original = (BASE / "archive_d1_qualification.py").read_bytes()
    assert identity(original) == {"bytes": 56606, "sha256": "5215519dbf168e11d4d13c2c6941be73959cb6217f343b499f4d3b6b75e146cc"}
    source = original.decode()
    old_pins = json.loads((BASE / "pinned-originals.json").read_bytes())
    pins = dict(old_pins)
    removed = pins.pop("archive_d1_qualification_01.py")
    assert removed == {"bytes": OLD["01"]["bytes"], "sha256": OLD["01"]["sha256"]}
    additions = {}
    references = {}
    for attempt, row in OLD.items():
        raw = row["local"].read_bytes()
        assert identity(raw) == {key: row[key] for key in ("bytes", "sha256")}
        assert hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest() == row["git_blob"]
        info_raw = (LOCAL / "d1-archive-script-file-info-originals" / (attempt + ".json")).read_bytes()
        info = json.loads(info_raw)
        assert info["path"] == row["path"] and info["size"] == row["bytes"] and info["sha256"] == row["sha256"]
        assert isinstance(info["version"], str) and info["version"]
        assert info["metadata"]["uid"] == info["metadata"]["gid"] == 1000
        assert info["metadata"]["link_count"] == 1 and info["metadata"]["metadata_platform"] == "linux"
        member = "provenance/qualification-archive-attempt-" + attempt + "-source-file-info.json"
        additions[member] = info_raw
        references[attempt] = {
            "source": {key: row[key] for key in ("path", "bytes", "sha256", "git_blob")},
            "repository": "TrillionniumFoundation/hepta-runtime",
            "git_blob_url": "https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/git/blobs/" + row["git_blob"],
            "file_info_member": member,
            "file_info_identity": identity(info_raw),
            "file_info_version": info["version"],
            "source_raw_in_tar": False,
            "scope": "Original tool source is preserved as a separate immutable Git object; this archive retains only its identity and original file_info receipt.",
        }
    external = {
        "schema": "hepta-d1-qualification-archive-external-tool-sources/v1",
        "sources": references,
        "code_bodies_are_tar_members": False,
        "source_content_reencoded_or_obfuscated_into_tar": False,
        "source_exclusion_reason": "Collector source contains its own content-detector literal. Preserve code separately instead of altering the unchanged archive scanner.",
        "credential_scanner_unchanged": True,
        "qualified_data_source_harness_or_case_logs_removed": False,
    }
    additions["provenance/qualification-archive-external-tool-sources.json"] = encode(external)
    failure_dir = LOCAL / "d1-archive-attempt-02-originals"
    native_raw, read_raw, start_raw = [(failure_dir / name).read_bytes() for name in ("native.json", "read.json", "start.json")]
    native, read, start = [json.loads(raw) for raw in (native_raw, read_raw, start_raw)]
    assert native["job_id"] == read["job_id"] == start["job"]["id"] == "1a1b01cee00-fc05-6e22"
    assert native["state"] == "failed" and native["exit_code"] == 1
    assert native["output_complete"] is True and native["output_durable"] is True
    assert start["launch"]["ok"] is True and start["reused"] is False
    assert start["job"]["args"] == ["-B", OLD["02"]["path"], "--kind", "qualification"]
    streams = {}
    for channel in ("stdout", "stderr"):
        value = read[channel]
        body = bytes.fromhex(value["bytes_hex"])
        assert value["offset"] == 0 and value["next_offset"] == value["size"] == len(body)
        assert len(body) == native["log_bytes"][channel]["seen"] == native["log_bytes"][channel]["stored"]
        assert value["eof"] is True and value["text"] == body.decode("utf-8", errors="replace")
        streams[channel] = body
    error = "ValueError: private-key material detected; archive was not written: archive_d1_qualification_01.py\n"
    assert streams == {"stdout": b"", "stderr": error.encode()} and len(streams["stderr"]) == 99
    note = {
        "schema": "hepta-d1-qualification-archive-attempt-02-failure/v1",
        "qualification_job_id": "1a1aff8769c-fc05-6d26",
        "qualification_reexecuted": False,
        "tests_or_original_auditor_reexecuted": False,
        "archive_job_id": native["job_id"], "archive_state": "failed", "archive_exit_code": 1,
        "archive_stdout_bytes": 0, "archive_stderr_bytes": 99, "original_error": error,
        "cause": "Archive02 selected archive01 collector source, whose own detector literal triggered the unchanged content scan.",
        "correction": "Archive03 keeps both original tool sources as separate Git objects and original file_info references, retains both failures, and leaves the scanner and qualified-data selection unchanged.",
        "prior_archive_script_sha256": OLD["02"]["sha256"], "prior_archive_script_git_blob": OLD["02"]["git_blob"],
        "failed_before_archive_write_branch_by_source_control_flow": True,
        "remote_output_absence_independently_probed_by_this_builder": False,
        "optimization_measurement_or_qualification_attempt": False,
    }
    additions.update({
        "provenance/qualification-archive-attempt-02-native.json": native_raw,
        "provenance/qualification-archive-attempt-02-read.json": read_raw,
        "provenance/qualification-archive-attempt-02-start.json": start_raw,
        "provenance/qualification-archive-attempt-02-failure.json": encode(note),
    })
    assert len(additions) == 7
    for name, raw in additions.items():
        assert name not in pins
        pins[name] = identity(raw)
    assert len(pins) == 69
    source = assignment(source, "PINNED", dict(sorted(pins.items())))
    source = assignment(source, "REQUIRED", tuple(sorted(pins)))
    anchor = "    first_terminal = json.loads(data['provenance/qualification-archive-attempt-01-native.json'])\n"
    external_check = """    external_sources = json.loads(data['provenance/qualification-archive-external-tool-sources.json'])
    need(external_sources['schema'] == 'hepta-d1-qualification-archive-external-tool-sources/v1'
         and set(external_sources['sources']) == {'01', '02'}
         and external_sources['code_bodies_are_tar_members'] is False
         and external_sources['source_content_reencoded_or_obfuscated_into_tar'] is False
         and external_sources['credential_scanner_unchanged'] is True
         and external_sources['qualified_data_source_harness_or_case_logs_removed'] is False,
         'external tool-source reference scope differs')
    for attempt, external in external_sources['sources'].items():
        source_identity = external['source']
        expected_path = str(ROOT / ('archive_d1_qualification_' + attempt + '.py'))
        info_name = 'provenance/qualification-archive-attempt-' + attempt + '-source-file-info.json'
        file_info = json.loads(data[info_name])
        need(source_identity['path'] == expected_path
             and external['repository'] == 'TrillionniumFoundation/hepta-runtime'
             and external['git_blob_url'] == 'https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/git/blobs/' + source_identity['git_blob']
             and len(source_identity['git_blob']) == 40
             and all(character in '0123456789abcdef' for character in source_identity['git_blob'])
             and external['file_info_member'] == info_name
             and external['file_info_identity'] == {'bytes': len(data[info_name]), 'sha256': sha(data[info_name])}
             and file_info['path'] == source_identity['path'] and file_info['size'] == source_identity['bytes']
             and file_info['sha256'] == source_identity['sha256']
             and file_info['version'] == external['file_info_version']
             and file_info['metadata']['uid'] == file_info['metadata']['gid'] == 1000
             and file_info['metadata']['link_count'] == 1 and file_info['metadata']['metadata_platform'] == 'linux'
             and external['source_raw_in_tar'] is False
             and Path(expected_path).name not in data,
             'external original collector identity or raw file_info differs')
    result['external_archive_tool_sources'] = external_sources
"""
    assert source.count(anchor) == 1
    source = source.replace(anchor, external_check + anchor)
    old_check = "         and sha(data['archive_d1_qualification_01.py']) == first_failure['prior_archive_script_sha256'],\n"
    new_check = "         and external_sources['sources']['01']['source']['sha256'] == first_failure['prior_archive_script_sha256'],\n"
    assert source.count(old_check) == 1
    source = source.replace(old_check, new_check)
    marker = "    result['archive_attempt_01_failure'] = first_failure\n"
    second_check = """    second_terminal = json.loads(data['provenance/qualification-archive-attempt-02-native.json'])
    native_terminal(second_terminal, '1a1b01cee00-fc05-6e22', 'failed', 1)
    second_streams = original_streams(json.loads(data['provenance/qualification-archive-attempt-02-read.json']), second_terminal)
    second_start = json.loads(data['provenance/qualification-archive-attempt-02-start.json'])
    second_failure = json.loads(data['provenance/qualification-archive-attempt-02-failure.json'])
    need(second_start['job']['id'] == second_terminal['job_id'] and second_start['launch']['ok'] is True
         and second_start['reused'] is False
         and second_start['job']['args'] == ['-B', str(ROOT / 'archive_d1_qualification_02.py'), '--kind', 'qualification']
         and second_streams['stdout'] == b'' and len(second_streams['stderr']) == 99
         and second_streams['stderr'] == second_failure['original_error'].encode('utf-8')
         and second_failure['archive_job_id'] == second_terminal['job_id']
         and second_failure['qualification_job_id'] == ACTUAL['qualification_job_id']
         and second_failure['archive_exit_code'] == 1 and second_failure['qualification_reexecuted'] is False
         and second_failure['tests_or_original_auditor_reexecuted'] is False
         and external_sources['sources']['02']['source']['sha256'] == second_failure['prior_archive_script_sha256']
         and external_sources['sources']['02']['source']['git_blob'] == second_failure['prior_archive_script_git_blob'],
         'original archive02 scan rejection provenance differs')
    result['archive_attempt_02_failure'] = second_failure
    result['original_qualification_or_measurement_retried'] = False
"""
    assert source.count(marker) == 1
    source = source.replace(marker, marker + second_check)
    assert source.count("base = root / 'qualification-evidence-02'") == 1
    source = source.replace("base = root / 'qualification-evidence-02'", "base = root / 'qualification-evidence-03'")
    ast.parse(source)
    old_functions, new_functions = function_sources(original.decode()), function_sources(source)
    assert set(old_functions) == set(new_functions)
    changed = [name for name in old_functions if old_functions[name] != new_functions[name]]
    assert changed == ["summary", "create_archive"], changed
    assert new_functions["create_archive"].replace("qualification-evidence-03", "qualification-evidence-02") == old_functions["create_archive"]
    assert new_functions["collect"] == old_functions["collect"] and new_functions["verify_archive"] == old_functions["verify_archive"]
    assert new_functions["qualified_summary"] == old_functions["qualified_summary"]
    for name, raw in additions.items():
        # This is a static check on the seven newly authored metadata files, not execution of the collector.
        assert b"PRIVATE KEY-----" not in raw and b"openssh-key-v1\0" not in raw, name
    template = source.encode()
    sealer = (BASE / "seal_collector.py").read_text()
    assert sealer.count(identity(original)["sha256"]) == 1
    sealer = sealer.replace(identity(original)["sha256"], identity(template)["sha256"])
    ast.parse(sealer)
    out_source = OUT / "archive_d1_qualification.py"
    OUT.mkdir(mode=0o700)
    create(out_source, template)
    create(OUT / "seal_collector.py", sealer.encode())
    create(OUT / "pinned-originals.json", encode(pins))
    for name, raw in additions.items():
        create(OUT / "input-originals" / name, raw)
    for attempt, row in OLD.items():
        create(OUT / "external-source-originals" / ("archive_d1_qualification_" + attempt + ".py"), row["local"].read_bytes())
    revision = {
        "schema": "hepta-d1-qualification-archive-revision/v1", "revision": 3,
        "prior_template": identity(original), "template": identity(template),
        "output_prefix": "qualification-evidence-03",
        "removed_raw_tool_member": {"name": "archive_d1_qualification_01.py", **removed},
        "external_source_originals": {attempt: {key: row[key] for key in ("path", "bytes", "sha256", "git_blob")} for attempt, row in OLD.items()},
        "new_metadata_inputs": {name: identity(raw) for name, raw in additions.items()},
        "fixed_originals": len(pins), "unchanged_original_data_pins": len(old_pins) - 1,
        "changed_functions": changed, "all_other_functions_byte_identical": True,
        "original_qualified_summary_byte_identical": True,
        "original_collect_and_verify_byte_identical": True,
        "credential_scan_rules_changed": False, "content_scan_bypassed": False,
        "tool_source_embedded_reencoded_or_obfuscated_in_tar": False,
        "old_files_modified": False, "collector_executed": False,
        "qualification_or_auditor_reexecuted": False, "actual_in_template": None,
        "qualification_job_id": "1a1aff8769c-fc05-6d26",
        "prior_failed_archive_jobs": ["1a1b01385a8-fc05-6df2", "1a1b01cee00-fc05-6e22"],
        "host_requests": 0,
    }
    create(OUT / "revision.json", encode(revision))
    print(json.dumps({"output": str(OUT), "template": identity(template), "sealer": identity(sealer.encode()),
                      "new_metadata_inputs": len(additions), "fixed_pins": len(pins),
                      "collector_executed": False, "host_requests": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
