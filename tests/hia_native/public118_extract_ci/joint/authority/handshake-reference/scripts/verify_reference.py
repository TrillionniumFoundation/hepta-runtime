"""Read retained sources, exact Rust build custody and all 54 real handshake observations."""
from pathlib import Path
import argparse, ast, hashlib, io, json, os, stat, sys, tarfile, tomllib
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import cases, LEGACY, META_PREFIX, VERSIONS, ID_LEXEMES
from prepare_reference import slices

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def pin(raw):
    return dict(bytes=len(raw), sha256=SHA(raw))


def check_source(source):
    source = Path(source).resolve(strict=True)
    raw = (source / "source-manifest.json").read_bytes();manifest = json.loads(raw)
    actual = {}
    for path in sorted(source.rglob("*")):
        assert not path.is_symlink()
        if not path.is_file():
            continue
        name = path.relative_to(source).as_posix()
        if name == "source-manifest.json":
            continue
        data = path.read_bytes();actual[name] = pin(data)
        if path.suffix == ".py":
            ast.parse(data, filename=name)
    assert actual == manifest["files"]
    assert manifest["actual_rust_execution_at_freeze"] is False
    return pin(raw)


def verify_case(case, observed):
    assert observed["label"] == case["label"]
    assert observed["terminal"] == {"phase": "running", "quit": "Closed"}
    assert observed["supported_protocol_versions"] == [*LEGACY, "2026-07-28"]
    fixed = json.loads(observed["fixed_get_info_wire"])
    assert fixed["protocolVersion"] == "2026-07-28"
    assert fixed["serverInfo"]["name"] == "rmcp" and fixed["serverInfo"]["version"] == "3.9.0"
    requested = case["requested_version"]
    selected = requested if requested in LEGACY else LEGACY[-1]
    original_init = json.loads(case["events"][0]["wire"])
    expected_peer = dict(original_init["params"], protocolVersion=selected)
    assert observed["negotiated_peer_info"] == expected_peer
    events = observed["events"];assert len(events) == 7
    request_records = [row for row in observed["trace"] if "before" in row]
    notifications = [row for row in observed["trace"] if "notification" in row]
    assert len(request_records) == 6 and len(notifications) == 1
    assert notifications[0]["notification"]["method"] == "notifications/initialized"
    assert notifications[0]["peer_info"] == expected_peer
    by_id = {json.dumps(row["before"]["request_id"], ensure_ascii=False, sort_keys=True): row
             for row in request_records}
    assert len(by_id) == 6
    for index, (event, captured) in enumerate(zip(case["events"], events)):
        assert captured["wire"] == event["wire"]
        if not event["response"]:
            assert captured == {"wire": event["wire"], "response_expected": False}
            continue
        request = json.loads(event["wire"]);response = captured["response"]
        assert captured["response_raw"].endswith("\n")
        assert json.loads(captured["response_raw"]) == response
        assert response["jsonrpc"] == "2.0" and response["id"] == request["id"]
        if index == 0 and case["id_profile"] in ("integer", "negative", "integral-float"):
            assert type(response["id"]) is int
        record = by_id[json.dumps(response["id"], ensure_ascii=False, sort_keys=True)]
        before = record["before"]
        assert before["request"]["method"] == request["method"]
        if index == 0:
            assert response["result"] == dict(fixed, protocolVersion=selected)
            assert before["protocol_version"] == requested
            assert before["peer_info"] == original_init["params"]
            assert record["peer_info_after"] == original_init["params"]
            continue
        assert before["peer_info"] == expected_peer and record["peer_info_after"] == expected_peer
        meta = request.get("params", {}).get("_meta", {})
        assert before["metadata"] == meta
        expected_version = meta.get(META_PREFIX + "protocolVersion", selected)
        expected_info = meta.get(META_PREFIX + "clientInfo", expected_peer["clientInfo"])
        expected_caps = meta.get(META_PREFIX + "clientCapabilities", expected_peer["capabilities"])
        assert before["protocol_version"] == expected_version
        assert before["client_info"] == expected_info and before["capabilities"] == expected_caps
        assert before["supports_cache_hints"] is (expected_version >= "2026-07-28")
        assert before["allows_unsolicited_notifications"] is (expected_version < "2026-07-28")
        if index == 5:
            assert response["error"]["code"] == -32601 and "result" not in response
            assert record["result"]["error"] == response["error"]
        else:
            assert response["result"] == {} and "error" not in response
            assert record["result"] == {"ok": {}}
    return dict(responses=6, modern_ping_errors=1)


def verify(source, run, require_pass=False):
    source_pin = check_source(source)
    summary = json.loads((run / "SUMMARY.json").read_bytes())
    assert summary["source_manifest"] == source_pin
    assert summary["status"] == "PASS" if require_pass else summary["status"] in ("CAPTURED", "PASS")
    assert summary["completed_sessions"] == 54 and summary["actual_target_sdk_executed"] is True
    inputs = json.loads((source / "SOURCE_INPUTS.json").read_bytes())
    generated, spans, original_imports = slices(source)
    assert (run / "oracle/generated_get_info.rs").read_bytes() == generated
    extracted = json.loads((run / "EXTRACTION.json").read_bytes())
    assert extracted["original_spans"] == spans and extracted["generated_sha256"] == SHA(generated)
    assert extracted["original_wire_used_as_implementation"] is False
    assert (run / "ORIGINAL_IMPORTS.txt").read_text() == original_imports + "\n"
    for name in ("oracle/main.rs", "oracle/Cargo.toml", "cache-seed/Cargo.toml", "cache-seed/Cargo.lock",
                 "cache-seed/src/main.rs", "target/Cargo.lock", "target/Cargo.toml"):
        assert (run / name).read_bytes() == (source / name).read_bytes()
    build = json.loads((run / "BUILD.json").read_bytes())
    assert build["fresh_target_dir"] and build["actual_target_sdk_built"] and build["actual_target_sdk_executed"]
    assert build["rust_version"].splitlines()[0].startswith("rustc 1.95.0 ")
    assert SHA((run / build["retained_binary_relative_path"]).read_bytes()) == build["binary_sha256"]
    assert build["source_sha256"] == SHA((source / "oracle/main.rs").read_bytes())
    for name, digest in build["project_files"].items():
        assert SHA((run / "oracle" / name).read_bytes()) == digest
    locked = {(p["name"], p["version"], p.get("source")): p.get("checksum")
              for p in tomllib.loads((source / "target/Cargo.lock").read_text())["package"] if p.get("source")}
    subset = json.loads((run / "evidence/target-lock-subset.json").read_bytes())
    assert subset["target_lock_sha256"] == SHA((source / "target/Cargo.lock").read_bytes())
    assert subset["fixture_lock_sha256"] == SHA((run / "oracle/Cargo.lock").read_bytes())
    retained = []
    for package in tomllib.loads((run / "oracle/Cargo.lock").read_text())["package"]:
        if not package.get("source"):
            assert package["name"] == "current-get-info-handshake-oracle"
            continue
        assert locked[(package["name"], package["version"], package["source"])] == package["checksum"]
        retained.append({name: package[name] for name in ("name", "version", "source", "checksum")})
    assert subset["retained_registry_packages"] == retained
    custody = {(r["name"], r["version"]): r for r in build["registry_archive_custody"]}
    assert len(custody) == len(retained) == len(subset["registry_source_verification"])
    for row in subset["registry_source_verification"]:
        entry = custody[(row["name"], row["version"])];raw = (run / entry["path"]).read_bytes()
        assert len(raw) == entry["bytes"] and SHA(raw) == entry["sha256"] == row["checksum"]
        assert row["checksum"] == locked[(row["name"], row["version"], row["source"])]
        files = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for member in archive:
                if member.isdir():
                    continue
                assert member.isfile()
                parts = Path(member.name).parts;assert parts[0] == row["name"] + "-" + row["version"]
                assert ".." not in parts
                files[Path(*parts[1:]).as_posix()] = SHA(archive.extractfile(member).read())
        assert files == row["source_files"] and len(files) == row["files_verified"]
        if row["name"] == "rmcp":
            assert row["version"] == "3.9.0" and row["checksum"] == inputs["sdk"]["registry_checksum"]
            for name, digest in inputs["sdk"]["source_files"].items():
                assert files[name] == digest
    for folder in ("evidence/cache-prefetch", "evidence/rust-build-processes"):
        for process in json.loads((run / folder / "processes.json").read_bytes()):
            assert process["exit_code"] == 0 and not process["timed_out"] and process["timeout_seconds"] == 180
            for stream in ("stdout", "stderr"):
                raw = (run / folder / (process["label"] + "." + stream)).read_bytes()
                assert len(raw) == process[stream + "_bytes"] and SHA(raw) == process[stream + "_sha256"]
    corpus = cases();assert json.loads((run / "CORPUS.json").read_bytes()) == corpus
    processes = json.loads((run / "processes.json").read_bytes());assert len(processes) == 54
    responses = modern = 0
    for index, (case, row) in enumerate(zip(corpus, processes)):
        assert row["index"] == index and row["label"] == case["label"]
        assert row["exit_code"] == 0 and not row["timed_out"] and row["deadline_seconds"] == 60
        assert row["executable_sha256"] == build["binary_sha256"]
        folder = run / row["folder"]
        streams = {name: (folder / filename).read_bytes() for name, filename in
                   (("stdin", "stdin.jsonl"), ("stdout", "stdout.jsonl"), ("stderr", "stderr.txt"))}
        assert not streams["stderr"]
        for name, raw in streams.items():
            assert pin(raw) == row[name]
        assert json.loads(streams["stdin"]) == case
        counts = verify_case(case, json.loads(streams["stdout"]))
        responses += counts["responses"];modern += counts["modern_ping_errors"]
    assert responses == 324 and modern == 54
    result = dict(status="READONLY_CURRENT_GET_INFO_HANDSHAKE54_PASS", source_manifest=source_pin,
                  original_binary_sha256=build["binary_sha256"], sessions=54, versions=len(VERSIONS),
                  id_profiles=len(ID_LEXEMES), responses=324, real_negotiated_peer_info=54,
                  actual_request_context_observations=324, modern_ping_method_not_found_responses=54,
                  unchanged_original_get_info=True, real_sdk_serve_and_negotiation=True,
                  native_or_rust_executed_by_reader=False, source_or_evidence_written_by_reader=False,
                  full_sdk_qualified=False, full_public_protocol_qualified=False,
                  production_activated=False, old_path_removed=False)
    if summary["status"] == "PASS":
        assert json.loads((run / "readonly.stdout").read_bytes()) == result
    return result


def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_relative_to(root / "rust-build"):
            continue
        assert not path.is_symlink()
        if not path.is_file():
            continue
        st = path.stat();assert stat.S_ISREG(st.st_mode)
        result[str(path)] = (st.st_size, st.st_mtime_ns, st.st_ctime_ns, SHA(path.read_bytes()))
    return result


def audit(event, args):
    if event == "open":
        mode, flags = args[1], args[2]
        if isinstance(mode, str) and any(x in mode for x in "wax+"):
            raise PermissionError("readonly evidence gate: write open")
        if isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise PermissionError("readonly evidence gate: write flags")
    if event.startswith(("subprocess.", "ctypes.", "mmap.")) or event in (
        "os.system", "os.fork", "os.posix_spawn", "os.exec", "os.remove", "os.unlink", "os.rename",
        "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.utime", "os.truncate", "os.link", "os.symlink",
    ):
        raise PermissionError("readonly evidence gate: " + event)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args();source = args.source.resolve(strict=True);run = args.run.resolve(strict=True)
    before = (snapshot(source), snapshot(run));sys.addaudithook(audit)
    result = verify(source, run, args.require_pass)
    assert before == (snapshot(source), snapshot(run))
    print(json.dumps(result, sort_keys=True))
