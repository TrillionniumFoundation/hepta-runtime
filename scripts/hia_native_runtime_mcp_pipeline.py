"""Integrate native public shards with the two shared unchanged Rust builds.

Only execute_original starts the fresh Workdir build and 43 supplemental
replays. View's admitted fresh build is reused. Retained entry points are pure
readers, including after source/output relocation.
"""
from __future__ import annotations

from pathlib import Path
import stat
import sys

from hia_native_runtime_mcp_evidence import (Evidence, compact, decode, exact, execution_origin,
    finite, owned, qualification_evidence, require, sha)
from hia_native_runtime_mcp_original import CLEARED, RUSTC_SHA, workdir_reference
from hia_native_runtime_mcp_reference import qualification_reference
import hia_native_runtime_mcp_fixtures as fixtures

WORKDIR_CHECK = "runtime-mcp-workdir-original"
REPLAY_CHECK = "runtime-mcp-original-replay"
ORIGINAL_CONTROLS = "test_runtime_mcp_original_evidence.py"
SOURCE_FILES = (
    "scripts/hia_native_runtime_mcp_pipeline.py", "scripts/hia_native_runtime_mcp_fixtures.py",
    "scripts/hia_native_runtime_mcp_original.py", "scripts/hia_native_runtime_mcp_reference.py",
    "scripts/hia_native_workdir_reference.py", "tests/hia_native/workdir_oracle/run.py",
    "tests/hia_native/runtime_mcp_oracle/run.py", "tests/hia_native/test_runtime_mcp_original_evidence.py",
)


def native_binding(root, output, report, completed, *, native=None, literal=None, regex=None):
    if native is None:
        native = qualification_evidence(root, output, report, completed)
    if literal is None:
        from hia_native_view_search_public_qualification import public_native_evidence
        literal = public_native_evidence(root, output, report, completed)
    if regex is None:
        from hia_native_view_regex_search_public_qualification import qualification_evidence as regex_evidence
        regex = regex_evidence(root, output, report, completed)
    raw = owned(output, "runtime-mcp/result.json").read_bytes()
    exact(sha(raw), native["artifact_sha256"]["runtime-mcp/result.json"],
          "public fixture execution origin differs from complete native evidence")
    origin = execution_origin(decode(raw))
    return dict(runtime_mcp=native, view_search_public=literal, view_regex_search_public=regex), origin


def native_fixture_evidence(root, output, report, completed, *, create=False,
                            native=None, literal=None, regex=None):
    root, output = Path(root), Path(output)
    binding, origin = native_binding(root, output, report, completed,
                                    native=native, literal=literal, regex=regex)
    return fixtures.retired(output, "native", binding, str(Path(origin["corpus_root"]).parent), create=create)


def wrapper(evidence, report, completed, name, command, expected):
    rows = [row for row in report.get("checks", ()) if row.get("name") == name]
    require(len(rows) == 1, "one actual public original wrapper required: " + name)
    row = rows[0]
    exact(row.get("command"), command, "public original wrapper command differs: " + name)
    require(type(row.get("exit_code")) is int and row["exit_code"] == 0
            and row.get("timed_out") is False and not row.get("start_error")
            and type(row.get("timeout_seconds")) is int and row["timeout_seconds"] == 180
            and finite(row.get("elapsed_seconds"), 180), "public original wrapper failed or changed its deadline")
    streams = {key: evidence.read(name + "." + key) for key in ("stdout", "stderr")}
    for key, raw in streams.items():
        exact(dict(bytes=row.get(key + "_bytes"), sha256=row.get(key + "_sha256")),
              dict(bytes=len(raw), sha256=sha(raw)), "public original wrapper full stream differs")
    exact(streams["stderr"], b"", "public original wrapper wrote diagnostics")
    summary = decode(streams["stdout"])
    exact(summary, expected, "public original wrapper summary differs")
    exact(row.get("summary"), summary, "public original wrapper summary copy differs")
    if completed is not None:
        exact(list(completed(evidence.output, report, name)), [row, summary],
              "public original callback admitted different process bytes")
    return row


def shared_workdir_evidence(root, output, report, completed):
    evidence = Evidence(output)
    admitted = workdir_reference(root, output / "workdir-original", evidence)
    result = evidence.object("workdir-original/result.json")
    pins = evidence.object("workdir-original/source-pins.json")
    runtime_origin, output_origin = result["execution_runtime_root"], result["execution_output_root"]
    for value in (runtime_origin, output_origin):
        require(type(value) is str and Path(value).is_absolute() and ".." not in Path(value).parts
                and str(Path(value)) == value, "shared Workdir execution origin is not canonical")
    exact(Path(output_origin).name, "workdir-original", "shared Workdir output owner differs")
    rustc, cargo = pins["executables"]["rustc"]["invocation"], pins["executables"]["cargo"]["invocation"]
    exact(rustc, report["rust_compiler"]["invocation_path"], "shared Workdir used a different aggregate Rust invocation")
    exact(pins["executables"]["rustc"]["sha256"], RUSTC_SHA, "shared Workdir compiler bytes differ")
    exact(cargo, str(Path(rustc).with_name("cargo")), "shared Workdir Cargo invocation differs")
    strace = pins["executables"]["strace"]["invocation"]
    exact(strace, "/usr/bin/strace", "shared Workdir strace invocation differs")
    command = [sys.executable, "-I", "-B", str(Path(runtime_origin) / "tests/hia_native/workdir_oracle/run.py"),
               "--runtime-root", runtime_origin, "--output", output_origin,
               "--cargo", cargo, "--rustc", rustc, "--strace", strace]
    expected = dict(status="REFERENCE_READY", summary=result["summary"], recorded_processes=10,
                    actual_original_rust_replays=7)
    receipt = wrapper(evidence, report, completed, WORKDIR_CHECK, command, expected)
    exact(admitted["processes"], 10, "shared Workdir actual process count differs")
    exact(admitted["fresh_builds"], 1, "shared Workdir fresh build count differs")
    return dict(admitted, actual_wrapper=receipt,
                artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
                artifacts=[evidence.artifacts[name] for name in sorted(evidence.artifacts)])


def bind_replay_reconstruction(output):
    before = decode(owned(output, fixtures.RESTORE + ".before.json").read_bytes())
    actual = decode(owned(output, "runtime-mcp-original/fixture-before.json").read_bytes())
    require(type(actual) is list and actual, "actual replay did not preserve a reconstructed Workdir tree")
    prefix = b"runtime-mcp/files/workdir"
    expected = {}
    for row in before:
        path = bytes.fromhex(row["path_hex"])
        if path == prefix or path.startswith(prefix + b"/"):
            expected[path[len(prefix):].lstrip(b"/").hex()] = row
    require(len(expected) == len(actual) and len({row.get("name_hex") for row in actual}) == len(actual),
            "actual replay reconstructed Workdir inventory differs")
    types = dict(directory=stat.S_IFDIR, file=stat.S_IFREG, symlink=stat.S_IFLNK, fifo=stat.S_IFIFO)
    for row in actual:
        name = row.get("name_hex")
        require(name in expected, "actual replay Workdir path escaped its reconstruction")
        item = expected[name]
        projection = dict(name_hex=name, device=item["source_device"], inode=item["source_inode"],
                          mode=types[item["kind"]] | item["mode"], uid=item["uid"], gid=item["gid"],
                          nlink=item["nlink"], xattrs=item["xattrs"], kind=item["kind"])
        if item["kind"] == "file":
            raw = row.get("data_hex")
            require(type(raw) is str and fixtures.HEX.fullmatch(raw), "actual replay retained file is not lossless")
            raw = bytes.fromhex(raw)
            exact(dict(bytes=len(raw), sha256=sha(raw)), dict(bytes=item["bytes"], sha256=item["sha256"]),
                  "actual replay file differs from complete reconstructed bytes")
            projection["data_hex"] = raw.hex()
        elif item["kind"] == "symlink":
            projection["target_hex"] = item["target_hex"]
        exact(row, projection, "actual replay inode/metadata differs from this reconstruction")


def finish(root, output, report, completed, public, workdir, native_retirement, origin, *, create):
    reconstruction = fixtures.retained_reconstruction(output, native_retirement,
                                                     str(Path(origin["corpus_root"]).parent))
    bind_replay_reconstruction(output)
    retirement = fixtures.retired(output, "original", dict(public=public, workdir=workdir),
                                 str(Path(origin["corpus_root"]).parent), create=create)
    if create:
        report["runtime_mcp_original_fixture_retirement"] = retirement
    else:
        exact(report.get("runtime_mcp_original_fixture_retirement"), retirement,
              "retained original public fixture retirement differs")
    artifacts = {}
    for value in (public, workdir):
        for row in value["artifacts"]:
            if row["path"] in artifacts:
                exact(artifacts[row["path"]], row, "shared public original artifact pin differs")
            artifacts[row["path"]] = row
    for value in (native_retirement, reconstruction, retirement):
        for name, expected in value["artifact_sha256"].items():
            row = dict(path=name, **fixtures.file_pin(owned(output, name)))
            exact(row["sha256"], expected, "public fixture artifact changed during original admission")
            if name in artifacts:
                exact(artifacts[name], row, "public fixture artifact pin conflicts")
            artifacts[name] = row
    sources = {name: sha(owned(root, name).read_bytes()) for name in SOURCE_FILES}
    result = dict(public)
    result["pipeline"] = dict(shared_workdir=workdir, native_fixture_retirement=native_retirement,
                              reconstructed_fixture=reconstruction, original_fixture_retirement=retirement,
                              source_sha256=sources, shared_view_build_reused=True,
                              extra_view_builds=0, fresh_workdir_builds=1,
                              actual_supplemental_original_replays=43,
                              native_calls_added_by_original_comparison=0,
                              pure_retained_reader_reconstructs_fixtures=False)
    result["artifact_sha256"] = {name: row["sha256"] for name, row in sorted(artifacts.items())}
    result["artifacts"] = [row for name, row in sorted(artifacts.items())]
    return decode(compact(result))


def retained_original(root, output, report, completed):
    root, output = Path(root), Path(output)
    binding, origin = native_binding(root, output, report, completed)
    native_retirement = fixtures.retired(output, "native", binding, str(Path(origin["corpus_root"]).parent))
    exact(report.get("runtime_mcp_fixture_retirement"), native_retirement,
          "retained native public fixture retirement differs")
    workdir = shared_workdir_evidence(root, output, report, completed)
    public = qualification_reference(root, output, report, completed)
    return finish(root, output, report, completed, public, workdir, native_retirement, origin, create=False)


def execute_original(root, output, report, rustc, record_check, completed, environment):
    root, output, rustc = Path(root).absolute(), Path(output).absolute(), Path(rustc).absolute()
    binding, origin = native_binding(root, output, report, completed)
    exact(str(root), origin["runtime_root"], "normal public original comparison requires the admitted native source origin")
    exact(str(output), str(Path(origin["corpus_root"]).parent),
          "normal public original comparison requires the admitted native output origin")
    for name in (WORKDIR_CHECK, REPLAY_CHECK, ORIGINAL_CONTROLS):
        require(not any(row.get("name") == name for row in report.get("checks", ())),
                "public original wrapper cannot be repeated under the same report")
    native_retirement = fixtures.retired(output, "native", binding, str(output))
    exact(report.get("runtime_mcp_fixture_retirement"), native_retirement,
          "native public fixture retirement changed before original execution")
    env = dict(environment)
    for key in CLEARED:
        env.pop(key, None)
    env.update(RUSTC=str(rustc), LC_ALL="C", TZ="UTC")
    command = [sys.executable, "-I", "-B", str(root / "tests/hia_native/workdir_oracle/run.py"),
               "--runtime-root", str(root), "--output", str(output / "workdir-original"),
               "--cargo", str(rustc.with_name("cargo")), "--rustc", str(rustc), "--strace", "/usr/bin/strace"]
    record_check(output, report, name=WORKDIR_CHECK, command=command, timeout=180, env=env)
    workdir = shared_workdir_evidence(root, output, report, completed)
    with fixtures.restored_native(output, native_retirement, binding, str(output)):
        record_check(output, report, name=REPLAY_CHECK, command=[sys.executable, "-I", "-B",
            str(root / "tests/hia_native/runtime_mcp_oracle/run.py"), "--runtime-root", str(root),
            "--native-output", str(output), "--view-original", str(output / "view-call-original"),
            "--workdir-original", str(output / "workdir-original"),
            "--output", str(output / "runtime-mcp-original")], timeout=180, env=env)
    env["HIA_RUNTIME_MCP_QUALIFICATION_OUTPUT"] = str(output)
    record_check(output, report, name=ORIGINAL_CONTROLS,
                 command=[sys.executable, "-I", "-B", str(root / "tests/hia_native" / ORIGINAL_CONTROLS)],
                 timeout=180, env=env)
    public = qualification_reference(root, output, report, completed)
    return finish(root, output, report, completed, public, workdir, native_retirement, origin, create=True)
