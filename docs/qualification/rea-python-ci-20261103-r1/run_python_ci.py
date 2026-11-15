#!/usr/bin/env python3
"""Execute the existing workflow's Python CI commands without Cargo or runtime services."""
from __future__ import annotations
import datetime, hashlib, importlib.metadata, json, os, pathlib, platform, re, shlex, signal, subprocess, sys, tempfile, time

REPO = pathlib.Path("/home/qian-qi/hepta-runtime-rea-full-20261103-r1")
OUT = REPO / "docs/qualification/rea-python-ci-20261103-r1"
EXPECTED = [
 "/usr/bin/python3 tests/file_capabilities.py",
 "/usr/bin/python3 -B tests/runtime_registry_page_tests.py",
 "/usr/bin/python3 -B tests/test_native_canary_resume.py",
 "/usr/bin/python3 -B tests/chatgpt_v11_layered_read_tests.py",
 "/usr/bin/python3 -B tests/chatgpt_v11_process_start_concurrency_tests.py",
 "/usr/bin/python3 -B tests/chatgpt_v11_v4_session_binding_tests.py",
 "/usr/bin/python3 -B tests/runtime_workflow_owner_tests.py",
 "/usr/bin/python3 -B tests/chatgpt_v10_single_v4_effect_tests.py",
 "/usr/bin/python3 -B tests/chatgpt_v10_stream_custody_tests.py",
 "/usr/bin/python3 -B tests/test_computer_http.py",
 "/usr/bin/python3 -B tests/full_operator_facade_tests.py",
 "/usr/bin/python3 -B tests/full_operator_cancel_tests.py",
 "/usr/bin/python3 -B tests/chatgpt_request_identity_tests.py",
 "/usr/bin/python3 -B tests/full_operator_session_recovery_tests.py",
 "/usr/bin/python3 -B deploy/maintenance_20261017/native_rollout_tests.py",
 "/usr/bin/python3 -B deploy/maintenance_20261017/recover_control_channel_tests.py",
 "/usr/bin/python3 -B -m unittest discover -s tools/x230/20261028 -p '*_tests.py' -v",
 "/usr/bin/python3 -B -m unittest discover -s tools/x230/20261029 -p '*_tests.py' -v",
 "/usr/bin/python3 -B -m unittest discover -s tools/x230/20261030 -p '*_tests.py' -v",
]
SOURCE_DIRS = ("src/", "tests/", "deploy/", "tools/", "scripts/", ".github/", ".cargo/", "examples/", "benches/")
SOURCE_ROOTS = {"Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml", "rust-toolchain", "rustfmt.toml", ".gitignore", ".gitattributes", "Makefile"}

def encoded(value):
 return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()

def digest(path):
 with path.open("rb") as stream:
  return hashlib.file_digest(stream, "sha256").hexdigest()

def save(name, value):
 path = OUT / name
 data = encoded(value)
 with path.open("wb") as stream:
  stream.write(data)
 return hashlib.sha256(data).hexdigest()

def snapshot():
 result = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
 files = {}
 for name in sorted(set(part.decode() for part in result.stdout.split(b"\0") if part)):
  if not (name.startswith(SOURCE_DIRS) or name in SOURCE_ROOTS):
   continue
  if "__pycache__" in pathlib.PurePosixPath(name).parts or name.endswith((".pyc", ".pyo")):
   continue
  path = REPO / name
  if path.is_symlink():
   target = os.readlink(path)
   files[name] = {"kind": "symlink", "target": target, "sha256": hashlib.sha256(target.encode()).hexdigest()}
  elif path.is_file():
   files[name] = {"kind": "file", "bytes": path.stat().st_size, "sha256": digest(path)}
  else:
   files[name] = {"kind": "missing"}
 return {"files": files, "source_set_sha256": hashlib.sha256(encoded(files)).hexdigest(), "file_count": len(files)}

def receipt(path):
 return {"path": path.name, "bytes": path.stat().st_size, "sha256": digest(path)}

def main():
 os.umask(0o077)
 if (OUT / "summary.json").exists():
  raise SystemExit("existing receipt: refuse to repeat this qualification")
 workflow = REPO / ".github/workflows/ci.yml"
 observed = []
 for line in workflow.read_text().splitlines():
  match = re.search(r"(/usr/bin/python3\s+.*)$", line)
  if match and match.group(1) not in observed:
   observed.append(match.group(1))
 if observed != EXPECTED:
  raise SystemExit("workflow Python commands changed after conflict review")
 before = snapshot()
 before_sha = save("source-before.json", before)
 version = subprocess.run(["/usr/bin/python3", "--version"], cwd=REPO, capture_output=True, text=True, check=True)
 try:
  jsonschema_version = importlib.metadata.version("jsonschema")
 except importlib.metadata.PackageNotFoundError:
  jsonschema_version = None
 temporary = pathlib.Path(tempfile.mkdtemp(prefix="hepta-rea-python-ci-20261103-r1-", dir="/tmp"))
 metadata = {
  "schema": "hepta.rea.python-ci-qualification.v1", "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
  "repo": str(REPO), "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
  "workflow": ".github/workflows/ci.yml", "workflow_sha256": digest(workflow), "runner_sha256": digest(pathlib.Path(__file__)),
  "source_before_sha256": before_sha, "source_before_set_sha256": before["source_set_sha256"],
  "python_version": version.stdout.strip() or version.stderr.strip(), "python_executable": os.path.realpath("/usr/bin/python3"),
  "python_executable_sha256": digest(pathlib.Path("/usr/bin/python3")), "platform": platform.platform(), "jsonschema_version": jsonschema_version,
  "temporary_root": str(temporary), "runtime_binary_executed": False, "cargo_executed": False,
  "production_credentials_used": False, "real_services_operated": False, "real_ssh_used": False,
  "execution_scope": "existing workflow Python tests; disposable local fixtures, mocked services, ephemeral loopback",
  "workflow_job_scope": "identical Python command lists in exact-head and merge jobs; one execution on this source snapshot, not a GitHub merge qualification",
  "environment": {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "inherited unchanged", "unrelated_credentials_and_runtime_environment": "not passed"},
  "retries": 0, "stages": [], "state": "running", "qualified": False,
 }
 save("summary.json", metadata)
 for number, command in enumerate(EXPECTED, 1):
  argv = shlex.split(command)
  label = pathlib.Path(argv[-1]).stem if "-m" not in argv else "x230-" + argv[argv.index("-s") + 1].split("/")[-1]
  prefix = f"{number:02d}-{label}"
  stage_tmp = temporary / prefix
  stage_tmp.mkdir(mode=0o700)
  env = {key: os.environ[key] for key in ("HOME", "USER", "LOGNAME") if key in os.environ}
  env.update(PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1", LANG="C.UTF-8", LC_ALL="C.UTF-8", TMPDIR=str(stage_tmp), TMP=str(stage_tmp), TEMP=str(stage_tmp), NO_PROXY="127.0.0.1,localhost,::1")
  stdout_path, stderr_path = OUT / (prefix + ".stdout.log"), OUT / (prefix + ".stderr.log")
  started = time.monotonic()
  timed_out = False
  with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
   process = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
   try:
    exit_code = process.wait(timeout=300)
   except subprocess.TimeoutExpired:
    timed_out = True
    os.killpg(process.pid, signal.SIGKILL)
    exit_code = process.wait()
  elapsed = time.monotonic() - started
  stdout_text = stdout_path.read_text(errors="replace")
  stderr_text = stderr_path.read_text(errors="replace")
  combined = stdout_text + "\n" + stderr_text
  test_counts = re.findall(r"Ran (\d+) tests? in ([0-9.]+)s", combined)
  summary_lines = [line for line in combined.splitlines() if line.startswith(("Ran ", "OK", "FAILED", "ERROR: ", "FAIL: "))]
  item = {"index": number, "command": command, "argv": argv, "cwd": str(REPO), "temporary_directory": str(stage_tmp), "elapsed_seconds": elapsed, "exit_code": exit_code, "timed_out": timed_out, "stdout": receipt(stdout_path), "stderr": receipt(stderr_path), "unittest_summary": summary_lines, "tests_run": int(test_counts[-1][0]) if test_counts else None, "attempts": 1}
  metadata["stages"].append(item)
  save("summary.json", metadata)
  print(json.dumps({"stage": number, "command": command, "exit_code": exit_code, "tests_run": item["tests_run"], "elapsed_seconds": elapsed}), flush=True)
 after = snapshot()
 metadata.update(source_after_sha256=save("source-after.json", after), source_after_set_sha256=after["source_set_sha256"], source_unchanged=before["files"] == after["files"], finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
 metadata["changed_source_paths"] = sorted(name for name in before["files"].keys() | after["files"].keys() if before["files"].get(name) != after["files"].get(name))
 metadata["state"] = "invalid_source_changed" if not metadata["source_unchanged"] else "complete"
 metadata["qualified"] = metadata["source_unchanged"] and len(metadata["stages"]) == len(EXPECTED) and all(row["exit_code"] == 0 and not row["timed_out"] and row["tests_run"] for row in metadata["stages"])
 metadata["total_tests_run"] = sum(row["tests_run"] or 0 for row in metadata["stages"])
 metadata["failed_stage_indices"] = [row["index"] for row in metadata["stages"] if row["exit_code"] != 0 or row["timed_out"] or not row["tests_run"]]
 save("summary.json", metadata)
 print(json.dumps({"qualified": metadata["qualified"], "state": metadata["state"], "total_tests_run": metadata["total_tests_run"], "failed_stage_indices": metadata["failed_stage_indices"], "source_set_sha256": after["source_set_sha256"]}), flush=True)
 return 0 if metadata["qualified"] else 1

if __name__ == "__main__":
 raise SystemExit(main())
