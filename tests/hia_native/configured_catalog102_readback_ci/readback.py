"""Independently restore and read fixed successful artifacts; never replay semantics."""
from pathlib import Path
import argparse, concurrent.futures, hashlib, json, os, signal, stat, subprocess
import sys, time, urllib.error, urllib.parse, urllib.request

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True


def need(value, message):
    if not value:
        raise ValueError("configured catalog readback: " + message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        need(stream.write(data) == len(data), "complete evidence write")


def pin(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and path.resolve() == path.absolute(), "owned regular file")
    with path.open("rb") as stream:
        return {"bytes": info.st_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def fetch_one(row, root, plan):
    expected = row["metadata"]
    artifact_id = expected["id"]
    api = "https://api.github.com/repos/" + plan["repository"] + "/actions/artifacts/" + str(artifact_id)
    headers = {"Authorization": "Bearer " + os.environ["GH_TOKEN"],
               "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    with urllib.request.urlopen(urllib.request.Request(api, headers=headers), timeout=60) as stream:
        actual = json.load(stream)
    for key in ("id", "name", "size_in_bytes", "digest", "expired", "workflow_run"):
        need(actual[key] == expected[key], "immutable artifact API field " + key)
    need(actual["expired"] is False, "retained artifact exists")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(urllib.request.Request(api + "/zip", headers=headers), timeout=60)
    except urllib.error.HTTPError as error:
        need(error.code == 302, "authenticated artifact redirect")
        location = error.headers["Location"]
        error.close()
    else:
        raise ValueError("expected signed artifact redirect")
    need(urllib.parse.urlparse(location).scheme == "https", "TLS artifact download")
    destination = root / ("artifact-" + str(artifact_id) + ".zip")
    digest = hashlib.sha256()
    size = 0
    # A separate unauthenticated request ensures no GitHub token follows the redirect.
    with urllib.request.urlopen(location, timeout=60) as source, destination.open("xb") as target:
        while block := source.read(1 << 20):
            need(target.write(block) == len(block), "full archive download write")
            digest.update(block)
            size += len(block)
    identity = {"bytes": size, "sha256": digest.hexdigest()}
    need(identity == {"bytes": actual["size_in_bytes"],
                      "sha256": actual["digest"].removeprefix("sha256:")}, "entire API ZIP digest")
    need(pin(destination) == identity, "independent whole ZIP reread")
    return {"path": str(destination), "metadata": actual}


def process(label, argv, root, timeout):
    stdout_path = root / (label + ".stdout")
    stderr_path = root / (label + ".stderr")
    started = time.monotonic_ns()
    child = None
    failed = True
    timed_out = False
    returncode = None
    caught = None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, cwd=root, start_new_session=True,
                                     env=os.environ | {"PYTHONDONTWRITEBYTECODE": "1"})
            try:
                returncode = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
            failed = returncode != 0 or timed_out
        except BaseException as error:
            caught = error
        finally:
            # Reaping is independent of evidence writes and includes exceptional waits.
            if child is not None:
                if failed or child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                while True:
                    try:
                        returncode = child.wait()
                        break
                    except InterruptedError:
                        continue
    receipt = {"label": label, "argv": argv, "cwd": str(root), "pid": child.pid if child else None,
               "parent_pid": os.getpid(), "pgid": child.pid if child else None,
               "timeout_seconds": timeout, "started_monotonic_ns": started,
               "ended_monotonic_ns": time.monotonic_ns(), "returncode": returncode,
               "timed_out": timed_out, "stdout": pin(stdout_path), "stderr": pin(stderr_path),
               "native_executions": 0, "rust_executions": 0}
    put(root / (label + ".process.json"), encoded(receipt))
    if caught is not None:
        raise caught
    need(not timed_out and returncode == 0 and receipt["stderr"]["bytes"] == 0,
         "successful bounded " + label)
    return receipt


def main(output):
    plan = json.loads((HERE / "PLAN.json").read_bytes())
    need(not output.exists(), "new independent namespace")
    output.mkdir(mode=0o700, parents=True)
    downloads = output / "archives"
    downloads.mkdir(mode=0o700)
    reports = output / "reports"
    reports.mkdir(mode=0o700)
    put(reports / "PLAN.source.json", (HERE / "PLAN.json").read_bytes())
    started = time.monotonic_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(lambda row: fetch_one(row, downloads, plan), plan["artifacts"]))
    bound_plan = plan | {"artifacts": rows}
    put(reports / "PLAN.actual.json", encoded(bound_plan))
    put(reports / "DOWNLOAD.json", encoded({"status": "COMPLETE_ZIP_DOWNLOAD_PASS",
        "elapsed_ns": time.monotonic_ns() - started, "archives": [
            {"id": row["metadata"]["id"], **pin(Path(row["path"]))} for row in rows]}))
    restored = output / "restored"
    archive_receipt = process("archive", [sys.executable, "-I", "-B", str(HERE / "read_archive.py"),
        "--plan", str(reports / "PLAN.actual.json"), "--output", str(restored)], reports, 180)
    archive = json.loads((restored / "ARCHIVE_READBACK.json").read_bytes())
    need(archive["status"] == "COMPLETE_CONFIGURED_ARCHIVE_READBACK_PASS", "complete archive qualification")
    put(reports / "ARCHIVE_READBACK.json", (restored / "ARCHIVE_READBACK.json").read_bytes())
    need(pin(restored / "download/MANIFEST.json") == plan["expected_manifest"], "exact frozen manifest")
    capture = restored / "capture"
    package = capture / "s"
    need(pin(package / "PACKAGE.json") == plan["expected_package"], "same-source configured catalog")
    foreign = reports / "foreign-probe.txt"
    put(foreign, b"owned read refusal probe\n")
    readonly = process("readonly", [sys.executable, "-I", "-B", str(package / "ci/run_recipe.py"),
        "--phase", "verify", "--package", str(package), "--output", str(capture),
        "--foreign-path", str(foreign)], reports, 180)
    proof = json.loads((reports / "readonly.stdout").read_bytes())
    need(proof["before"] == proof["after"] and len(proof["probes"]) == 12
         and proof["reader_writes"] == proof["native_or_rust_executions"] == 0
         and proof["source_bound_guard"] is True, "full fixed read-only guard")
    summary = proof["evidence"]["summary"]
    need(summary["status"] == "COMPLETE_CONFIGURED_CATALOG_QUALIFICATION_PASS"
         and summary["component_cases"] == 391 and summary["component_native_calls"] == 478
         and summary["physical_refusals"] == 12 and summary["runtime_images"] == 102,
         "full original qualified domains")
    result = {"status": "EXTERNAL_RELOCATED_CONFIGURED_CATALOG_READBACK_PASS", "head": plan["head"],
        "original_run_id": plan["run_id"], "original_job_id": plan["job_id"],
        "archive": archive, "archive_process": archive_receipt, "readonly_process": readonly,
        "readonly_proof": pin(reports / "readonly.stdout"), "readonly_entries": len(proof["before"]),
        "readonly_probes": len(proof["probes"]), "summary": summary,
        "retained_remote_unknown": plan["retained_remote_unknown"],
        "native_executions": 0, "rust_executions": 0, "reader_writes": 0}
    put(reports / "READBACK.json", encoded(result))
    print(json.dumps({"status": result["status"], "files": archive["files"],
        "logical_bytes": archive["logical_bytes"], "readonly_entries": result["readonly_entries"],
        "native_executions": 0, "rust_executions": 0}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    main(args.output.absolute())
