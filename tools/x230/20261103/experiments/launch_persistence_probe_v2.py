import pathlib, sys, subprocess, json, hashlib, time, re, shutil, statistics
work = pathlib.Path("/home/qian/hepta-runtime-optimization-20261103-r11/persistence-probe")
deps = pathlib.Path("/home/qian/hepta-runtime-optimization-20261103-r10/target/debug/deps")
lock = pathlib.Path("/home/qian/hepta-runtime-optimization-20261103-r10/source-r10e/Cargo.lock")
source = sys.stdin.read()
meta = {"attempt": 2, "prior_failed_job": "1a1a0f6cbe9-96a-6bca", "prior_failure": "setup FileNotFoundError for wrong Cargo.lock path; no compile or benchmark", "work": str(work), "limits": {"timeout_seconds":120,"nice":15,"cpu_quota_percent":50,"memory_max_bytes":536870912}, "source_sha256":hashlib.sha256(source.encode()).hexdigest(), "started_unix":time.time()}
stage = "preflight"
def textlog(name, value):
    if isinstance(value, bytes): value = value.decode(errors="replace")
    (work / name).write_text(value or "")
try:
    assert work.is_dir(), "isolated probe directory missing"
    assert lock.is_file(), "corrected Cargo.lock missing"
    assert deps.is_dir(), "cached deps directory missing"
    src = work / "probe.rs"
    assert src.is_file(), "prior probe source missing"
    assert src.read_text() == source, "source differs from prior attempt"
    assert meta["source_sha256"] == "5a8b14e2d6086b0a47f5d349b9b804de225d21e52d5339504bc1dd56211d0d34"
    candidates = list(deps.glob("libserde_json-*.rlib"))
    assert candidates, "no cached serde_json rlib"
    rlib = max(candidates, key=lambda p:p.stat().st_mtime_ns)
    rustc = pathlib.Path("/home/qian/.cargo/bin/rustc")
    if not rustc.exists():
        found = shutil.which("rustc")
        assert found, "rustc unavailable"
        rustc = pathlib.Path(found)
    version = re.search(r'\[\[package\]\]\s+name = "serde_json"\s+version = "([^"]+)"', lock.read_text())
    assert version and version.group(1) == "1.0.151", "serde_json lock version mismatch"
    assert not (work / "results.json").exists(), "do not overwrite completed results"
    meta.update({"lock":str(lock),"lock_sha256":hashlib.sha256(lock.read_bytes()).hexdigest(),"serde_json_version":version.group(1),"rlib":str(rlib),"rustc":str(rustc)})
    meta["rustc_version"] = subprocess.run([str(rustc),"--version"],check=True,capture_output=True,text=True,timeout=5).stdout.strip()
    print("PREFLIGHT " + json.dumps({k:meta[k] for k in ["source_sha256","serde_json_version","rlib","rustc_version"]}),flush=True)
    stage = "compile"
    command = [str(rustc),"--edition=2021","-C","opt-level=2","-C","debuginfo=0","-C","codegen-units=1","--extern","serde_json="+str(rlib),"-L","dependency="+str(deps),str(src),"-o",str(work/"probe-v2")]
    meta["compile_command"] = command
    started = time.monotonic()
    compiled = subprocess.run(command,capture_output=True,text=True,timeout=45)
    meta["compile_wall_seconds"] = time.monotonic()-started
    meta["compile_returncode"] = compiled.returncode
    textlog("compile-v2.stdout",compiled.stdout)
    textlog("compile-v2.stderr",compiled.stderr)
    print("COMPILE " + json.dumps({"returncode":compiled.returncode,"wall_seconds":meta["compile_wall_seconds"]}),flush=True)
    if compiled.returncode:
        print(compiled.stderr,flush=True)
        raise RuntimeError("standalone rustc compilation failed")
    stage = "run"
    started = time.monotonic()
    ran = subprocess.run([str(work/"probe-v2"),str(work)],capture_output=True,text=True,timeout=65)
    meta["run_wall_seconds"] = time.monotonic()-started
    meta["run_returncode"] = ran.returncode
    textlog("run-v2.stdout",ran.stdout)
    textlog("run-v2.stderr",ran.stderr)
    print(ran.stdout,end="",flush=True)
    print("RUN " + json.dumps({"returncode":ran.returncode,"wall_seconds":meta["run_wall_seconds"]}),flush=True)
    if ran.returncode:
        print(ran.stderr,flush=True)
        raise RuntimeError("probe verification or measurement failed")
    stage = "summary"
    result = json.loads((work/"results.json").read_text())
    groups = {}
    for row in result["pure_rows"]:
        groups.setdefault((row["size"],row["escaped"],row["mode"]),[]).append(row)
    allocations = {(r["size"],r["escaped"],r["mode"]):r["allocation"] for r in result["allocation_rows"]}
    cases = []
    for size, escaped in sorted(set((k[0],k[1]) for k in groups)):
        case = {"size":size,"escaped":escaped}
        for mode in ["vec","count_stream_16k"]:
            rows = groups[(size,escaped,mode)]
            case[mode] = {"cpu_us":statistics.median(r["cpu_seconds_per_call"] for r in rows)*1e6,"wall_us":statistics.median(r["wall_seconds"]/r["iterations"] for r in rows)*1e6,**allocations[(size,escaped,mode)]}
        case["cpu_change_percent"] = (case["count_stream_16k"]["cpu_us"]/case["vec"]["cpu_us"]-1)*100
        cases.append(case)
    durables = []
    for size in sorted(set(r["size"] for r in result["durable_rows"])):
        row = {"size":size}
        for mode in ["vec","count_stream_16k"]:
            rows = [r for r in result["durable_rows"] if r["size"]==size and r["mode"]==mode]
            row[mode] = {"wall_ms":statistics.median(r["wall_seconds"] for r in rows)*1e3,"cpu_ms":statistics.median(r["cpu_seconds"] for r in rows)*1e3,"samples":len(rows)}
        durables.append(row)
    summary = {"verification":result["verification"],"pure_medians":cases,"durable_medians":durables,"notes":result["measurement_notes"]}
    (work/"summary-v2.json").write_text(json.dumps(summary,indent=2))
    print("SUMMARY " + json.dumps(summary,separators=(",",":")),flush=True)
    meta["completed"] = True
except subprocess.TimeoutExpired as error:
    textlog(stage+"-v2.stdout",error.stdout)
    textlog(stage+"-v2.stderr",error.stderr)
    meta["error"] = repr(error)
    print("FAILED " + json.dumps({"stage":stage,"error":repr(error)}),flush=True)
    raise
except Exception as error:
    meta["error"] = repr(error)
    print("FAILED " + json.dumps({"stage":stage,"error":repr(error)}),flush=True)
    raise
finally:
    meta["final_stage"] = stage
    meta["finished_unix"] = time.time()
    if work.is_dir():
        (work/"metadata-v2.json").write_text(json.dumps(meta,indent=2))

