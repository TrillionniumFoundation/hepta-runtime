# Included after common.py. Fixed private prepare/inspect/release operations only.
def transported(raw):
    if raw is None:
        return None
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "bytes_hex": raw.hex()}


def coordinate_remote_main():
    payload = stdin_payload()
    need(set(payload) == {"mode", "ticket", "job_id", "launch_nonce", "kind", "terminal"}, "unexpected coordinator fields")
    need(type(payload["terminal"]) is bool, "fixed terminal inspection flag required")
    mode, ticket = payload["mode"], payload["ticket"]
    need(mode in ("prepare", "inspect", "release"), "unsupported private operation")
    base, fixture, stored_origin = open_fixture(ticket, prepare=mode == "prepare")
    try:
        ticket = {key: stored_origin[key] for key in ticket}
        result = {"schema": "hepta-r34-capacity-remote/v1", "mode": mode, "ticket": ticket, "files": {}}
        if mode == "prepare":
            need(payload["job_id"] is None and payload["launch_nonce"] is None and payload["kind"] is None,
                 "fresh preparation cannot name an existing effect")
        else:
            for name in ("workload.ready.json", "workload.finished.json", "gate-release.json", "job-release.json"):
                result["files"][name] = transported(read_at(fixture, name, 8192, optional=True))
            for index in range(gate_count(ticket)):
                for suffix in ("ready", "finished"):
                    name = "gate-" + str(index) + "." + suffix + ".json"
                    result["files"][name] = transported(read_at(fixture, name, 8192, optional=True))
            job_id = payload["job_id"]
            need(isinstance(job_id, str) and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", job_id),
                 "original private job identity required")
            jobs = directory_at(fixture, "jobs")
            try:
                job = directory_at(jobs, job_id)
                try:
                    request_raw = read_at(job, "request.json", 65536)
                    request = json.loads(request_raw)
                    need(request["job_id"] == job_id, "original job request differs")
                    if payload["launch_nonce"] is not None:
                        need(request["launch_nonce"] == payload["launch_nonce"], "original launch nonce differs")
                    result["files"]["request.json"] = transported(request_raw)
                    observed = [("child.json", 8192), ("started.json", 8192), ("cancel-request.json", 8192),
                                ("exit.json", 1048576), ("exit.witness.json", 8192), ("stdin.bin", 4096)]
                    if payload["terminal"]:
                        observed.extend((("stdout.log", 16384), ("stderr.log", 16384)))
                    for name, limit in observed:
                        result["files"][name] = transported(read_at(job, name, limit, optional=True))
                    ready_raw = read_at(fixture, "workload.ready.json", 8192, optional=True)
                    child_raw = read_at(job, "child.json", 8192, optional=True)
                    if ready_raw is not None:
                        ready = json.loads(ready_raw)
                        need(ready["job_id"] == job_id and ready["nonce"] == ticket["nonce"],
                             "workload ready identity differs")
                        if child_raw is not None:
                            child = json.loads(child_raw)
                            need(ready["process"]["pid"] == child["pid"], "ready PID differs from original child")
                            if ticket["expected_platform"] == "linux":
                                birth = child.get("identity") or {}
                                need(birth.get("kind") == "proc_start_ticks"
                                     and birth["value"].rsplit(":", 1)[1] == str(ready["process"]["start_ticks"]),
                                     "ready birth differs from original Linux child")
                    if mode == "release":
                        need(payload["launch_nonce"] is not None and payload["kind"] in ("gate", "job"),
                             "release needs the original launch and a fixed private role")
                        # Never edit runtime receipts or signal a process. Publish just this fixture marker.
                        kind = payload["kind"]
                        write_once(fixture, kind + "-release.json", canonical(release_value(ticket, kind)))
                        result["release"] = transported(read_at(fixture, kind + "-release.json", 8192))
                    else:
                        need(payload["kind"] is None, "inspection cannot select a release role")
                finally:
                    os.close(job)
            finally:
                os.close(jobs)
        still_named(ticket, base, fixture)
        raw = canonical(result)
        need(len(raw) <= 2 * 1024 * 1024, "remote fixture receipt exceeds 2 MiB")
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
    finally:
        os.close(fixture)
        os.close(base)


if __name__ == "__main__":
    coordinate_remote_main()
