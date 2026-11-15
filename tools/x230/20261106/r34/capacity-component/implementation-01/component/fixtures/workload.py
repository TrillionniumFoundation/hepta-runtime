# Included after common.py. Only this new workload handles its own SIGTERM.
import signal


def workload_main():
    need(len(sys.argv) == 2, "one exact fixture ticket argument required")
    ticket = json.loads(sys.argv[1])
    expected_input = ("HEPTA-R34-CAPACITY " + ticket["nonce"] + " " + ticket["host"] + "\n").encode()
    need(sys.stdin.buffer.read(4097) == expected_input, "original fixture stdin differs")
    job_id = os.environ.get("HEPTA_RUNTIME_JOB_ID", "")
    need(re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", job_id) is not None,
         "original supervisor job identity was not inherited")
    started = time.monotonic_ns()
    stopping = {"at": None, "signals": 0}

    def terminate(_signum, _frame):
        stopping["signals"] += 1
        if stopping["at"] is None:
            stopping["at"] = time.monotonic_ns() + 1_000_000_000

    signal.signal(signal.SIGTERM, terminate)
    base, fixture, _ = open_fixture(ticket)
    try:
        who = own_process_identity()
        ready = {"schema": "hepta-r34-capacity-workload-ready/v1", "nonce": ticket["nonce"],
                 "host": ticket["host"], "job_id": job_id, "fixture_identity": ticket["fixture_identity"],
                 "process": who, "started_monotonic_ns": started, "ttl_seconds": WORKLOAD_TTL}
        need(not released(ticket, fixture, "job"), "workload was released before ready")
        write_once(fixture, "workload.ready.json", canonical(ready))
        print("BEGIN " + ticket["host"] + " " + ticket["nonce"], flush=True)
        print("OWNED-COMPONENT " + ticket["host"], file=sys.stderr, flush=True)
        reason = "ttl_expired"
        deadline = started + WORKLOAD_TTL * 1_000_000_000
        while time.monotonic_ns() < deadline:
            if stopping["at"] is not None and time.monotonic_ns() >= stopping["at"]:
                reason = "sigterm_cleanup_finished"
                break
            if stopping["at"] is None and released(ticket, fixture, "job"):
                reason = "released"
                break
            time.sleep(0.05)
        still_named(ticket, base, fixture)
        result = {**ready, "schema": "hepta-r34-capacity-workload-finished/v1", "reason": reason,
                  "signals": stopping["signals"], "finished_monotonic_ns": time.monotonic_ns()}
        write_once(fixture, "workload.finished.json", canonical(result))
        print("END " + ticket["host"] + " " + reason, flush=True)
        return 0 if reason != "ttl_expired" else 3
    finally:
        os.close(fixture)
        os.close(base)


if __name__ == "__main__":
    raise SystemExit(workload_main())
