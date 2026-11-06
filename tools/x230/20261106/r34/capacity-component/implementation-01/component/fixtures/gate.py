# Included after common.py; one actual ordinary SSH child, no subprocess or fork.
def gate_main():
    started = time.monotonic_ns()
    payload = stdin_payload()
    need(set(payload) == {"ticket", "index"}, "unexpected gate payload")
    ticket, index = payload["ticket"], payload["index"]
    need(type(index) is int and 0 <= index < gate_count(ticket), "unfrozen gate index")
    base, fixture, _ = open_fixture(ticket)
    try:
        role = "gate-" + str(index)
        who = own_process_identity()
        ready = {"schema": "hepta-r34-capacity-gate-ready/v1", "nonce": ticket["nonce"],
                 "host": ticket["host"], "role": role, "fixture_identity": ticket["fixture_identity"],
                 "process": who, "started_monotonic_ns": started, "ttl_seconds": GATE_TTL}
        need(not released(ticket, fixture, "gate"), "gate was released before ready")
        write_once(fixture, role + ".ready.json", canonical(ready))
        deadline = started + GATE_TTL * 1_000_000_000
        reason = "ttl_expired"
        while time.monotonic_ns() < deadline:
            if released(ticket, fixture, "gate"):
                reason = "released"
                break
            time.sleep(0.05)
        still_named(ticket, base, fixture)
        result = {**ready, "schema": "hepta-r34-capacity-gate-finished/v1",
                  "reason": reason, "finished_monotonic_ns": time.monotonic_ns()}
        write_once(fixture, role + ".finished.json", canonical(result))
        sys.stdout.buffer.write(canonical(result))
        sys.stdout.buffer.flush()
        return 0 if reason == "released" else 3
    finally:
        os.close(fixture)
        os.close(base)


if __name__ == "__main__":
    raise SystemExit(gate_main())
