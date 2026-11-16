"""Apply the unchanged lane deadline while letting its owner reap its child.

The alarm raises inside the recording driver. Its existing finally block closes
or kills and reaps the exact owned process group before the failure is retained.
No extra Python process owns a detached native child on the timeout path.
"""
from pathlib import Path
import contextlib
import io
import os
import signal
import time
from receipt_support import PIN, put, regular, require
import qualify_public
import qualify_stdio

LIMIT = 180


def run(kind, role, binary, fixture, output, domain):
    require(kind in ("private", "stdio") and role in ("native", "original"), "lane owner selection")
    output = Path(output).absolute()
    receipt = output.parent / (output.name + ".lane.json")
    require(not receipt.exists() and not output.exists(), "lane already attempted")
    module = qualify_public if kind == "private" else qualify_stdio
    row = {"schema": "hepta.runtime.batch-public-lane-guard.v1", "status": "RUNNING",
        "execution_kind": "in_process_recording_driver", "kind": kind, "role": role, "domain": domain,
        "fixture": str(Path(fixture).absolute()), "output": str(output),
        "binary": str(Path(binary).resolve(strict=True)), "driver": Path(module.__file__).name,
        "driver_pin": PIN(regular(module.__file__)), "owner_pid": os.getpid(),
        "outer_lane_deadline_seconds": LIMIT, "per_exchange_deadline_seconds": 60,
        "alarm_fired": False, "cleanup_in_recording_driver": True}
    put(receipt, row)
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "an unrelated lane alarm is already armed")
    previous = signal.getsignal(signal.SIGALRM)
    stdout, stderr = io.StringIO(), io.StringIO()
    before = time.monotonic()
    def expired(signum, frame):
        signal.setitimer(signal.ITIMER_REAL, 0)
        row["alarm_fired"] = True
        raise TimeoutError("complete public lane exceeded the unchanged 180 second deadline")
    try:
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, LIMIT)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = module.execute(role, binary, fixture, output, domain)
        signal.setitimer(signal.ITIMER_REAL, 0)
        require(not row["alarm_fired"] and time.monotonic() - before < LIMIT, "complete lane deadline")
        row.update(status="PASS", capture=PIN(regular(output / "result.json")))
        return result
    except BaseException as error:
        row.update(status="FAIL", failure=repr(error))
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        row["elapsed_seconds"] = time.monotonic() - before
        for name, raw in (("stdout", stdout.getvalue().encode()), ("stderr", stderr.getvalue().encode())):
            path = output.parent / (output.name + ".lane." + name)
            path.write_bytes(raw)
            row[name] = {"path": path.name, **PIN(raw)}
        put(receipt, row)
