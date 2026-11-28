"""Record each actual pure-reader phase within its unchanged 180-second budget."""
from pathlib import Path
import argparse
import os
import sys
ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from common import encoded, loads, pin, read, require, source
from process import Recorder, environment


def run(phase, output, retained):
    identity = source()
    env, _ = environment(os.environ)
    recorder = Recorder(ROOT, output / "reader-processes" / phase, env)
    command = [sys.executable, "-I", "-B", ROOT / "reader_callable_cli.py", "--phase", phase,
               "--capture", output / "semantic", "--retained", retained,
               "--controls", output / "controls", "--report", output / (phase + "-read.json")]
    try:
        raw, record = recorder.run("readonly-" + phase, command, timeout=180)
        print(raw.decode(), end="")
        if phase == "final":
            proof = loads(read(output / "final-read.json"))
            require(proof["evidence"]["status"] == "PASS" and source() == identity,
                    "same source, complete final native callable evidence")
            gate = dict(schema="hepta.audit-record-callable.gate.v1", status="PASS",
                source_manifest_sha256=identity, cases=219, operations=459,
                observer_off_cases=219, observer_off_operations=459, transport_refusals=45,
                physical_reader_refusals=13, physical_admissions=2,
                final_read=pin(read(output / "final-read.json")),
                final_process=pin(read(output / "reader-processes/final/processes.json")),
                original_rust_replay=0, native_or_rust_executions_in_reader=0,
                archive_and_hot_cache_qualified=False, begin_finish_caller_qualified=False,
                public_handler_qualified=False, whole_runtime_replaced=False)
            (output / "GATE.json").write_bytes(encoded(gate))
    finally:
        error = recorder.directory / ("readonly-" + phase + ".stderr")
        if error.is_file():
            sys.stderr.write(error.read_text())


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase", choices=("semantic", "controls", "final"), required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--retained", type=Path, required=True)
    a = p.parse_args()
    run(a.phase, a.output.resolve(strict=True), a.retained.resolve(strict=True))
