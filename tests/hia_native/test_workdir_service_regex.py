"""Exercise installed HIA regex continuations before actual public workdir calls."""
from pathlib import Path
import argparse
import fcntl
import hashlib
import json
import os
import select
import signal
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))
from compare_workdir_original import decode, encoded, framed, words

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
VALID = (
    ("literal", ["a"]), ("character-class", [r"[a-z]+"]),
    ("unicode-property", [r"\p{Greek}+"]),
    ("anchored-wrapper-alternation", [r")|foo(?:"]),
    ("size-bound-accepted", ["a{327674}"]),
    ("ordered-multiple", ["a", r"\p{Greek}+", r")|foo(?:"]),
)
INVALID = (("syntax", "("), ("unicode-size", r"\w{500}"),
           ("size-bound-refused", "a{327675}"), ("invalid-byte", r"(?-u:\xFF)"))


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def action(patterns):
    return dict(executable="/echo", allow_extra_args=True, extra_arg_patterns=patterns)


def exclusive(path):
    with path.open("rb") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(stream, fcntl.LOCK_UN)
        return True


class Process:
    def __init__(self, executable, variant, fixture, config, mode, output):
        self.variant, self.mode, self.output = variant, mode, output
        self.started = time.monotonic()
        self.input = bytearray(); self.stdout = bytearray()
        self.snapshot = b""; self.events = []; self.closed = False
        argv = [str(executable), "--runtime-config", str(config), "--session-root", str(fixture)]
        kwargs = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=fixture, env={"PATH": "", "USER": "operator"}, start_new_session=True)
        if variant == "native":
            read, write = os.pipe2(os.O_CLOEXEC)
            reserve = None
            try:
                os.fstat(4)
            except OSError:
                reserve = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
                require(reserve == 4, "workdir snapshot descriptor reservation differs")
            def arrange():
                os.dup2(read, 4, inheritable=True)
                if read != 4:
                    os.close(read)
            try:
                self.process = subprocess.Popen(argv, pass_fds=tuple({read, 4}), preexec_fn=arrange, **kwargs)
            except BaseException:
                os.close(write)
                raise
            finally:
                os.close(read)
                if reserve is not None:
                    os.close(reserve)
            self.snapshot = words(b"HMWINIT1", mode, 0, 0)
            try:
                require(os.write(write, self.snapshot) == len(self.snapshot), "workdir snapshot short write")
            except BrokenPipeError:
                pass  # A rejected startup can exit before the private descriptor is consumed.
            finally:
                os.close(write)
        else:
            self.process = subprocess.Popen(argv, **kwargs)
        self.executable_sha256 = SHA(executable.read_bytes())

    def exact(self, size):
        end = time.monotonic() + 30
        result = bytearray()
        while len(result) < size:
            remaining = end - time.monotonic()
            require(remaining > 0, "workdir actual response deadline exceeded")
            ready, _, _ = select.select([self.process.stdout], [], [], remaining)
            require(ready, "workdir actual response timed out")
            raw = os.read(self.process.stdout.fileno(), size - len(result))
            require(raw, "workdir process ended before complete response")
            result.extend(raw)
        return bytes(result)

    def call(self, label, params):
        wire = framed([(label, encoded(params), None)], self.variant, self.mode, None)
        self.process.stdin.write(wire); self.process.stdin.flush()
        self.input.extend(wire)
        header = self.exact(8)
        size = struct.unpack("<Q", header)[0]
        require(0 < size <= 134217792, "workdir response size differs")
        output = header + self.exact(size)
        self.stdout.extend(output)
        observed = decode(output, self.variant)
        require(len(observed) == 1, "workdir response count differs")
        tag, latch, current, text = observed[0]
        row = dict(label=label, tag=tag, latch=latch, current_hex=current.hex(), text_hex=text.hex())
        self.events.append(row)
        return row

    def close(self, expected_error=None):
        self.process.stdin.close(); self.process.stdin = None
        timed = False
        try:
            stdout, stderr = self.process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timed = True
            os.killpg(self.process.pid, signal.SIGKILL)
            stdout, stderr = self.process.communicate()
        self.stdout.extend(stdout)
        self.closed = True
        record = dict(variant=self.variant, pid=self.process.pid, executable_sha256=self.executable_sha256,
            exit_code=self.process.returncode, timed_out=timed, reaped=True, timeout_seconds=30,
            elapsed_seconds=time.monotonic() - self.started, events=self.events)
        for name, raw in dict(input=bytes(self.input), stdout=bytes(self.stdout), stderr=stderr,
                              snapshot=self.snapshot).items():
            (self.output / (self.variant + "." + name)).write_bytes(raw)
            record[name] = dict(bytes=len(raw), sha256=SHA(raw))
        (self.output / (self.variant + ".process.json")).write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
        require(not timed and not Path("/proc", str(self.process.pid)).exists(), "workdir process not fully retired")
        if expected_error is None:
            require(self.process.returncode == 0 and stdout == b"", "workdir valid process failed")
            if self.variant == "native":
                require(stderr == b"", "native workdir emitted unexpected stderr")
            else:
                bootstrap = json.loads(stderr)
                require(bootstrap["schema"] == "hepta.client-context.actual-sdk-bootstrap.v1",
                        "actual original SDK bootstrap differs")
        else:
            require(self.process.returncode == 78 and self.stdout == b""
                    and stderr == expected_error + b"\n", ("workdir startup refusal differs", record, stderr))
        return record

    def retire(self):
        if not self.closed:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original", type=Path)
    parser.add_argument("--original-sha256")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = args.manifest.resolve(strict=True)
    metadata = json.loads(manifest.read_bytes())
    native = manifest.parent / metadata["executable"]
    require(SHA(native.read_bytes()) == metadata["elf_sha256"]
            and len(metadata["members"]) == 21 and metadata["regex_continuation_graph"] is True,
            "workdir complete regex graph is not selected")
    variants = [("native", native)]
    if args.original:
        original = args.original.resolve(strict=True)
        require(SHA(original.read_bytes()) == args.original_sha256, "original executable pin differs")
        variants.append(("original", original))
    fixture = args.output / "fixture"
    fixture.mkdir()
    for name in ("sub", "other", "outside"):
        (fixture / name).mkdir()
    config = args.output / "runtime.json"
    started = time.monotonic()
    report = dict(schema="hepta.workdir.installed-regex-comparison.v1", status="FAIL", cases=[],
        manifest_sha256=SHA(manifest.read_bytes()), native_sha256=SHA(native.read_bytes()),
        actual_original=bool(args.original), source_sha256=SHA(Path(__file__).read_bytes()),
        public_sdk_routing_qualified=False, remote_execution_qualified=False,
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)
    def save():
        (args.output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    def paired(label, actions, mode=0, error=None):
        output = args.output / label
        output.mkdir()
        state = args.output / (label + "-state")
        configuration = dict(state_dir=str(state), controller_workspace_roots=[str(fixture)],
            hosts={"h": dict(ssh_target="target", remote_state_dir="/remote", privileged_actions=actions)})
        events = {}
        for variant, executable in variants:
            config.write_bytes(encoded(configuration)); config.chmod(0o600)
            process = Process(executable, variant, fixture, config, mode, output)
            try:
                if error is None:
                    first = process.call("set-sub", {"path": "sub"})
                    require(first["tag"] == 0 and first["latch"] == 1, "valid regex config refused workdir")
                    for lock in ("controller.owner.lock", "controller.lock"):
                        require(not exclusive(state / lock), "installed configuration lock not retained")
                    changed = dict(configuration, state_dir=str(args.output / "uninstalled"),
                        controller_workspace_roots=[str(fixture / "outside")],
                        hosts={"h": dict(configuration["hosts"]["h"], privileged_actions={"inspect": action(["("])})})
                    config.write_bytes(encoded(changed))
                    require(process.call("reset", {"reset": True})["tag"] == 0, "reset after config replacement failed")
                    require(process.call("set-other", {"path": "other"})["tag"] == 0,
                            "ordinary call used replaced configuration")
                    require(not (args.output / "uninstalled").exists(), "ordinary request installed changed config")
                row = process.close(error)
                if error is None:
                    for lock in ("controller.owner.lock", "controller.lock"):
                        require(exclusive(state / lock), "completed process retained configuration locks")
                else:
                    require(not state.exists(), "invalid regex created installation state")
                events[variant] = row["events"]
                report["cases"].append(dict(label=label, mode=mode, error_hex=None if error is None else error.hex(), process=row))
                save()
            finally:
                process.retire()
        if args.original:
            require(events["native"] == events["original"], (label, "actual original responses/state differ", events))
    try:
        for name, patterns in VALID:
            for mode in (0, 1):
                paired(name + "-mode-" + str(mode), {"inspect": action(patterns)}, mode)
        for name, pattern in INVALID:
            paired(name, {"inspect": action([pattern])}, error=b"host `h` privileged action `inspect` has invalid argument regex")
        actions = {"middle": action(["a", "("]), "zlast": {"executable": "relative"}}
        paired("regex-before-later-action", actions,
               error=b"host `h` privileged action `middle` has invalid argument regex")
        paired("earlier-action-before-regex", dict(actions, afirst={"executable": "relative"}),
               error=b"host `h` has invalid privileged action `afirst`")
        counts = {}
        for variant in ("native", "original"):
            rows = [row for row in report["cases"] if row["process"]["variant"] == variant]
            counts[variant + "_processes"] = len(rows)
            counts[variant + "_requests"] = sum(len(row["process"]["events"]) for row in rows)
            counts[variant + "_startup_refusals"] = sum(row["process"]["exit_code"] == 78 for row in rows)
        expected = dict(native_processes=18, native_requests=36, native_startup_refusals=6,
            original_processes=18 if args.original else 0, original_requests=36 if args.original else 0,
            original_startup_refusals=6 if args.original else 0)
        require(counts == expected, "complete regex scenario inventory differs")
        require(report["source_sha256"] == SHA(Path(__file__).read_bytes()), "workdir test source changed")
        report.update(status="PASS", expected_counts=expected, **counts, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}, sort_keys=True))


if __name__ == "__main__":
    main()
