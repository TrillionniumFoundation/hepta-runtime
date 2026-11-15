"""Actual HIA receipt/ordering controls with explicitly identified policy/OS fixtures."""
from contextlib import ExitStack
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get("HIA_REFERENCE_RUNTIME", ROOT))
sys.path[:0] = [str(REFERENCE / "scripts"), str(Path(__file__).parent)]
from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
from workdir_controls_support import ParameterBridge, ClientBridge, ContextBridge

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
INVALID, CAPACITY, CALL = 0xffffffff, 0xfffffffe, 0xfffffff0
Q = lambda magic, *values: magic + struct.pack("<" + "Q" * len(values), *values)


def invoke(session, wire):
    try:
        raw = session.invoke(wire)
        return len(raw), raw
    except (NativeRejected, NativeCapacityError) as error:
        return error.code, b""


def wire(parameters=b'{"path":"sub"}', metadata=None):
    return Q(b"HMWDCR01", len(parameters), int(metadata is not None), len(metadata or b""), 0) + parameters + (metadata or b"")


class Bridge:
    def __init__(self, sessions):
        self.sessions = sessions
        self.owner = sessions["caller"]
        self.parameters = ParameterBridge(sessions["params"], sessions["value"])
        self.client = ClientBridge(sessions["client"], sessions["value"])
        self.context = ContextBridge(sessions["context"], sessions["state"], self.client)
        self.calls = []
        self.entries = 0

    def read(self, at, size):
        return ctypes.string_at(ctypes.addressof(self.owner._workspace) + at, size)

    def write(self, at, raw):
        ctypes.memmove(ctypes.addressof(self.owner._workspace) + at, raw, len(raw))

    def word(self, at, value=None):
        cell = ctypes.c_uint64.from_address(ctypes.addressof(self.owner._workspace) + at)
        if value is None:
            return cell.value
        cell.value = value

    def reset(self, *, mode=0, legacy=None, installed=True):
        self.installed = installed
        self.context.reset()
        ctypes.memset(self.owner._workspace, 0, 4096)
        startup = Q(b"HMWDCF01", 1, 8, mode, int(legacy is not None), len(legacy or b""), 0) + b"operator" + (legacy or b"")
        assert invoke(self.owner, startup) == (0, b"")
        self.calls = []

    def enter(self, request):
        self.entries += 1
        return invoke(self.owner, request)

    def action(self):
        row = struct.unpack("<8s11Q", self.read(256, 96))
        magic, seq, child, reserved, start, n, output, cap, ack, code, z1, z2 = row
        assert magic == b"HMWDCA01" and seq > 0 and 1 <= child <= 8
        assert reserved == ack == code == z1 == z2 == 0
        assert start == 4096 and output == 67117056 and 24 <= n <= 67108864 and cap <= 134217728
        return dict(seq=seq, child=child, wire=self.read(start, n), cap=cap, phase=self.word(8))

    def complete(self, action):
        child, request = action["child"], action["wire"]
        fixture = None
        if child == 1:
            code, response, _ = self.parameters.run(request)
        elif child == 2:
            code, response, _ = self.context.run(request, True, True)
            fixture = "context-installed-policy-and-is-dir"
        elif child == 3:
            code, response = invoke(self.sessions["state"], request)
        elif child == 4:
            assert request[:8] == b"HRCFGQ01"
            op = struct.unpack_from("<Q", request, 8)[0]
            if op == 6:
                text = b"/fixture-root" if self.installed else b"runtime tools are disabled; start with --runtime-config <file>"
                response = Q(b"HRCFGM01", 0 if self.installed else 1, 0 if self.installed else 9, len(text)) + text
                fixture = "installed-configuration-accessor"
            else:
                assert op == 8
                text = b"explicit remote-policy refusal fixture"
                response = Q(b"HRCFGM01", 1, 0, len(text)) + text
                fixture = "remote-policy-refusal"
            code = len(response)
        elif child == 5:
            code, response = invoke(self.sessions["path"], request)
        elif child == 6:
            assert request[:8] == b"HRLPCQ01"
            response = Q(b"HLPCR001", 0, 0, 0)
            code, fixture = len(response), "local-policy-allow"
        elif child == 7:
            assert request[:8] == b"HRCNLQ01"
            path = b"/fixture-root/sub"
            response = Q(b"HRCNLR01", 0, len(path), 0) + path
            code, fixture = len(response), "local-canonical-path"
        else:
            assert request[:8] == b"HRCANQ01"
            response = Q(b"HRCANR01", 2, 0, 1, 0)
            code, fixture = len(response), "directory-is-dir"
        assert len(response) <= action["cap"]
        self.write(67117056, response)
        self.word(256 + 64, action["seq"])
        self.word(256 + 72, code)
        self.calls.append(dict(child=child, phase=action["phase"], input_sha256=SHA(request), response_sha256=SHA(response),
            response_code=code, explicit_fixture=fixture))
        return code, response

    def finish(self, request, entered=None):
        result = self.enter(request) if entered is None else entered
        for _ in range(48):
            code, response = result
            if code != CALL:
                return code, response
            self.complete(self.action())
            result = self.enter(request)
        raise AssertionError("workdir continuation bound")

    def advance(self, request, phase):
        for _ in range(48):
            code, _ = self.enter(request)
            assert code == CALL, (phase, code, self.calls)
            action = self.action()
            self.complete(action)
            if action["phase"] == phase:
                return action
        raise AssertionError("phase not reached")

    def current(self):
        return self.context.current()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["manifest", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads(args.manifest.read_bytes())
    members = {row["name"]: row for row in metadata["members"]}
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema="hepta.workdir.caller-controls.v1", status="FAIL", controls=[], modules={},
        installed_policy_and_os_results_are_explicit_fixtures=True, original_method_comparison_in_separate_recipe=True,
        whole_runtime_replaced=False, production_activated=False, old_stack_removal_qualified=False)
    started = time.monotonic()
    def save():
        (args.output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    try:
        with ExitStack() as stack:
            sessions = {}
            for name in ["caller", "params", "context", "client", "state", "value", "path"]:
                member = members[name]
                path = args.manifest.resolve().parent / member["manifest"]
                assert SHA(path.read_bytes()) == member["manifest_sha256"]
                module = stack.enter_context(NativeModule(path, manifest_sha256=member["manifest_sha256"]))
                assert module.metadata["source_sha256"] == member["source_sha256"] and module.metadata["image_sha256"] == member["image_sha256"]
                report["modules"][name] = dict(source_sha256=member["source_sha256"], image_sha256=member["image_sha256"])
                output = {"caller": 1 << 20, "params": 128 << 20, "context": 32, "client": (64 << 20) + 32,
                    "state": (8 << 20) + 32, "value": 64 << 20, "path": 32 << 20}[name]
                workspace = (16 << 20) + 64 if name == "state" else 256 << 20
                sessions[name] = stack.enter_context(module.session(output_capacity=output, workspace_capacity=workspace))
            bridge = Bridge(sessions)
            path = wire()
            for phase in range(1, 12):
                request = wire(b'{"path":"ssh://h/work"}') if phase == 7 else wire(b'{"reset":true}') if phase == 11 else path
                bridge.reset()
                baseline = bridge.finish(request)
                baseline_state = bridge.current()
                for offset in range(0, 96, 8):
                    bridge.reset()
                    action = bridge.advance(request, phase)
                    old = bridge.word(256 + offset)
                    replacement = action["cap"] + 1 if offset == 72 else old ^ 1
                    bridge.word(256 + offset, replacement)
                    before = bytes(bridge.owner._output)
                    state = bridge.current()
                    actual = bridge.enter(request)
                    assert actual == (INVALID, b"") and bytes(bridge.owner._output) == before and bridge.current() == state, (phase, offset, actual)
                    bridge.word(256 + offset, old)
                    assert bridge.finish(request) == baseline and bridge.current() == baseline_state
                    report["controls"].append(dict(kind="forged-action", phase=phase, offset=offset,
                        output_unchanged=True, existing_state_unchanged=True, recovery=True))
                bridge.reset()
                action = bridge.advance(request, phase)
                old = bridge.read(67117056, 8)
                bridge.write(67117056, b"BADMAGIC")
                before = bytes(bridge.owner._output)
                state = bridge.current()
                assert bridge.enter(request) == (INVALID, b"")
                assert bytes(bridge.owner._output) == before and bridge.current() == state
                bridge.write(67117056, old)
                assert bridge.finish(request) == baseline and bridge.current() == baseline_state
                report["controls"].append(dict(kind="forged-child-magic", phase=phase, output_unchanged=True,
                    existing_state_unchanged=True, recovery=True))
            malformed = [("short-" + str(n), path[:n], INVALID) for n in range(40)]
            malformed += [("magic", b"BADMAGIC" + path[8:], INVALID),
                ("trailing", path + b"x", INVALID), ("reserved", path[:32] + struct.pack("<Q", 1) + path[40:], INVALID),
                ("metadata-flag", path[:16] + struct.pack("<Q", 2) + path[24:], INVALID),
                ("parameter-limit", Q(b"HMWDCR01", (8 << 20) + 1, 0, 0, 0), CAPACITY),
                ("metadata-limit", Q(b"HMWDCR01", 0, 1, (8 << 20) + 1, 0), CAPACITY),
                ("startup-replacement", Q(b"HMWDCF01", 0, 0, 1, 0, 0, 0), INVALID)]
            for label, request, expected in malformed:
                bridge.reset(mode=0)
                before = bytes(bridge.owner._output)
                state = bridge.current()
                assert bridge.enter(request) == (expected, b"")
                assert bytes(bridge.owner._output) == before and bridge.current() == state
                assert bridge.word(88) == 0 and not bridge.calls
                assert bridge.finish(wire(b'{"reset":true}'))[0] > 32
                report["controls"].append(dict(kind="private-frame", label=label, output_unchanged=True,
                    trusted_mode_unchanged=True, existing_state_unchanged=True, recovery=True))
            bridge.reset()
            result = bridge.finish(wire(b'{"path":false}', b'{bad'))
            assert result[1][:8] == b"HMWDCS01" and struct.unpack_from("<Q", result[1], 8)[0] == 2
            assert [x["child"] for x in bridge.calls] == [1]
            assert sessions["state"].invoke(Q(b"HRSWQ001", 5, 0, 0)) == Q(b"HRSWR001", 2, 1, 0)
            report["controls"].append(dict(kind="typed-parameter-before-metadata-and-latch", actual_child_order=[1]))
            bridge.reset()
            assert bridge.finish(wire(b'{"path":"sub","reset":true}'))[0] > 32
            assert [x["child"] for x in bridge.calls] == [1, 2, 3, 3]
            report["controls"].append(dict(kind="reset-bypasses-path-and-configuration", actual_child_order=[1, 2, 3, 3]))
            bridge.reset(installed=False)
            assert bridge.finish(path)[0] > 32
            assert [x["child"] for x in bridge.calls] == [1, 2, 3, 4, 5, 7, 8, 3]
            report["controls"].append(dict(kind="absent-configuration-bypasses-preflight", actual_child_order=[1, 2, 3, 4, 5, 7, 8, 3]))
            report.update(status="PASS", control_count=len(report["controls"]), actual_caller_entries=bridge.entries,
                actual_parameter_entries=bridge.parameters.entries, actual_value_calls=bridge.parameters.calls + bridge.client.value_calls,
                elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k not in ("controls", "modules")}, sort_keys=True))


if __name__ == "__main__":
    main()
