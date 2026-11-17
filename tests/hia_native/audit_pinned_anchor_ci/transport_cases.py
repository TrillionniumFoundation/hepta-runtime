"""Fixed admission-only native controls; all pointers are owned allocations or NULL."""
from protocol import INVALID, CAPACITY, cases, initial
from common import ROOT, require

BUSY = 0xfffffffd
MECHANICAL = 0xfffffffc

# Each mutation changes only caller-owned test memory before invoking the export.
# None supplies a foreign executable capability or causes a policy/effect substitute.
SPECS = (
    ("initialize", "short-context", {"capacity": 98303}, (), CAPACITY),
    ("initialize", "null-context", {"context": 0}, (), INVALID),
    ("initialize", "unaligned-context", {"context": "context+1"}, (), INVALID),
    ("initialize", "null-table", {"table": 0}, (), INVALID),
    ("initialize", "unaligned-table", {"table": "table+1"}, (), INVALID),
    ("initialize", "out-of-range-root", {"directory": 1 << 31}, (), INVALID),
    ("initialize", "zero-first-function", {}, (("table", 0, "00" * 8),), INVALID),
    ("initialize", "zero-last-function", {}, (("table", 128, "00" * 8),), INVALID),
    ("initialize", "reserved-table-word", {}, (("table", 136, "01" + "00" * 7),), INVALID),
    ("initialize", "dirty-context-head", {}, (("context", 0, "01"),), INVALID),
    ("initialize", "dirty-context-tail", {}, (("context", 98303, "01"),), INVALID),
    ("initialize", "user-without-callback", {"user": 1}, (), INVALID),
    ("initialize", "overlapping-table", {"table": "context"}, (), INVALID),
    ("entry", "empty-input", {"input_bytes": 0}, (), INVALID),
    ("entry", "short-input", {"input_bytes": 127}, (), INVALID),
    ("entry", "oversized-input", {"input_bytes": 4353}, (), INVALID),
    ("entry", "small-output", {"output_capacity": 8191}, (), CAPACITY),
    ("entry", "small-context", {"capacity": 98303}, (), CAPACITY),
    ("entry", "null-input", {"input": 0}, (), INVALID),
    ("entry", "null-output", {"output": 0}, (), INVALID),
    ("entry", "null-context", {"context": 0}, (), INVALID),
    ("entry", "unaligned-context", {"context": "context+1"}, (), INVALID),
    ("entry", "overlapping-input-output", {"output": "input"}, (), INVALID),
    ("entry", "overlapping-input-context", {"input": "context"}, (), INVALID),
    ("entry", "overlapping-output-context", {"output": "context"}, (), INVALID),
    ("entry", "bad-context-magic", {}, (("context", 0, "00"),), INVALID),
    ("entry", "busy-context", {}, (("context", 8, "01" + "00" * 7),), BUSY),
    ("entry", "poisoned-context", {}, (("context", 8, "02" + "00" * 7),), MECHANICAL),
    ("entry", "wrong-table-count", {}, (("context", 40, "0f" + "00" * 7),), INVALID),
    ("entry", "reserved-context-word", {}, (("context", 32, "01" + "00" * 7),), INVALID),
    ("entry", "bad-next-capability", {}, (("context", 24, "01" + "00" * 7),), INVALID),
    ("entry", "reserved-context-tail", {}, (("context", 248, "01" + "00" * 7),), INVALID),
    ("entry", "missing-root", {}, (("context", 256, "00" * 8),), INVALID),
    ("entry", "wrong-root-kind", {}, (("context", 264, "02" + "00" * 7),), INVALID),
    ("entry", "unconsumed-owned-slot", {}, (("context", 280, "02" + "00" * 7),), INVALID),
    ("entry", "zero-copied-function", {}, (("context", 640, "00" * 8),), INVALID),
    ("entry", "wrong-input-magic", {}, (("input", 0, "00"),), INVALID),
    ("entry", "wrong-borrowed-directory", {}, (("input", 24, "02" + "00" * 7),), INVALID),
    ("dispose", "short-context", {"capacity": 98303}, (), CAPACITY),
    ("dispose", "null-context", {"context": 0}, (), INVALID),
    ("dispose", "unaligned-context", {"context": "context+1"}, (), INVALID),
    ("dispose", "wrong-context-magic", {}, (("context", 0, "00"),), INVALID),
    ("dispose", "busy-context", {}, (("context", 8, "01" + "00" * 7),), BUSY),
    ("dispose", "bad-state", {}, (("context", 8, "03" + "00" * 7),), INVALID),
    ("dispose", "unconsumed-owned-slot", {}, (("context", 280, "02" + "00" * 7),), INVALID),
)


def wire():
    # A real missing anchor opens through the native pump and returns original ENOENT.
    return initial(0,0,{"operation":1})


def defaults(function):
    if function == "initialize":
        return dict(context="context", capacity=98304, directory="root", table="table", observer=0, user=0)
    if function == "entry":
        return dict(input="input", input_bytes=len(wire()), output="output", output_capacity=8192,
                    context="context", capacity=98304)
    require(function == "dispose", "fixed exported function")
    return dict(context="context", capacity=98304)


def argv(function, parameters, addresses):
    order = {"initialize": ("context", "capacity", "directory", "table", "observer", "user"),
             "entry": ("input", "input_bytes", "output", "output_capacity", "context", "capacity"),
             "dispose": ("context", "capacity")}[function]
    result = []
    for name in order:
        value = parameters[name]
        if type(value) is str:
            parts = value.split("+")
            require(len(parts) in (1, 2) and parts[0] in addresses, "only actual owned control pointers")
            value = addresses[parts[0]] + (int(parts[1]) if len(parts) == 2 else 0)
        require(type(value) is int and 0 <= value < 1 << 64, "exact native argument")
        result.append(value)
    return result


def mutate(buffers, changes):
    result = {key: bytearray(value) for key, value in buffers.items()}
    for key, offset, hexadecimal in changes:
        value = bytes.fromhex(hexadecimal)
        require(0 <= offset <= len(result[key]) and len(value) <= len(result[key]) - offset,
                "whole controlled owned mutation")
        result[key][offset:offset + len(value)] = value
    return {key: bytes(value) for key, value in result.items()}


def sequence(spec):
    function, name, overrides, changes, expected = spec
    rows = []
    if function != "initialize":
        rows.append(("before-init", "initialize", defaults("initialize"), (), 0))
    rows.append(("refusal", function, dict(defaults(function), **overrides), changes, expected))
    if function == "initialize":
        rows.append(("recovery-init", "initialize", defaults("initialize"), (), 0))
    rows += [("recovery-run", "entry", defaults("entry"), (), None),
             ("recovery-dispose", "dispose", defaults("dispose"), (), 0)]
    return rows
