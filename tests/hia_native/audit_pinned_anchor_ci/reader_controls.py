"""Physical rehashed controls for the complete new native pump evidence.

Only copies are changed. Verification recomputes each exact mutation in memory
and reads the retained physical copy; it never repairs or rewrites evidence.
"""
from pathlib import Path
import gzip
import struct
from common import ROOT, encoded, loads, pin, read, require, files, source
import read_capture
import read_only_guard

NAMES = ("hia-input", "hia-output-tail", "hia-workspace", "syscall-errno", "syscall-capability",
         "missing-boundary", "outer-context-tail", "off-missing-operation", "control-return",
         "libc-address", "source-copy", "packer-output-tail", "process-parent", "missing-dispose", "owner-control-return")


def roots(folder,prepared=None):
    return [folder,ROOT]


def copy_capture(capture, target):
    admitted = files(capture)
    target.mkdir(parents=True, exist_ok=False)
    for name, row in admitted.items():
        raw = read(capture / name)
        require(pin(raw) == {k: row[k] for k in ("bytes", "sha256")}, "complete admitted copy input")
        out = target / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(raw)
        out.chmod(row["mode"])
    require(files(target) == admitted, "complete independent copy without shared inodes")
    return admitted


def changes(capture, name, *, compressed=None):
    require(name in NAMES, "fixed new physical refusal")
    changed = {}
    def get(path):
        return changed[path] if path in changed else read(capture / path)
    def obj(path):
        return loads(get(path))
    def put(path, value):
        changed[path] = encoded(value)
    def compressed_write(path, logical):
        logical = bytes(logical)
        if compressed is None:
            changed[path] = gzip.compress(logical, compresslevel=1, mtime=0)
        else:
            require(path in compressed and gzip.decompress(compressed[path]) == logical,
                    "complete physical compressed mutation equals the exact source-derived logical bytes")
            changed[path] = compressed[path]
    if name in ("hia-input", "hia-output-tail", "hia-workspace"):
        p = "native-observed/buffers.bin.gz"
        raw = bytearray(gzip.decompress(get(p)))
        inv = obj("native-observed/INVOCATIONS.json")
        require(raw[:8] == b"AIOLOG01" and raw[8:16] == b"AIOCAL01", "existing first full HIA invocation")
        fields = struct.unpack_from("<9Q", raw, 16)
        ni, no, nw = fields[5:8]
        sizes = (ni + 16, no + 16, nw + 16) * 2
        positions = [88]
        for size in sizes:
            positions.append(positions[-1] + size)
        if name == "hia-input":
            raw[positions[0] + 8] ^= 1
            raw[positions[3] + 8] ^= 1
        else:
            at = positions[4] + no - 1 if name == "hia-output-tail" else positions[5]
            raw[at] ^= 1
        inv[0]["before"] = [pin(bytes(raw[positions[i]:positions[i + 1]])) for i in range(3)]
        inv[0]["after"] = [pin(bytes(raw[positions[i]:positions[i + 1]])) for i in range(3, 6)]
        compressed_write(p, raw)
        put("native-observed/INVOCATIONS.json", inv)
    elif name in ("syscall-errno", "syscall-capability", "missing-boundary", "missing-dispose"):
        p = "native-observed/boundaries.bin.gz"
        raw = bytearray(gzip.decompress(get(p)))
        rows = obj("native-observed/BOUNDARIES.json")
        at = 8
        chosen = None
        for i, row in enumerate(rows):
            require(raw[at:at + 8] == b"AIOFX001", "existing complete native boundary")
            f = struct.unpack_from("<12Q", raw, at + 8)
            sizes = tuple(f[j] + f[j + 3] for j in (4, 5, 6))
            record = at + 104
            positions = [record + 256]
            for size in sizes * 2:
                positions.append(positions[-1] + size)
            end = positions[-1] + f[10] + f[11]
            actual = struct.unpack_from("<16Q", raw, record + 128)
            if (name=="missing-dispose" and f[3]==4) or (name!="missing-dispose" and (name!="syscall-errno" or actual[12]==(1<<64)-1)):
                chosen = (i, at, record, positions, end, f, actual)
                break
            at = end
        require(chosen is not None, "real boundary selected for physical mutation")
        i, at, record, positions, end, f, actual = chosen
        if name in ("missing-boundary","missing-dispose"):
            del raw[at:end]
            rows.pop(i)
            struct.pack_into("<Q", raw, len(raw) - 8, len(rows))
        else:
            if name == "syscall-errno":
                # Change actual returned errno, retaining the real ACK to prove their binding.
                struct.pack_into("<Q", raw, record + 128 + 104, 1 if actual[13] != 1 else 2)
            else:
                raw[positions[5] + 16] ^= 1  # Real root-FD capability, not a summary.
            row = rows[i]
            row["before_record"] = pin(bytes(raw[record:record + 128]))
            row["after_record"] = pin(bytes(raw[record + 128:record + 256]))
            row["before"] = [pin(bytes(raw[positions[j]:positions[j + 1]])) for j in range(3)]
            row["after"] = [pin(bytes(raw[positions[j]:positions[j + 1]])) for j in range(3, 6)]
            row["complete_record"] = pin(bytes(raw[at + 8:end]))
        compressed_write(p, raw)
        put("native-observed/BOUNDARIES.json", rows)
    elif name == "outer-context-tail":
        p = "native-observed/outer.bin.gz"
        raw = bytearray(gzip.decompress(get(p)))
        rows = obj("native-observed/OUTER.json")
        at = 8
        for i, row in enumerate(rows):
            require(raw[at:at + 8] == b"AIOENT01", "existing complete outer invocation")
            f = struct.unpack_from("<12Q", raw, at + 8)
            sizes = (f[5] + f[9], f[6] + f[10], f[7] + f[11], f[8])
            positions = [at + 104]
            for size in sizes * 2:
                positions.append(positions[-1] + size)
            if f[3] == 1:
                raw[positions[6] + f[7] - 1] ^= 1
                row["after"] = [pin(bytes(raw[positions[j]:positions[j + 1]])) for j in range(4, 8)]
                break
            at = positions[-1]
        else:
            raise ValueError("missing actual outer operation")
        compressed_write(p, raw)
        put("native-observed/OUTER.json", rows)
    elif name == "off-missing-operation":
        p = "native-observer-off/OBSERVATIONS.json"
        value = obj(p)
        value.pop()
        put(p, value)
    elif name == "control-return":
        p = "transport-controls/buffers.bin.gz"
        raw = bytearray(gzip.decompress(get(p)))
        rows = obj("transport-controls/CALLS.json")
        at = 8
        for i, row in enumerate(rows):
            require(raw[at:at + 8] == b"AIOCTL01", "actual control invocation")
            f = struct.unpack_from("<7Q", raw, at + 8)
            meta_at = at + 64
            end = meta_at + f[2]
            if row["phase"] == "refusal":
                row["returned"] = 0
                meta = encoded(row)
                raw[meta_at:end] = meta
                struct.pack_into("<Q", raw, at + 16, 0)
                struct.pack_into("<Q", raw, at + 24, len(meta))
                break
            at = end + 2 * sum(f[3:])
        else:
            raise ValueError("missing actual refusal")
        compressed_write(p, raw)
        put("transport-controls/CALLS.json", rows)
    elif name=="owner-control-return":
        p="owner-controls/buffers.bin.gz";raw=bytearray(gzip.decompress(get(p)));rows=obj("owner-controls/CALLS.json");at=8
        for i,row in enumerate(rows):
            require(raw[at:at+8]==b"HAPCALL1","actual direct control")
            v=struct.unpack_from("<6Q",raw,at+8);meta_at=at+56;end=meta_at+v[5]
            if row["expected"] in (0xffffffff,0xfffffffe):
                row["returned"]=0;meta=encoded(row);raw[meta_at:end]=meta
                struct.pack_into("<Q",raw,at+16,0);struct.pack_into("<Q",raw,at+48,len(meta));break
            at=end+2*sum(n+16 for n in v[2:5])
        else:raise ValueError("missing actual owner refusal")
        compressed_write(p,raw);put("owner-controls/CALLS.json",rows)
        report=obj("owner-controls/CONTROLS.json");report["calls"]=pin(get("owner-controls/CALLS.json"));report["buffers"]=pin(get(p));put("owner-controls/CONTROLS.json",report)
    elif name == "libc-address":
        p = "native-observed/LIBC-BINDINGS.json"
        value = obj(p)
        value[0]["pointer"] += 1
        value[0]["observed_symbol_address"] += 1
        put(p, value)
    elif name == "source-copy":
        p = "source/read_context.py"
        changed[p] = get(p) + b"\n"
    elif name == "packer-output-tail":
        p = "build/emission/valid.output-after.bin"
        value = bytearray(get(p))
        value[-1] ^= 1
        changed[p] = bytes(value)
        emission = obj("build/emission/EMISSION.json")
        row = next(r for r in emission["calls"] if r["name"] == "valid")
        row["files"]["output-after"].update(pin(changed[p]))
        put("build/emission/EMISSION.json", emission)
        build = obj("build/BUILD.json")
        build["emission"] = emission
        put("build/BUILD.json", build)
    elif name == "process-parent":
        p = "native-observed/NATIVE.json"
        value = obj(p)
        value["parent_pid"] += 1
        put(p, value)
    # Rebind every public report/stream hash that could otherwise mask the actual semantic rejection.
    for folder in ("native-observed", "native-observer-off"):
        p = folder + "/NATIVE.json"
        value = obj(p)
        mapping = dict(observations="OBSERVATIONS.json", contexts="CONTEXTS.json", outer="OUTER.json",
            outer_buffers="outer.bin.gz", retirement="RETIREMENT.json", libc="LIBC.bin",
            libc_bindings="LIBC-BINDINGS.json", maps="PROCESS-MAPS.txt")
        if folder == "native-observed":
            mapping.update(buffers="buffers.bin.gz", invocations="INVOCATIONS.json", boundary_buffers="boundaries.bin.gz",
                boundary_rows="BOUNDARIES.json", effects="effects.jsonl", observer_errors="OBSERVER-ERRORS.json")
        for key, filename in mapping.items():
            value[key] = pin(get(folder + "/" + filename))
        put(p, value)
    p = "transport-controls/CONTROLS.json"
    value = obj(p)
    value["files"] = {n: pin(get("transport-controls/" + n)) for n in value["files"]}
    put(p, value)
    process = obj("processes/processes.json")
    reports = {"native-build": "build/BUILD.json", "native-observed": "native-observed/NATIVE.json",
               "native-observer-off": "native-observer-off/NATIVE.json", "native-controls": "transport-controls/CONTROLS.json", "owner-controls": "owner-controls/CONTROLS.json"}
    for row in process:
        if row["name"] in reports:
            p = "processes/" + row["name"] + ".stdout"
            changed[p] = encoded(obj(reports[row["name"]]))
            row["stdout"] = dict(file=row["name"] + ".stdout", **pin(changed[p]))
    put("processes/processes.json", process)
    metadata = obj("CAPTURE.json")
    for path, raw in changed.items():
        require(path in metadata["files"], "only already admitted physical files are mutated")
        metadata["files"][path] = dict(**pin(raw), mode=metadata["files"][path]["mode"])
    put("CAPTURE.json", metadata)
    return changed


def refused(folder, prepared):
    try:
        read_capture.verify(folder)
    except ValueError as error:
        return dict(refused=True, error=str(error))
    raise ValueError("physical callable evidence mutation was accepted")


def run(capture, output):
    prepared=None
    output.mkdir(parents=True, exist_ok=False)
    baseline = read_capture.verify(capture)
    rows = []
    for name in ("one", "nested/two", *NAMES):
        target = output / (name if name in ("one", "nested/two") else "refusals/" + name)
        physical = copy_capture(capture, target)
        admission = name in ("one", "nested/two")
        changed = {} if admission else changes(capture, name)
        for path, raw in changed.items():
            (target / path).write_bytes(raw)
        operation = (lambda: read_capture.verify(target)) if admission else (lambda: refused(target, prepared))
        proof = read_only_guard.guarded(operation, roots=roots(target, prepared),
                                        foreign_path=str(capture / "CAPTURE.json"))
        if admission:
            require(proof["evidence"] == baseline, "entire physical relocated admission")
        filename = name.replace("/", "-") + ".json"
        (output / filename).write_bytes(encoded(proof))
        rows.append(dict(name=name, admission=admission, capture=target.relative_to(output).as_posix(),
            proof=filename, physical=files(target), changes={p: pin(b) for p, b in changed.items()},
            evidence=proof["evidence"]))
    report = dict(schema="hepta.audit-pinned-anchor.reader-controls.v1", status="PASS",
        source_manifest_sha256=source(), names=list(NAMES), admissions=2, refusals=len(NAMES), rows=rows,
        native_or_rust_executions=0, reader_writes_during_verification=0)
    (output / "CONTROLS.json").write_bytes(encoded(report))
    return report


def verify(capture, output, baseline):
    prepared=None
    report = loads(read(output / "CONTROLS.json"))
    require(report["schema"] == "hepta.audit-pinned-anchor.reader-controls.v1" and report["status"] == "PASS" and
            report["source_manifest_sha256"] == source() and report["names"] == list(NAMES) and
            report["admissions"] == 2 and report["refusals"] == len(NAMES) and len(report["rows"]) == 2 + len(NAMES),
            "complete exact new physical refusal/admission domain")
    base_files = files(capture)
    for name, row in zip(("one", "nested/two", *NAMES), report["rows"], strict=True):
        admission = name in ("one", "nested/two")
        relative = name if admission else "refusals/" + name
        require(row["name"] == name and row["admission"] is admission and row["capture"] == relative and
                row["proof"] == name.replace("/", "-") + ".json", "complete fixed physical control identity")
        require(set(row["changes"]).issubset(base_files), "only original admitted relative mutation paths")
        compressed = {p: read(output / relative / p) for p in row["changes"] if p.endswith(".bin.gz")}
        changed = {} if admission else changes(capture, name, compressed=compressed)
        require(set(compressed) == {p for p in changed if p.endswith(".bin.gz")},
                "only exact actual compressed mutation paths")
        expected = dict(base_files)
        for path, raw in changed.items():
            expected[path] = dict(**pin(raw), mode=base_files[path]["mode"])
        folder = output / relative
        require(files(folder) == row["physical"] == expected and
                row["changes"] == {p: pin(b) for p, b in changed.items()},
                "each complete retained clone equals exactly its source-derived mutation")
        observed = read_capture.verify(folder) if admission else refused(folder, prepared)
        require(observed == row["evidence"] and (not admission or observed == baseline),
                "same complete unchanged reader verdict for every retained physical copy")
        proof = loads(read(output / row["proof"]))
        require(proof["evidence"] == observed and proof["before"] == proof["after"] and
                proof["native_or_rust_executions"] == proof["reader_writes"] == 0 and
                len(proof["probes"]) == len({p["name"] for p in proof["probes"]}) == 12,
                "every complete unchanged-byte guard and original twelve probes")
    return dict(status="COMPLETE_PHYSICAL_READER_CONTROLS_PASS", admissions=2, refusals=len(NAMES),
                guard_probes=12 * (2 + len(NAMES)), native_or_rust_executions=0, reader_writes=0)
