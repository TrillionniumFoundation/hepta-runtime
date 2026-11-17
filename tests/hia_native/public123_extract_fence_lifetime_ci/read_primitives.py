"""Complete byte readers retained from qualified build evidence; no image invocation."""
from pathlib import Path
import hashlib,json,stat,struct
def require(ok,message):
    if not ok:raise ValueError(message)
def pin(path):
    raw=Path(path).read_bytes()
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def files(root):
    root=Path(root);result={}
    for p in sorted(root.rglob("*")):
        require(not p.is_symlink(),"source symlink")
        if p.is_file():result[p.relative_to(root).as_posix()]={**pin(p),"mode":stat.S_IMODE(p.stat().st_mode)}
    return result
COMPILER = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
PORT_PIN = "2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1"
PROFILES = {"standard": (8<<20, 8<<20, 32<<20),
    "history.v1": (128<<20, 128<<20, 256<<20),
    "serde-json.v1": (16<<20, 64<<20, 256<<20),
    "sdk-message-target.v1": (32<<20, 64<<20, 256<<20),
    "batch-plan.v1": (512<<20, 1024<<20, 1152<<20),
    "batch-write.v1": (512<<20, 2048<<20, 3072<<20)}
def raw(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), "nonregular evidence: " + str(path))
    return path.read_bytes()

def doc(path):
    return json.loads(raw(path))

def sha(value):
    return hashlib.sha256(value).hexdigest()

def compile_module(worker, folder, name, body, profile, dependency, custody):
    manifest = doc(folder/"manifest.json")
    produced = raw(folder/"module.image.bin")
    require(raw(folder/(name+".hepta")) == body, "compiled source copy differs: " + name)
    expected = {"schema": "hepta.runtime.native-module.v1", "name": name,
        "abi": "hepta.runtime.borrowed-bytes.linux-x86_64.v1", "target": "linux-x86_64",
        "compiler_commit": COMMIT, "compiler_sha256": COMPILER,
        "source": name+".hepta", "source_sha256": sha(body),
        "image": "module.image.bin", "image_sha256": sha(produced),
        "input_capacity": PROFILES[profile][0], "output_capacity": PROFILES[profile][1],
        "workspace_capacity": PROFILES[profile][2], "qualification": "development_fixed_point",
        "standalone": None}
    if profile != "standard":
        expected["buffer_profile"] = profile
    require(manifest == expected, "complete module manifest differs: " + name)
    receipt = custody.compile_receipt(worker, folder, "module",
        raw(worker/"build/bootstrap/B3.image.bin"), body, "module.image.bin", "flat-x86-64")
    require(doc(folder/"build.json") == {"compile_receipt": receipt,
        "compiler_dependency": dependency, "whole_runtime_replaced": False},
        "complete actual compile receipt differs: " + name)
    require(produced and len(produced) <= 1<<20 and not produced.startswith(b"\x7fELF"),
            "flat module extent differs")
    return manifest, produced

def object_text_and_symbols(obj):
    require(obj[:16] == b"\x7fELF\x02\x01\x01" + bytes(9), "object ELF identity")
    require(struct.unpack_from("<HHI", obj, 16) == (1, 62, 1), "object architecture/type")
    shoff, = struct.unpack_from("<Q", obj, 40)
    entsize, count, names_index = struct.unpack_from("<HHH", obj, 58)
    require(entsize == 64 and count > 0 and shoff + count*64 <= len(obj), "object section extent")
    sections = [struct.unpack_from("<IIQQQQIIQQ", obj, shoff+i*64) for i in range(count)]
    require(names_index < count, "object section name table")
    for row in sections:
        if row[1] != 8:
            require(row[4] + row[5] <= len(obj), "object complete section extent")
        require(row[1] not in (4, 9) or row[5] == 0, "object contains relocations")
    names_row = sections[names_index]
    names = obj[names_row[4]:names_row[4]+names_row[5]]
    section_names = [names[r[0]:names.index(0, r[0])].decode() for r in sections]
    index = section_names.index(".text")
    row = sections[index]
    body = obj[row[4]:row[4]+row[5]]
    symbols = {}
    for table in sections:
        if table[1] != 2:
            continue
        require(table[9] == 24 and table[5] % 24 == 0 and table[6] < count, "object symbol extent")
        strings = sections[table[6]]
        data = obj[strings[4]:strings[4]+strings[5]]
        for at in range(table[4], table[4]+table[5], 24):
            name, info, other, section, value, size = struct.unpack_from("<IBBHQQ", obj, at)
            if section == index:
                key = data[name:data.index(0, name)].decode()
                require(value <= len(body), "object text symbol outside body")
                if key:
                    require(key not in symbols or symbols[key] == value, "ambiguous object symbol")
                    symbols[key] = value
    require("_start" in symbols, "actual text entry missing")
    return body, symbols

def boundary_process(folder, label, command, origin, limit):
    record = doc(folder/(label+".process.json"))
    expected = {"name": label, "command": command, "cwd": origin,
        "timeout_seconds": limit, "exit_code": 0, "timed_out": False,
        "stdout": pin(folder/(label+".stdout")), "stderr": pin(folder/(label+".stderr"))}
    require(set(record) == set(expected)|{"elapsed_seconds"}, "boundary receipt schema differs")
    require(all(record[k] == v and type(record[k]) is type(v) for k, v in expected.items()),
            "boundary process command/status differs: " + label)
    require(type(record["elapsed_seconds"]) in (int, float) and 0 <= record["elapsed_seconds"] <= limit,
            "boundary process deadline differs: " + label)
    require(raw(folder/(label+".stderr")) == b"", "boundary process stderr differs: " + label)
    return record

