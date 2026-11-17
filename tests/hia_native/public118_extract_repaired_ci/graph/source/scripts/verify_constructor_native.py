"""Read retained constructor evidence only. Never launches HIA or original code."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import struct
import sys

sys.dont_write_bytecode = True


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_artifact(folder, record, *, materialize=False):
    path = folder / record["path"]
    if path.parent != folder or not path.is_file() or path.is_symlink():
        raise ValueError("artifact escaped capture folder")
    packed = path.read_bytes()
    if len(packed) != record["compressed_bytes"] or sha(packed) != record["compressed_sha256"]:
        raise ValueError("compressed artifact differs")
    digest, count, parts = hashlib.sha256(), 0, []
    with gzip.open(path, "rb") as handle:
        while block := handle.read(1 << 20):
            digest.update(block)
            count += len(block)
            if materialize:
                parts.append(block)
    if count != record["bytes"] or digest.hexdigest() != record["sha256"]:
        raise ValueError("complete retained artifact differs")
    return b"".join(parts) if materialize else None


def verify(source, build, evidence):
    sys.path.insert(0, str(source / "tests"))
    from constructor_cases import cases
    summary = json.loads((evidence / "SUMMARY.json").read_bytes())
    if summary["status"] != "NATIVE_CONSTRUCTOR_NORMAL_PASS":
        raise ValueError("qualification did not complete")
    selected = cases(summary["profile"])
    if summary["expected_cases"] != len(selected) or summary["completed_cases"] != len(selected):
        raise ValueError("case count differs")
    if len(summary["rows"]) != len(selected):
        raise ValueError("case rows differ")
    built = json.loads((build / "BUILD.json").read_bytes())
    if built["status"] != "HIA_COMPILE_PASS" or built["actual_rust_executed"]:
        raise ValueError("build scope differs")
    for name, row in built["modules"].items():
        path = build / row["manifest"]
        raw = path.read_bytes()
        if sha(raw) != row["manifest_sha256"]:
            raise ValueError("module manifest differs")
        module = json.loads(raw)
        for key in ("source", "image"):
            if sha((path.parent / module[key]).read_bytes()) != module[key+"_sha256"]:
                raise ValueError("module input differs")
        actual_source = "native/text_result_constructor.hepta" if name == "text-result-constructor" else "native/typed_result_json.hepta"
        if sha((source / actual_source).read_bytes()) != row["source_sha256"]:
            raise ValueError("current source differs from executed source")
        if module["compiler_commit"] != "d3e2c90173cf733e42b299d0c4274df4b593a12f":
            raise ValueError("compiler source identity differs")
    calls, typed = 0, 0
    for index, (case, row) in enumerate(zip(selected, summary["rows"])):
        folder = evidence / f"case-{index:03d}"
        if row["folder"] != folder.name or row["case"] != case.name:
            raise ValueError("ordered domain differs")
        receipt_raw = (folder / "CASE.json").read_bytes()
        if sha(receipt_raw) != row["receipt_sha256"]:
            raise ValueError("case receipt differs")
        receipt = json.loads(receipt_raw)
        process = json.loads((evidence / f"{index:03d}.process.json").read_bytes())
        if process["returncode"] != 0 or process["native_deadline_seconds"] != 60:
            raise ValueError("case process did not finish within native contract")
        if (evidence / f"{index:03d}.stderr").read_bytes() or (evidence / f"{index:03d}.stdout").read_bytes():
            raise ValueError("case process emitted unexpected streams")
        if receipt["status"] != "NATIVE_CONSTRUCTOR_NORMAL_PASS" or receipt["actual_target_rust_comparison"]:
            raise ValueError("case status/scope differs")
        expected_captures = 3 + int(case.retained_typed)
        if len(receipt["captures"]) != expected_captures:
            raise ValueError("native invocation count differs")
        outputs = []
        for attempt, capture in enumerate(receipt["captures"]):
            child = folder / capture["folder"]
            stored = json.loads((child / "CAPTURE.json").read_bytes())
            if stored != {k:v for k,v in capture.items() if k not in ("owner","folder")}:
                raise ValueError("capture receipt differs")
            inp = load_artifact(child, capture["input"], materialize=True)
            out = load_artifact(child, capture["output"], materialize=True)
            load_artifact(child, capture["workspace"])
            if len(out) != capture["output_capacity"] or capture["workspace"]["bytes"] != capture["workspace_capacity"]:
                raise ValueError("full allocation extent differs")
            if capture["deadline_seconds"] != 60 or capture["elapsed_seconds"] > 60:
                raise ValueError("native invocation deadline differs")
            if attempt < 3:
                if inp != case.frame() or capture["owner"] != "text-result-constructor":
                    raise ValueError("constructor input differs")
            outputs.append(out)
            calls += 1
        first, second, final = receipt["captures"][:3]
        if [first["return_code"],second["return_code"],final["return_code"]] != [0xffffffd0,0xffffffd0,64]:
            raise ValueError("growth/completion sequence differs")
        need_work = 16384+len(case.text.encode())
        if struct.unpack("<8s3Q",outputs[0]) != (b"HGRWS002",1,need_work,0):
            raise ValueError("workspace growth differs")
        if struct.unpack("<8s3Q",outputs[1]) != (b"HGRWS002",2,len(outputs[2]),0):
            raise ValueError("output growth differs")
        header = struct.unpack("<8s7Q",outputs[2][:64])
        if header != (b"HRTCRS01",0,case.is_error,case.policy,64,len(outputs[2])-64,0,0):
            raise ValueError("complete descriptor differs")
        wire = load_artifact(folder,receipt["wire"],materialize=True)
        if outputs[2][64:] != wire or sha(wire) != row["wire_sha256"] or len(wire) != row["wire_bytes"]:
            raise ValueError("completed wire differs")
        expected = dict(content=[dict(type="text",text=case.text)],isError=bool(case.is_error))
        if case.policy != 1:
            expected["resultType"] = "complete"
        if json.loads(wire) != expected:
            raise ValueError("wire semantic result differs")
        if case.retained_typed:
            record = receipt["captures"][3]
            if record["owner"] != "retained-typed-result" or record["return_code"] != len(wire) or outputs[3][:len(wire)] != wire:
                raise ValueError("retained typed complete wire differs")
            typed += 1
    if calls != summary["native_calls"] or typed != summary["retained_typed_comparisons"]:
        raise ValueError("summary counts differ")
    if summary["actual_target_rust_comparison"] or summary["public_publish_qualified"] or summary["full_sdk_qualified"]:
        raise ValueError("qualification scope was overclaimed")
    return dict(schema="hepta.text-constructor-retained-reader.v2",status="PASS",
        profile=summary["profile"],cases=len(selected),native_calls=calls,
        retained_typed_comparisons=typed,complete_buffers_read=True,
        native_or_original_code_launched=False,actual_target_rust_comparison=False,
        public_publish_qualified=False,full_sdk_qualified=False,
        source_sha256=built["modules"]["text-result-constructor"]["source_sha256"],
        image_sha256=built["modules"]["text-result-constructor"]["image_sha256"],
        summary_sha256=sha((evidence/"SUMMARY.json").read_bytes()))


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--build",type=Path,required=True)
    p.add_argument("--evidence",type=Path,required=True)
    p.add_argument("--output",type=Path)
    a=p.parse_args()
    result=verify(a.source.resolve(),a.build.resolve(),a.evidence.resolve())
    raw=json.dumps(result,sort_keys=True,indent=2)+"\n"
    if a.output:
        with a.output.open("x") as handle:
            handle.write(raw)
    print(raw,end="")

