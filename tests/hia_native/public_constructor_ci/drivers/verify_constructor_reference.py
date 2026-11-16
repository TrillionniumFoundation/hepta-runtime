"""Independently read the fresh Rust constructor capture; never execute code."""
from pathlib import Path
import argparse, gzip, hashlib, io, json, sys, tarfile, tomllib
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
TARGET="d3d75c30719db966b004756f610007a7c723729e"
SDK_CHECKSUM="d24a7e92f4bcaa36b97fa93c4fa7ca8f3e669eced949345b3462dba333c7f909"

def read(path):
    return json.loads(path.read_bytes())

def raw_pin(path,pin):
    raw=path.read_bytes()
    assert SHA(raw)==pin["sha256"] and len(raw)==pin["bytes"],str(path)
    return raw

def local(root,relative):
    path=Path(relative)
    assert not path.is_absolute() and ".." not in path.parts
    result=root/path
    assert result.is_file() and not result.is_symlink()
    return result

def captured(folder,pin):
    raw=raw_pin(local(folder,pin["path"]),
        dict(bytes=pin["compressed_bytes"],sha256=pin["compressed_sha256"]))
    unpacked=gzip.decompress(raw)
    assert len(unpacked)==pin["bytes"] and SHA(unpacked)==pin["sha256"]
    return unpacked

def processes(root,relative,labels):
    directory=root/relative
    rows=read(directory/"processes.json")
    assert [row["label"] for row in rows]==labels
    for row in rows:
        assert row["exit_code"]==0 and row["timed_out"] is False
        assert row["timeout_seconds"]==180 and row["elapsed_seconds"]>=0
        assert row["stdin_sha256"] is None
        for stream in ("stdout","stderr"):
            raw=local(directory,row["label"]+"."+stream).read_bytes()
            assert SHA(raw)==row[stream+"_sha256"] and len(raw)==row[stream+"_bytes"]
    return rows

def verify(source,original,native):
    source=source.resolve(strict=True)
    original=original.resolve(strict=True)
    native=native.resolve(strict=True)
    provenance=read(source/"reference/SOURCES.json")
    assert provenance["target_application_commit"]==TARGET and provenance["target_rmcp"]=="3.9.0"
    for relative,pin in provenance["files"].items():
        raw_pin(local(source,relative),pin)
    for group in ("oracle","cache-seed","target"):
        for path in sorted((source/"reference"/group).rglob("*")):
            if path.is_file():
                assert path.read_bytes()==local(original,group+"/"+str(path.relative_to(source/"reference"/group))).read_bytes()
    built=read(original/"BUILD.json")
    summary=read(original/"SUMMARY.json")
    assert summary["status"]=="ACTUAL_TARGET_CONSTRUCTOR_PASS"
    assert summary["target_application_commit"]==TARGET
    assert summary["actual_target_rust_compared"] is True
    assert summary["fresh_exact_rust_built"] is True and summary["complete_output_compared"] is True
    assert summary["full_sdk_qualified"] is False and summary["public_target_handler_comparison"] is False
    for key in ("fresh_target_dir","actual_target_sdk_built","actual_target_sdk_executed",
                "offline_resolution","all_retained_exactly_match_target"):
        assert built[key] is True,key
    assert built["rust_version"].splitlines()[0].startswith("rustc 1.95.0 ")
    binary=local(original,built["retained_binary_relative_path"]).read_bytes()
    assert SHA(binary)==built["binary_sha256"] and binary[:4]==b"\x7fELF"
    assert built["source_sha256"]==SHA((source/"reference/oracle/main.rs").read_bytes())
    assert built["project_files"]=={p.name:SHA(p.read_bytes()) for p in sorted((original/"oracle").iterdir()) if p.is_file()}
    pref=processes(original,"evidence/cache-prefetch",["rustc-version","cargo-fetch-locked"])
    fresh=processes(original,"evidence/rust-build-processes",
        ["rustc-version","cargo-version","metadata-offline","cargo-build-locked-offline"])
    for path in ("evidence/cache-prefetch/rustc-version.stdout","evidence/rust-build-processes/rustc-version.stdout"):
        assert (original/path).read_text().splitlines()[0].startswith("rustc 1.95.0 ")
    assert "--locked" in pref[1]["argv"]
    assert "--offline" in fresh[2]["argv"]
    assert "--locked" in fresh[3]["argv"] and "--offline" in fresh[3]["argv"]
    target=(original/"target/Cargo.lock").read_bytes()
    lock=(original/"oracle/Cargo.lock").read_bytes()
    assert target==(original/"evidence/rust-build-processes/lock-before-metadata.toml").read_bytes()
    assert SHA(lock)==built["fixture_lock_sha256"]
    target_pkgs={(r["name"],r["version"],r.get("source")):r.get("checksum")
        for r in tomllib.loads(target.decode())["package"] if r.get("source")}
    registry=[]
    for package in tomllib.loads(lock.decode())["package"]:
        if package.get("source"):
            key=(package["name"],package["version"],package["source"])
            assert target_pkgs.get(key)==package["checksum"],key
            registry.append({k:package[k] for k in ("name","version","source","checksum")})
        else:
            assert package["name"]=="target-text-result-constructor"
    subset=read(original/"evidence/target-lock-subset.json")
    assert subset["target_lock_sha256"]==SHA(target) and subset["fixture_lock_sha256"]==SHA(lock)
    assert subset["all_retained_exactly_match_target"] is True and subset["offline_resolution"] is True
    assert subset["retained_registry_packages"]==registry
    expected={(r["name"],r["version"],r["source"]):r for r in registry}
    source_rows={(r["name"],r["version"],r["source"]):r for r in subset["registry_source_verification"]}
    custody={(r["name"],r["version"],r["source"]):r for r in built["registry_archive_custody"]}
    assert set(expected)==set(source_rows)==set(custody)
    assert len(source_rows)==len(subset["registry_source_verification"])
    assert len(custody)==len(built["registry_archive_custody"])
    total_files=0
    for key,pin in expected.items():
        recorded=source_rows[key]
        raw=raw_pin(local(original,custody[key]["path"]),custody[key])
        assert SHA(raw)==pin["checksum"]==recorded["checksum"]==recorded["archive_sha256"]
        files={}
        prefix=key[0]+"-"+key[1]
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as archive:
            for member in archive:
                parts=Path(member.name).parts
                assert parts and parts[0]==prefix and ".." not in parts and not Path(member.name).is_absolute()
                if member.isdir():continue
                assert member.isfile()
                relative=str(Path(*parts[1:]))
                assert relative not in files
                files[relative]=SHA(archive.extractfile(member).read())
        assert files==recorded["source_files"] and len(files)==recorded["files_verified"]
        total_files+=len(files)
    rmcp=next(row for row in source_rows.values() if row["name"]=="rmcp")
    assert rmcp["version"]=="3.9.0" and rmcp["checksum"]==SDK_CHECKSUM
    for rel in ("src/model.rs","src/model/content.rs"):
        assert rmcp["source_files"][rel]==provenance["files"]["reference/sdk/"+rel]["sha256"]
    sys.path.insert(0,str(source/"source/tests"))
    from constructor_cases import cases
    selected=cases("wide")
    assert len(selected)==65
    assert summary["expected_cases"]==summary["completed_cases"]==len(summary["rows"])==len(selected)
    native_summary=read(native/"SUMMARY.json")
    assert native_summary["status"]=="NATIVE_CONSTRUCTOR_NORMAL_PASS"
    assert native_summary["profile"]=="wide" and native_summary["completed_cases"]==65
    bytes_compared=0
    for index,(case,row) in enumerate(zip(selected,summary["rows"],strict=True)):
        assert row["case"]==case.name and row["folder"]==f"case-{index:03d}"
        folder=original/row["folder"]
        raw=(folder/"CASE.json").read_bytes()
        assert SHA(raw)==row["receipt_sha256"]
        record=json.loads(raw)
        assert record["index"]==index and record["case"]==case.name
        assert record["exit_code"]==0 and record["timed_out"] is False
        assert record["deadline_seconds"]==60 and record["elapsed_seconds"]>=0
        assert record["native_full_output_equal"] is True
        assert captured(folder,record["stdin"])==case.frame()
        out=captured(folder,record["stdout"])
        assert captured(folder,record["stderr"])==b""
        assert len(out)==row["stdout_bytes"] and SHA(out)==row["stdout_sha256"]
        nfolder=native/f"case-{index:03d}"
        nreceipt=read(nfolder/"CASE.json")
        nrow=native_summary["rows"][index]
        assert SHA((nfolder/"CASE.json").read_bytes())==nrow["receipt_sha256"]
        capture=nreceipt["captures"][2]
        assert capture["owner"]=="text-result-constructor" and capture["return_code"]==64
        assert captured(nfolder/capture["folder"],capture["output"])==out
        bytes_compared+=len(out)
    return dict(schema="hepta.text-constructor-actual-target-readonly.v1",
        status="READONLY_ACTUAL_TARGET_CONSTRUCTOR_PASS",cases=len(selected),
        complete_output_bytes_compared=bytes_compared,registry_archives_read=len(custody),
        registry_source_files_hashed=total_files,fresh_rust_1_95=True,
        actual_target_constructor_comparison=True,native_or_original_code_launched=False,
        binary_sha256=built["binary_sha256"],target_application_commit=TARGET,
        full_sdk_qualified=False,public_target_handler_comparison=False)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","original","native"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(verify(args.source,args.original,args.native),sort_keys=True))

if __name__=="__main__":main()

