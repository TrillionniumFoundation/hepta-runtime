#!/usr/bin/env python3
"""Retire only fully archived and reread build copies; retain the complete original ZIP."""
from pathlib import Path
import argparse,os,shutil,stat,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,pin,require,source_evidence
from build_reuse import binding,identity
def retire(source,work):
    bound=binding(source);original=work/"original";restored=original/"restored"
    require(pin(work/"download/complete.zip")=={k:bound["artifact"][k]for k in("bytes","sha256")},"retained whole original ZIP")
    read=decode((work/"BUILD_READ.json").read_bytes())
    require(read["status"]=="READONLY_PASS"and read["before"]==read["after"]and len(read["probes"])==11
        and read["evidence"]["status"]=="COMPLETE_QUALIFIED_BUILD_REUSE_PASS"and read["evidence"]["application_calls"]==0,
        "complete pure build reread before copy retirement")
    manifest=decode((original/"ARTIFACT_MANIFEST.json").read_bytes())
    expected={p:{k:v[k]for k in("bytes","sha256","mode")}for p,v in manifest["files"].items()}
    files={p.relative_to(restored).as_posix():identity(p)for p in restored.rglob("*")if p.is_file()}
    dirs={p.relative_to(restored).as_posix():stat.S_IMODE(p.stat().st_mode)for p in restored.rglob("*")if p.is_dir()}
    require(files==expected and dirs==manifest["directories"],"every expanded file/byte/mode/directory equals complete retained archive")
    production=work/"production";production.mkdir()
    elf=production/"binary-write-body-callable.elf"
    shutil.copyfile(restored/"run/build/binary-write-body-callable.elf",elf);elf.chmod(0o755)
    require(pin(elf)==bound["elf"],"one exact executable retained")
    evidence=work/"build-evidence";evidence.mkdir()
    for name in("ARTIFACT_MANIFEST.json","UNPACK.json"):
        raw=(original/name).read_bytes();(evidence/name).write_bytes(raw)
        require((evidence/name).read_bytes()==raw,"complete build index retained")
    proof=dict(status="COMPLETE_ARCHIVE_EQUALITY_BEFORE_RETIREMENT",archive=pin(work/"download/complete.zip"),
        manifest=pin(evidence/"ARTIFACT_MANIFEST.json"),unpack=pin(evidence/"UNPACK.json"),read=pin(work/"BUILD_READ.json"),
        files=len(files),directories=len(dirs),logical_bytes=sum(v["bytes"]for v in files.values()),
        all_file_bytes_modes_and_directories_equal=True,retained_executable=pin(elf),application_calls=0)
    (evidence/"RETIREMENT_PROOF.json").write_bytes(encoded(proof))
    shutil.rmtree(original)
    require(not original.exists()and pin(work/"download/complete.zip")==proof["archive"]and pin(elf)==bound["elf"],
        "retained complete archive/executable after ordinary copy retirement")
    return proof
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True)
    a=p.parse_args();print(encoded(retire(a.source.resolve(strict=True),a.work.resolve(strict=True))).decode(),end="")
