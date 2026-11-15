#!/usr/bin/env python3
"""Bounded file-only export of pinned MIT Qwen base/p50c text weights.
No model construction, generation, package installation, or source mutation.
Copyright 2026 Hepta contributors. SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations
import argparse
import gc
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
from pathlib import Path
import resource
import shutil
import stat
import struct
import subprocess
import sys
import time

COMMIT = "4d09ba6d6a7e891dd8063974dfe81b3d78e3494f"
REVISION = "2fc06364715b967f1860aea9cf38778875588b17"
SOURCE_FILES = {
    "base/model.safetensors-00001-of-00001.safetensors": "04b1c301231dd422b8860db31311ab2721511346a32cb1e079c4c4e5f1fe4696",
    "source/edit.npz": "e92a92aafd1f1068b4fd94aa0fbe081ba3ddea2047ee7bcac7161d861be299e7",
    "source/manifest.json": "83185c1db46e3dafb34af645f8c5ce033c09cc99d4512b9e1b8e3aba9d269225",
    "base/config.json": "b90b86f35c8e6925ef74ee04d0e758f0a845c83a42089ad82bbaa948de9b4204",
    "base/tokenizer.json": "5f9e4d4901a92b997e463c1f46055088b6cca5ca61a6522d1b9f64c4bb81cb42",
    "base/merges.txt": "a9d356d7bdf1ef4949e3e748e95b8e10ad9d4e2e838eddc38a0a7b6b94d1db8d",
    "base/vocab.json": "ce99b4cb2983d118806ce0a8b777a35b093e2000a503ebde25853284c9dfa003",
}
AUTHOR_FILES = {
    "exp8_math/code/apply_edit.py": "d2b627a6cf344f309cca4bcab4ff6ccc6ad1c8f29cabda78d11f99c19d1b1c5d",
    "exp8_math/code/st_numpy.py": "3c4e532fb8edf374e1a4636aa806a04d062f824943eaf4bca0d3af5b0e7dca40",
    "exp8_math/base_model/Qwen3.5-0.8B-text/config.json": "3f56b6210db3c52e0bafb50da005eb52b6d340ab4ad980091879b397743675fc",
    "exp8_math/base_model/Qwen3.5-0.8B-text/generation_config.json": "62153eb6c69f2e1f426beaa8002b7186437e949c7588167085df14e10e9c0a73",
    "exp8_math/base_model/Qwen3.5-0.8B-text/tokenizer_config.json": "66e427c470fe580fe8c7b5725d857af23d8417e37fae62667ec698306a19987b",
    "exp8_math/base_model/Qwen3.5-0.8B-text/chat_template.jinja": "273d8e0e683b885071fb17e08d71e5f2a5ddfb5309756181681de4f5a1822d80",
}
BYTES_PER = {"BF16":2,"F16":2,"F32":4,"F64":8,"I64":8,"I32":4,"I16":2,"I8":1,"U8":1,"BOOL":1}
LIMIT_BYTES = 5_000_000_000
START = time.monotonic()
DEADLINE = START + 900
PHASES = {}

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def remaining():
    left = DEADLINE-time.monotonic()
    require(left > 0, "15-minute export deadline exceeded")
    return left

def fingerprint(path):
    s=path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, "Expected a regular nonlinked input/output")
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def sha(path):
    remaining()
    before=fingerprint(path)
    h=hashlib.sha256()
    with path.open("rb") as f:
        while chunk:=f.read(4*1024*1024):
            h.update(chunk);remaining()
    require(fingerprint(path)==before, "File changed while hashing")
    return h.hexdigest()

def phase(name, fn):
    w,c=time.monotonic(),time.process_time()
    result=fn()
    PHASES[name]={"wall_seconds":time.monotonic()-w,"self_cpu_seconds":time.process_time()-c}
    print(json.dumps({"phase":name,"completed":True}),flush=True)
    return result

def header(path):
    size=path.stat().st_size
    with path.open("rb") as f:
        count=struct.unpack("<Q",f.read(8))[0]
        require(0<count<4*1024*1024 and count+8<=size,"Invalid bounded safetensors header")
        h=json.loads(f.read(count))
    result={k:v for k,v in h.items() if k!="__metadata__"}
    intervals=[]
    for k,v in result.items():
        require(v["dtype"] in BYTES_PER,"Unsupported tensor dtype")
        require(all(type(d) is int and d>=0 for d in v["shape"]),"Invalid shape")
        a,b=v["data_offsets"]
        require(type(a) is int and type(b) is int and 0<=a<=b and b+8+count<=size,"Invalid offsets")
        require(b-a==math.prod(v["shape"])*BYTES_PER[v["dtype"]],"Tensor byte/shape mismatch")
        intervals.append((a,b))
    intervals.sort();cursor=0
    for a,b in intervals:
        require(a==cursor,"Noncontiguous or overlapping tensor layout")
        cursor=b
    require(cursor+8+count==size,"Unexpected safetensors trailing bytes")
    return result,8+count

def tensor_hashes(path):
    h,off=header(path);out={}
    with path.open("rb") as f:
        for name,v in h.items():
            a,b=v["data_offsets"];f.seek(off+a);left=b-a;digest=hashlib.sha256()
            while left:
                chunk=f.read(min(left,4*1024*1024));require(bool(chunk),"Truncated tensor")
                digest.update(chunk);left-=len(chunk);remaining()
            out[name]={"dtype":v["dtype"],"shape":v["shape"],"bytes":b-a,"sha256":digest.hexdigest()}
    return out

def shared_differences(a,b,prefix=""):
    differences=[]
    for k in sorted(a.keys() & b.keys()):
        key=prefix+k
        if isinstance(a[k],dict) and isinstance(b[k],dict):
            differences.extend(shared_differences(a[k],b[k],key+"."))
        elif a[k]!=b[k]:
            differences.append(key)
    return differences

def write_json(path,value):
    require(not path.exists(),"Receipt destination already exists")
    path.write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+"\n")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--reference-root",type=Path,required=True)
    ap.add_argument("--author-source-dir",type=Path,required=True)
    ap.add_argument("--output-root",type=Path,required=True)
    args=ap.parse_args()
    src=args.reference_root.resolve();author=args.author_source_dir.resolve();out=args.output_root
    require(out.is_absolute() and not out.exists(),"Output root must be a new absolute directory")
    require(src.is_dir() and author.is_dir(),"Missing source directory")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE,(LIMIT_BYTES,LIMIT_BYTES))
    source_stats={rel:fingerprint(src/rel) for rel in SOURCE_FILES}
    source_hashes=phase("verify_pinned_sources",lambda:{rel:sha(src/rel) for rel in SOURCE_FILES})
    require(source_hashes==SOURCE_FILES,"Pinned source mismatch")
    author_hashes=phase("verify_pinned_author_files",lambda:{rel:sha(author/rel) for rel in AUTHOR_FILES})
    require(author_hashes==AUTHOR_FILES,"Pinned original script/config mismatch")
    original=src/"base/model.safetensors-00001-of-00001.safetensors"
    original_header,_=header(original)
    names=[k for k in original_header if not k.startswith("model.visual.")]
    require(all(k.startswith(("model.language_model.","mtp.")) for k in names),"Unexpected nonvisual tensor namespace")
    require(sum(k.startswith("model.language_model.") for k in names)==320,"Wrong language tensor count")
    require(sum(k.startswith("mtp.") for k in names)==15,"Wrong MTP tensor count")
    require(len(original_header)-len(names)==153,"Wrong excluded visual tensor count")
    payload=sum(original_header[k]["data_offsets"][1]-original_header[k]["data_offsets"][0] for k in names)
    copy_bytes=sum((src/"base"/n).stat().st_size for n in ("tokenizer.json","vocab.json","merges.txt"))
    estimated=2*(payload+copy_bytes+4*1024*1024)+4*1024*1024
    free=shutil.disk_usage(out.parent).free
    require(estimated<LIMIT_BYTES and free>=estimated+1024**3,"Insufficient bounded output space")
    cfgroot=author/"exp8_math/base_model/Qwen3.5-0.8B-text"
    published=json.loads((cfgroot/"config.json").read_text())
    base_config=json.loads((src/"base/config.json").read_text())["text_config"]
    require(published["architectures"]==["Qwen3_5ForCausalLM"],"Wrong published architecture")
    require(not shared_differences(base_config,published),"Shared text config field mismatch")
    require(published["tie_word_embeddings"] is True and published["mtp_num_hidden_layers"]==1,"Unexpected tie/MTP contract")
    out.mkdir(mode=0o700)
    (out/"base").mkdir(mode=0o700);(out/"p50c").mkdir(mode=0o700)
    import numpy as np
    spec=importlib.util.spec_from_file_location("pinned_st_numpy",author/"exp8_math/code/st_numpy.py")
    S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
    base=out/"base/model.safetensors";edited=out/"p50c/model.safetensors"
    def build_base():
        tensors=S.load(original,names)
        require(set(tensors)==set(names),"Export selection mismatch")
        S.save(base,tensors,metadata={"format":"pt"})
        del tensors;gc.collect()
    phase("base_nonvisual_export",build_base)
    def apply():
        cp=subprocess.run([sys.executable,"-B",str(author/"exp8_math/code/apply_edit.py"),
                           str(base),str(src/"source"),str(edited)],
                          capture_output=True,text=True,timeout=remaining(),check=False)
        require(cp.returncode==0,"Pinned author apply_edit failed: "+cp.stderr[-1000:])
        require(not cp.stderr,"Unexpected author stderr")
        return cp.stdout.replace(str(out),"<export>").replace(str(src),"<reference>").strip().splitlines()
    stdout=phase("original_apply_edit",apply)
    def copy_assets():
        records={}
        for variant in ("base","p50c"):
            for name in ("config.json","generation_config.json","tokenizer_config.json","chat_template.jinja"):
                shutil.copyfile(cfgroot/name,out/variant/name)
            for name in ("tokenizer.json","vocab.json","merges.txt"):
                shutil.copyfile(src/"base"/name,out/variant/name)
            for p in sorted((out/variant).iterdir()):
                if p.name!="model.safetensors":
                    digest=sha(p)
                    expected_sha=(SOURCE_FILES["base/"+p.name] if p.name in ("tokenizer.json","vocab.json","merges.txt")
                                  else AUTHOR_FILES["exp8_math/base_model/Qwen3.5-0.8B-text/"+p.name])
                    require(digest==expected_sha,"Copied text asset mismatch")
                    records[str(p.relative_to(out))]={"bytes":p.stat().st_size,"sha256":digest}
        return records
    assets=phase("copy_and_verify_text_assets",copy_assets)
    source_tensors=phase("source_tensor_hashes",lambda:tensor_hashes(original))
    base_tensors=phase("base_tensor_hashes",lambda:tensor_hashes(base))
    edited_tensors=phase("edited_tensor_hashes",lambda:tensor_hashes(edited))
    require(set(base_tensors)==set(edited_tensors)==set(names),"Text export name mismatch")
    manifest=json.loads((src/"source/manifest.json").read_text())
    expected={e["name"]:e for e in manifest["tensors"]}
    require(len(expected)==2,"Wrong p50c tensor count")
    records=[];changed_entries=0
    for name in sorted(names):
        s,b,e=source_tensors[name],base_tensors[name],edited_tensors[name]
        require(s==b,"Base tensor differs from original public source")
        require(b["dtype"]==e["dtype"] and b["shape"]==e["shape"],"Edited dtype/shape mismatch")
        changed=b["sha256"]!=e["sha256"]
        require(changed==(name in expected),"Unexpected changed or unchanged tensor")
        record={"name":name,"dtype":b["dtype"],"shape":b["shape"],"bytes":b["bytes"],
                "source_sha256":s["sha256"],"base_sha256":b["sha256"],"p50c_sha256":e["sha256"],"changed":changed}
        if changed:
            t=expected[name]
            require(b["sha256"]==t["base_sha256"] and e["sha256"]==t["edited_sha256"],"Author BF16 tensor hash mismatch")
            bb=S.load(base,[name])[name][1];ee=S.load(edited,[name])[name][1]
            n=int(np.count_nonzero(bb!=ee));del bb,ee
            require(n==t["changed_entries"],"Changed BF16 element count mismatch")
            record["changed_bf16_entries"]=n;changed_entries+=n
        records.append(record)
    require(changed_entries==130188,"Total edited entry count mismatch")
    full_hashes=phase("full_export_hashes",lambda:{
        "base":{"bytes":base.stat().st_size,"sha256":sha(base)},
        "p50c":{"bytes":edited.stat().st_size,"sha256":sha(edited)}})
    end_hashes=phase("reverify_sources",lambda:{rel:sha(src/rel) for rel in SOURCE_FILES})
    require(end_hashes==SOURCE_FILES,"Source content changed during export")
    require(all(fingerprint(src/rel)==source_stats[rel] for rel in SOURCE_FILES),"Source identity/stat changed during export")
    require({rel:sha(author/rel) for rel in AUTHOR_FILES}==AUTHOR_FILES,"Original code/config changed during export")
    tensor_doc={"schema":"hepta.mit_qwen.text_export_tensors.v1","commit":COMMIT,"base_revision":REVISION,
                "tensor_count":len(records),"tensors":records}
    write_json(out/"tensor_manifest.json",tensor_doc)
    used=sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    require(used<LIMIT_BYTES-1024*1024,"Output byte ceiling exceeded")
    child=resource.getrusage(resource.RUSAGE_CHILDREN);self_usage=resource.getrusage(resource.RUSAGE_SELF)
    receipt={"schema":"hepta.mit_qwen.text_export_qualification.v1","status":"passed_file_identity_only",
      "source_repository":"RikiyaT/lm_understand-logs","source_commit":COMMIT,
      "base_repository":"Qwen/Qwen3.5-0.8B","base_revision":REVISION,"edit_run":"p50c",
      "driver_sha256":sha(Path(__file__).resolve()),"source_files":SOURCE_FILES,"author_files":AUTHOR_FILES,
      "export_contract":{"retained_language_tensors":320,"retained_mtp_tensors":15,"excluded_visual_tensors":153,
          "rule":"Remove only model.visual.*; retain all model.language_model.* and mtp.* with unchanged names.",
          "tied_lm_head":"No standalone lm_head tensor in source; published tie_word_embeddings=true preserved.",
          "config_shared_fields_equal":True,"config_published_extra_top_level_keys":sorted(published.keys()-base_config.keys()),
          "original_author_full_text_export_file_identity_available":False},
      "checks":{"all_335_base_tensors_match_source":True,"edited_tensors":2,"changed_bf16_entries":changed_entries,
          "all_333_other_export_tensors_unchanged":True,"all_318_other_main_language_tensors_unchanged":True,
          "all_15_mtp_tensors_unchanged":True,"both_edited_hashes_match_author_manifest":True,
          "source_content_and_stat_unchanged":True,"author_code_and_config_unchanged":True},
      "exports":full_hashes,"text_assets":assets,"tensor_manifest_sha256":sha(out/"tensor_manifest.json"),
      "original_apply_edit_stdout":stdout,
      "budget":{"max_wall_seconds":900,"max_new_output_bytes":LIMIT_BYTES,"estimated_output_bytes":estimated,
          "free_bytes_before":free,"output_bytes_before_final_receipt":used},
      "runtime":{"python":sys.version.split()[0],"numpy":np.__version__,"platform":sys.platform,
          "torch_imported":"torch" in sys.modules,"gpu_initialized":False,"framework_model_instances":0,"generated_answers":0,"gradient_steps":0,
          "new_packages_installed":0},
      "timing":{"wall_seconds_before_receipt":time.monotonic()-START,
          "self_cpu_seconds":time.process_time(),"child_cpu_seconds":child.ru_utime+child.ru_stime,
          "total_cpu_seconds":time.process_time()+child.ru_utime+child.ru_stime,
          "self_peak_rss_kib_linux":self_usage.ru_maxrss,"child_peak_rss_kib_linux":child.ru_maxrss,"phases":PHASES},
      "not_claimed":["vLLM or Transformers loading/generation compatibility","MATH/GSM8K/IFEval benchmark efficacy",
          "independent Astra discovery","exact full-file identity of the author's unpublished text export",
          "full evaluation environment reproducibility","training superiority"]}
    write_json(out/"receipt.json",receipt)
    print(json.dumps({"status":receipt["status"],"exports":full_hashes,
                      "receipt_sha256":sha(out/"receipt.json"),"tensor_manifest_sha256":receipt["tensor_manifest_sha256"],
                      "wall_seconds":receipt["timing"]["wall_seconds_before_receipt"],"output_bytes":used}),flush=True)

if __name__=="__main__":
    main()
