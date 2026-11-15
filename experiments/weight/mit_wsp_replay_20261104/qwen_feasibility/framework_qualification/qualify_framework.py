#!/usr/bin/env python3
"""Strict CPU-only Qwen text-class compatibility and finite-forward qualification.
SPDX-License-Identifier: Apache-2.0
No generation, benchmark, optimizer, package install, or source/export mutation.
"""
from __future__ import annotations
import argparse
import copy
import gc
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import time

START=time.monotonic()
CPU_START=time.process_time()
LIMIT=12*1024**3
STAGE="startup"
RESULT={}
PINS={
 "receipt.json":"87ae658c7bee2d89a16cb7a828347a36d474ff485c870fe629e1753cc2b92768",
 "tensor_manifest.json":"84bdcf921a6f9ccc5e5d1a6d447baf8efda9314d8dc199f5176ffc13582ecf62",
 "base/model.safetensors":"e9f6dd9e3636887f8bb04a467241c894af8828fd548c3d8f627a386ccf2a4765",
 "p50c/model.safetensors":"6a211ed8a9b0b977c13889c3fd4f14dabeaee779ea001dd01f17c899877a0374",
}
FRAMEWORK_PINS={
 "models/qwen3_5/modeling_qwen3_5.py":"b4b17fe08d8d54da34a0fce78639666279ae7fd0a9e4ec06fce6602774707ca3",
 "models/qwen3_5/configuration_qwen3_5.py":"e5316490555c2d3590682f1d84ca656bdf3d2aff7475b95b682c03afbb69e748",
 "modeling_utils.py":"553412f58334f65abba617f3b344828698dbf63615e109159fd03dafd3422d38",
 "initialization.py":"a2392653161633d4f8aefb473e776113ec5df8844acdba892569407ca56c2d6a",
 "modeling_rope_utils.py":"6a0727073e080e163d0287e15fc1acb90035e9a9df9cb19a13b632a40abfac24",
}
TEXT="A quiet morning brings clear light."

def require(ok,message):
    if not ok:raise RuntimeError(message)

def tick(stage):
    global STAGE
    STAGE=stage
    require(time.monotonic()-START<285,"CPU qualification wall deadline exceeded")
    print(json.dumps({"stage":stage}),flush=True)

def fp(path):
    s=path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"Input is not an ordinary unlinked regular file")
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def sha(path):
    before=fp(path);h=hashlib.sha256()
    with path.open("rb") as f:
        while b:=f.read(4*1024*1024):
            h.update(b);require(time.monotonic()-START<285,"Deadline during hash")
    require(fp(path)==before,"File changed while reading")
    return h.hexdigest()

def write(path,value):
    require(not path.exists(),"Output already exists")
    path.write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+"\n")

def timecost(w,c):
    return {"wall_seconds":time.monotonic()-w,"cpu_seconds":time.process_time()-c}

def main(args):
    global RESULT
    src=args.exports_root.resolve();out=args.output_root
    require(out.is_absolute() and not out.exists(),"Output must be a new absolute directory")
    os.umask(0o077);out.mkdir(mode=0o700)
    RESULT={"schema":"hepta.mit_qwen.strict_text_forward.v1","status":"started",
      "scope":"CPU text-class loading and one fixed nonbenchmark forward per variant; not generated efficacy",
      "driver_sha256":sha(Path(__file__).resolve()),"budget":{"wall_seconds":300,"driver_alarm_seconds":285,"address_space_bytes":LIMIT,"rss_limit_bytes":LIMIT},
      "protocol":{"text":TEXT,"maximum_input_tokens":32,"batch":1,"forward_calls_per_variant":1,
          "logits_to_keep":1,"use_cache":False,"attention_implementation":"eager","sample_or_generate":False,"cpu_threads":4},
      "framework_source_sha256":FRAMEWORK_PINS,"variants":{}}
    try:
        tick("input_identity")
        pins=dict(PINS);initial={k:fp(src/k) for k in pins}
        require({k:sha(src/k) for k in pins}==pins,"Export identity mismatch")
        export=json.loads((src/"receipt.json").read_text())
        for rel,entry in export["text_assets"].items():
            require(rel.startswith(("base/","p50c/")) and ".." not in Path(rel).parts,"Unsafe source asset path")
            pins[rel]=entry["sha256"];initial[rel]=fp(src/rel)
            require(sha(src/rel)==entry["sha256"],"Export config/tokenizer identity mismatch")
        tensor_doc=json.loads((src/"tensor_manifest.json").read_text())
        tensors={t["name"]:t for t in tensor_doc["tensors"]}
        require(len(tensors)==335,"Wrong text export tensor count")
        language={n:v for n,v in tensors.items() if n.startswith("model.language_model.")}
        mtp=sorted(n for n in tensors if n.startswith("mtp."))
        require(len(language)==320 and len(mtp)==15,"Unexpected namespace")
        dist=importlib.metadata.distribution("transformers")
        framework=Path(dist.locate_file("transformers"))
        require({k:sha(framework/k) for k in FRAMEWORK_PINS}==FRAMEWORK_PINS,"Inspected framework source changed")
        RESULT["input_sha256"]=pins
        RESULT["runtime"]={"python":sys.version.split()[0],"transformers":dist.version,
             "torch_distribution":importlib.metadata.version("torch"),
             "safetensors":importlib.metadata.version("safetensors"),
             "numpy":importlib.metadata.version("numpy")}
        tick("framework_import")
        import numpy as np
        import torch
        from safetensors import safe_open
        from transformers import AutoTokenizer
        from transformers.models.qwen3_5.configuration_qwen3_5 import Qwen3_5TextConfig
        from transformers.models.qwen3_5.modeling_qwen3_5 import Qwen3_5ForCausalLM
        from transformers import initialization
        torch.set_num_threads(4);torch.set_num_interop_threads(1)
        require(not torch.cuda.is_initialized(),"Unexpected accelerator initialization")
        cfg=Qwen3_5TextConfig.from_pretrained(str(src/"base"),local_files_only=True)
        cfg._attn_implementation="eager";cfg.use_cache=False
        require(cfg.tie_word_embeddings is True,"Unexpected untied model contract")
        # Meta is for key/shape planning only. No meta buffer is materialized for the actual forward.
        tick("meta_key_shape_contract")
        with torch.device("meta"),initialization.no_init_weights():
            meta=Qwen3_5ForCausalLM(copy.deepcopy(cfg))
        meta.tie_weights()
        target_shapes={n:list(t.shape) for n,t in meta.state_dict().items()}
        require(all(t.device.type=="meta" for t in meta.parameters()),"Meta planning allocated a parameter")
        mapping={n:"model."+n[len("model.language_model."):] for n in language}
        require(len(set(mapping.values()))==320,"Mapping is not injective")
        shapes={mapping[n]:v["shape"] for n,v in language.items()}
        embed="model.language_model.embed_tokens.weight"
        require(embed in language,"Missing source embedding")
        shapes["lm_head.weight"]=language[embed]["shape"]
        require(target_shapes==shapes,"Mapped export does not exactly cover text-class state keys/shapes")
        require(meta._tied_weights_keys=={"lm_head.weight":"model.embed_tokens.weight"},"Unexpected tied-weight contract")
        patterns=sorted(meta._keys_to_ignore_on_load_unexpected)
        require(r"^mtp.*" in patterns,"Installed class does not declare MTP exclusion")
        del meta;gc.collect()
        RESULT["contract"]={"main_language_source_keys":320,"target_state_keys_including_tied_alias":321,
            "mapping":"model.language_model.<suffix> -> model.<suffix>",
            "tied_alias":{"lm_head.weight":"model.embed_tokens.weight"},
            "excluded_mtp_keys":mtp,"installed_unexpected_key_patterns":patterns,
            "meta_exact_key_shape_cover":True,"automatic_from_pretrained_loader_tested":False,
            "strict_loader":"torch.nn.Module.load_state_dict(strict=True,assign=True)",
            "nonpersistent_buffers":"Constructed deterministically on CPU by the inspected text class, not materialized from meta"}
        tokenizer=AutoTokenizer.from_pretrained(str(src/"base"),local_files_only=True,trust_remote_code=False)
        batch=tokenizer(TEXT,return_tensors="pt",add_special_tokens=False)
        input_ids=batch["input_ids"];mask=batch.get("attention_mask",torch.ones_like(input_ids))
        require(input_ids.shape[0]==1 and 0<input_ids.shape[1]<=32,"Input bounds")
        RESULT["protocol"]["input_ids"]=input_ids.tolist()
        RESULT["protocol"]["input_tokens"]=input_ids.shape[1]
        output_arrays={}
        mapping_manifest=[]
        for variant in ("base","p50c"):
            tick(variant+"_strict_load")
            w,c=time.monotonic(),time.process_time()
            # Real CPU constructor computes RoPE buffers; all learned state must then be assigned from source.
            with initialization.no_init_weights(),torch.device("cpu"):
                model=Qwen3_5ForCausalLM(copy.deepcopy(cfg))
            loaded={}
            with safe_open(str(src/variant/"model.safetensors"),framework="pt",device="cpu") as archive:
                require(set(archive.keys())==set(tensors),"Safetensors key set changed")
                for source_name,target in mapping.items():loaded[target]=archive.get_tensor(source_name)
            loaded["lm_head.weight"]=loaded["model.embed_tokens.weight"]
            require(set(loaded)==set(target_shapes),"CPU load dictionary does not cover every state key")
            incompatible=model.load_state_dict(loaded,strict=True,assign=True)
            require(not incompatible.missing_keys and not incompatible.unexpected_keys,"Strict load returned incompatible keys")
            model.tie_weights()
            require(model.lm_head.weight is model.model.embed_tokens.weight,"Tied output head does not share the embedding parameter")
            require(all(p.device.type=="cpu" for p in model.parameters()),"A parameter is not on CPU")
            require(all(b.device.type=="cpu" for b in model.buffers()),"A buffer is not on CPU")
            state=model.state_dict()
            def raw_hash(t):
                require(t.device.type=="cpu" and not t.is_meta and t.is_contiguous(),"Unexpected tensor storage")
                return hashlib.sha256(memoryview(t.detach().view(torch.uint8).numpy())).hexdigest()
            loaded_hashes={}
            for source_name,target in mapping.items():
                t=state[target];expected=tensors[source_name]["base_sha256" if variant=="base" else "p50c_sha256"]
                require(list(t.shape)==tensors[source_name]["shape"],"Loaded shape mismatch")
                actual=raw_hash(t);require(actual==expected,"Loaded raw parameter bytes differ from qualified export")
                loaded_hashes[target]=actual
                mapping_manifest.append({"variant":variant,"source_name":source_name,"target_name":target,
                   "shape":list(t.shape),"dtype":str(t.dtype),"source_and_loaded_sha256":actual})
            require(raw_hash(state["lm_head.weight"])==loaded_hashes["model.embed_tokens.weight"],"Output-head alias hash mismatch")
            buffer_hashes={n:{"shape":list(b.shape),"dtype":str(b.dtype),"sha256":raw_hash(b)} for n,b in model.named_buffers()}
            require(all(torch.isfinite(b).all().item() for b in model.buffers()),"Nonfinite constructed buffer")
            load_cost=timecost(w,c)
            model.eval()
            del state,loaded;gc.collect()
            tick(variant+"_single_forward")
            w,c=time.monotonic(),time.process_time()
            with torch.inference_mode():
                result=model(input_ids=input_ids,attention_mask=mask,use_cache=False,logits_to_keep=1,return_dict=True)
                logits=result.logits
            forward_cost=timecost(w,c)
            require(tuple(logits.shape)==(1,1,cfg.vocab_size),"Unexpected output shape")
            require(bool(torch.isfinite(logits).all()),"Nonfinite last-token logits")
            a=logits.detach().float().cpu().numpy().copy()
            output_arrays[variant]=a
            # Confirm forward did not mutate any learned parameter.
            after=model.state_dict()
            require(all(raw_hash(after[k])==v for k,v in loaded_hashes.items()),"Forward mutated a learned parameter")
            RESULT["variants"][variant]={"missing_keys":[],"unexpected_keys":[],
                 "strict":True,"assign":True,"loaded_main_tensor_hashes_verified":320,
                 "tied_embedding_head_identity_verified":True,"no_missing_weight_initialization":True,
                 "learned_parameters_unchanged_by_forward":True,"buffers":buffer_hashes,
                 "load_and_weight_verification":load_cost,"forward":forward_cost,
                 "output":{"shape":list(logits.shape),"dtype":str(logits.dtype),"finite":True,
                     "float32_array_sha256":hashlib.sha256(memoryview(a)).hexdigest(),
                     "minimum":float(a.min()),"maximum":float(a.max()),"mean":float(a.mean(dtype=np.float64))}}
            del after,model,result,logits,t;gc.collect()
        tick("output_comparison")
        d=output_arrays["p50c"].astype(np.float64)-output_arrays["base"].astype(np.float64)
        RESULT["comparison"]={"maximum_absolute_logit_difference":float(np.abs(d).max()),
            "mean_absolute_logit_difference":float(np.abs(d).mean()),
            "root_mean_square_logit_difference":float(np.sqrt(np.mean(d*d))),
            "different_float32_output_elements":int(np.count_nonzero(d)),
            "nonzero_difference_required_for_acceptance":False,
            "interpretation":"Numerical difference only on one fixed short input; no accuracy or capability inference"}
        tick("reverify_input_immutability")
        require(all(fp(src/k)==initial[k] for k in pins),"An export/config/receipt file identity changed")
        require({k:sha(src/k) for k in pins}==pins,"An export/config/receipt content changed")
        require({k:sha(framework/k) for k in FRAMEWORK_PINS}==FRAMEWORK_PINS,"Inspected framework source changed")
        require(not torch.cuda.is_initialized(),"Accelerator context was initialized")
        RESULT["checks"]={"all_export_files_unchanged":True,"inspected_framework_sources_unchanged":True,
            "cpu_only":True,"framework_model_instances":2,"meta_planning_instances":1,
            "actual_forward_calls":2,"generated_answers":0,"new_packages_installed":0,
            "random_or_missing_learned_weights_used":False,"benchmark_items_used":0}
        write(out/"mapping_manifest.json",{"schema":"hepta.qwen.strict_text_mapping.v1","entries":mapping_manifest})
        RESULT["mapping_manifest_sha256"]=sha(out/"mapping_manifest.json")
        RESULT["status"]="passed_strict_cpu_load_and_finite_forward"
        RESULT["not_claimed"]=["original vLLM harness replay","MATH/GSM8K/IFEval efficacy","full-context generation compatibility",
            "MTP speculative generation support","default from_pretrained conversion behavior","general circuit understanding"]
    except Exception as exc:
        RESULT["status"]="blocked"
        RESULT["blocked_stage"]=STAGE
        RESULT["error_type"]=type(exc).__name__
        RESULT["error"]=str(exc).replace(str(src),"<exports>").replace(str(out),"<qualification>").replace(str(Path.home()),"<home>")
    finally:
        RESULT["measurement"]={"wall_seconds":time.monotonic()-START,"cpu_seconds":time.process_time()-CPU_START,
            "peak_rss_kib_linux":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
        write(out/"receipt.json",RESULT)
        print(json.dumps({"status":RESULT["status"],"receipt_sha256":sha(out/"receipt.json"),
                         "measurement":RESULT["measurement"],"blocked_stage":RESULT.get("blocked_stage")}),flush=True)
    return 0 if RESULT["status"]=="passed_strict_cpu_load_and_finite_forward" else 2

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--exports-root",type=Path,required=True)
    parser.add_argument("--output-root",type=Path,required=True)
    args=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS,(LIMIT,LIMIT))
    resource.setrlimit(resource.RLIMIT_RSS,(LIMIT,LIMIT))
    resource.setrlimit(resource.RLIMIT_CPU,(290,300))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("285-second deadline")))
    signal.alarm(285)
    sys.exit(main(args))
