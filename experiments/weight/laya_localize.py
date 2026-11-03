#!/usr/bin/env python3
"""Read-only layer localization and input-layout control on known Laya DEV states.

The explicitly hash-pinned worker profile is supplied by the operator. No gradients,
parameter writes, outcome evaluation or production activation occur here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time

for key in ("OMP_NUM_THREADS","MKL_NUM_THREADS","OPENBLAS_NUM_THREADS"):
    os.environ[key]="2"
os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",
                  TOKENIZERS_PARALLELISM="false",USE_TF="0")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workers" / "weight"))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",required=True)
    parser.add_argument("--rows",required=True)
    parser.add_argument("--rows-sha256",required=True)
    parser.add_argument("--out",required=True)
    parser.add_argument("--indices",default="0,8,16,24,4,12,20,28")
    parser.add_argument("--seconds",type=int,default=480)
    args=parser.parse_args()
    if sha(args.rows)!=args.rows_sha256:
        raise ValueError("SOURCE_IDENTITY_MISMATCH")
    from weight_runtime.artifacts import atomic_create
    from weight_runtime.errors import canonical, digest, loads
    from weight_runtime.session import Session
    config = loads(Path(args.config).read_bytes())
    run_identity = {"config_sha256": sha(args.config), "script_sha256": sha(__file__),
                    "rows_sha256": args.rows_sha256, "indices": args.indices}
    destination=Path(args.out)
    destination.mkdir(parents=True,exist_ok=True)
    summary_path=destination/"summary.json"
    if summary_path.exists():
        old=json.loads(summary_path.read_text())
        if old.get("run_identity") != run_identity:
            raise ValueError("RESUME_IDENTITY_MISMATCH")
        print(json.dumps(old));return
    if any(destination.iterdir()):
        raise ValueError("PARTIAL_RUN_REQUIRES_NEW_EXPLICIT_OUTPUT")
    import numpy as np
    import torch
    torch.set_grad_enabled(False)
    rows=json.loads(Path(args.rows).read_text())
    indices=[int(x) for x in args.indices.split(",")]
    if len(set(indices))!=len(indices) or not 1<=len(indices)<=16:
        raise ValueError("INDICES_LIMIT")
    started, cpu_started = time.monotonic(), time.process_time()
    session = Session("laya-localization-v2")
    opened = session.open(config)
    provider = session.provider
    cell, base_id = provider.module, provider.identity["base_id"]
    modules={"encoder.embeddings":cell.model.encoder.embeddings}
    modules.update({f"encoder.layers.{i}":m for i,m in enumerate(cell.model.encoder.layers)})
    if cell.model.head is not None:
        modules.update({f"head.layers.{i}":m for i,m in enumerate(cell.model.head.layers)})
    modules["scorer.input"]=cell.model.scorer
    orders=[list(range(7)),list(reversed(range(7))),list(range(1,7))+[0]]
    results=[];arrays={};forwards=0;hook_baseline_max=0.
    for mode in ("sequential","parallel"):
        for index in indices:
            for order_index,order in enumerate(orders):
                if time.monotonic()-started>args.seconds:
                    raise TimeoutError("EXPERIMENT_WALL_BUDGET")
                _, batch, meta = provider.prepare_inputs({"state": rows[index]["state"],
                    "order": order, "parallel_layout": mode == "parallel"})
                markers=batch["marker_pos"][0]
                inverse=torch.argsort(torch.tensor(order))
                captured={}
                def collect(name,value):
                    if isinstance(value,(tuple,list)):value=value[0]
                    if hasattr(value,"last_hidden_state"):value=value.last_hidden_state
                    if not isinstance(value,torch.Tensor):raise ValueError("HOOK_NOT_TENSOR:"+name)
                    if name=="scorer.input":
                        selected=value[0]
                    elif value.ndim==3 and value.shape[0]==1:
                        selected=value[0].index_select(0,markers)
                    elif value.ndim==2 and value.shape[0]==batch["input_ids"].shape[1]:
                        selected=value.index_select(0,markers)
                    else:raise ValueError("HOOK_LAYOUT_UNSUPPORTED:"+name+str(tuple(value.shape)))
                    captured[name]=selected.index_select(0,inverse).detach().float().cpu().clone()
                handles=[]
                for name,module in modules.items():
                    if name=="scorer.input":
                        handles.append(module.register_forward_pre_hook(
                            lambda m,a,n=name:collect(n,a[0])))
                    else:
                        handles.append(module.register_forward_hook(
                            lambda m,a,o,n=name:collect(n,o)))
                before=time.monotonic()
                try:
                    with torch.inference_mode():
                        price,action=cell(**batch)
                finally:
                    for handle in handles:handle.remove()
                forwards+=1
                logits=price[0].index_select(0,inverse).detach().float().cpu()
                if set(captured)!=set(modules):
                    raise ValueError("MISSING_HOOKS")
                if mode=="sequential" and index==indices[0] and order_index==0:
                    with torch.inference_mode():
                        plain,_=cell(**batch)
                    forwards+=1
                    hook_baseline_max=float((plain[0].index_select(0,inverse)-logits).abs().max())
                key=f"{mode}-{index:02}-{order_index}"
                target=destination/(key+".npz")
                tensors={name:value.numpy() for name,value in captured.items()}
                tensors["price_logits"]=logits.numpy()
                tensors["action_logits"]=action[0].detach().float().cpu().numpy()
                np.savez_compressed(target,**tensors)
                arrays[(mode,index,order_index)]=tensors
                result={"key":key,"mode":mode,"row_index":index,"order":order,
                        "input_sha256":digest(rows[index]["state"]),
                        "model_input_id": meta["model_input_id"],
                        "tokens":meta["tokens"],"markers":meta["markers"],"seconds":time.monotonic()-before,
                        "artifact_sha256":sha(target),"probabilities":logits.softmax(-1).tolist(),
                        "action_probabilities":action[0].detach().float().cpu().softmax(-1).tolist()}
                results.append(result)
                print(json.dumps({"event":"probe_complete","key":key,"seconds":result["seconds"]}),flush=True)
    metrics={}
    for mode in ("sequential","parallel"):
        layer={}
        for name in modules:
            values=np.stack([[arrays[(mode,i,p)][name] for p in range(3)] for i in indices]).astype(np.float64)
            differences=values[:,1:]-values[:,:1]
            amplitude=float(np.sqrt(np.mean(values[:,0]**2)))
            nuisance=float(np.sqrt(np.mean(differences**2)))
            state=float(np.sqrt(np.mean((values[:,0]-values[:,0].mean(axis=0,keepdims=True))**2)))
            layer[name]={"permutation_difference_rms":nuisance,"canonical_rms":amplitude,
                         "relative_permutation_rms":nuisance/max(amplitude,1e-30),
                         "canonical_state_variation_rms":state}
        probabilities=np.array([[next(x["probabilities"] for x in results
                          if x["mode"]==mode and x["row_index"]==i and x["order"]==orders[p])
                          for p in range(3)] for i in indices])
        tv=.5*np.abs(probabilities[:,1:]-probabilities[:,:1]).sum(-1)
        metrics[mode]={"layers":layer,"mean_order_tv":float(tv.mean()),"max_order_tv":float(tv.max()),
                       "top1_disagreement":float((probabilities[:,1:].argmax(-1)!=probabilities[:,:1].argmax(-1)).mean())}
    cell.assert_frozen()
    summary={"schema":"hepta.weight.laya-localization.v2","base_id":base_id,
             "run_identity": run_identity, "model_id": opened["model_id"],
             "backend_id": opened["backend_id"], "model_identity": opened["model"]["identity"],
             "backend": opened["model"]["backend"],
             "rows_sha256":args.rows_sha256,"indices":args.indices,
             "forward_calls":forwards,"wall_seconds":time.monotonic()-started,
             "cpu_seconds": time.process_time()-cpu_started,
             "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
             "hook_vs_plain_max_abs_logit_difference":hook_baseline_max,
             "gradient_steps":0,"optimizer_calls":0,"parameters_modified":False,
             "new_unseen_or_prospective_data":False,"metrics":metrics,"probes":results,
             "limitations":["Known DEV inputs only","State variation is not proven predictive signal",
                            "Input-layout control is not a weight edit","Hooks may change kernel selection; plain comparison is recorded"]}
    session.close({})
    atomic_create(summary_path, canonical(summary) + b"\n")
    print(json.dumps({k:v for k,v in summary.items() if k not in ("metrics","probes")}),flush=True)


if __name__=="__main__":
    main()

