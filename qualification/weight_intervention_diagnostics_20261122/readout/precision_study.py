"""Compare two sealed forward-only locators on a new independent injection/probe draw."""
import argparse
import hashlib
import json
import resource
import struct
import subprocess
import sys
import time
from pathlib import Path

import numpy as np


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quantized_cells(values, precision):
    f = values.astype(np.float32)
    if precision == "bf16":
        bits = f.view(np.uint32)
        bits += np.uint32(0x7fff) + ((bits >> 16) & 1)
        rounded = (bits & np.uint32(0xffff0000)).view(np.float32).astype(np.float64)
        eps = 2.**-7
    else:
        rounded = f.astype(np.float64)
        eps = 2.**-23
    # A full ulp envelope on either side is conservative, including at binade boundaries.
    # The floor covers subnormals. Guard the small binary64 contraction roundoff as well.
    radius = eps * np.maximum(abs(rounded), 2.**-126) + 1e-13
    return rounded, radius


def ask(worker, magic, jobs, make_bytes):
    payload = bytearray(magic + struct.pack("<I", len(jobs)))
    for j in jobs:
        packet = make_bytes(j)
        payload.extend(struct.pack("<I", len(packet)))
        payload.extend(packet.astype("<f8").tobytes())
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall = time.monotonic()
    p = subprocess.run([worker], input=payload, capture_output=True, check=True)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    answers = p.stdout.decode().splitlines()
    if len(answers) != len(jobs):
        raise ValueError("incomplete native result")
    return answers, dict(count=len(jobs), wire_hash=hashlib.sha256(payload).hexdigest(),
                         response_hash=hashlib.sha256(p.stdout).hexdigest(),
                         cpu_s=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                         wall_s=time.monotonic()-wall)


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("neuron", type=Path)
    cli.add_argument("worker", type=Path)
    cli.add_argument("out", type=Path)
    cli.add_argument("--seed", type=int, help="reproduce a previous draw")
    args = cli.parse_args()
    args.out.mkdir(parents=True,exist_ok=False)
    src = Path(__file__).resolve().parent
    method = dict(worker=sha(args.worker),source={k:sha(src/k) for k in ("localize.rs","interval.rs","precision_study.py")},
                  threshold="unique feasible coordinate, full-ulp roundoff bounds",
                  orders=[8,32],corruption_abs_uniform=[.1,.5],fit_worlds="first 16",held_worlds="last 16")
    (args.out/"method.json").write_text(json.dumps(method,indent=2))
    import secrets
    seed = secrets.randbits(128) if args.seed is None else args.seed
    (args.out/"seed.json").write_text(json.dumps({"seed":seed}))
    random = np.random.default_rng(seed)
    sys.path.insert(0,str(args.neuron/"pinned"))
    from study_io import gen_items
    from data_contract import head
    import value_graph as vg
    proto = args.neuron/"pinned/PROTOCOL_FROZEN.json"
    assert sha(proto)=="adca7eed0c7dc63a5d884fc44f8e8431d7dae56eb44d0566d522eb8dae405d10"
    p = json.loads(proto.read_text())
    rows, receipts, policies = [], [], []
    start = time.process_time()
    for fit in p["fit_ids"]:
        base, worlds = gen_items(p,args.neuron/"inputs",fit)
        clean = head(base)
        develop = np.vstack([w["H"] for w in worlds[:16]])
        hidden = develop[random.choice(len(develop),32,replace=False)]
        heldmax = np.max(abs(np.vstack([w["H"] for w in worlds[16:]])),axis=0)
        edits=[]
        for k in range(4):
            for c in range(49):
                edit=np.zeros_like(clean)
                edit[k,c]=random.choice((-1.,1.))*random.uniform(.1,.5)
                edits.append(("single",k,c,edit))
        for i in range(24):
            edit=np.zeros_like(clean)
            c1,c2=random.choice(49,2,replace=False)
            k=i%4
            edit[k,c1]=.28
            edit[k if i<12 else (k+1)%4,c2]=-.2
            edits.append(("two",None,None,edit))
        swapped=np.zeros_like(clean)
        swapped[[0,1]] = clean[[1,0]]-clean[[0,1]]
        edits.extend([("swap",None,None,swapped),("clean",None,None,np.zeros_like(clean)),
                      ("wrong_ref",None,None,np.zeros_like(clean)),("same_probe",0,19,np.zeros_like(clean))])
        edits[-1][3][0,19]=.3
        for precision in ("fp32","bf16"):
            jobs=[]
            for kind,k,c,edit in edits:
                h=np.repeat(hidden[:1],32,axis=0) if kind=="same_probe" else hidden
                corrupt=clean+edit
                before=h@clean.T
                if kind=="wrong_ref":
                    before=np.roll(before,1,axis=0)
                y, ey=quantized_cells(before,precision)
                z, ez=quantized_cells(h@corrupt.T,precision)
                d=y-z; lo=d-ey-ez; hi=d+ey+ez
                for n in method["orders"]:
                    jobs.append(dict(kind=kind,k=k,c=c,corrupt=corrupt,n=n,h=h[:n],d=d[:n],lo=lo[:n],hi=hi[:n]))
            random.shuffle(jobs)
            plain, rc0=ask(args.worker.resolve(),b"WSL1",jobs,lambda j:np.c_[j["h"],j["d"]])
            aware, rc1=ask(args.worker.resolve(),b"WSL2",jobs,lambda j:np.c_[j["h"],j["lo"],j["hi"]])
            receipts.append(dict(fit=fit,precision=precision,strict=rc0,interval=rc1))
            for j,s0,s1 in zip(jobs,plain,aware):
                words=s1.split()
                record=dict(fit=fit,precision=precision,kind=j["kind"],n=j["n"],k=j["k"],c=j["c"],
                            strict=s0,interval=s1)
                repaired=j["corrupt"].copy()
                if words[0]=="EDIT":
                    k,c=int(words[1]),int(words[2])
                    mid,lo,hi=map(float,words[3:])
                    truth=clean[k,c]-repaired[k,c]
                    repaired[k,c]+=mid
                    record.update(right=(k,c)==(j["k"],j["c"]),covers=bool(lo<=truth<=hi),width=hi-lo,
                                  held_logit_bound=float(np.max(abs(repaired-clean)@heldmax)))
                if j["kind"]=="single" and j["n"]==8 and j["c"]==[12,21,36,48][j["k"]]:
                    for widx in (16,25):
                        w=worlds[widx]; vals={}
                        for name,matrix in (("original",clean),("corrupt",j["corrupt"]),("after",repaired)):
                            val,_=vg.evaluate(w["graph"],vg.strict_scores(matrix,w["H"])[0])
                            vals[name]=float(val["utility"])
                        policies.append(dict(fit=fit,precision=precision,k=j["k"],c=j["c"],world=widx,**vals))
                rows.append(record)
    (args.out/"results.json").write_text(json.dumps(dict(receipts=receipts,cases=rows,policy=policies,
               harness_cpu_s=time.process_time()-start),allow_nan=False,separators=(",",":")))

if __name__=="__main__":
    main()
