"""Check paired outcomes and confidence-set coverage against the sequestered faults."""
import collections
import json
import sys
from pathlib import Path
import numpy as np

data=json.loads(Path(sys.argv[1]).read_text())
out={}
for precision in ("fp32","bf16"):
    for n in (8,32):
        cases=[r for r in data["cases"] if r["precision"]==precision and r["n"]==n]
        singles=[r for r in cases if r["kind"]=="single"]
        accepted=[r for r in singles if r["interval"].startswith("EDIT")]
        controls=[r for r in cases if r["kind"]!="single"]
        out[f"{precision}/{n}"]=dict(singles=len(singles),strict_edits=sum(r["strict"].startswith("EDIT") for r in singles),
            interval_edits=len(accepted),interval_correct=sum(r["right"] for r in accepted),
            interval_cover=sum(r["covers"] for r in accepted),max_halfwidth=max((r["width"]/2 for r in accepted),default=None),
            max_logit_error_bound=max((r["held_logit_bound"] for r in accepted),default=None),
            controls={t:dict(collections.Counter(r["interval"].split()[0] for r in controls if r["kind"]==t))
                      for t in sorted({r["kind"] for r in controls})})
    rows=[r for r in data["policy"] if r["precision"]==precision]
    out[f"{precision}/policy"]=dict(cases=len(rows),max_abs_value_gap=max(abs(r["after"]-r["original"]) for r in rows),
        changed_after=sum(abs(r["after"]-r["original"])>1e-12 for r in rows),
        damaged_differed=sum(abs(r["corrupt"]-r["original"])>1e-12 for r in rows))
out["counts"]=dict(cases=len(data["cases"]),native_queries=len(data["cases"])*2,policy_DPs=len(data["policy"])*3,
     strict_cpu_s=sum(r["strict"]["cpu_s"] for r in data["receipts"]),interval_cpu_s=sum(r["interval"]["cpu_s"] for r in data["receipts"]),
     harness_cpu_s=data["harness_cpu_s"])
print(json.dumps(out,indent=2,sort_keys=True))
