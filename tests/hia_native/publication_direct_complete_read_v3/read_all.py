#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every retained direct role once after a single complete dependency admission."""
from pathlib import Path
import argparse,json,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
def main():
    p=argparse.ArgumentParser()
    for name in ("prepared","build-recipe","direct-recipe","public-reader","retained","output"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);a.retained.mkdir(parents=True,exist_ok=False)
    source=source_evidence(HERE);info=decode((HERE/"INPUTS.json").read_bytes());rows=[]
    for role in info["read_scheduling"]["roles"]:
        out=a.output/role;stdout=a.output/(role+".stdout");stderr=a.output/(role+".stderr")
        command=[sys.executable,"-I","-S","-B",str(HERE/"recover_direct.py"),
            "--prepared",str(a.prepared),"--build-recipe",str(a.build_recipe),
            "--direct-recipe",str(a.direct_recipe),"--public-reader",str(a.public_reader),
            "--retained",str(a.retained/role),"--output",str(out),"--role",role]
        start=time.monotonic()
        with stdout.open("xb") as so,stderr.open("xb") as se:
            result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=so,stderr=se)
        row=dict(role=role,command=command,exit_code=result.returncode,elapsed_seconds=time.monotonic()-start,
            stdout=pin(stdout),stderr=pin(stderr),no_outer_repeated_timeout=True,
            per_case_limit_seconds=180,applications_executed=0)
        if result.returncode==0:
            summary=decode((out/"SUMMARY.json").read_bytes())
            require(summary["status"]=="COMPLETE_RETAINED_DIRECT_CASE_JOIN_PASS"
                and summary["role"]==role and [x["case"] for x in summary["cases"]]==info["roles"][role]["completed"],
                "all exact completed cases in each role")
            row["summary"]=pin(out/"SUMMARY.json");row["cases"]=summary["cases"]
        else:
            sys.stderr.buffer.write(stderr.read_bytes());sys.stderr.flush()
        rows.append(row);(a.output/"ROLE_RESULTS.json").write_bytes(canonical(rows))
        print("DIRECT_RETAINED_ROLE "+json.dumps(row,sort_keys=True),flush=True)
    require(all(row["exit_code"]==0 for row in rows),"all retained direct roles must pass")
    cases=sorted((case for row in rows for case in row["cases"]),key=lambda x:x["case"])
    require([case["case"] for case in cases]==info["all_direct_inputs"],"complete eight-case union without duplication")
    summary=dict(status="COMPLETE_EIGHT_DIRECT_FUTURES_JOIN_PASS",source=source,
        production=info["production"],source_binding=info["source_binding"],roles=rows,cases=cases,
        original_replayed=False,native_replayed=False,physical_controls_pending=True,full_sdk=False)
    (a.output/"SUMMARY.json").write_bytes(canonical(summary));print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
