#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read all previous archives, and refuse to re-run a completed direct case."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
def main():
    p=argparse.ArgumentParser()
    for name in ("prepared","build-recipe"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();source_evidence(HERE)
    old=(HERE/"retained_capture_direct.py.txt").read_bytes()
    new=(HERE/"capture_direct.py").read_bytes()
    before=b"        def command(step,source_step):\n";after=before+b"            nonlocal blocklocked\n"
    require(old.count(before)==1 and new.count(after)==1 and old.replace(before,after,1)==new
        and new.replace(after,before,1)==old,"exact single observer scoping repair")
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    inputs=decode((HERE/"RETAINED_CAPTURE_INPUTS.json").read_bytes())
    completed=[];failed=[];archives={};rows=[]
    for key,identity in inputs.items():
        root,receipt=restore(a.prepared/("prior-"+key),identity);archives[key]=receipt
        source_evidence(root/"recipe-source")
        require((root/"recipe-source/capture_direct.py").read_bytes()==old,"entire retained first observer source")
        native=root/"capture/native";plan=decode((native/"PLAN.json").read_bytes())
        require((plan["first"],plan["count"])==(int(key),2),"whole original attempted partition")
        if (native/"RESULTS.json").exists():declared=decode((native/"RESULTS.json").read_bytes())
        else:declared=[]
        actual=[]
        for case in sorted((native/"cases").iterdir()):
            number=int(case.name);process=decode((case/"process/PROCESS.json").read_bytes())
            require(process["cleanup_errors"]==[] and process["process_group_absent"] is True,
                "every old process has a known reaped terminal")
            if (case/"RESULT.json").exists():
                result=decode((case/"RESULT.json").read_bytes())
                require(result["case"]==number and result["status"]=="ACTUAL_NATIVE_DIRECT_FUTURE_CAPTURED"
                    and result["process"]==process and process["exit_code"]==0
                    and process["expected_success"] is True and process["timed_out"] is False,
                    "complete retained native process")
                completed.append(number);actual.append(result)
                rows.append(dict(case=number,kind="complete",result=pin(case/"RESULT.json"),process=process))
            else:
                failure=decode((case/"FAILURE.json").read_bytes())
                require(failure["type"]=="UnboundLocalError" and
                    failure["message"]=="cannot access local variable 'blocklocked' where it is not associated with a value",
                    "only the actual failed observer scope is continued")
                failed.append(number);rows.append(dict(case=number,kind="failed",failure=failure,process=process))
        require(actual==declared,"all old complete results retained")
    require(sorted(completed)==[22,23,24,28] and sorted(failed)==[25,26,29],
        "exact complete/failed case sets; never replay a completed process")
    require(set(range(22,30))-set(completed)-set(failed)=={27},"one previously unstarted input")
    result=dict(status="ONLY_RETAINED_UNCOMPLETED_INPUTS_ADMITTED",archives=archives,
        completed=sorted(completed),failed=sorted(failed),unstarted=[27],continue_cases=[25,26,27,29],
        application_replayed=False,production_changed=False,rows=rows)
    (a.prepared/"CONTINUATION_ADMISSION.json").write_bytes(canonical(result))
    print(json.dumps({k:v for k,v in result.items() if k not in ("rows","archives")},sort_keys=True),flush=True)
if __name__=="__main__":main()
