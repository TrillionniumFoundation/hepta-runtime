#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual shipped MCP path against frozen public/synthetic references."""
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import resource
import struct
import time

import numpy as np

from mcp_fixture_client import Mcp, encode_weight, pin_binary, sha, verify_binary


def exact_square(before, after) -> Fraction:
    return sum((Fraction(float(b))-Fraction(float(a)))**2 for a,b in zip(np.ravel(before),np.ravel(after)))


def verify_budget(report: dict, before, after, radius: float) -> dict:
    exact = exact_square(before,after)
    expected = exact <= Fraction(radius)**2
    units = exact * (1 << 298)
    assert units.denominator == 1
    assert report["squared_update_units_hex"] == format(units.numerator,"x")
    assert report["squared_update_unit_exponent"] == -298
    assert report["radius_f64_bits"] == format(struct.unpack("<Q",struct.pack("<d",radius))[0],"016x")
    assert report["within_budget"] is expected
    return {"within_budget":expected,"squared_update_units_hex":format(units.numerator,"x"),
            "squared_update_unit_exponent":-298,"radius_f64_bits":report["radius_f64_bits"],
            "python_fraction_match":True}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ["binary","fixtures","work-dir","output"]:
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    started,cpu=time.perf_counter(),time.process_time()
    child_before=resource.getrusage(resource.RUSAGE_CHILDREN)
    work=args.work_dir.resolve()
    work.mkdir(mode=0o700,parents=True,exist_ok=False)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    if args.output.exists():
        raise FileExistsError(args.output)
    cases_path=args.fixtures/"reference_cases.json"
    norm_path=args.fixtures/"norm_cases.json"
    derived_path=args.fixtures/"derived_public_fixture.json"
    cases=json.loads(cases_path.read_bytes())
    norms=json.loads(norm_path.read_bytes())
    derived=json.loads(derived_path.read_bytes())
    assert cases["derived_fixture_sha256"]==sha(derived_path.read_bytes())
    expected_norm_checks=sum(len(f["radii"]) for f in norms["families"])
    summary={"schema":"hepta.native-wsp-trust-region-rpc-qualification.v1",
        "driver_sha256":sha(Path(__file__).read_bytes()),
        "helper_sha256":sha(Path(__file__).with_name("mcp_fixture_client.py").read_bytes()),
        "fixture_sha256":{"references":sha(cases_path.read_bytes()),"norms":sha(norm_path.read_bytes()),"derived_public":sha(derived_path.read_bytes())},
        "original_public_fixture_sha256":derived["original_fixture_sha256"],
        "source_model_sha256":derived["source_model_sha256"],
        "numeric_change":derived["numeric_change"],
        "expected_plan_cases":len(cases["cases"]),"expected_norm_checks":expected_norm_checks,
        "plans":[],"norm_checks":[],"public_head_guards":[],"negative_controls":[],
        "passed":False,"completed":False,"failure":None,
        "production_eligible":False,"independent_holdout_verified":False,
        "new_end_to_end_utility_evidence":False,
        "scope":"Bounded solver, exact one-patch numeric budget, source authentication and normal-return restoration; public TRAIN fixture and synthetic boundaries only. No live state or full graph qualification.",
        "cost_excludes":["original training","feature/target construction","independent reference generation","Rust compilation","LLM usage","transfer","energy"]}
    raw_receipts={"plans":[],"guards":[],"norms":[]}
    def save() -> None:
        args.output.write_text(json.dumps(summary,indent=2,allow_nan=False)+"\n")
        (work/"raw-receipts.json").write_text(json.dumps(raw_receipts,indent=2,allow_nan=False)+"\n")
    config=work/"runtime.json"
    config.write_text(json.dumps({"state_dir":str(work/"state"),"controller_workspace_roots":[str(work)],
        "weight_workers":{},"hosts":{"unused":{"ssh_target":"unused.invalid","remote_state_dir":str(work/"unused"),"allow_execute":False}}}))
    pinned,binary_sha,binary_stat=pin_binary(args.binary.resolve(),work)
    summary["binary_sha256"]=binary_sha
    current_case="initialize"
    mcp=None
    try:
        mcp=Mcp(pinned,config,work/"mcp.stderr.log")
        for case in cases["cases"]:
            current_case=case["name"]
            params=case["params"]
            report=mcp.call("weight_linear_ridge_plan",params)
            raw_receipts["plans"].append({"case":current_case,"report":report})
            expected=np.asarray(case["reference"]["weights_f64"])
            found=np.asarray(report["weights_f64"])
            error=float(np.max(np.abs(found-expected)))
            threshold=1e-8*(1+float(np.max(np.abs(expected))))
            assert error<=threshold,(current_case,error,threshold)
            before=np.asarray(params["base_weights"],dtype=np.float32)
            after=np.asarray(report["weights_f32"],dtype=np.float32)
            budget=verify_budget(report["f32_update_budget"],before,after,params["max_update_l2_norm"])
            assert budget["within_budget"]
            lowered=before.tobytes()
            patched=bytearray(lowered)
            for edit in report["f32_element_edits"]:
                at=4*edit["index"]
                assert patched[at:at+4]==bytes.fromhex(edit["expected_hex"])
                patched[at:at+4]=bytes.fromhex(edit["replacement_hex"])
            assert bytes(patched)==after.tobytes()
            assert report["gradient_steps"]==0 and report["training_targets_used"]
            assert report["source_weights_verified"] is False and report["production_eligible"] is False
            assert report["f32_optimality_certified"] is False
            assert report["trust_region"]["f64_global_optimality_certified"] is False
            assert report["operation_charged_units"]<=report["operation_budget_units"]<=80000000
            entry={"name":current_case,"max_absolute_f64_reference_error":error,"error_threshold":threshold,
                "reference_shared_multiplier":case["reference"]["shared_multiplier"],
                "native_trust_region":report["trust_region"],"f32_budget":budget,
                "changed_f32_elements":report["f32_edit_count"],"f32_patch_bytes_match_returned_weights":True,
                "native_wall_seconds":report["native_operation_wall_seconds"],
                "operation_charged_units":report["operation_charged_units"],"operation_budget_units":report["operation_budget_units"],
                "request_sha256":report["request_sha256"],"diagnostics":report["diagnostics"]}
            summary["plans"].append(entry)
            if case.get("public_fixture"):
                parent=np.vstack([before,np.asarray(derived["frozen_belief_weights"],dtype=np.float32)])
                original=encode_weight(parent)
                source=work/(current_case+".safetensors")
                source.write_bytes(original)
                source_sha=sha(original)
                inputs=np.asarray(params["features"],dtype=np.float32).tolist()
                forward=mcp.call("weight_linear_forward",{"source":{"kind":"path","path":str(source),"expected_sha256":source_sha,"tensor_name":"weight"},"inputs":inputs,"bias":None})
                targets=np.c_[np.asarray(params["targets"],dtype=np.float32),np.asarray(forward["outputs"],dtype=np.float32)[:,3]].tolist()
                guard_params={"patch":{"path":str(source),"expected_sha256":source_sha,"tensor_name":"weight","edits":report["f32_element_edits"]},
                    "inputs":inputs,"bias":None,"objective":{"kind":"squared_error","targets":targets},
                    "minimum_gain":0.0,"constraints":[{"kind":"preserve","column":3,"max_absolute_change":0.0}],
                    "max_update_l2_norm":params["max_update_l2_norm"]}
                gate=mcp.call("weight_guarded_linear_patch",guard_params)
                raw_receipts["guards"].append({"case":current_case,"kind":"primary","report":gate})
                verify_budget(gate["f32_update_budget"],before,after,params["max_update_l2_norm"])
                assert gate["f32_update_budget_source_bytes_authenticated"] is True
                assert gate["accepted"] is (gate["gain"]>0 and not gate["candidate_constraint_violations"] and gate["evaluation_error"] is None)
                assert source.read_bytes()==original
                candidate=Path(gate["candidate"]["artifact_path"]).read_bytes()
                assert candidate[-49*4:]==original[-49*4:]
                if not gate["accepted"]:
                    assert gate["outcome"]=="rejected_and_restored"
                    assert Path(gate["restoration"]["artifact_path"]).read_bytes()==original
                guard_params["constraints"].append({"kind":"preserve","column":0,"max_absolute_change":0.0})
                rejected=mcp.call("weight_guarded_linear_patch",guard_params)
                raw_receipts["guards"].append({"case":current_case,"kind":"forced_preserve_conflict","report":rejected})
                assert rejected["outcome"]=="rejected_and_restored"
                assert 1 in rejected["candidate_constraint_violations"]
                assert Path(rejected["restoration"]["artifact_path"]).read_bytes()==original
                assert rejected["candidate"]["sha256"]==gate["candidate"]["sha256"]
                summary["public_head_guards"].append({"name":current_case,"parent_f32_sha256":source_sha,
                    "candidate_f32_sha256":gate["candidate"]["sha256"],"primary_outcome":gate["outcome"],
                    "gain_on_supplied_train_rows":gate["gain"],"mse_before":-gate["primary_before"],"mse_after":-gate["primary_after"],
                    "frozen_belief_bytes_preserved":True,"source_bytes_unchanged":True,
                    "forced_preservation_failure_restored_all_bytes":True,"forced_failure_is_natural_model_failure":False,
                    "native_guard_wall_seconds":[gate["native_operation_wall_seconds"],rejected["native_operation_wall_seconds"]],
                    "quality_scope":"Original TRAIN rows with explicitly F32-lowered inputs/targets/anchor; no new policy episode or held-out utility evidence."})
            save()
        current_case="optional_field_identity"
        original_params=dict(cases["cases"][0]["params"])
        original_params.pop("max_update_l2_norm")
        omitted=mcp.call("weight_linear_ridge_plan",original_params)
        explicit_null=mcp.call("weight_linear_ridge_plan",dict(original_params,max_update_l2_norm=None))
        old_canonical=b'{"features":[[1.0]],"targets":[[3.0]],"sample_weights":[[1.0]],"base_weights":[[1.0]],"lambda":1.0}'
        assert omitted["request_sha256"]==explicit_null["request_sha256"]==sha(old_canonical)
        assert omitted["request_sha256"]!=summary["plans"][1]["request_sha256"]
        summary["optional_field_identity"]={"absent_and_null_match_old_canonical_commitment":True,"some_changes_commitment":True,"old_canonical_sha256":sha(old_canonical),"additional_planner_calls":2}
        for family in norms["families"]:
            before=np.frombuffer(bytes.fromhex(family["before_f32_hex"]),dtype="<f4").reshape(1,-1)
            after=np.frombuffer(bytes.fromhex(family["after_f32_hex"]),dtype="<f4").reshape(1,-1)
            original=encode_weight(before)
            source=work/("norm_"+family["name"]+".safetensors")
            source.write_bytes(original)
            edits=[{"index":i,"expected_hex":struct.pack("<f",a).hex(),"replacement_hex":struct.pack("<f",b).hex()} for i,(a,b) in enumerate(zip(before.flat,after.flat))]
            old_eval=None
            for index,entry in enumerate(family["radii"]):
                current_case=f"norm:{family['name']}:{index}"
                params={"patch":{"path":str(source),"expected_sha256":sha(original),"tensor_name":"weight","edits":edits},
                    "inputs":[[0.0]*family["elements"]],"bias":None,"objective":{"kind":"squared_error","targets":[[0.0]]},
                    "minimum_gain":0.0,"constraints":[],"max_update_l2_norm":entry["radius"]}
                expected=exact_square(before,after)<=Fraction(entry["radius"])**2
                assert expected is entry["within_budget"]
                row={"family":family["name"],"radius_index":index,"elements":family["elements"],
                    "radius":entry["radius"],"radius_f64_bits":entry["radius_f64_bits"],"expected_within_budget":expected,
                    "squared_update_units_hex":family["squared_update_units_hex"],"squared_update_unit_exponent":-298}
                if not expected:
                    try:
                        unexpected=mcp.call("weight_guarded_linear_patch",params)
                    except RuntimeError as error:
                        assert "exact joint L2 update budget" in str(error)
                        row["outcome"]="rejected_before_publication_by_exact_budget"
                    else:
                        raw_receipts["norms"].append({"case":current_case,"unexpected":unexpected})
                        raise AssertionError("over-budget F32 patch was not rejected")
                else:
                    report=mcp.call("weight_guarded_linear_patch",params)
                    raw_receipts["norms"].append({"case":current_case,"report":report})
                    verify_budget(report["f32_update_budget"],before,after,entry["radius"])
                    assert report["f32_update_budget_source_bytes_authenticated"]
                    assert report["outcome"]=="rejected_and_restored" and report["gain"]==0
                    assert Path(report["restoration"]["artifact_path"]).read_bytes()==original
                    if old_eval is not None:
                        assert old_eval!=report["evaluation_id"]
                    old_eval=report["evaluation_id"]
                    row.update(outcome=report["outcome"],native_wall_seconds=report["native_operation_wall_seconds"],python_fraction_match=True,restored_all_bytes=True)
                assert source.read_bytes()==original
                row["source_bytes_unchanged"]=True
                summary["norm_checks"].append(row)
                save()
        current_case="negative_controls"
        source=work/"forged_or_duplicate.safetensors"
        original=encode_weight(np.asarray([[1.0,-3.0]],dtype=np.float32));source.write_bytes(original)
        for name in ["forged_expected_bytes","duplicate_address"]:
            edits=[{"index":0,"expected_hex":struct.pack("<f",1.0).hex(),"replacement_hex":struct.pack("<f",2.0).hex()}]
            if name=="forged_expected_bytes":
                edits[0]["expected_hex"]=struct.pack("<f",0.0).hex()
            else:
                edits.append(dict(edits[0]))
            params={"patch":{"path":str(source),"expected_sha256":sha(original),"tensor_name":"weight","edits":edits},
                "inputs":[[0.0,0.0]],"bias":None,"objective":{"kind":"squared_error","targets":[[0.0]]},
                "minimum_gain":0.0,"constraints":[],"max_update_l2_norm":10.0}
            try:
                mcp.call("weight_guarded_linear_patch",params)
            except RuntimeError as error:
                summary["negative_controls"].append({"name":name,"rejected":True,"error":str(error).replace(str(work),"<WORK>")[:2048]})
            else:
                raise AssertionError(name+" accepted")
            assert source.read_bytes()==original
        for name,changes in [("negative_radius",{"max_update_l2_norm":-1.0}),("non_f32_anchor",{"base_weights":[[0.1]]})]:
            params=dict(cases["cases"][0]["params"],**changes)
            try:
                mcp.call("weight_linear_ridge_plan",params)
            except RuntimeError as error:
                summary["negative_controls"].append({"name":name,"rejected":True,"error":str(error).replace(str(work),"<WORK>")[:2048]})
            else:
                raise AssertionError(name+" accepted")
        summary["completed"]=True
        summary["passed"]=len(summary["plans"])==len(cases["cases"]) and len(summary["norm_checks"])==expected_norm_checks and len(summary["public_head_guards"])==2 and len(summary["negative_controls"])==4
    except BaseException as error:
        summary["failure"]={"case":current_case,"type":type(error).__name__,"message":str(error).replace(str(work),"<WORK>")[:4096]}
    finally:
        if mcp is not None:
            mcp.close()
        verify_binary(pinned,binary_sha,binary_stat)
        summary["executed_binary_unchanged"]=True
        summary["driver_wall_seconds"]=time.perf_counter()-started
        summary["driver_process_cpu_seconds"]=time.process_time()-cpu
        child_after=resource.getrusage(resource.RUSAGE_CHILDREN)
        summary["child_user_cpu_seconds"]=child_after.ru_utime-child_before.ru_utime
        summary["child_system_cpu_seconds"]=child_after.ru_stime-child_before.ru_stime
        save()
    print(json.dumps({"passed":summary["passed"],"completed":summary["completed"],"failure":summary["failure"],"plan_cases":len(summary["plans"]),"norm_checks":len(summary["norm_checks"]),"wall_seconds":summary["driver_wall_seconds"]}))
    raise SystemExit(0 if summary["passed"] else 1)


if __name__=="__main__":
    main()
