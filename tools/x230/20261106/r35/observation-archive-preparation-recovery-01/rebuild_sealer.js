function buildR35ObservationSealer(reference,templateSha) {
 const checks=[];function need(x,m){if(!x)throw Error(m);}
 function replace(s,a,b,label){need(s.split(a).length===2,"replacement count: "+label);checks.push(label);return s.replace(a,b);}
 function block(s,a,b,replacement,label){const i=s.indexOf(a),j=s.indexOf(b,i+a.length);need(i>=0&&j>i&&s.indexOf(a,i+1)<0,"block anchors: "+label);checks.push(label);return s.slice(0,i)+replacement+s.slice(j);}
 let s=reference.replaceAll("r34","r35").replaceAll("R34","R35");
 s=replace(s,'TEMPLATE_SHA = "3e717ec2bcb434daabcce3caeb106afbf588ad5b1b2328207f8ff443a50db65f"','TEMPLATE_SHA = '+JSON.stringify(templateSha),"recovered-template-identity");
 s=replace(s,'template_path = HERE / "archive_r35_observation.unsealed-02.py"','template_path = HERE / "archive_r35_observation.py"',"template-path");
 const outcomes=String.raw`    need(parent.get("schema") == "hepta-r25-observation-campaign-control/v1"
         and parent.get("attempt") == "01" and parent.get("finished_utc")
         and parent.get("passed") is True
         and gates.get("schema") == "hepta-r25-observation-gates/v1"
         and type(gates.get("observation_gate_passed")) is bool
         and type(gates.get("performance_gates_passed")) is bool
         and type(gates.get("rejection_reasons")) is list
         and type(gates.get("controller_rss", {}).get("passed")) is bool
         and parent.get("observation_gate_passed") == gates["observation_gate_passed"]
         and parent.get("rejection_reasons") == gates["rejection_reasons"],
         "completed original R35 workflow with actual performance outcome required")
    need(native.get("state") == "succeeded" and native.get("exit_code") == 0
         and holder.get("passed") is True and holder.get("remote_returncode") == 0
         and holder.get("owned_agent_reaped") is True,
         "original completed holder custody is required for this OBS-only snapshot")
    namespace_paths = {"lifecycle-inputs-01.json", "lifecycle-campaign-01", "lifecycle-abba-01",
                       "lifecycle-materialization-native-01.json", "lifecycle-materialization-read-01.json"}
    need(postflight.get("schema") == "hepta-r35-observation-postflight/v1"
         and postflight.get("original_observation_job_id") == job
         and postflight.get("candidate_adopted") is False
         and postflight.get("normal_lifecycle_started") is False
         and postflight.get("lifecycle_materialization_started") is False
         and postflight.get("normal_lifecycle_state") == "not_started_at_capture"
         and postflight.get("normal_lifecycle_final_outcome") is None
         and postflight.get("original_lifecycle_materializer_job_id") is None
         and postflight.get("original_normal_lifecycle_job_id") is None
         and postflight.get("normal_lifecycle_path_presence") == {name: False for name in namespace_paths}
         and set(postflight.get("normal_lifecycle_paths_absent", []))
             == {"lifecycle-inputs-01.json", "lifecycle-campaign-01", "lifecycle-abba-01"}
         and postflight.get("lifecycle_nonlaunch_source"),
         "actual first OBS snapshot before lifecycle launch required")
    need(all(postflight.get(key) == gates.get(key) for key in
             ("observation_gate_passed", "performance_gates_passed", "rejection_reasons"))
         and postflight.get("controller_rss_passed") == gates["controller_rss"]["passed"],
         "postflight and actual original gates differ")
    counts = postflight.get("native_audit_counts")
    need(type(counts) is dict and set(counts) == {"verified", "measured_calls", "warmup_calls",
         "preflight_restart_calls", "total_calls", "failed_calls"}
         and type(counts["verified"]) is bool
         and all(type(value) is int and value >= 0 for key, value in counts.items() if key != "verified"),
         "actual native audit counts required")
    monitor_count = postflight.get("compiler_monitor_sample_count")
    need(type(monitor_count) is int and monitor_count > 0, "actual compiler monitor sample count required")
`;
 s=block(s,'    need(parent.get("schema")','    pins, sizes, origins =',outcomes,"current-outcome-and-at-capture-closure");
 s=replace(s,'        "capacity_build_or_campaign_started_by_coordinator": postflight.get("capacity_build_or_campaign_started_by_coordinator"),\n','',"no-R34-capacity-state");
 s=replace(s,'        "observation_gate_passed": False, "performance_gates_passed": False,',
  '        "observation_gate_passed": gates["observation_gate_passed"],\n        "performance_gates_passed": gates["performance_gates_passed"],\n        "controller_rss_passed": gates["controller_rss"]["passed"],\n        "native_audit_counts": counts, "compiler_monitor_sample_count": monitor_count,',"actual-performance-and-counts");
 s=replace(s,'        "lifecycle_materializer_job_id": None,',
  '        "lifecycle_materializer_job_id": None, "normal_lifecycle_job_id": None,\n        "normal_lifecycle_state": "not_started_at_capture", "normal_lifecycle_final_outcome": None,\n        "lifecycle_nonlaunch_source": postflight["lifecycle_nonlaunch_source"],',"unrun-at-capture");
 need(!s.includes("rejected-observation-owner")&&!s.includes("capacity_build_or_campaign"),"historical scope remains");
 return {source:s,transformations:checks};
}
