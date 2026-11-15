(function build(oldParent,oldSealer,oldInstaller,ordinaryHelper){
 function replace(s,a,b){if(s.split(a).length!==2)throw Error("unique anchor missing: "+a);return s.replace(a,b);}
 let p=oldParent;
 p=replace(p,'PREREQUISITES = ROOT / "c1-prerequisites-01.json"\n','PREREQUISITES = ROOT / "c1-prerequisites-01.json"\nORDINARY_VERIFIER = ROOT / "ordinary-tools-01/verify_ordinary_01.py"\nORDINARY_INPUT = ROOT / "ordinary-verification-input-01.json"\nORDINARY_POSTFLIGHT = ROOT / "ordinary-postflight-01.json"\n');
 p=replace(p,'{"sealed", "prerequisites", "qualification_binder", "adapter", "adapter_spec", "compiler_monitor"}','{"sealed", "prerequisites", "qualification_binder", "ordinary", "adapter", "adapter_spec", "compiler_monitor"}');
 p=replace(p,'         "D1 sealed outer input shape differs")\n','         "D1 sealed outer input shape differs")\n    need(isinstance(ACTUAL["ordinary"], dict)\n         and set(ACTUAL["ordinary"]) == {"verifier", "verification_input", "postflight"}\n         and all(isinstance(pin, dict) and set(pin) == {"path", "bytes", "sha256"}\n                 and isinstance(pin["path"], str) and type(pin["bytes"]) is int and pin["bytes"] > 0\n                 and isinstance(pin["sha256"], str) and HEX.fullmatch(pin["sha256"])\n                 for pin in ACTUAL["ordinary"].values()),\n         "actual ordinary closure is mandatory before any output or monitor")\n');
 p=replace(p,'            "qualification_binder": ACTUAL["qualification_binder"], "adapter": ACTUAL["adapter"],\n','            "qualification_binder": ACTUAL["qualification_binder"], "ordinary": ACTUAL["ordinary"],\n            "adapter": ACTUAL["adapter"],\n');
 p=replace(p,'def bind_adapter(bind, prerequisites, qualified):\n',ordinaryHelper+'def bind_adapter(bind, prerequisites, qualified):\n');
 p=replace(p,'        report["qualification_binder"] = binder_id\n','        report["qualification_binder"] = binder_id\n        report["ordinary_supplement"] = bind_ordinary_prerequisite(ACTUAL["ordinary"], bind, binder, qualified)\n');
 let s=oldSealer;
 s=replace(s,'"""Seal D1 C1 only from complete real local Q/CI files; never run a workload.','"""Seal D1 C1 only after actual Q/CI and mandatory ordinary closure.');
 s=replace(s,'prerequisite document, runs its read-only binder, then writes a new staged','prerequisite document, runs its read-only binder and ordinary verifier, then writes a new staged');
 s=replace(s,'have closed. Reads the frozen preparation package and the supplied actual','and ordinary have closed. Reads the frozen preparation package and the supplied actual');
 const after='         "actual first D1 qualification/CI closure did not pass")\n';
 const body='    ordinary_source = sources["ordinary/verify_ordinary_01.py"]\n'+
 '    ordinary_pins = {\n'+
 '        "verifier": identity(parent.ORDINARY_VERIFIER, ordinary_source),\n'+
 '        "verification_input": parent.checked(parent.ORDINARY_INPUT, maximum=4 * 1024 * 1024),\n'+
 '        "postflight": parent.checked(parent.ORDINARY_POSTFLIGHT, maximum=16 * 1024 * 1024),\n'+
 '    }\n'+
 '    ordinary_bindings = []\n'+
 '    def bind_ordinary(path, expected=None, maximum=128 * 1024 * 1024, retain=False):\n'+
 '        result = parent.checked(path, expected, maximum, retain)\n'+
 '        ordinary_bindings.append(result[0] if retain else result)\n'+
 '        return result\n'+
 '    ordinary_proof = parent.bind_ordinary_prerequisite(ordinary_pins, bind_ordinary, binder, proof)\n';
 s=replace(s,after,after+body);
 s=replace(s,'              "adapter": adapter_pin, "adapter_spec": adapter_spec, "compiler_monitor": monitor}\n','              "ordinary": ordinary_pins, "adapter": adapter_pin, "adapter_spec": adapter_spec, "compiler_monitor": monitor}\n');
 s=replace(s,'              "qualification_binder": binder_pin, "adapter": adapter_pin, "compiler_monitor": monitor}\n','              "qualification_binder": binder_pin, "ordinary": ordinary_pins,\n              "adapter": adapter_pin, "compiler_monitor": monitor}\n');
 s=replace(s,'    need(len(linux) + len(mac) <= MAX_FILES\n','    for pin in ordinary_bindings:\n        need(parent.checked(pin["path"], pin) == pin, "ordinary original changed during metadata sealing")\n    need(len(linux) + len(mac) <= MAX_FILES\n');
 s=replace(s,'        "prerequisites": foundation_pin, "qualification_and_exact_ci": proof,\n','        "prerequisites": foundation_pin, "qualification_and_exact_ci": proof,\n        "ordinary_inputs": ordinary_pins, "ordinary_supplement": ordinary_proof,\n');
 let i=oldInstaller;
 const anchor='    need(manifest.get("holder_sha256") == HOLDER_SHA\n';
 const guard='    ordinary = manifest.get("ordinary_supplement")\n'+
 '    need(isinstance(ordinary, dict) and ordinary.get("passed") is True\n'+
 '         and ordinary.get("original_postflight_revalidated") is True\n'+
 '         and ordinary["inputs"] == manifest.get("ordinary_inputs")\n'+
 '         and ordinary["validation"].get("ordinary_five_stages_passed") is True\n'+
 '         and ordinary["validation"]["qualified_feature_programs_after"]\n'+
 '             == manifest["qualification_and_exact_ci"]["binaries"],\n'+
 '         "mandatory actual ordinary closure is absent from the source seal")\n';
 i=replace(i,anchor,guard+anchor);
 return {parent:p,sealer:s,installer:i};
})
