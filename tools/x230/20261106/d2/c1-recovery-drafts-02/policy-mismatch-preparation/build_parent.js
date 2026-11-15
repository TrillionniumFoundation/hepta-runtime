// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
// Pure source derivation. Inputs are exact pinned D1 outer05 source texts.
// Does not import or execute a target Python module or access a host.
function deriveD2Outer(original) {
  const ledger = [];
  function change(source, name, before, after, count=1) {
    const actual = source.split(before).length-1;
    if (actual !== count) throw new Error(name+": expected "+count+", observed "+actual);
    ledger.push({name,before,after,count});
    return source.split(before).join(after);
  }
  function namespace(source,name) {
    source=change(source,name+":root","/home/qian/hepta-runtime-phase-cost-20261106-d1",
      "/home/qian/hepta-runtime-validation-cost-20261106-d2",
      source.split("/home/qian/hepta-runtime-phase-cost-20261106-d1").length-1);
    source=change(source,name+":socket","/home/qian/hd1c01","/home/qian/hd2c01");
    for(const [a,b] of [["d1_","d2_"],["-d1-","-d2-"],["D1","D2"]]) {
      const count=source.split(a).length-1;
      if(count) source=change(source,name+":"+a,a,b,count);
    }
    return source;
  }
  let parent=namespace(original.parent,"parent");
  parent=change(parent,"source construction baseline",
    'BASELINE_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r24")',
    'BASELINE_ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")');
  for(const [a,b] of [
    ['ordinary-tools-02/verify_ordinary_02.py','ordinary-tools-01/verify_ordinary_01.py'],
    ['ordinary-verification-input-02.json','ordinary-verification-input-01.json'],
    ['ordinary-postflight-02.json','ordinary-postflight-01.json'],
    ['"ordinary-02"','"ordinary-01"'],
    ['hepta-d2-ordinary-supplement-validation/v3','hepta-d2-ordinary-supplement-validation/v1'],
    ['hepta-d2-ordinary-supplement-postflight/v3','hepta-d2-ordinary-supplement-postflight/v1'],
    ['len(added) == 2 and len(changed) == 13','len(added) == 0 and len(changed) == 2']
  ]) parent=change(parent,"parent:"+a,a,b);
  parent=change(parent,"D2 parser static pin",
    '"reference/summarize_trace.py": [\n        15057,\n        "f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5"\n    ],',
    '"reference/summarize_trace.py": [\n        15070,\n        "ca0e7e0d7c670daec20e54c6703bc1849f80138224570ef5366abd60079c7927"\n    ],\n    "reference/correlate_trace.py": [\n        15615,\n        "891f511e80273c5fb4a1a76ff3606b7de90827c3eab5d01bb3e283dba952cd84"\n    ],');
  parent=change(parent,"strict actual adapter correlation result",
    'and len(adapted["bindings"]) == len(adapted["traces"]) == 8,',
    'and len(adapted["bindings"]) == len(adapted["traces"]) == 8\n'+
    '         and adapted["strict_on_request_bijection_count"] == 468\n'+
    '         and adapted["measured_on_request_count"] == 384\n'+
    '         and adapted["validation_whole_cost_field"] == "inclusive CPU of validation_worker and validation_owner",');
  parent=change(parent,"whole-cost result semantics",
    '"trace_cost_scope": "recorded synchronous spans selected by original native request IDs and original intervals",',
    '"trace_cost_scope": "recorded synchronous spans matched bijectively by controller, host, operation and complete original RPC interval",\n'+
    '            "on_trace_request_bijection_count": adapted["strict_on_request_bijection_count"],\n'+
    '            "on_measured_request_count": adapted["measured_on_request_count"],\n'+
    '            "validation_whole_cost_field": adapted["validation_whole_cost_field"],\n'+
    '            "read_loop_scope": "original whole loop, including reads, comparison or hash updates and original cancellation/deadline checks",');
  let sealer=namespace(original.sealer,"sealer");
  sealer=change(sealer,"corrected unsealed adapter source",
    'ADAPTER_TEMPLATE_SHA = "b49b95b00f67b33b05b726527ee5f63766fe568f7fed6d372f32417d3f811189"',
    'ADAPTER_TEMPLATE_SHA = "ba2cd36aa4755888fe01be6a5e0487fb6bf6d7fb0d486618b046e2c166778740"');
  sealer=change(sealer,"ordinary initial verifier",
    'sources["ordinary/verify_ordinary_02.py"]','sources["ordinary/verify_ordinary_01.py"]');
  const parserPatch = [
    'def adapter_with_d2_parser(raw):',
    '    """Change only the inherited parser identity before the actual SPEC seal."""',
    '    old = b\'"summarize_trace.py": (15057, "f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5")\'',
    '    new = b\'"summarize_trace.py": (15070, "ca0e7e0d7c670daec20e54c6703bc1849f80138224570ef5366abd60079c7927")\'',
    '    need(raw.count(old) == 1 and raw.count(new) == 0, "original unsealed parser placeholder differs")',
    '    revised = raw.replace(old, new, 1)',
    '    need(revised.replace(new, old, 1) == raw, "parser-pin edit is not exactly reversible")',
    '    before, after = ast.parse(raw), ast.parse(revised)',
    '    def declaration(tree):',
    '        matches = [node for node in tree.body if isinstance(node, ast.Assign)',
    '                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)',
    '                   and node.targets[0].id == "REFERENCE"]',
    '        need(len(matches) == 1, "one literal adapter REFERENCE required")',
    '        return matches[0]',
    '    old_node, new_node = declaration(before), declaration(after)',
    '    expected = dict(ast.literal_eval(old_node.value))',
    '    expected["summarize_trace.py"] = (15070, "ca0e7e0d7c670daec20e54c6703bc1849f80138224570ef5366abd60079c7927")',
    '    need(ast.literal_eval(new_node.value) == expected, "another adapter reference changed")',
    '    new_node.value = old_node.value',
    '    need(ast.dump(before, include_attributes=False) == ast.dump(after, include_attributes=False),',
    '         "parser identity seal changed other adapter code")',
    '    return revised',
    '',
    '',
  ].join("\n");
  sealer=change(sealer,"parser-only adapter identity seal",'\ndef seal(args):','\n'+parserPatch+'def seal(args):');
  sealer=change(sealer,"parser identity then actual SPEC",
    'adapter = assignment(sources["run_c1_phase_cost.unsealed.py"], "SPEC", adapter_spec)',
    'adapter = assignment(adapter_with_d2_parser(sources["run_c1_phase_cost.unsealed.py"]), "SPEC", adapter_spec)');
  let installer=namespace(original.installer,"installer");
  installer=change(installer,"include exact correlation module",
    '    "c1-tools-01/reference/observation_resources.py",',
    '    "c1-tools-01/reference/correlate_trace.py",\n    "c1-tools-01/reference/observation_resources.py",');
  return {parent,sealer,installer,ledger};
}
deriveD2Outer;
