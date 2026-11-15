function buildD2C1Archive(source, sealer, knownPins) {
  const edits=[];
  function change(s,before,after,label,all=false) {
    const n=s.split(before).length-1;
    if((all && n<1)||(!all && n!==1))throw Error(label+": matches="+n);
    edits.push({label,matches:n,before,after});
    return all?s.split(before).join(after):s.replace(before,after);
  }
  function py(x) {
    if(x===null)return "None";
    if(x===true)return "True"; if(x===false)return "False";
    if(typeof x==="string")return JSON.stringify(x);
    if(typeof x==="number")return String(x);
    if(Array.isArray(x))return "["+x.map(py).join(", ")+"]";
    return "{"+Object.keys(x).sort().map(k=>py(k)+": "+py(x[k])).join(", ")+"}";
  }
  function assignment(s,name,value,label) {
    const lines=s.split("\n"), ix=lines.map((l,i)=>l.startsWith(name+" = ")?i:-1).filter(i=>i>=0);
    if(ix.length!==1)throw Error("assignment "+name);
    return change(s,lines[ix[0]],name+" = "+value,label);
  }
  const runtime=["c1-campaign-inputs-01.json","c1-prerequisites-01.json","c1-tools-01/d2_campaign.py","c1-tools-01/run_c1_phase_cost.py"];
  const core=["c1-holder-native-01.json","c1-holder-report-01.json","c1-holder-start-01.json","c1-parent-install-01.json","c1-campaign-01/report.json","c1-campaign-01/summary.json","c1-campaign-01/source-inputs.json","c1-campaign-01/baseline-source-inputs.json","c1-campaign-01/compiler-monitor.json","c1-campaign-01/compiler-monitor.audit.json","c1-observation-01/report.json","c1-observation-01/independent-summary.json","c1-adapter-evidence-01/adapter-report.json",...runtime];
  source=change(source,"original D1 C1 diagnostic capture","original D2 C1 diagnostic capture","doc version");
  source=change(source,"/home/qian/hepta-runtime-phase-cost-20261106-d1","/home/qian/hepta-runtime-validation-cost-20261106-d2","fixed root",true);
  source=change(source,"/Users/qianqi/work/hepta-runtime-d1-c1-holder-01","/Users/qianqi/work/hepta-runtime-d2-c1-holder-01","fixed Mac output");
  source=change(source,"hepta-d1-c1-","hepta-d2-c1-","C1 schema namespace",true);
  source=change(source,"c1-tools-01/d1_campaign.py","c1-tools-01/d2_campaign.py","runtime parent basename",true);
  source=assignment(source,"PINNED",py(knownPins),"fifteen fixed D2 source identities");
  source=assignment(source,"CORE_PATHS",py(core),"thirteen original result slots plus four future runtime source slots");
  source=change(source,"REQUIRED = sorted(PINNED)","REQUIRED = sorted(PINNED)\nRUNTIME_PATHS = "+py(runtime)+"\nCHANGED_PATHS = {'src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/ssh_observation_profile.rs'}","fixed runtime and two-source sets");
  source=assignment(source,"SOURCE_REFERENCE_SHA256",py("7ac7eaf9a5861d5a4cd7e7fe16ebcedab4996551f0ada79a1a3cfb2066495bcc"),"exact original C1 collector ancestry");
  source=assignment(source,"EXTERNAL_EVIDENCE_REFERENCES",py({
    qualification_archive:null,exact_ci_collection_or_archive:null,ordinary_archive:null,
    current_full_prerequisite_document:"/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-prerequisites-01.json",
    scope:"Current full Q/CI prerequisite bytes and original parent ordinary proof are retained. Separate complete prerequisite collections remain external; no future archive hash is invented and no prerequisite body is revalidated or executed here."
  }),"do not inherit D1 prerequisite archive identities");
  source=assignment(source,"ACTUAL","None","unsealed actual result");
  source=change(source,"need(all(files[name] is not None for name in ['c1-holder-native-01.json', *pages]),\n         'actual original holder terminal and stored native pages are mandatory')",
    "need(all(files[name] is not None for name in ['c1-holder-native-01.json', *pages, *RUNTIME_PATHS]),\n         'actual original holder terminal/pages and installed runtime sources are mandatory')","bind real future runtime source bytes in every outcome");
  const newBinding=`
    installed = documents.get('c1-parent-install-01.json')
    inputs = documents.get('c1-campaign-inputs-01.json')
    prerequisites = documents.get('c1-prerequisites-01.json')
    runtime_sources = {}
    def runtime_binding():
        need(installed is not None and inputs is not None and prerequisites is not None,
             'original installed runtime intent receipts are incomplete')
        need(installed['schema'] == 'hepta-d2-c1-source-install/v1' and installed['target'] == 'x230'
             and installed['installed'] is True and installed['campaign_started'] is False
             and installed['source_or_test_execution'] is False and installed['automatic_retries'] == 0
             and installed['cleanup_or_overwrite_performed'] is False,
             'original source-only installation scope differs')
        expected = set(PINNED) | set(RUNTIME_PATHS)
        rows = installed['files']
        need(type(rows) is list and installed['file_count'] == len(rows) == len(expected) == 19
             and {Path(row['path']).relative_to(ROOT).as_posix() for row in rows} == expected
             and sum(row['bytes'] for row in rows) == installed['payload_bytes'],
             'original nineteen-file runtime installation inventory differs')
        for pin in rows:
            match_original(data, pin)
        need(inputs['schema'] == 'hepta-d2-c1-campaign-inputs/v1' and inputs['sealed'] is True
             and inputs['attempt'] == '01'
             and inputs['launcher_sha256'] == sha(data['c1-tools-01/d2_campaign.py']),
             'original C1 campaign input scope differs')
        need(inputs['prerequisites'] == archived_identity(data, 'c1-prerequisites-01.json')
             and inputs['qualification_binder'] == archived_identity(data, 'c1-tools-01/d2_prerequisites.py')
             and inputs['adapter'] == archived_identity(data, 'c1-tools-01/run_c1_phase_cost.py'),
             'original campaign core identity differs')
        need(prerequisites['schema'] == 'hepta-d2-c1-prerequisites/v1'
             and prerequisites['qualification_sealed'] is True and prerequisites['exact_ci_sealed'] is True,
             'original full prerequisite declaration differs')
        canonical = prerequisites['prerequisite_module']
        need(canonical == {'path': str(ROOT / 'full-prerequisites-01/d2_prerequisites.py'),
             **PINNED['c1-tools-01/d2_prerequisites.py']},
             'original canonical D2 module identity differs')
        runtime_sources.update({name: archived_identity(data, name) for name in RUNTIME_PATHS})
    checked('original installed runtime intent and source identities', runtime_binding)
`;
  source=change(source,"    stages, closures, traces, holder_logs = [], [], [], []\n","    stages, closures, traces, holder_logs = [], [], [], []\n"+newBinding,"bind captured actual four runtime source files to original installation");
  source=change(source,"and len(adapted['traces']) == len(adapted['bindings']) == 8,\n",
    "and len(adapted['traces']) == len(adapted['bindings']) == 8\n                     and adapted['strict_on_request_bijection_count'] == 468\n                     and adapted['measured_on_request_count'] == 384\n                     and adapted['validation_whole_cost_field'] == 'inclusive CPU of validation_worker and validation_owner',\n","reconcile original D2 correlation declarations");
  source=change(source,"and diagnostic['counts'] == counts, 'original diagnostic summary differs')",
    "and diagnostic['counts'] == counts\n                     and diagnostic['on_trace_request_bijection_count'] == 468\n                     and diagnostic['on_measured_request_count'] == 384\n                     and diagnostic['validation_whole_cost_field'] == 'inclusive CPU of validation_worker and validation_owner',\n                     'original diagnostic summary differs')","reconcile D2 diagnostic summary fields");
  source=change(source,"and baseline['file_count'] == 220 and len(source['files']) == 222\n                 and len(baseline['files']) == 220,\n",
    "and baseline['file_count'] == 222 and len(source['files']) == 222\n                 and len(baseline['files']) == 222\n                 and source['root'] == str(ROOT / 'source')\n                 and baseline['root'] == '/home/qian/hepta-runtime-phase-cost-20261106-d1/source'\n                 and set(source['files']) == set(baseline['files'])\n                 and {name for name in source['files'] if source['files'][name] != baseline['files'][name]} == CHANGED_PATHS,\n","qualified D1 to D2 snapshot shape");
  source=change(source,"        'external_prerequisite_references': EXTERNAL_EVIDENCE_REFERENCES,",
    "        'original_installed_runtime_sources': runtime_sources,\n        'reported_strict_on_request_bijection_count': None if adapted is None else adapted.get('strict_on_request_bijection_count'),\n        'reported_on_measured_request_count': None if adapted is None else adapted.get('measured_on_request_count'),\n        'reported_validation_whole_cost_field': None if adapted is None else adapted.get('validation_whole_cost_field'),\n        'external_prerequisite_references': EXTERNAL_EVIDENCE_REFERENCES,","retain actual correlation scope without recomputation");
  sealer=change(sealer,"hepta-d1-c1-","hepta-d2-c1-","sealer schema namespace",true);
  sealer=change(sealer,"archive_d1_c1.py","archive_d2_c1.py","sealed output basename");
  sealer=assignment(sealer,"CORE_PATHS",py(core),"same seventeen actual core slots");
  sealer=change(sealer,"def need(value, reason):","RUNTIME_PATHS = "+py(runtime)+"\n\n\ndef need(value, reason):","same future source slots");
  sealer=change(sealer,"    pages = load_pages(originals, 'c1-holder-native-read-01-', snapshots, data, True)\n",
    "    need(all(name in data for name in RUNTIME_PATHS),\n         'actual installed parent/adapter/campaign-input/full-prerequisite originals are required')\n    pages = load_pages(originals, 'c1-holder-native-read-01-', snapshots, data, True)\n","require actual runtime mirror instead of predicted hashes");
  return {collector:source,sealer,edits,core,runtime};
}

function finalizeTemplatePin(result, sha256Utf8) {
  const before = "TEMPLATE_SHA256 = '5018c7bc509e965fc96206f10a2e582309193d93366be079c1b9681bba6cfd98'";
  if (result.sealer.split(before).length !== 2) throw Error("one original template pin required");
  result.sealer = result.sealer.replace(before, "TEMPLATE_SHA256 = '" + sha256Utf8(result.collector) + "'");
  return result;
}
