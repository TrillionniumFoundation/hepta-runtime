// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
// Pure source transformation. Inputs must be the pinned original texts and identities.
function buildD2OrdinaryArchive(input) {
  const ledger = {collector:[],sealer:[]};
  function one(s,a,b,key,label) { if(s.split(a).length!==2) throw Error(label+" unique count"); ledger[key].push({label,before:a,after:b,occurrences:1,offsets:[s.indexOf(a)]}); return s.replace(a,b); }
  function all(s,a,b,key,label) { const n=s.split(a).length-1; if(n<1)throw Error(label+" absent");const offsets=[];let offset=0;while((offset=s.indexOf(a,offset))>=0){offsets.push(offset);offset+=a.length;}ledger[key].push({label,before:a,after:b,occurrences:n,offsets});return s.split(a).join(b); }
  function line(s,prefix,value,key,label){const rows=s.split("\n").filter(x=>x.startsWith(prefix));if(rows.length!==1)throw Error(label+" line count");return one(s,rows[0],prefix+value,key,label);}
  const core01 = JSON.parse(input.collector.match(/^CORE_PATHS = (.+)$/m)[1]).map(x=>x.replaceAll("-02","-01"));
  let c=input.collector;
  c=one(c,"bounded D1 ordinary supplement","bounded D2 ordinary supplement","collector","doc namespace");
  c=one(c,"/home/qian/hepta-runtime-phase-cost-20261106-d1",input.root,"collector","fixed root");
  c=line(c,"PINNED = ",JSON.stringify(input.pinned),"collector","current twelve fixed sources");
  c=line(c,"CORE_PATHS = ",JSON.stringify(core01),"collector","first attempt core names");
  c=line(c,"EXPECTED_JOB_ID = ","'"+input.job+"'","collector","actual first ordinary launch identity");
  c=line(c,"SOURCE_REFERENCE_SHA256 = ","'"+input.collectorSHA+"'","collector","direct D1 ordinary reference");
  c=line(c,"EXTERNAL_EVIDENCE_REFERENCES = ",input.externalPython,"collector","D2 actual prerequisite references only");
  const start=c.indexOf("def prior_failure_summary(data):\n"),end=c.indexOf("def compressed_case_inventory(",start);
  if(start<0||end<0)throw Error("failure function span");
  c=one(c,c.slice(start,end),"","collector","drop foreign prior-failure function");
  const ps=c.indexOf("    prior = postflight['prior_preflight_failure']\n"),pe=c.indexOf("    post_terminal, post_streams = captured_native(",ps);
  if(ps<0||pe<0)throw Error("success failure chain span");
  c=one(c,c.slice(ps,pe),"","collector","drop foreign prior-failure success requirement");
  c=one(c,"    prior = prior_failure_summary(data)\n","","collector","drop foreign summary call");
  c=one(c,"prior_preflight_failure=prior, external_evidence_references=","external_evidence_references=","collector","drop foreign summary field");
  c=one(c,"'1a1aff8769c-fc05-6d26'","'"+input.qJob+"'","collector","actual D2 Q job");
  c=one(c,"'1a1b0238605-fc05-6e78'","'"+input.ciJob+"'","collector","actual D2 exact CI job");
  c=one(c,"'ordinary-evidence-02-01'","'ordinary-evidence-01'","collector","create-only first output namespace");
  c=one(c,"frozen ordinary preparation or prior failure differs","frozen ordinary preparation differs","collector","message scope");
  const pathBases=["ordinary-native-read","ordinary-postflight-native-read","ordinary-postflight-native","ordinary-native","ordinary-plan","ordinary-verification-input","ordinary-postflight","ordinary-installation-started","ordinary-installation"];
  for(const prefix of pathBases) if(c.includes(prefix+"-02"))c=all(c,prefix+"-02",prefix+"-01","collector",prefix+" first namespace");
  c=all(c,"ordinary-02","ordinary-01","collector","first ordinary output directory");
  c=all(c,"ordinary02 supplement","ordinary01 supplement","collector","first attempt messages");
  c=all(c,"hepta-d1-ordinary-","hepta-d2-ordinary-","collector","ordinary schema namespace");
  const schemas=[...new Set((c.match(/hepta-d2-ordinary-[a-z-]+\/v3/g)||[]))];
  for(const schema of schemas)c=all(c,schema,schema.replace("/v3","/v1"),"collector",schema+" first schema");
  if(c.includes("prior_preflight")||c.includes("ordinary-preflight-failure")||c.includes("ordinary-tools-02")||c.includes("full-prerequisites-03")||c.includes("1a1b03a9d15")||!c.includes("ACTUAL = None\n"))throw Error("old chain/unsealed mismatch");
  let s=input.sealer;
  s=line(s,"TEMPLATE_SHA256 = ","'"+input.sha256(c)+"'","sealer","new unsealed collector pin");
  s=line(s,"EXPECTED_JOB_ID = ","'"+input.job+"'","sealer","actual first ordinary launch identity");
  s=line(s,"CORE_PATHS = ",JSON.stringify(core01),"sealer","first attempt core names");
  for(const prefix of pathBases) if(s.includes(prefix+"-02"))s=all(s,prefix+"-02",prefix+"-01","sealer",prefix+" first namespace");
  s=all(s,"ordinary-02","ordinary-01","sealer","first ordinary output directory");
  s=all(s,"hepta-d1-ordinary-","hepta-d2-ordinary-","sealer","ordinary schema namespace");
  s=all(s,"hepta-d2-ordinary-supplement-postflight/v3","hepta-d2-ordinary-supplement-postflight/v1","sealer","first postflight schema");
  s=one(s,"archive_d1_ordinary.py","archive_d2_ordinary.py","sealer","sealed collector filename");
  return {collector:c,sealer:s,ledger,core:core01};
}
