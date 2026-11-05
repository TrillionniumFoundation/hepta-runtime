// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Generate shared input data with the pinned original domain constructors.
// All behavioral observations are taken separately through actual MCP servers.
import {pathToFileURL} from 'node:url';
import {writeFileSync, mkdirSync, readFileSync} from 'node:fs';
import {join} from 'node:path';
const [reference, destination, captureFixture] = process.argv.slice(2);
const load = name => import(pathToFileURL(join(reference,'dist',name)).href);
const {createEvidence,parseEvidence} = await load('domain/evidence.js');
const {createEvidenceBundle,parseEvidenceBundle} = await load('domain/evidenceBundle.js');
const {createResidualUnknown,updateResidualUnknown,recordUnknownInputSchema,residualUnknownSchema} = await load('domain/residualUnknown.js');
const {digestCanonicalValue} = await load('domain/canonicalDigest.js');
mkdirSync(destination,{recursive:true});
const files = [];
const save = (name, value, valid=true) => {
  if (valid) parseEvidenceBundle(value);
  const text=JSON.stringify(value);
  writeFileSync(join(destination,name+'.json'),text);
  files.push({name,valid,bytes:Buffer.byteLength(text)});
  return value;
};
const provider={id:'import-contract-fixture',name:'Controlled Evidence data fixture',version:'1'};
const target={path:join(destination,'declared-artifact.bin'),sha256:'a'.repeat(64),format:'file',architecture:null};
const record = (operation, result, predicateType='rea.analysis') => createEvidence(target,provider,{
  operation,parameters:{z:1,a:{y:2,x:3}},result,predicateType,
  confidence:'observed',authority:'shipped-artifact',locations:[],evidenceLinks:[],limitations:[]});
const observed=record('import_fixture_observation',{z:1,a:{y:2,x:3},'3':'three','2':'two'});
const mutation1=record('record_unknown',{revision:1},'rea.residual-unknown-mutation');
const mutation2=record('update_unknown',{revision:2},'rea.residual-unknown-mutation');
const extra=record('import_fixture_extra',{additional:true});
const inputs={question:'Does the imported observation preserve its complete data?',severity:'medium',domain:'import-protocol',
  supporting_evidence_ids:[observed.evidence_id],contradicting_evidence_ids:[],required_authority:null,
  required_confidence:'observed',required_environment:null,recommended_probes:[{operation:'read-back',rationale:'Read complete retained data.'}],relationships:[]};
const first=createResidualUnknown(recordUnknownInputSchema.parse(inputs),mutation1.evidence_id,null);
const second=updateResidualUnknown(first,{...inputs,unknown_id:first.unknown_id,expected_revision:1,status:'investigating',severity:'high',resolution:null},mutation2.evidence_id);
const revision = (value,changes) => {
  const next={...structuredClone(value),...changes};
  delete next.revision_digest;
  next.revision_digest=digestCanonicalValue(next,'Unknown identity');
  return next;
};
const bundle=(records,unknowns=[])=>createEvidenceBundle(records,unknowns);
save('empty',bundle([]));
save('record',bundle([observed]));
const metadata=structuredClone(observed);
metadata.subject.name='replacement-display-name';metadata.subject.local_path=join(destination,'moved-display.bin');
metadata.caller_input_path=join(destination,'selected-alias.bin');
parseEvidence(metadata);
save('metadata',bundle([metadata]));
const reordered=structuredClone(metadata);
reordered.parameters={a:{x:3,y:2},z:1};
reordered.normalized_result={a:{x:3,y:2},z:1,'2':'two','3':'three'};
parseEvidence(reordered);
save('reordered-same-metadata',bundle([reordered]));
save('unknown-first',bundle([metadata,mutation1],[first]));
save('unknown-second',bundle([reordered,mutation1,mutation2],[first,second]));
const conflict=revision(first,{severity:'critical'});residualUnknownSchema.parse(conflict);
save('unknown-conflict',bundle([extra,mutation1,metadata],[conflict]));
const verified=updateResidualUnknown(second,{...inputs,unknown_id:first.unknown_id,expected_revision:2,status:'resolved',severity:'medium',resolution:{disposition:'verified',rationale:'A qualifying retained observation supports this conclusion.',evidence_ids:[observed.evidence_id]}},mutation2.evidence_id);
save('unknown-verified',bundle([metadata,mutation1,mutation2],[first,second,verified]));
save('duplicate-record',bundle([observed,observed]),false);
const manifest=bundle([observed]);manifest.providers=[];save('noncanonical-manifest',manifest,false);
const invalid=structuredClone(observed);invalid.normalized_result.z=99;save('record-id-mismatch',bundle([invalid]),false);
writeFileSync(join(destination,'single-record.json'),JSON.stringify(observed));files.push({name:'single-record',valid:false});
save('unknown-id-mismatch',bundle([observed,mutation1],[{...first,unknown_id:'unk_'+'0'.repeat(64)}]),false);
save('unknown-revision-digest',bundle([observed,mutation1],[{...first,revision_digest:'0'.repeat(64)}]),false);
save('unknown-history-gap',bundle([observed,mutation1,mutation2],[second]),false);
save('unknown-history-chain',bundle([observed,mutation1,mutation2],[first,revision(second,{previous_revision_digest:'0'.repeat(64)})]),false);
save('unknown-missing-evidence',bundle([observed,mutation1],[revision(first,{supporting_evidence_ids:['ev_'+'b'.repeat(64)]})]),false);
save('unknown-missing-related',bundle([observed,mutation1],[revision(first,{relationships:[{type:'related-to',unknown_id:'unk_'+'b'.repeat(64)}]})]),false);
save('unknown-empty-mutation',bundle([observed,mutation1],[revision(first,{mutation_evidence_ids:[]})]),false);
save('unknown-verified-mutation-only',bundle([observed,mutation1],[revision(first,{status:'resolved',supporting_evidence_ids:[mutation1.evidence_id],resolution:{disposition:'verified',rationale:'Only mutation data is supplied.',evidence_ids:[mutation1.evidence_id]}})]),false);
save('unknown-verified-contradiction',bundle([observed,mutation1,extra],[revision(first,{status:'resolved',contradicting_evidence_ids:[extra.evidence_id],resolution:{disposition:'verified',rationale:'Contradicting evidence remains.',evidence_ids:[observed.evidence_id]}})]),false);
const a=createResidualUnknown(recordUnknownInputSchema.parse({...inputs,question:'Cycle candidate A?'}),mutation1.evidence_id,null);
const b=createResidualUnknown(recordUnknownInputSchema.parse({...inputs,question:'Cycle candidate B?'}),mutation1.evidence_id,null);
const aCycle=revision(a,{relationships:[{type:'depends-on',unknown_id:b.unknown_id}]});
const bCycle=revision(b,{relationships:[{type:'depends-on',unknown_id:a.unknown_id}]});
save('unknown-cycle',bundle([observed,mutation1],[aCycle,bCycle]),false);
// Each candidate is valid alone. Their latest heads form a cycle only after
// merging A revision 2 with B revision 2 in an already populated session.
const aSecond=updateResidualUnknown(a,{...inputs,unknown_id:a.unknown_id,expected_revision:1,status:'open',resolution:null,relationships:[{type:'depends-on',unknown_id:b.unknown_id}]},mutation2.evidence_id);
const bSecond=updateResidualUnknown(b,{...inputs,unknown_id:b.unknown_id,expected_revision:1,status:'open',resolution:null,relationships:[{type:'depends-on',unknown_id:a.unknown_id}]},mutation2.evidence_id);
save('union-cycle-seed',bundle([observed,mutation1,mutation2],[a,aSecond,b]));
save('union-cycle-candidate',bundle([observed,mutation1,mutation2,extra],[a,b,bSecond]));
// Input trim is part of the original schema parser, not a semantic-ID rewrite.
const whitespace=structuredClone(first);whitespace.question='\ufeff '+first.question+' \t';whitespace.domain=' '+first.domain+' ';
whitespace.recommended_probes[0].rationale=' '+first.recommended_probes[0].rationale+' ';
save('unknown-schema-trim',bundle([observed,mutation1],[whitespace]));
// Schema objects strip only __proto__; arbitrary JSON retains that own key.
const ownProto=value=>Object.defineProperty(value,'__proto__',{value:{marker:'retained own data'},enumerable:true,writable:true,configurable:true});
const schemaProto=bundle([structuredClone(observed)]);
ownProto(schemaProto);ownProto(schemaProto.records[0]);ownProto(schemaProto.records[0].subject);ownProto(schemaProto.records[0].provider);ownProto(schemaProto.providers[0]);
save('proto-schema',schemaProto);
const jsonPayload=ownProto({z:1,a:2});const jsonParameters=ownProto({z:1,a:2});
const payloadProto=createEvidence(target,provider,{operation:'import_proto_payload',parameters:jsonParameters,result:jsonPayload,rawResult:jsonPayload});
save('proto-payload',bundle([payloadProto]));
const extras=bundle([observed]);extras.z=1;ownProto(extras);extras.a=2;save('proto-unknown-order',extras,false);
for (const key of ['constructor','toString']) {const value=bundle([observed]);value[key]='not an admitted manifest';save('proto-'+key,value,false);}
// Frozen Zod's minimum-length coercion throws on this own non-callable
// toString. Observe the public SDK's exact error without executing payloads.
const exceptionRecord=bundle([structuredClone(observed)]);exceptionRecord.records[0].operation={length:{toString:null}};
save('exception-record',exceptionRecord,false);
const exceptionUnknown=bundle([observed,mutation1],[structuredClone(first)]);exceptionUnknown.unknowns[0].question={length:{toString:null}};
save('exception-unknown',exceptionUnknown,false);
const exceptionBare=structuredClone(observed);exceptionBare.operation={length:{toString:null}};
save('exception-bare',exceptionBare,false);
const labelKeys=['quote"key','back\\slash','line\nbreak','tab\tkey','\0','中文😀'];
const multipleLabels=bundle([observed]);for(const key of labelKeys)multipleLabels[key]=1;
save('labels-multiple',multipleLabels,false);
const singleLabel=bundle([observed]);singleLabel[labelKeys[0]]=1;
save('labels-single',singleLabel,false);
if (captureFixture) {
  const {safeParseProcessCapture}=await load('domain/process/processCaptureParsing.js');
  const capture=JSON.parse(readFileSync(captureFixture,'utf8'));
  if(!safeParseProcessCapture(capture).success) throw new Error('Original process capture fixture is invalid');
  const captured=record('import_process_capture',capture,'rea.process-capture');
  save('capture-valid',bundle([captured]));
  const wrongId=structuredClone(captured);delete wrongId.normalized_result.manifest;
  save('capture-id-mismatch',bundle([wrongId]),false);
  const invalid=structuredClone(capture);delete invalid.manifest;
  const badCapture=record('import_process_capture',invalid,'rea.process-capture');
  save('capture-invalid-payload',bundle([badCapture]));
}
writeFileSync(join(destination,'invalid-json.json'),'{"artifacts":[');
writeFileSync(join(destination,'bom.json'),Buffer.concat([Buffer.from([239,187,191]),Buffer.from(JSON.stringify(bundle([])))]));
writeFileSync(join(destination,'invalid-utf8.json'),Buffer.from([255]));
writeFileSync(join(destination,'catalog.json'),JSON.stringify({files,label_keys:labelKeys,ids:{observed:observed.evidence_id,mutation1:mutation1.evidence_id,mutation2:mutation2.evidence_id,extra:extra.evidence_id,unknown:first.unknown_id},unknown_revisions:[first,second,verified]}));
console.log(JSON.stringify({files:files.length,ids:{observed:observed.evidence_id,unknown:first.unknown_id}}));
