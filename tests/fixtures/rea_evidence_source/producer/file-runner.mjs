
import {readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const request=JSON.parse(readFileSync(0,'utf8'));
const get=path=>import(pathToFileURL(request.root+'/dist/'+path).href);
const {createEvidenceBundle}=await get('domain/evidenceBundle.js');
const {createEvidence}=await get('domain/evidence.js');
const {readEvidenceFileSource}=await get('application/analysisView/evidenceFileSource.js');
const {projectAnalysisError}=await get('domain/analysisErrorProjection.js');
const [first,second]=request.records,one=createEvidenceBundle([first]),two=createEvidenceBundle([first,second]);
const absent='ev_'+'0'.repeat(64),cases=[];
const add=(name,input,selected)=>cases.push({name,input,...(selected===undefined?{}:{selected})});
add('one',one);add('one-selected',one,first.evidence_id);add('one-unavailable',one,absent);
add('empty',createEvidenceBundle([]));add('two',two);add('two-selected',two,first.evidence_id);add('two-unavailable',two,absent);
add('duplicate',{...one,records:[first,first]});
add('noncanonical-manifest',{...one,providers:[]});
add('noncanonical-order',{...two,records:[...two.records].reverse()});
const tampered=structuredClone(two);const changed=tampered.records.find(r=>r.evidence_id!==first.evidence_id);changed.normalized_result.owned_tampering=true;
add('tampered-unselected',tampered,first.evidence_id);
const bad=structuredClone(two);bad.records[1].provider.version=123;add('record-shape',bad,first.evidence_id);
add('bare',first);add('bare-selected',first,first.evidence_id);add('bare-unavailable',first,absent);
add('bare-tampered',{...first,evidence_id:absent});
add('records-discriminates',{...first,records:null});
const target={path:first.subject.local_path,sha256:first.subject.digest.sha256,format:first.subject.format};
const many=Array.from({length:40},(_,i)=>createEvidence(target,first.provider,{operation:'\u754c'.repeat(1000),parameters:{owned:i},result:{owned:i}}));
add('bounded-id-preview',createEvidenceBundle(many),absent);
const rows=[];
for(const row of cases){
 const path=request.out+'/'+row.name+'.json';
 const encoded=JSON.stringify(row.input);writeFileSync(path,encoded);
 const result=await readEvidenceFileSource(path,{},row.selected);
 rows.push({...row,path,expected:result.ok?{ok:true,evidence_id:result.value.evidence_id}:{ok:false,
 typed_error:Object.fromEntries(Object.entries(result.error).filter(([key])=>key!=='cause')),
 projected:projectAnalysisError(result.error)}});
}
writeFileSync(request.out+'/file-goldens.json',JSON.stringify({format:'hepta.evidence-file-source-original.v1',
 frozen_npm_tarball_sha256:'8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb',cases:rows},null,2)+'\n');
process.stdout.write(JSON.stringify({node:process.version,cases:rows.length,valid:rows.filter(r=>r.expected.ok).length})+'\n');
