
import {readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const request=JSON.parse(readFileSync(0,'utf8'));
const get=path=>import(pathToFileURL(request.root+'/dist/'+path).href);
const {safeParseEvidence}=await get('domain/evidenceValidation.js');
const {projectInputIssues}=await get('domain/inputIssueProjection.js');
const {describeValidationFailure}=await get('domain/validationFailure.js');
const rows=[];
for(const row of request.cases){
 let value=structuredClone(request.seed);
 for(const change of row.changes){
  if(change.path.length===0){value=structuredClone(change.value);continue;}
  let object=value;for(const part of change.path.slice(0,-1))object=object[part];
  const key=change.path.at(-1);if(change.delete)delete object[key];else object[key]=structuredClone(change.value);
 }
 const result=safeParseEvidence(value);
 rows.push({...row,expected:result.ok?{ok:true}:{ok:false,issues:projectInputIssues(result.error.issues,value),
  raw_issues:result.error.issues,description:describeValidationFailure(result.error)}});
}
writeFileSync(process.argv[2],JSON.stringify({format:'hepta.evidence-source-schema-original.v1',seed:request.seed,
 frozen_npm_tarball_sha256:'8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb',cases:rows},null,2)+'\n');
process.stdout.write(JSON.stringify({node:process.version,cases:rows.length,valid:rows.filter(r=>r.expected.ok).length})+'\n');
