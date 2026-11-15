
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const out=process.argv[2];
const request=JSON.parse(await fs.readFile(out+'/request.json','utf8'));
const {readJsonFile}=await import(pathToFileURL(request.npm+'/dist/application/JsonFiles.js'));
const {projectAnalysisError}=await import(pathToFileURL(request.npm+'/dist/domain/analysisErrorProjection.js'));
const cases=[];
for(const row of request.cases){
 const result=await readJsonFile(row.path,undefined,undefined,'inspect_analysis_view');
 cases.push({...row,expected:result.ok?{ok:true}:{ok:false,typed_error:Object.fromEntries(Object.entries(result.error).filter(([k])=>k!=='cause')),projected:projectAnalysisError(result.error)}});
}
await fs.writeFile(out+'/goldens.json',JSON.stringify({format:'hepta.evidence-file-access-original.v1',node:process.version,uid:process.getuid(),cases},null,2)+'\n');
console.log(JSON.stringify(cases.map(c=>({name:c.name,expected:c.expected}))));
