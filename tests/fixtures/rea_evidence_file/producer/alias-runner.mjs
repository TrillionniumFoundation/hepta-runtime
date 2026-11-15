
import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const out=process.argv[2];
const request=JSON.parse(await fs.readFile(out+'/request.json','utf8'));
const {readJsonFile,readJsonFileWithSource}=await import(pathToFileURL(request.npm+'/dist/application/JsonFiles.js'));
const {readEvidenceFileSource}=await import(pathToFileURL(request.npm+'/dist/application/analysisView/evidenceFileSource.js'));
const {absoluteCallerPath}=await import(pathToFileURL(request.npm+'/dist/filesystem/callerPath.js'));
const {projectAnalysisError}=await import(pathToFileURL(request.npm+'/dist/domain/analysisErrorProjection.js'));
const cases=[];
for(const row of request.cases){
 const result=row.api==='select'?await readEvidenceFileSource(row.path,{},row.evidence_id):row.api==='read-with-source'?await readJsonFileWithSource(row.path,undefined,undefined,'inspect_analysis_view'):await readJsonFile(row.path,undefined,undefined,'inspect_analysis_view');
 const expected=result.ok?{ok:true,selected_path:result.value.path,evidence_id:result.value.data?.evidence_id}:{ok:false,typed_error:Object.fromEntries(Object.entries(result.error).filter(([k])=>k!=='cause')),projected:projectAnalysisError(result.error)};
 cases.push({...row,normalized_path:absoluteCallerPath(row.path),expected});
}
await fs.writeFile(out+'/goldens.json',JSON.stringify({format:'hepta.evidence-file-alias-original.v1',node:process.version,cases},null,2)+'\n');
console.log(JSON.stringify(cases));
