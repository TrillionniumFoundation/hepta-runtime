
import fs from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const out = process.argv[2];
const request = JSON.parse(await fs.readFile(out+'/request.json','utf8'));
const {readJsonFile}=await import(pathToFileURL(request.npm+'/dist/application/JsonFiles.js'));
const {projectAnalysisError}=await import(pathToFileURL(request.npm+'/dist/domain/analysisErrorProjection.js'));
const cases=[];
function classify(value){
 let nonfinite=false,lone=false;
 const stack=[value];
 while(stack.length){
  const v=stack.pop();
  if(typeof v==='number'&&!Number.isFinite(v))nonfinite=true;
  if(typeof v==='string'){
   for(let i=0;i<v.length;i++){let c=v.charCodeAt(i);if(c>=0xd800&&c<=0xdbff){const d=v.charCodeAt(i+1);if(!(d>=0xdc00&&d<=0xdfff))lone=true;else i++;}else if(c>=0xdc00&&c<=0xdfff)lone=true;}
  }else if(Array.isArray(v))stack.push(...v);
  else if(v&&typeof v==='object')for(const key of Object.keys(v)){stack.push(key,v[key]);}
 }
 return {nonfinite,lone_surrogate:lone};
}
function order(value,path=[],rows=[]){
 if(Array.isArray(value)){for(let i=0;i<value.length;i++)order(value[i],[...path,i],rows);}
 else if(value&&typeof value==='object'){rows.push({path,keys:Object.keys(value)});for(const k of Object.keys(value))order(value[k],[...path,k],rows);}
 return rows;
}
for(const item of request.cases){
 const result=await readJsonFile(item.path,undefined,undefined,'inspect_analysis_view');
 let expected;
 if(result.ok){
  const encoded=JSON.stringify(result.value);
  expected={ok:true,json_sha256:createHash('sha256').update(encoded).digest('hex'),json_bytes:Buffer.byteLength(encoded),...classify(result.value),object_order:order(result.value)};
  if(encoded.length<65536)expected.json_text=encoded;
 }else{
  expected={ok:false,typed_error:Object.fromEntries(Object.entries(result.error).filter(([k])=>k!=='cause')),projected:projectAnalysisError(result.error)};
 }
 cases.push({...item,expected});
}
await fs.writeFile(out+'/goldens.json',JSON.stringify({format:'hepta.evidence-json-file-reference.v1',node:process.version,cases},null,2)+'\n');
console.log(JSON.stringify({cases:cases.length,valid:cases.filter(c=>c.expected.ok).length,node:process.version}));
