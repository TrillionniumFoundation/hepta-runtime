#!/usr/bin/env node
// Copyright 2026 TrillionniumFoundation. Apache-2.0.
// Real Babel/gen-mapping production and fixed REA function observations only.
// The authored sources and source-map URLs are parsed as inert data, never executed.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';

const [reaPackage, oracleProject] = process.argv.slice(2);
assert.ok(reaPackage && oracleProject, 'expected fixed REA_PACKAGE ORACLE_PROJECT');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const pin = file => { const bytes=fs.readFileSync(file); return {path:file,bytes:bytes.length,sha256:sha(bytes)}; };
const originalFiles = {
  trace: path.join(reaPackage,'dist/javascript/sourceMaps/TraceSourceMap.js'),
  offset: path.join(reaPackage,'dist/domain/webSourcePosition.js'),
  package: path.join(reaPackage,'package.json'),
};
const original = Object.fromEntries(Object.entries(originalFiles).map(([name,file])=>[name,pin(file)]));
assert.equal(original.trace.sha256,'2bf3b1e6d022bffc2e931133275846188141ffa6bd6e5b636c24d54225986ea1');
assert.equal(original.offset.sha256,'85450f73f3c9e4ffe9484dc5709b0fbe8a00c5f368380d7d47578a2063caa77b');
assert.equal(original.package.sha256,'b0fc212f6bea9b4ee6e2b3ab0b52dd95402c229da3b8652127e5f131c3445b39');
const {traceSourceMap}=await import(pathToFileURL(originalFiles.trace));
const {webSourceOffset}=await import(pathToFileURL(originalFiles.offset));
const req=createRequire(path.resolve(oracleProject,'package.json'));
const gen=req('@jridgewell/gen-mapping');
const trace=req('@jridgewell/trace-mapping');
const parser=await import(pathToFileURL(req.resolve('@babel/parser')));
const generator=await import(pathToFileURL(req.resolve('@babel/generator')));
const versions={};
for(const name of ['@jridgewell/trace-mapping','@jridgewell/gen-mapping','@babel/parser','@babel/generator'])
  versions[name]=JSON.parse(fs.readFileSync(path.join(oracleProject,'node_modules',name,'package.json'),'utf8')).version;
assert.deepEqual(versions,{'@jridgewell/trace-mapping':'0.3.31','@jridgewell/gen-mapping':'0.4.0-beta.0','@babel/parser':'8.0.6','@babel/generator':'8.1.0'});
const maps=[];
function addMap(id,map,queries,producer,native='exact',extra={}) {
  maps.push({id,text:typeof map==='string'?map:JSON.stringify(map),queries,producer,native,...extra});
}
function generated(id,content,positions,options={}) {
  const mapping=new gen.GenMapping({file:id+'.generated.js'});
  const source=options.source??id+'.original.js';
  if(content!==undefined)gen.setSourceContent(mapping,source,content);
  positions.forEach((p,i)=>gen.addSegment(mapping,0,i*2,source,p.line-1,p.column));
  const map=gen.toEncodedMap(mapping);
  if(options.omitContent)delete map.sourcesContent;
  if(options.nullContent)map.sourcesContent=null;
  if(options.nullSource)map.sources=[null];
  const queries=positions.map((_,i)=>({line:1,column:i*2}));
  addMap(id,map,queries,'@jridgewell/gen-mapping 0.4.0-beta.0'+(options.mutation?' with '+options.mutation:''),options.native??'exact');
  return map;
}
const positions=(line,columns)=>columns.map(column=>({line,column}));
generated('ascii','abc',[...positions(1,[0,3,4]),{line:2,column:0}]);
generated('empty','',[...positions(1,[0,1]),{line:2,column:0}]);
generated('missing',undefined,[{line:1,column:0},{line:8,column:9}],{omitContent:true,mutation:'omitted sourcesContent'});
generated('null-content',null,[{line:1,column:0},{line:2,column:0}]);
generated('null-content-array',undefined,[{line:1,column:0}],{nullContent:true,mutation:'null sourcesContent member'});
generated('web-line-breaks','a\r\nb\rc\nd\u2028e\u2029',[
  ...[1,2,3,4,5].flatMap(line=>positions(line,[0,1,2])),
  ...positions(6,[0,1]),{line:7,column:0}]);
generated('astral','a🔥é',positions(1,[0,1,2,3,4,5]));
generated('astral-lines','🔥\r\nx😀\n',[...positions(1,[0,1,2,3]),...positions(2,[0,1,2,3,4]),...positions(3,[0,1]),{line:4,column:0}]);
generated('non-web-next-line','a\u0085b',[...positions(1,[0,1,2,3,4]),{line:2,column:0}]);
generated('consecutive-breaks','\r\n\n\r\u2028\u2029',[...[1,2,3,4,5,6].flatMap(line=>positions(line,[0,1])),{line:7,column:0}]);
generated('null-source-name','z',[{line:1,column:1}],{nullSource:true,mutation:'null source declaration'});
generated('huge-original-line','x',[{line:1000000,column:0},{line:1,column:1000000}]);
const coincident=new gen.GenMapping({file:'coincident.generated.js'});
gen.setSourceContent(coincident,'a.js','🔥');gen.setSourceContent(coincident,'b.js','');
gen.addSegment(coincident,0,0,'a.js',0,1);gen.addSegment(coincident,0,2,'b.js',0,0);
const coincidentMap=gen.toEncodedMap(coincident);
coincidentMap.mappings='AAAC,ACAD';
addMap('coincident',coincidentMap,[{line:1,column:0},{line:1,column:1},{line:2,column:0}],
  'gen-mapping declarations with independently authored coincident VLQ');
const nestedLeaf=new gen.GenMapping({file:'nested.generated.js'});
gen.setSourceContent(nestedLeaf,'nested.js','tail\r\n🔥');
gen.addSegment(nestedLeaf,0,0,'nested.js',0,4);gen.addSegment(nestedLeaf,0,2,'nested.js',1,1);
addMap('nested-index',{version:3,sections:[{offset:{line:2,column:9},map:{version:3,sections:[
  {offset:{line:1,column:3},map:gen.toEncodedMap(nestedLeaf)}]}}]},
  [{line:4,column:3},{line:4,column:5},{line:5,column:0}],
  'gen-mapping leaf with independently authored nested section offsets');
const babelSource='export const flame = "🔥";\r\n// café\u2028export function add(v) { return v + flame.length; }\u2029';
for(const compact of [false,true]) {
  const ast=parser.parse(babelSource,{sourceType:'module',sourceFilename:'babel-original.js'});
  const result=generator.default(ast,{sourceMaps:true,sourceFileName:'babel-original.js',compact},babelSource);
  const rows=trace.decodedMappings(new trace.TraceMap(result.map));
  const coordinates=rows.flatMap((segments,line)=>segments.map(segment=>({line:line+1,column:segment[0]})));
  const unique=new Map(coordinates.map(position=>[JSON.stringify(position),position]));
  const queries=Array.from(unique.values());
  assert.ok(queries.length>0&&queries.length<80);
  addMap(compact?'babel-compact':'babel-readable',result.map,queries,'@babel/parser 8.0.6 + @babel/generator 8.1.0',
    'exact',{authored_source:babelSource,generated_text:result.code,generated_text_executed:false});
}
const simple={version:3,sources:['source.js'],sourcesContent:['x'],names:[],mappings:'AAAA'};
const bad=[
  ['unterminated-vlq',{...simple,mappings:'g'}],
  ['source-index-outside',{...simple,mappings:'ACAA'}],
  ['wrong-version',{...simple,version:4}],
  ['nontext-content',{...simple,sourcesContent:[12]}],
  ['malformed-json-suffix',JSON.stringify(simple)+'!'],
  ['malformed-unicode-escape','{"version":3,"sources":["s"],"sourcesContent":["\\uQ000"],"names":[],"mappings":"AAAA"}'],
];
for(const [id,map] of bad)addMap(id,map,[{line:1,column:0}],'independently damaged generated map','refuse');
for(const [id,content] of [['lone-high','\ud800'],['lone-low','\udc00'],['reversed-surrogates','\udc00\ud800']])
  generated(id,content,[{line:1,column:0},{line:1,column:1}],{native:'profile-gap'});
const escaped={...simple,sourcesContent:['🔥'],mappings:'AAAC'};
addMap('escaped-valid-pair',JSON.stringify(escaped).replace('🔥','\\ud83d\\udd25'),
  [{line:1,column:0}],'JSON escape mutation of valid generated-map shape');
const cases=[];
for(const map of maps) {
  for(const [index,position] of map.queries.entries()) {
    const row={id:map.id+'-'+String(index).padStart(2,'0'),map_id:map.id,producer:map.producer,
      map_text:map.text,map_sha256:sha(Buffer.from(map.text)),generated_position:position,
      native_admission:map.native,generated_text_executed:false};
    try {
      const result=traceSourceMap(map.text,'https://source-map.invalid/assets/generated.js.map',position);
      row.reference_status='ok';
      row.reference_json=JSON.stringify(result);
      row.reference_sha256=sha(Buffer.from(row.reference_json));
      row.reference_projection={matched_generated_position:result.lookup.matched_generated_position,
        matches:result.matches.map(match=>match.state==='mapped'?{
          mapped:true,source_index:match.flattened_source_index,source:match.reported_source,root:match.reported_source_root,
          line:match.original_position.line,column:match.original_position.column,
          offset:match.original_position.offset,content_position:match.original_position.content_position,
          ignored:match.ignored,name:match.name,section:match.section_path,
          content_present:match.content.state==='embedded',
          content_sha256:match.content.state==='embedded'?match.content.utf8_sha256:null,
          content_bytes:match.content.state==='embedded'?match.content.utf8_bytes:null,
        }:{mapped:false})};
    } catch(error) {
      row.reference_status='error';
      row.reference_json=JSON.stringify({name:error.name,message:error.message,kind:error.kind??null,stack:error.stack??null});
      row.reference_sha256=sha(Buffer.from(row.reference_json));
    }
    process.stdout.write(JSON.stringify({event:'case',case:row})+'\n');
    cases.push(row);
    assert.equal(row.reference_status,map.native==='refuse'?'error':'ok',row.id+' original outcome');
  }
}
const directInputs=[
  ['empty','',{line:1,column:0}],
  ['empty-outside','',{line:1,column:1}],
  ['pair-middle','🔥',{line:1,column:1}],
  ['pair-end','🔥',{line:1,column:2}],
  ['pair-outside','🔥',{line:1,column:3}],
  ['after-crlf','a\r\n🔥',{line:2,column:1}],
  ['trailing-empty','x\n',{line:2,column:0}],
  ['line-zero','x',{line:0,column:0}],
  ['negative-column','x',{line:1,column:-1}],
  ['fractional-column','x',{line:1,column:0.5}],
  ['unsafe-line','x',{line:9007199254740992,column:0}],
];
const direct=directInputs.map(([id,text,position])=>{
  const offset=webSourceOffset(text,position);
  return {id,text_json:JSON.stringify(text),position,offset:offset??null,defined:offset!==undefined,
    source:'fixed original webSourceOffset'};
});
const sourceChecks=Object.fromEntries(Object.entries(originalFiles).map(([name,file])=>[name,pin(file)]));
assert.deepEqual(sourceChecks,original);
const counts={
  maps:maps.length,cases:cases.length,
  exact:cases.filter(row=>row.native_admission==='exact').length,
  refused:cases.filter(row=>row.native_admission==='refuse').length,
  explicit_profile_gaps:cases.filter(row=>row.native_admission==='profile-gap').length,
  direct_offsets:direct.length
};
assert.ok(counts.exact>=80&&counts.refused===6&&counts.explicit_profile_gaps===6);
const result={
  schema:'hepta.rea.source-map-content-position-original.v1',
  scope:'Real fixed REA traceSourceMap/webSourceOffset function observations and real Babel/gen-mapping production; native comparison is pending. No public MCP, browser, network acquisition or complete Evidence qualification.',
  producer:{script:pin(new URL(import.meta.url).pathname),node:{...pin(process.execPath),version:process.version},versions,
    fixed_original:original,source_inputs_unchanged:true},
  counts,
  authored_sources:maps.filter(row=>row.authored_source!==undefined).map(row=>({id:row.id,authored_source:row.authored_source,
    generated_text:row.generated_text,generated_text_executed:false})),
  cases,direct_offsets:direct,
  native_started:false,authored_source_executed:false,source_urls_fetched:false
};
process.stdout.write(JSON.stringify({event:'fixture',fixture:result})+'\n');
