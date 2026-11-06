#!/usr/bin/env node
// Copyright 2026 TrillionniumFoundation. Apache-2.0.
// Independent Babel-generated maps and trace-mapping decoding/position oracle.
// Usage: node SCRIPT ORACLE_NODE_PROJECT RUNTIME_BINARY OUTPUT_DIRECTORY
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const [oracleProject, runtime, outputDirectory] = process.argv.slice(2);
if (![oracleProject,runtime,outputDirectory].every(Boolean)) throw Error('expected ORACLE_NODE_PROJECT RUNTIME_BINARY OUTPUT_DIRECTORY');
const root=path.resolve(outputDirectory);
fs.mkdirSync(root,{recursive:false,mode:0o700});
const req=createRequire(path.resolve(oracleProject,'package.json'));
const trace=req('@jridgewell/trace-mapping');
const gen=req('@jridgewell/gen-mapping');
const parser=await import(pathToFileURL(req.resolve('@babel/parser')));
const generator=await import(pathToFileURL(req.resolve('@babel/generator')));
const versions={};
for(const name of ['@jridgewell/trace-mapping','@jridgewell/gen-mapping','@babel/parser','@babel/generator']) {
 versions[name]=JSON.parse(fs.readFileSync(path.join(oracleProject,'node_modules',name,'package.json'),'utf8')).version;
}
assert.deepEqual(versions,{'@jridgewell/trace-mapping':'0.3.31','@jridgewell/gen-mapping':'0.4.0-beta.0','@babel/parser':'8.0.6','@babel/generator':'8.1.0'});
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const source='export function twice(input) {\n  const text = "🔥"; return input * 2 + text.length;\n}\nconst branch = flag => flag ? twice(3) : 0;\n';
const fixtures=[];
for(const compact of [false,true]) {
 const ast=parser.parse(source,{sourceType:'module',sourceFilename:'original.js'});
 const result=generator.default(ast,{sourceMaps:true,sourceFileName:'original.js',compact},source);
 fixtures.push({name:compact?'babel-compact':'babel-readable',map:result.map,generated:result.code});
}
const authored=new gen.GenMapping({file:'generated.js',sourceRoot:'declared-root'});
gen.setSourceContent(authored,'alpha.js','const value="🔥"; export { value };\n');
gen.setSourceContent(authored,'empty.js','');
gen.addSegment(authored,0,3,'alpha.js',0,0,'value');
gen.addSegment(authored,0,7);
gen.addSegment(authored,0,12,'alpha.js',0,17);
gen.addSegment(authored,2,0,'empty.js',0,0);
fixtures.push({name:'gen-mapping-unmapped-empty',map:gen.toEncodedMap(authored)});
fixtures.push({name:'negative-delta-coincident',map:{version:3,sources:['a.js','b.js'],names:[],mappings:'KAAA,LCAA,ADAA;AACA'}});
fixtures.push({name:'unknown-sources',map:{version:3,sources:[null,'missing.js'],sourcesContent:[null,null],names:[],mappings:'AAAA,CCAA'}});
fixtures.push({name:'empty-map',map:{version:3,sources:[],names:[],mappings:''}});
const leaf=(name,mappings)=>({version:3,sources:[name],names:[],mappings});
fixtures.push({name:'indexed-offsets',map:{version:3,sections:[
 {offset:{line:2,column:7},map:leaf('one.js','AAAA;AACA')},
 {offset:{line:5,column:3},map:leaf('two.js','CAAA;AACA')}
]}});
fixtures.push({name:'nested-index',map:{version:3,sections:[{offset:{line:2,column:9},map:{version:3,sections:[
 {offset:{line:1,column:3},map:leaf('nested.js','CAAA;AACA')}
]}}]},referenceMap:{version:3,sections:[{offset:{line:3,column:3},map:leaf('nested.js','CAAA;AACA')}]}});

let callCount=0;
const native=(text,overrides={})=>{
 const input=JSON.stringify({text,expected_analysis_sha256:null,collection:'mappings',offset:0,limit:256,generated_position:null,...overrides});
 const run=spawnSync(runtime,['rea-source-map-worker'],{input,encoding:'utf8',env:{},cwd:'/',timeout:25000,maxBuffer:2*1024*1024});
 callCount++;
 if(run.error) throw run.error;
 assert.equal(run.status,0,run.stderr);
 return JSON.parse(run.stdout);
};
const compactRow=row=>({line:row.generated.line,column:row.generated.column,
 source:row.original?.source??null,originalLine:row.original?.line??null,
 originalColumn:row.original?.column??null,name:row.original?.name??null,
 mapped:row.mapped});
const referenceRows=reference=>{
 const rows=[];
 trace.decodedMappings(reference).forEach((line,lineIndex)=>line.forEach(segment=>rows.push({
  line:lineIndex+1,column:segment[0],source:segment.length>=4?reference.sources[segment[1]]:null,
  originalLine:segment.length>=4?segment[2]+1:null,originalColumn:segment.length>=4?segment[3]:null,
  name:segment.length===5?reference.names[segment[4]]:null,mapped:segment.length>=4
 })));
 return rows;
};
const results=[];
for(const fixture of fixtures) {
 const text=JSON.stringify(fixture.map);
 fs.writeFileSync(path.join(root,fixture.name+'.map'),text,{flag:'wx'});
 if(fixture.generated)fs.writeFileSync(path.join(root,fixture.name+'.js'),fixture.generated,{flag:'wx'});
 const directReference=new trace.AnyMap(fixture.map);
 const directRows=referenceRows(directReference);
 const reference=fixture.referenceMap?new trace.AnyMap(fixture.referenceMap):directReference;
 const expected=referenceRows(reference);
 if(fixture.referenceMap) {
  // ECMA-426 10.1 applies a parent's column offset only to decoded child
  // mappings on line zero. Here the inner section starts on line one, so
  // (outer 2,9)+(inner 1,3)+(leaf 0,1) is (3,4), not (3,13).
  // trace-mapping 0.3.31's direct nested AnyMap disagrees. Preserve and pin
  // that observation; do not silently call it direct-consumer agreement.
  assert.deepEqual(expected,[
   {line:4,column:4,source:'nested.js',originalLine:1,originalColumn:0,name:null,mapped:true},
   {line:5,column:0,source:'nested.js',originalLine:2,originalColumn:0,name:null,mapped:true},
  ]);
  assert.deepEqual(directRows,[{...expected[0],column:13},expected[1]]);
  fs.writeFileSync(path.join(root,fixture.name+'.reference-equivalent.json'),JSON.stringify(fixture.referenceMap),{flag:'wx'});
  fs.writeFileSync(path.join(root,fixture.name+'.consumer-divergence.json'),JSON.stringify({
   consumer:versions['@jridgewell/trace-mapping'],direct_rows:directRows,
   normative_equivalent_rows:expected,reference:'https://tc39.es/ecma426/#sec-decode-index-source-map',
   reason:'Parent column offset propagated to a nested section whose relative line is nonzero',
   actual_rea_projection:'qualified separately by rea-source-map-upstream-reference.mjs',
  },null,2)+'\n',{flag:'wx'});
 }
 const first=native(text);
 let rows=[...first.rows];
 for(let next=first.next_offset;next!==null;){
  const page=native(text,{offset:next,expected_analysis_sha256:first.analysis_sha256});
  rows.push(...page.rows);next=page.next_offset;
 }
 assert.deepEqual(rows.map(compactRow),expected,fixture.name+' decoded mappings');
 assert.equal(first.map_sha256,sha(Buffer.from(text)));
 const queries=[];
 // Single-mapping coordinates use the mature consumer's actual public query API.
 // Coincident positions are independently checked as a set of decoded records;
 // the native report deliberately retains all records rather than picking one.
 for(const row of expected.slice(0,80)) {
  const same=expected.filter(x=>x.line===row.line&&x.column===row.column);
  const got=native(text,{collection:'summary',generated_position:{line:row.line,column:row.column}}).query;
  assert.deepEqual(got.mappings.map(compactRow),same);
  if(same.length===1 && row.source!==null) {
   const origin=trace.originalPositionFor(reference,{line:row.line,column:row.column});
   assert.equal(origin.line,row.originalLine);assert.equal(origin.column,row.originalColumn);assert.equal(origin.name,row.name);
  }
  queries.push({line:row.line,column:row.column,coincident:same.length});
 }
 results.push({name:fixture.name,map_sha256:sha(Buffer.from(text)),map_bytes:Buffer.byteLength(text),
  mappings:expected.length,queries:queries.length,decoded_projection_equal:true,query_projection_equal:true,
  reference_input:fixture.referenceMap?'independently_authored_flat_equivalent':'original_map',
  direct_consumer_projection_equal:fixture.referenceMap?false:true,
  native_analysis_sha256:first.analysis_sha256});
}

const malformed=[
 {name:'unterminated-vlq',map:leaf('bad.js','g')},
 {name:'out-of-range-source',map:leaf('bad.js','ACAA')},
 {name:'signed-zero-is-minimum',map:leaf('bad.js','BAAA')},
 {name:'external-index-url',map:{version:3,sections:[{offset:{line:0,column:0},url:'http://127.0.0.1:1/never'}]}},
 {name:'overlap',map:{version:3,sections:[{offset:{line:0,column:0},map:leaf('one','AAAA;AAAA;AAAA')},{offset:{line:1,column:0},map:leaf('two','AAAA')}]}},
];
const denied=[];
for(const fixture of malformed) {
 const input=JSON.stringify({text:JSON.stringify(fixture.map),expected_analysis_sha256:null,collection:'summary',offset:0,limit:64,generated_position:null});
 const run=spawnSync(runtime,['rea-source-map-worker'],{input,encoding:'utf8',env:{},cwd:'/',timeout:25000,maxBuffer:1024*1024});
 callCount++;
 if(run.error)throw run.error;
 assert.notEqual(run.status,0,fixture.name);assert.equal(run.stdout,'');
 denied.push({name:fixture.name,exit_code:run.status,stderr:run.stderr.trim()});
}
const receipt={schema:'hepta.rea.source-map-independent-differential.v1',status:'pass',versions,
 runtime_sha256:sha(fs.readFileSync(runtime)),runtime_bytes:fs.statSync(runtime).size,
 script_sha256:sha(fs.readFileSync(new URL(import.meta.url))),node:process.version,
 successful_fixtures:results.length,decoded_mappings:results.reduce((a,r)=>a+r.mappings,0),
 direct_consumer_agreements:results.filter(r=>r.direct_consumer_projection_equal).length,
 recorded_direct_consumer_divergences:results.filter(r=>!r.direct_consumer_projection_equal).length,
 position_queries:results.reduce((a,r)=>a+r.queries,0),worker_invocations:callCount,
 results,denied,scope:'Independent Babel/gen-mapping production and trace-mapping interpretation. Seven direct fixtures; one normative authored flat equivalent with the pinned nested-consumer divergence explicitly retained. Actual REA is checked separately. Finite native worker projection, not complete upstream REA equivalence.'};
fs.writeFileSync(path.join(root,'qualification.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify(receipt));
