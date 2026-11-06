#!/usr/bin/env node
// Copyright 2026 TrillionniumFoundation. Apache-2.0.
// Compare actual installed REA's traceSourceMap point contract with the native
// decoder. This is an intentionally named projection, not an Evidence adapter.
// Usage: node SCRIPT REA_PACKAGE RUNTIME_BINARY FIXTURE_DIRECTORY OUTPUT_DIRECTORY
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const [reaPackage, runtime, fixtureDirectory, outputDirectory] = process.argv.slice(2);
if (![reaPackage,runtime,fixtureDirectory,outputDirectory].every(Boolean))
 throw Error('expected REA_PACKAGE RUNTIME_BINARY FIXTURE_DIRECTORY OUTPUT_DIRECTORY');
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const packageBytes=fs.readFileSync(path.join(reaPackage,'package.json'));
assert.equal(sha(packageBytes),'b0fc212f6bea9b4ee6e2b3ab0b52dd95402c229da3b8652127e5f131c3445b39');
assert.equal(JSON.parse(packageBytes).version,'6.8.0');
const moduleFile=path.join(reaPackage,'dist/javascript/sourceMaps/TraceSourceMap.js');
const {traceSourceMap}=await import(pathToFileURL(moduleFile));
fs.mkdirSync(outputDirectory,{recursive:false,mode:0o700});
const native=(text,overrides={})=>{
 const input=JSON.stringify({text,expected_analysis_sha256:null,collection:'summary',offset:0,limit:256,generated_position:null,...overrides});
 const run=spawnSync(runtime,['rea-source-map-worker'],{input,encoding:'utf8',env:{},cwd:'/',timeout:25000,maxBuffer:2*1024*1024});
 if(run.error) throw run.error;
 assert.equal(run.status,0,run.stderr);
 return JSON.parse(run.stdout);
};
const nativeMatch=row=>row.mapped?{
 mapped:true,source_index:row.original.source_index,source:row.original.source,
 root:row.original.source_root,line:row.original.line,column:row.original.column,
 offset:row.original.offset,content_position:row.original.content_position,
 name:row.original.name,ignored:row.original.ignored,
 section:Array.from(row.section_pointer.matchAll(/\/sections\/(\d+)\/map/g),m=>Number(m[1])),
}:{mapped:false};
const upstreamMatch=row=>row.state==='mapped'?{
 mapped:true,source_index:row.flattened_source_index,source:row.reported_source,
 root:row.reported_source_root,line:row.original_position.line,column:row.original_position.column,
 offset:row.original_position.offset,content_position:row.original_position.content_position,
 name:row.name,ignored:row.ignored,section:row.section_path,
}:{mapped:false};
const fixtures=fs.readdirSync(fixtureDirectory).filter(name=>name.endsWith('.map')).sort();
assert.equal(fixtures.length,8,'fixture inventory changed; review scope');
const results=[];
let queries=0;
for(const filename of fixtures) {
 const text=fs.readFileSync(path.join(fixtureDirectory,filename),'utf8');
 const mappings=native(text,{collection:'mappings'});
 assert.equal(mappings.next_offset,null,'fixture exceeded one full projection page');
 const sourceRows=native(text,{collection:'sources'});
 assert.equal(sourceRows.next_offset,null);
 const coordinates=new Map();
 const add=p=>coordinates.set(JSON.stringify(p),p);
 add({line:1,column:0});add({line:2,column:0});add({line:3,column:1});
 for(const row of mappings.rows) {
  add(row.generated);
  add({line:row.generated.line,column:row.generated.column+1});
  add({line:row.generated.line+1,column:0});
 }
 const last=mappings.rows.at(-1)?.generated??{line:1,column:0};
 add({line:last.line+2,column:0});
 const records=[];
 for(const position of coordinates.values()) {
  const reference=traceSourceMap(text,'https://source-map.invalid/assets/generated.js.map',position);
  const actual=native(text,{generated_position:position});
  const record={position,reference,actual};
  records.push(record);
  // Save before assertion: a failure is reproducible and cannot masquerade as
  // a successful qualification by dropping its attempted comparison.
  fs.writeFileSync(path.join(outputDirectory,filename+'.comparisons.json'),JSON.stringify(records,null,2)+'\n');
  assert.equal(reference.source_map_sha256,actual.map_sha256,filename+' map identity');
  assert.deepEqual(actual.query.matched_generated_position,reference.lookup.matched_generated_position,
   filename+' selected generated position');
  assert.deepEqual(actual.query.mappings.map(nativeMatch),reference.matches.map(upstreamMatch),
   filename+' all coincident point records');
  for(const match of reference.matches.filter(row=>row.state==='mapped')) {
   const source=sourceRows.rows[match.flattened_source_index];
   assert.equal(source.embedded_content.present,match.content.state==='embedded');
   if(match.content.state==='embedded') {
    assert.equal(source.embedded_content.sha256,match.content.utf8_sha256);
    assert.equal(source.embedded_content.bytes,match.content.utf8_bytes);
   }
  }
  queries++;
 }
 results.push({fixture:filename,map_sha256:sha(Buffer.from(text)),queries:records.length,
  point_projection_equal:true,embedded_content_identity_equal:true,embedded_content_positions_equal:true});
}
const receipt={schema:'hepta.rea.source-map-upstream-point-differential.v1',status:'pass',
 upstream:{name:'rea-agents',version:'6.8.0',package_json_sha256:sha(packageBytes),
  module:'dist/javascript/sourceMaps/TraceSourceMap.js',module_sha256:sha(fs.readFileSync(moduleFile))},
 runtime:{sha256:sha(fs.readFileSync(runtime)),bytes:fs.statSync(runtime).size},
 script_sha256:sha(fs.readFileSync(new URL(import.meta.url))),node:process.version,
 fixture_count:results.length,position_queries:queries,results,
 scope:'Actual REA point selection across lines, coincident records, source/name/section declarations and embedded-content identities and exact original UTF-16 offsets/three content-position states on finite fixtures. URL resolution, browser acquisition, Evidence envelopes and full REA tools are not qualified.'};
fs.writeFileSync(path.join(outputDirectory,'qualification.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify(receipt));
