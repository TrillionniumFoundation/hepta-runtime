
return async function auditGitTrees({tools,load,store,H,sourceRows,install,candidateRows}) {
 const inflight=new Map(),checked=new Set();
 async function tree(sha){
  if(!sha)return {tree:[]};
  if(inflight.has(sha))return inflight.get(sha);
  const p=(async()=>{
   let o=load("final-install/tree-cache/"+sha);
   if(!o){const r=await tools.mcp__codex_apps__github_fetch({url:"https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/git/trees/"+sha});if(r.isError)throw Error(JSON.stringify(r));o=JSON.parse(r.structuredContent.content);}
   if(o.sha!==sha||o.truncated)throw Error("tree custody "+sha);
   let raw=[];for(const r of o.tree){if(r.path.includes("/")||!r.path||r.path==="."||r.path==="..")throw Error("tree name");raw.push(...H.utf8((r.mode==="040000"?"40000":r.mode)+" "+r.path+"\0"),...r.sha.match(/../g).map(x=>parseInt(x,16)));}
   if(H.sha1([...H.utf8("tree "+raw.length+"\0"),...raw])!==sha)throw Error("tree SHA "+sha);
   store("final-install/tree-cache/"+sha,o);checked.add(sha);return o;
  })();inflight.set(sha,p);return p;
 }
 const roots={candidate:"14806304ac775b5ed1360321dda8651e34657bda",parent:"59dcd1f36617e01f5fbc366ddfdfd61c585689f6",integration:"a2b2049c94a02f1a5a9af35c7f287a6881a0a9a8"};
 async function diff(oldRoot,newRoot){
  let pending=[{old:oldRoot,new:newRoot,prefix:""}],changes=[],unchangedTrees=[];
  while(pending.length){
   const batch=pending.splice(0,8);
   const results=await Promise.allSettled(batch.map(async q=>{
    if(q.old===q.new){unchangedTrees.push({path:q.prefix,sha:q.old});return;}
    const [a,b]=await Promise.all([tree(q.old),tree(q.new)]),A=new Map(a.tree.map(r=>[r.path,r])),B=new Map(b.tree.map(r=>[r.path,r]));
    for(const name of new Set([...A.keys(),...B.keys()])){
     const x=A.get(name),y=B.get(name),path=q.prefix+name;
     if(x&&y&&x.mode===y.mode&&x.type===y.type&&x.sha===y.sha){if(x.type==="tree")unchangedTrees.push({path,sha:x.sha});continue;}
     if(x?.type==="tree"||y?.type==="tree"){
      if(x&&x.type!=="tree")changes.push({path,before:x,after:null});
      if(y&&y.type!=="tree")changes.push({path,before:null,after:y});
      pending.push({old:x?.type==="tree"?x.sha:null,new:y?.type==="tree"?y.sha:null,prefix:path+"/"});
     }else changes.push({path,before:x||null,after:y||null});
    }
   }));
   for(const r of results)if(r.status!=="fulfilled")throw r.reason;
  }
  changes.sort((a,b)=>a.path.localeCompare(b.path));unchangedTrees.sort((a,b)=>a.path.localeCompare(b.path));return {changes,unchangedTrees};
 }
 async function lookup(root,paths){
  let pending=[{sha:root,prefix:"",paths}],result={};
  while(pending.length){
   const batch=pending.splice(0,8),rs=await Promise.allSettled(batch.map(async q=>{
    const o=await tree(q.sha),M=new Map(o.tree.map(r=>[r.path,r])),groups=new Map();
    for(const p of q.paths){const z=p.slice(q.prefix.length),slash=z.indexOf("/"),name=slash<0?z:z.slice(0,slash),r=M.get(name);if(!r){result[p]=null;continue;}if(slash<0){result[p]=r;continue;}if(r.type!=="tree")throw Error("path is non-tree "+p);if(!groups.has(name))groups.set(name,[]);groups.get(name).push(p);}
    for(const [name,ps]of groups)pending.push({sha:M.get(name).sha,prefix:q.prefix+name+"/",paths:ps});
   }));for(const r of rs)if(r.status!=="fulfilled")throw r.reason;
  }return result;
 }
 const finalDiff=await diff(roots.parent,roots.candidate),baseDiff=await diff(roots.integration,roots.candidate);
 const expected=new Map(candidateRows.map(r=>[r.path,r]));if(finalDiff.changes.length!==expected.size)throw Error("final delta cardinality");
 for(const r of finalDiff.changes){const x=expected.get(r.path);if(!x||r.after?.sha!==x.git_blob||r.after.mode!=="100644"||r.after.size!==x.bytes)throw Error("final delta "+r.path);}
 const paths=[...new Set([...sourceRows.map(r=>r.path),...install.historical_profile_changes.map(r=>r.path),...install.docs_and_ci_changes.map(r=>r.path)])];
 const [after,before]=await Promise.all([lookup(roots.candidate,paths),lookup(roots.integration,paths)]);
 for(const r of sourceRows){let v=after[r.path];if(!v||v.mode!==r.mode||v.sha!==r.git_blob||v.size!==r.bytes)throw Error("536 source "+r.path);}
 for(const r of [...install.changes,...install.historical_profile_changes,...install.docs_and_ci_changes]){
  const a=after[r.path],b=before[r.path],A=r.after,B=r.before;
  if(!a||a.sha!==A.git_blob||a.size!==A.bytes||a.mode!=="100644")throw Error("install after "+r.path);
  if((B===null&&b!==null)||(B!==null&&(!b||b.sha!==B.git_blob||b.size!==B.bytes||b.mode!=="100644")))throw Error("install before "+r.path);
 }
 for(const p of install.retained){let a=after[p],b=before[p];if(!a||!b||a.sha!==b.sha||a.mode!==b.mode||a.size!==b.size)throw Error("retained "+p);}
 const classified=new Set([...sourceRows.map(r=>r.path),...install.historical_profile_changes.map(r=>r.path),...install.docs_and_ci_changes.map(r=>r.path)]);
 const other=baseDiff.changes.filter(r=>!classified.has(r.path));
 if(other.some(r=>!r.path.startsWith("qualification/")&&!r.path.startsWith("tests/hia_native/publication124_ordinary_ci/")&&!r.path.startsWith(".github/workflows/hia-publication")))throw Error("unexpected nonqualification base delta "+JSON.stringify(other));
 return {schema:"hepta.runtime.public124.git-tree-audit.v1",roots,git_tree_objects_independently_sha1_checked:[...checked].sort(),source536_equal:true,source_rows:sourceRows.length,production_changed:install.changes.length,production_unchanged:install.retained.length,historical_rows:install.historical_profile_changes.length,docs_ci_rows:install.docs_and_ci_changes.length,final_delta:finalDiff.changes,integration_delta:baseDiff.changes,integration_unchanged_subtrees:baseDiff.unchangedTrees,qualification_only_other_changes:other.length,application_executions:0};
};