function lineOps(oldLines,newLines){
 const n=oldLines.length,m=newLines.length,v=new Map([[1,0]]),trace=[];
 for(let d=0;d<=n+m;d++){
  trace.push(new Map(v));
  for(let k=-d;k<=d;k+=2){
   let x;if(k===-d||(k!==d&&(v.get(k-1)??-Infinity)<(v.get(k+1)??-Infinity)))x=v.get(k+1)??0;else x=(v.get(k-1)??0)+1;
   let y=x-k;while(x<n&&y<m&&oldLines[x]===newLines[y]){x++;y++;}
   v.set(k,x);
   if(x>=n&&y>=m){
    const out=[];x=n;y=m;
    for(let depth=trace.length-1;depth>=0;depth--){
     const before=trace[depth],diagonal=x-y;
     const previousDiagonal=diagonal===-depth||(diagonal!==depth&&(before.get(diagonal-1)??-Infinity)<(before.get(diagonal+1)??-Infinity))?diagonal+1:diagonal-1;
     const previousX=before.get(previousDiagonal)??0,previousY=previousX-previousDiagonal;
     while(x>previousX&&y>previousY){out.push({kind:" ",line:oldLines[x-1]});x--;y--;}
     if(depth===0)break;
     if(x===previousX){out.push({kind:"+",line:newLines[y-1]});y--;}else{out.push({kind:"-",line:oldLines[x-1]});x--;}
    }
    return out.reverse();
   }
  }
 }
 throw Error("unreachable diff");
}
function filePatch(path,oldSource,newSource,oldGit,newGit){
 if(oldSource!==undefined&&!oldSource.endsWith("\n"))throw Error("old source lacks final LF");
 if(!newSource.endsWith("\n"))throw Error("new source lacks final LF");
 const oldLines=oldSource===undefined?[]:oldSource.slice(0,-1).split("\n"),newLines=newSource.slice(0,-1).split("\n");
 const ops=lineOps(oldLines,newLines);
 if(ops.filter(x=>x.kind!=="+").map(x=>x.line).join("\n")!==oldLines.join("\n"))throw Error("diff old roundtrip");
 if(ops.filter(x=>x.kind!=="-").map(x=>x.line).join("\n")!==newLines.join("\n"))throw Error("diff new roundtrip");
 const changes=ops.flatMap((x,i)=>x.kind===" "?[]:[i]),ranges=[];
 for(const i of changes){const a=Math.max(0,i-3),z=Math.min(ops.length-1,i+3),last=ranges[ranges.length-1];if(last&&a<=last[1]+1)last[1]=z;else ranges.push([a,z]);}
 let patch="diff --git a/"+path+" b/"+path+"\n";
 if(oldSource===undefined)patch+="new file mode 100644\n";
 patch+="index "+(oldGit||"0000000000000000000000000000000000000000")+".."+newGit+(oldSource===undefined?"":" 100644")+"\n";
 patch+="--- "+(oldSource===undefined?"/dev/null":"a/"+path)+"\n+++ b/"+path+"\n";
 const preA=[0],preB=[0];for(const op of ops){preA.push(preA.at(-1)+(op.kind!=="+"?1:0));preB.push(preB.at(-1)+(op.kind!=="-"?1:0));}
 for(const [a,z] of ranges){
  const oldCount=preA[z+1]-preA[a],newCount=preB[z+1]-preB[a];
  const oldStart=preA[a]+(oldCount?1:0),newStart=preB[a]+(newCount?1:0);
  patch+="@@ -"+oldStart+","+oldCount+" +"+newStart+","+newCount+" @@\n";
  for(let i=a;i<=z;i++)patch+=ops[i].kind+ops[i].line+"\n";
 }
 return patch;
}
function verifyUnified(patch,base,candidate){
 const lines=patch.split("\n");let i=0,verified=[];
 while(i<lines.length&&lines[i]){
  const header=/^diff --git a\/(.+) b\/(.+)$/.exec(lines[i++]);
  if(!header||header[1]!==header[2])throw Error("patch path header");
  const path=header[1],original=base[path]===undefined?[]:base[path].slice(0,-1).split("\n"),out=[];let consumed=0;
  while(i<lines.length&&!lines[i].startsWith("@@ "))i++;
  while(i<lines.length&&lines[i].startsWith("@@ ")){
   const h=/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(lines[i++]);if(!h)throw Error("bad hunk");
   const countA=Number(h[2]),countB=Number(h[4]),startA=Number(h[1])-(countA?1:0),startB=Number(h[3])-(countB?1:0);
   while(consumed<startA)out.push(original[consumed++]);if(out.length!==startB)throw Error("hunk new offset");
   let seenA=0,seenB=0;
   while(seenA<countA||seenB<countB){
    const line=lines[i++],kind=line[0],value=line.slice(1);
    if(kind===" "||kind==="-"){if(original[consumed++]!==value)throw Error("context differs "+path);seenA++;}
    if(kind===" "||kind==="+"){out.push(value);seenB++;}
    if(![" ","+","-"].includes(kind))throw Error("bad patch op");
   }
   if(seenA!==countA||seenB!==countB)throw Error("hunk count");
  }
  while(consumed<original.length)out.push(original[consumed++]);
  if(out.join("\n")+"\n"!==candidate[path])throw Error("candidate roundtrip "+path);
  verified.push(path);
 }
 return verified;
}
