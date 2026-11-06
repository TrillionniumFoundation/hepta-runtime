function rustTokens(source){
 const tokens=[];let i=0;
 function add(start,end){tokens.push({value:source.slice(start,end),start,end});i=end;}
 while(i<source.length){
  const start=i,c=source[i];
  if(/\s/.test(c)){i++;continue;}
  if(source.startsWith("//",i)){const n=source.indexOf("\n",i+2);i=n<0?source.length:n+1;continue;}
  if(source.startsWith("/*",i)){let n=1;i+=2;while(i<source.length&&n){if(source.startsWith("/*",i)){n++;i+=2;}else if(source.startsWith("*/",i)){n--;i+=2;}else i++;}if(n)throw Error("unclosed comment "+start);continue;}
  const raw=/^(?:b|c)?r(#{0,255})"/.exec(source.slice(i));
  if(raw){const end=source.indexOf('"'+raw[1],i+raw[0].length);if(end<0)throw Error("unclosed raw string "+start);add(start,end+1+raw[1].length);continue;}
  const quoted=source[i]==='"'?i:((source[i]==='b'||source[i]==='c')&&source[i+1]==='"'?i+1:-1);
  if(quoted>=0){let j=quoted+1;for(;j<source.length;j++){if(source[j]==="\\"){j++;continue;}if(source[j]==='"')break;}if(j>=source.length)throw Error("unclosed string "+start);add(start,j+1);continue;}
  const charAt=c==="'"?i:(c==="b"&&source[i+1]==="'"?i+1:-1);
  if(charAt>=0){
   let j=charAt+1;
   if(source[j]==="\\"){j+=2;if(source[j-1]==="u"&&source[j]==="{"){j=source.indexOf("}",j)+1;}else if(source[j-1]==="x"){j+=2;}}
   else if(j<source.length){j+=source.codePointAt(j)>65535?2:1;}
   if(source[j]==="'"){add(start,j+1);continue;}
  }
  if(/[A-Za-z_0-9]/.test(c)){let j=i+1;while(j<source.length&&/[A-Za-z_0-9]/.test(source[j]))j++;add(start,j);continue;}
  add(start,i+1);
 }
 return tokens;
}
function groupEnd(tokens,start){
 const open=tokens[start].value,close={"(":")","[":"]","{":"}"}[open];if(!close)throw Error("not a group");
 let stack=[close];for(let i=start+1;i<tokens.length;i++){const v=tokens[i].value;if(v==="("||v==="["||v==="{")stack.push({"(":")","[":"]","{":"}"}[v]);else if(v===")"||v==="]"||v==="}"){if(stack.pop()!==v)throw Error("unbalanced at "+tokens[i].start);if(!stack.length)return i;}}
 throw Error("unclosed group at "+tokens[start].start);
}
function splitArgs(tokens){
 const out=[];let start=0;for(let i=0;i<tokens.length;i++){const v=tokens[i].value;if(v==="("||v==="["||v==="{"){i=groupEnd(tokens,i);continue;}if(v===","){out.push(tokens.slice(start,i));start=i+1;}}
 if(start<tokens.length)out.push(tokens.slice(start));return out;
}
function eraseDiagnostic(tokens,proof){
 let out=[];
 for(let i=0;i<tokens.length;i++){
  if(tokens[i].value==="#"&&tokens[i+1]?.value==="["){
   const end=groupEnd(tokens,i+1),attrs=tokens.slice(i+2,end).map(t=>t.value);
   if(attrs.includes('"phase-cost-diagnostics"')){
    let j=end+1;
    if(tokens[j]?.value==="{"){j=groupEnd(tokens,j)+1;}
    else if(tokens[j]?.value==="if"){
     while(j<tokens.length&&tokens[j].value!=="{")j++;
     j=groupEnd(tokens,j)+1;
     if(tokens[j]?.value==="else")throw Error("unexpected cfg-if else normalization");
    }else if(tokens[j]?.value==="diagnostic"&&tokens[j+1]?.value===":"){
     while(j<tokens.length&&tokens[j].value!==",")j++;
     j++;
    }else{
     while(j<tokens.length){const v=tokens[j].value;if(v==="("||v==="["||v==="{"){j=groupEnd(tokens,j)+1;continue;}if(v===";"){j++;break;}j++;}
    }
    proof.cfgRemoved++;i=j-1;continue;
   }
  }
  const prefix=["crate",":",":","mcp",":",":","runtime",":",":"];
  if(prefix.every((v,k)=>tokens[i+k]?.value===v)&&/^phase_cost_(sync|wall|future|context_future|context|request)$/.test(tokens[i+9]?.value||"")&&tokens[i+10]?.value==="!"&&tokens[i+11]?.value==="("){
   const end=groupEnd(tokens,i+11),name=tokens[i+9].value,args=splitArgs(tokens.slice(i+12,end));
   const wanted=name==="phase_cost_request"?args[2]:args[1];
   if(!wanted)throw Error("macro missing expected argument "+name);
   let body=wanted;
   if(["phase_cost_sync","phase_cost_wall","phase_cost_context","phase_cost_request"].includes(name)){
    if(body[0]?.value!=="{"||groupEnd(body,0)!==body.length-1)throw Error("nonblock "+name);
    body=body.slice(1,-1);
   }
   if(name==="phase_cost_sync"){
    const awaits=body.filter(t=>t.value==="await");
    if(awaits.length)throw Error("synchronous CPU wrapper contains await");
    proof.syncSpans++;
   }
   proof.macros[name]=(proof.macros[name]||0)+1;
   out.push(...eraseDiagnostic(body,proof));i=end;continue;
  }
  out.push(tokens[i]);
 }
 return out;
}
function collapsedLiveBreak(tokens){
 const text=tokens.map(t=>t.value);
 const wanted=["ChildLiveness",":",":","Live","=",">","{","break","(","master",",","host",",","budget",",","active",")","}",","];
 for(let i=0;i+wanted.length<=text.length;i++){
  if(wanted.every((v,j)=>text[i+j]===v))return tokens.slice(0,i+6).concat(tokens.slice(i+7,i+17),tokens.slice(i+18));
 }
 return tokens;
}
