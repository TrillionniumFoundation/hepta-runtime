
const fs=require('node:fs');
const cases=JSON.parse(fs.readFileSync(0,'utf8'));
const output=cases.map(c=>{
 const raw=Buffer.from(c.input_hex,'hex');
 let source;
 try { source=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw); }
 catch(error) { return {id:c.id,utf8:false,json_parse:false,error_name:error.name,message:error.message}; }
 try {
  const value=JSON.parse(source);
  const kind=value===null?'null':Array.isArray(value)?'array':typeof value;
  const row={id:c.id,utf8:true,json_parse:true,root_kind:kind};
  if(kind==='string') row.utf16_units=Array.from({length:value.length},(_,i)=>value.charCodeAt(i));
  if(kind==='number') {row.number_finite=Number.isFinite(value);row.number_spelling=String(value);}
  return row;
 } catch(error) {return {id:c.id,utf8:true,json_parse:false,error_name:error.name,message:error.message};}
});
process.stdout.write(JSON.stringify({node:process.version,executable:process.execPath,cases:output})+'\n');
