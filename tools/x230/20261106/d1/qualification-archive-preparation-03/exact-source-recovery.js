(function recover(oldTemplate, builder, newRows, actualLine){
 function pyrepr(x){if(x===null)return "None";if(x===true)return "True";if(x===false)return "False";if(typeof x==="number")return String(x);if(typeof x==="string")return "'"+x.replace(/\\/g,"\\\\").replace(/'/g,"\\'").replace(/\n/g,"\\n").replace(/\r/g,"\\r").replace(/\t/g,"\\t")+"'";if(Array.isArray(x))return "["+x.map(pyrepr).join(", ")+"]";return "{"+Object.entries(x).map(([k,v])=>pyrepr(k)+": "+pyrepr(v)).join(", ")+"}";}
 const pins=JSON.parse(oldTemplate.match(/^PINNED = (.*)$/m)[1].replace(/'/g,'"'));
 delete pins["archive_d1_qualification_01.py"];
 for (const [name,row] of Object.entries(newRows)) { if(pins[name])throw Error("duplicate"); pins[name]={bytes:row.bytes,sha256:row.sha256}; }
 if(Object.keys(pins).length!==69)throw Error("pin count");
 const sorted=Object.fromEntries(Object.keys(pins).sort().map(n=>[n,pins[n]]));
 let source=oldTemplate.replace(/^PINNED = .*$/m,"PINNED = "+pyrepr(sorted));
 source=source.replace(/^REQUIRED = .*$/m,"REQUIRED = ("+Object.keys(sorted).map(pyrepr).join(", ")+")");
 const external=builder.match(/    external_check = """([\s\S]*?)"""/)[1];
 const second=builder.match(/    second_check = """([\s\S]*?)"""/)[1];
 function one(a,b){if(source.split(a).length!==2)throw Error("anchor "+a);source=source.replace(a,b);}
 const anchor="    first_terminal = json.loads(data['provenance/qualification-archive-attempt-01-native.json'])\n";
 one(anchor,external+anchor);
 one("         and sha(data['archive_d1_qualification_01.py']) == first_failure['prior_archive_script_sha256'],\n","         and external_sources['sources']['01']['source']['sha256'] == first_failure['prior_archive_script_sha256'],\n");
 const marker="    result['archive_attempt_01_failure'] = first_failure\n";
 one(marker,marker+second);
 one("base = root / 'qualification-evidence-02'","base = root / 'qualification-evidence-03'");
 return {template:source,sealed:source.replace(/^ACTUAL = None$/m,actualLine),pins:sorted};
})
