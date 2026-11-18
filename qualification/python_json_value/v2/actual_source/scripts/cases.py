"""Frozen value commands and complete buffer admissions; no reference JSON operation."""
import hashlib,struct
LIMIT=8388608
REQUEST=int.from_bytes(b"HPYJSQ01","little")
GROUPS=tuple(range(19))
def quote(text):
    out=['"']
    for cp in map(ord,text):
        if cp==34:out.append('\\"')
        elif cp==92:out.append("\\\\")
        elif cp<32:out.append("\\u%04x"%cp)
        else:out.append(chr(cp))
    return "".join(out)+'"'
def pack(command,primary,auxiliary="",parse_budget=9997,encode_budget=9997,compare_budget=None):
    if compare_budget is None:compare_budget=9998 if command==5 else 0
    body=(primary+auxiliary).encode("utf-32-le","surrogatepass")
    return struct.pack("<8Q",REQUEST,command,len(primary),len(auxiliary),parse_budget,encode_budget,compare_budget,len(body))+body
def chain(depth,leaf,shape="array"):
    opening=[];closing=[]
    for i in range(depth):
        obj=shape=="object"or(shape=="alternating"and i%2)
        opening.append('{"x":'if obj else"[");closing.append("}"if obj else"]")
    return "".join(opening)+leaf+"".join(reversed(closing))
def recipe(label,command,primary,auxiliary="",**kw):
    return dict(label=label,command=command,primary=primary,auxiliary=auxiliary,**kw)
def basic():
    scalars=["null","false","true","-0","1","-1","256","257","-5","-6","0.0","-0.0","1.5","NaN","Infinity","-Infinity",
        '""','"a"','"\\u0000"','"\\ud800"','"\\udfff"','"\\ud834\\udd1e"','"\\ud834\\u0041"',
        '"\\ud834\\ud834"','"\\b\\f\\n\\r\\t\\\\\\/\\""','"\ufeff"']
    containers=['[]','{}','[1, true, null, -0.0, NaN]','{"z":1,"a":2,"z":3}',
        '{"a":1,"\\u0061":2,"a":3}','{"":1,"b":null,"a":[]}',
        '{"\U00010000":1,"\ue000":2,"\\ud800":3,"a":4}',
        '{"x":{"z":[false,0.25],"a":"\ud800"},"n":42}']
    for i,text in enumerate(scalars+containers):
        for command in(1,3):yield recipe("basic-%d-%d"%(i,command),command,text)
    for text in [" \n\t\rnull \r\n","[\n1,\r\n2,\t3\n]"," \n{\"a\":1,\"b\":2} \t"]:
        for command in(1,3):yield recipe("whitespace-"+str(command)+"-"+text,command,text)
def syntax():
    values=[""," ","\ufeffnull","\x00","nul","True","False","Null","+1","01","-01",".5","1.","1e","1e+","--1","-NaN",
        "NaNx","Infinityx","[]x","null false","[","{","[1","[1,]","[,1]","[1 2]","{1:2}",'{"a"}','{"a":}',
        '{"a":1,}','{"a":1 "b":2}',"]","}","\"","\"x\\","\"\\u\"","\"\\u123\"",
        '"\\ud800\\uQ000"','"\\ud800\\u123"','"\n"']
    for i,text in enumerate(values):yield recipe("syntax-%d"%i,1,text)
    for cp in range(32):yield recipe("raw-control-%d"%cp,1,'"a'+chr(cp)+'b"')
    for cp in range(256):
        if cp not in map(ord,'"\\/bfnrtu'):yield recipe("escape-%d"%cp,1,chr(34)+chr(92)+chr(cp)+chr(34))
    bad=[chr(cp)for cp in range(128)if chr(cp)not in"0123456789abcdefABCDEF"]
    for position in range(4):
        for cp in bad:
            digits=list("1234");digits[position]=cp
            yield recipe("bad-hex-%d-%d"%(position,ord(cp)),1,'"\\u'+"".join(digits)+'"')
    for prefix in(""," ","\n","\r\n","\t"):
        for text in('{"a" 1}','[1 2]','{"a":tru}','"\\x"','"unterminated'):
            yield recipe("position-"+quote(prefix+text),1,prefix+text)
    for cp in(0x00a0,0x1680,0x2000,0x200b,0x2028,0x2029,0x202f,0x3000):
        for before in(True,False):
            text=chr(cp)+"1"if before else"1"+chr(cp)
            yield recipe("non-json-space-%d-%d"%(cp,int(before)),1,text)
def numbers():
    seen=set()
    def unique(value):
        if value=="0"or value in seen:return False
        seen.add(value);return True
    fixed=["0.0000000000000000000000001","1.00000000000000011102230246251565404236316680908203125",
        "1.00000000000000011102230246251565404236316680908203126",
        "2.2250738585072011e-308","2.2250738585072012e-308","2.2250738585072013e-308",
        "2.2250738585072014e-308","4.9406564584124654e-324","2.4703282292062327e-324",
        "2.4703282292062328e-324","1.7976931348623157e308","1.7976931348623158e308","1.7976931348623159e308",
        "9007199254740991","9007199254740992","9007199254740993","-9007199254740993",
        "18446744073709551615","18446744073709551616","-9223372036854775809",
        "1e999999999999999999999999999999999999999999","-1e-99999999999999999999999999999999999999999",
        "0e999999999999999999999999999999999999999999","-0e99999999999999999999999999999999999999999"]
    for value in fixed:
        if unique(value):yield value
    for exp in range(-330,311):
        for sign in("","-"):
            value=sign+"1e"+str(exp)
            if unique(value):yield value
    for power in range(0,65):
        for adjustment in(-1,0,1):
            for sign in(1,-1):
                value=str(sign*((1<<power)+adjustment))
                if unique(value):yield value
    state=0x6791a2b3c4d5e6f7
    for i in range(256):
        state=(state*6364136223846793005+1442695040888963407)&0xffffffffffffffff
        bits=state
        if (bits>>52)&2047==2047:bits^=1<<52
        value=repr(struct.unpack("<d",struct.pack("<Q",bits))[0])
        if unique(value):yield value
def numeric(group):
    for n,text in enumerate(numbers()):
        for k,command in enumerate((1,3)):
            if (2*n+k)%8==group-2:yield recipe("number-%d-%d"%(n,command),command,text)
def equality():
    values=["null","false","true","-0","1","-1","2","-5","-6","256","257","0.0","-0.0","0.5",
        "1.0","9007199254740992","9007199254740993","9007199254740992.0","1e309","Infinity","-Infinity","NaN",
        '""','"x"','"\\u0078"','"value"','[]','{}','[NaN]','{"x":NaN}','[1,true]','{"a":1,"b":2}']
    for i,left in enumerate(values):
        for j,right in enumerate(values):yield recipe("equal-%d-%d"%(i,j),5,left,right)
    pairs=[('{"z":1,"a":2,"z":3}','{"a":2,"z":3}'),
        ('{"a":1,"\\u0061":2}','{"a":2}'),
        ('[9007199254740993]','[9007199254740992.0]'),
        ('{"x":NaN,"y":Infinity}','{"y":1e999,"x":NaN}'),
        ('{"x":[null,true,false,-0,"x","value"]}','{"x":[null,1,0,0.0,"\\u0078","value"]}')]
    for i,(left,right)in enumerate(pairs):yield recipe("equal-structure-%d"%i,5,left,right)
def updates():
    lefts=['{}','{"z":1,"a":2,"z":3}','{"a":{"x":[1,2]},"m":null}',
        '{"":0,"\\ud800":"old","a":NaN}','{"b":1,"a":2,"c":3}']
    rights=['{}','{"state":"committed","result":{"size":3,"version":"1:2:3","sha256":"abc","mode":384}}',
        '{"a":false,"z":7}','{"\\ud800":"new","":42}','{"b":null,"b":[true],"n":Infinity}']
    for i,left in enumerate(lefts):
        for j,right in enumerate(rights):yield recipe("update-%d-%d"%(i,j),4,left,right)
    for i,text in enumerate(["null","false","true","7","2.5",'"value"',"[]","[1,2]"]):
        yield recipe("update-nondict-%d"%i,4,text,'{"a":1}')
    for n in(2,3,4,7,8,9,31,32,33,127,128,129):
        left="{"+",".join(quote("k%04d"%i)+":"+str(i)for i in reversed(range(n)))+"}"
        right="{"+",".join(quote("k%04d"%i)+":"+str(-i)for i in range(n//2,n+n//2))+"}"
        yield recipe("update-sort-%d"%n,4,left,right)
def lookups():
    fields=["","name","state","expected_version","result","metadata","xattrs","offset","\\","\x00","\n","'\"","\x7f"]
    values=['null','false','true','-0','257','0.5','NaN','"value"','"\\ud800"','[1,2]','{"z":1,"a":2}']
    for i,key in enumerate(fields):
        for j,text in enumerate(values):
            primary="{"+quote(key)+":"+text+'}' 
            for command in(2,6):yield recipe("lookup-%d-%d-%d"%(i,j,command),command,primary,key,selected_span=text if text[0]in"[{"else None)
    for key in fields:
        for command in(2,6):yield recipe("missing-%d-%s"%(command,quote(key)),command,'{"present":true}',key)
    for primary in ["null","false","true","257","0.5",'"value"',"[]","[1,2]"]:
        for command in(2,6):yield recipe("lookup-type-%d-%s"%(command,primary),command,primary,"state")
    yield recipe("duplicate-container-lookup",2,'{"k":[1],"k":[2,3]}',"k",selected_span="[2,3]")
def unicode(group):
    if group==13:
        text=quote("".join(chr(cp)for cp in range(0x110000)))
        yield recipe("all-codepoints-parse",1,text)
        yield recipe("all-codepoints-dump",3,text)
    elif group==14:
        text='"'+"".join("\\u%04x"%cp for cp in range(65536))+'"'
        yield recipe("all-utf16-units-parse",1,text)
        yield recipe("all-utf16-units-dump",3,text)
    elif group==15:
        pieces=["\\u%04x\\u%04x"%(hi,lo)for hi in(0xd800,0xd801,0xdbfe,0xdbff)for lo in range(0xdc00,0xe000)]
        pieces+=["\\u%04x\\u%04x"%(hi,lo)for hi in range(0xd800,0xdc00)for lo in(0xdc00,0xdc01,0xdffe,0xdfff)]
        text='"'+"".join(pieces)+'"'
        yield recipe("surrogate-pair-grid-parse",1,text)
        yield recipe("surrogate-pair-grid-dump",3,text)
def large(group):
    if group==16:
        for digits in(4299,4300,4301):
            for sign in("","-"):
                for command in(1,3):
                    yield recipe("integer-digits-%d-%s-%d"%(digits,sign,command),command,sign+"9"*digits)
        for digits in(4300,10000,65536):
            for sign in("","-"):
                text=sign+"0."+"0"*digits+"1"
                yield recipe("long-fraction-%d-%s"%(digits,sign),1,text)
        text="["+",".join(str(i%257)for i in range(16384))+"]"
        yield recipe("wide-array",3,text)
    else:
        for n in(3,7,8,9,63,64,65,1024):
            pairs=[quote("key%06d"%i)+':'+quote("value%06d"%i)for i in reversed(range(n))]
            pairs+=[quote("key%06d"%i)+':'+str(i)for i in range(0,n,3)]
            yield recipe("wide-dictionary-%d"%n,3,"{"+",".join(pairs)+"}")
        for depth in(3,17,127,1025):
            yield recipe("mixed-depth-%d"%depth,3,chain(depth,'{"end":"done"}',"alternating"))
def branches():
    for shape in("array","object"):
        for kind in("false_first","deep_first","missing_after_deep","missing_before_deep","length_diff","duplicate_position"):
            for depth in(9996,9997,9998):
                deep=chain(depth,'"value"',shape)
                if kind=="false_first":
                    left='{"z":0,"a":'+deep+'}';right='{"z":1,"a":'+deep+'}'
                elif kind=="deep_first":
                    left='{"z":'+deep+',"a":0}';right='{"z":'+deep+',"a":1}'
                elif kind=="missing_after_deep":
                    left='{"z":'+deep+',"a":1}';right='{"z":'+deep+',"b":1}'
                elif kind=="missing_before_deep":
                    left='{"z":1,"a":'+deep+'}';right='{"b":1,"a":'+deep+'}'
                elif kind=="length_diff":
                    left='{"z":'+deep+'}';right='{"z":'+deep+',"a":1}'
                else:
                    left='{"z":'+deep+',"a":0,"z":'+deep+'}';right='{"z":'+deep+',"a":1}'
                yield recipe("branch-%s-%s-%d"%(shape,kind,depth),5,left,right,parse_budget=20000,
                    constructed=dict(shape=shape,kind=kind,depth=depth))
def recipes(group):
    if group==0:yield from basic()
    elif group==1:yield from syntax()
    elif 2<=group<=9:yield from numeric(group)
    elif group==10:yield from equality()
    elif group==11:yield from updates()
    elif group==12:yield from lookups()
    elif 13<=group<=15:yield from unicode(group)
    elif group in(16,17):yield from large(group)
    elif group==18:yield from branches()
    else:raise ValueError("undeclared JSON value group")
def unique_recipes(group):
    seen=set()
    for prior in range(int(group)+1):
        for number,value in enumerate(recipes(prior)):
            wire=pack(value["command"],value["primary"],value["auxiliary"],parse_budget=value.get("parse_budget",9997))
            digest=hashlib.sha256(wire).digest()
            if digest in seen:continue
            seen.add(digest)
            if prior==int(group):yield number,value
def cases(group):
    for number,value in unique_recipes(int(group)):
        primary,aux=value["primary"],value["auxiliary"]
        command=value["command"];budget=value.get("parse_budget",9997)
        wire=pack(command,primary,aux,parse_budget=budget)
        units=len(primary)+len(aux)
        yield dict(**value,case_id=int(group)*1000000+number,wire=wire,
            output_capacity=512+12*units,workspace_capacity=16480+40*units,
            output_fill=(number*37+19)%256,workspace_fill=(number*71+43)%256)
def controls():
    base=next(cases(0));number=0
    def row(label,wire,oc,wc,expected,unchanged=True,oracle=None):
        nonlocal number
        result=dict(case_id=99000000+number,label=label,wire=wire,output_capacity=oc,workspace_capacity=wc,
            output_fill=(number*23+211)%256,workspace_fill=(number*61+151)%256,
            expected_code=expected,workspace_unchanged=unchanged,oracle=oracle)
        number+=1;return result
    wire=base["wire"];wc=base["workspace_capacity"]
    for capacity in(0,1,63,64,65,512):
        yield row("output-capacity-%d"%capacity,wire,capacity,wc,0xfffffffe if capacity<64 else 64,False,0)
    for capacity in(0,1024,wc-1):
        yield row("workspace-capacity-%d"%capacity,wire,512,capacity,0xfffffffd)
    headers=list(struct.unpack("<8Q",wire[:64]))
    for field,value in[(0,0),(1,0),(1,7),(2,LIMIT+1),(3,LIMIT+1),(4,0),(4,20001),(5,0),(5,20001),(6,1),(7,0)]:
        changed=headers.copy();changed[field]=value
        yield row("header-%d-%d"%(field,value),struct.pack("<8Q",*changed)+wire[64:],512,wc,0xffffffff)
    for length in(0,1,63,len(wire)-1):
        yield row("truncated-%d"%length,wire[:length],512,wc,0xffffffff)
    yield row("invalid-codepoint",wire[:64]+struct.pack("<I",0x110000)+wire[68:],512,wc,0xffffffff)
    for key in("x"*97,"\u0080"):
        changed=pack(2,"{}",key);yield row("unadmitted-key-"+str(len(key)),changed,512,16480+40*(2+len(key)),0xffffffff)
    for budget in(0,20001):
        changed=pack(5,"null","null",compare_budget=budget)
        yield row("comparison-budget-%d"%budget,changed,512,16800,0xffffffff)
    changed=pack(4,"{}","[]")
    yield row("auxiliary-dictionary-required",changed,512,16640,0xffffffff,False)
def group_count(group):return sum(1 for _ in unique_recipes(group))
def domain():
    groups=[dict(id=i,cases=group_count(i))for i in GROUPS]
    return dict(schema="hepta.runtime.python-json-value.actual-domain.v2",groups=groups,
        semantic_cases=sum(x["cases"]for x in groups),controls=sum(1 for _ in controls()),shards=6,
        parse_budget=9997,encode_budget=9997,comparison_budget=9998,
        constructed_comparison_inputs=36,all_unicode_codepoints=0x110000,all_utf16_units=65536)
def shard_domain(shard):
    if shard not in range(6):raise ValueError("undeclared value shard")
    rows=[dict(id=i,cases=group_count(i))for i in GROUPS if i%6==shard]
    return dict(shard=shard,groups=rows,semantic_cases=sum(r["cases"]for r in rows),
        private_native_calls=sum(1 for _ in controls())if shard==0 else 0)
def plan(shard):
    rows=shard_domain(shard)["groups"]
    result=[(role,str(r["id"]))for r in rows for role in("original","native")]
    if shard==0:result.append(("native","controls"))
    return result
