"""Frozen JSON object item order, scalar values and exact source spans."""
import hashlib,struct,itertools
LIMIT=8388608
REQUEST=int.from_bytes(b"HPYJSQ01","little")
GROUPS=tuple(range(4))
def quote(text):
    out=['"']
    for cp in map(ord,text):
        if cp==34:out.append('\\"')
        elif cp==92:out.append("\\\\")
        elif cp<32:out.append("\\u%04x"%cp)
        else:out.append(chr(cp))
    return "".join(out)+'"'
def pack(primary,command=1,auxiliary="",parse_budget=9997,encode_budget=9997,compare_budget=0):
    body=(primary+auxiliary).encode("utf-32-le","surrogatepass")
    return struct.pack("<8Q",REQUEST,command,len(primary),len(auxiliary),parse_budget,encode_budget,compare_budget,len(body))+body
def object_case(label,pairs,pretty=False):
    fields=[];values={}
    for key,key_token,value in pairs:
        fields.append(key_token+(" : \n"if pretty else":")+value)
        values[key]=value
    primary=("{ \n"if pretty else"{")+(", \t\n"if pretty else",").join(fields)+("\n }"if pretty else"}")
    if pretty:primary=" \t\n"+primary+"\r\n "
    return dict(label=label,command=1,primary=primary,auxiliary="",item_spans=list(values.items()))
def ordinary(label,pairs,pretty=False):
    return object_case(label,[(key,quote(key),value)for key,value in pairs],pretty)
def chain(depth,leaf,obj=False):
    return ('{"n":'if obj else"[")*depth+leaf+("}"if obj else"]")*depth
def recipes(group):
    if group==0:
        yield ordinary("empty",[])
        yield ordinary("physical-scalar",[("a",'"x"')])
        values=["null","false","true","0","-0","1","-1","256","257","-6",
            "9223372036854775807","9223372036854775808","-9223372036854775809",
            "18446744073709551615","18446744073709551616","0.0","-0.0","1.5","-2.75",
            "NaN","Infinity","-Infinity","1e309","-1e-999",
            "4.9406564584124654e-324","1.00000000000000011102230246251565404236316680908203126",
            '""','"a"','"\\u0000"','"\\ud800"','"\\udfff"','"\\ud834\\udd1e"',
            '"\\b\\f\\n\\r\\t\\\\\\/\\""','[]','{}',
            '[1, true, null, -0.0, NaN]','{"z":1,"a":2,"z":3}',
            '{"a":1,"\\u0061":2,"a":3}','{"x":{"z":[false,0.25],"a":"\\ud800"},"n":42}']
        for i,value in enumerate(values):
            for pretty in(False,True):
                yield ordinary("scalar-%d-%d"%(i,pretty),[("field",value)],pretty)
        yield ordinary("all-value-types",[(str(i),v)for i,v in enumerate(values)])
        for n in(4299,4300):
            yield ordinary("long-integer-%d"%n,[("n","-"+"9"*n)])
    elif group==1:
        for i,keys in enumerate(itertools.permutations(("z","a","m",""))):
            pairs=[(k,str(j))for j,k in enumerate(keys)]
            pairs.extend((k,quote("last-"+str(j)))for j,k in enumerate(reversed(keys)))
            yield ordinary("duplicate-order-%d"%i,pairs,i%2==0)
        yield object_case("escaped-key-duplicates",[("a",'"a"',"1"),("b",'"b"',"2"),
            ("a",'"\\u0061"','{"new":true}'),("b",'"\\u0062"',"null"),("a",'"a"','"last"')])
        for n in(1,2,3,7,8,9,31,63,64,65,255,256,257,1024,4096):
            pairs=[("key%06d"%i,str(i))for i in reversed(range(n))]
            pairs.extend(("key%06d"%i,'{"final":'+str(i)+"}")for i in range(0,n,3))
            yield ordinary("wide-order-%d"%n,pairs)
        for depth in(1,2,17,127,511):
            for obj in(False,True):
                value=chain(depth,'{"z":0,"a":[1,2,3]}',obj)
                yield ordinary("full-span-%d-%d"%(depth,obj),[("first",value),("last","true")],True)
    elif group==2:
        keys=["",'"',"\\","/","\0","\n","\t","\r","\b","\f","é","中","\u2028","\ufeff",
            "\ud800","\udfff","\U00010000","\U0010ffff","\ue000"]
        for i,key in enumerate(keys):
            yield ordinary("unicode-key-%d"%i,[(key,quote(key)),("tail",str(i))],i%2==0)
        yield object_case("astral-escaped-duplicate",[("\U0001d11e",'"\\ud834\\udd1e"',"1"),
            ("a",'"a"',"2"),("\U0001d11e",'"\U0001d11e"','"last"')])
        yield object_case("surrogate-escaped-duplicate",[("\ud800",'"\\ud800"',"1"),
            ("b",'"b"',"2"),("\ud800",'"\ud800"',"false")])
        yield ordinary("all-control-key-codepoints",[(chr(i),quote(chr(i)))for i in range(32)])
        yield ordinary("unicode-range-order",[(chr(i),str(i))for i in reversed(range(256))])
        for n in(96,97,255,256,1024,65536,262144):
            yield ordinary("unbounded-decoded-key-%d"%n,[("x"*n,quote("v"*min(n,4096)))])
        for n in(4096,65536,262144):
            yield ordinary("full-original-string-span-%d"%n,[("data",quote("xy"[0]*(n-1)+"\ud800"))])
    elif group==3:
        values=["null","false","true","0","1","-1","0.0","-0.0","NaN","Infinity",'""','"items"',"[]","[1,2,3]"]
        invalid=[""," ","\ufeff{}","\0","nul","True","+1","01","1.","1e","--1","{}x","{} {}",
            "{","[",'{1:2}','{"a"}','{"a":}','{"a":1,}','{"a":1 "b":2}',
            '{"a":"\\x"}','{"a":"\\u123"}','{"a":"\\ud800\\uQ000"}','{"a":"\n"}',
            '{"a":'+"9"*4301+"}",'{"a": [1,]}','{"a": [1 2]}']
        for i,value in enumerate(values+invalid):
            yield dict(label="nonobject-or-syntax-%d"%i,command=1,primary=value,auxiliary="",item_spans=None)
        for pre in(" ","\n","\r\n","\t"):
            yield dict(label="error-position-"+repr(pre),command=1,primary=pre+'{"a" 1}',auxiliary="",item_spans=None)
    else:raise ValueError("undeclared object items group")
def unique_recipes(group):
    seen=set()
    for prior in range(int(group)+1):
        for number,value in enumerate(recipes(prior)):
            wire=pack(value["primary"]);digest=hashlib.sha256(wire).digest()
            if digest in seen:continue
            seen.add(digest)
            if prior==int(group):yield number,value
def cases(group):
    for number,value in unique_recipes(int(group)):
        units=len(value["primary"]);wire=pack(value["primary"])
        yield dict(**value,case_id=int(group)*1000000+number,wire=wire,
            output_capacity=512+24*units,workspace_capacity=16480+40*units,
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
    for field,value in[(0,0),(1,0),(1,2),(2,LIMIT+1),(3,1),(4,0),(4,20001),(5,0),(5,20001),(6,1),(7,0)]:
        changed=headers.copy();changed[field]=value
        yield row("header-%d-%d"%(field,value),struct.pack("<8Q",*changed)+wire[64:],512,wc,0xffffffff)
    for length in(0,1,63,len(wire)-1):
        yield row("truncated-%d"%length,wire[:length],512,wc,0xffffffff)
    yield row("invalid-codepoint",wire[:64]+struct.pack("<I",0x110000)+wire[68:],512,wc,0xffffffff)
def group_count(group):return sum(1 for _ in unique_recipes(group))
def domain():
    groups=[dict(id=i,cases=group_count(i))for i in GROUPS]
    return dict(schema="hepta.runtime.python-json-items.actual-domain.v1",groups=groups,
        semantic_cases=sum(x["cases"]for x in groups),controls=sum(1 for _ in controls()),shards=4,
        parse_budget=9997,encode_budget=9997,dictionary_original_order=True,complete_original_value_spans=True)
def shard_domain(shard):
    if shard not in range(4):raise ValueError("undeclared object items shard")
    rows=[dict(id=shard,cases=group_count(shard))]
    return dict(shard=shard,groups=rows,semantic_cases=sum(r["cases"]for r in rows),
        private_native_calls=sum(1 for _ in controls())if shard==0 else 0)
def plan(shard):
    result=[(role,str(shard))for role in("original","native")]
    if shard==0:result.append(("native","controls"))
    return result
