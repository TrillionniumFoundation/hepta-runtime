"""Frozen original-only recursion/call-site profiles; deterministic input recipes."""
LEAVES={"zero":("0",0),"large":("257",257),"none":("null",None),"true":("true",True),
    "char":('"x"',"x"),"string":('"value"',"value"),"half":("0.5",0.5),
    "emptylist":("[]",[]),"emptydict":("{}",{}),"nan":("NaN",None),"inf":("Infinity",None),
    "overflow":("1e999",None),"invalid":("!",None),"unicode":('"\\uQ000"',None),"missing":('"',None)}
SHAPES=("array","object","alternating")
def text(shape,depth,leaf):
    start=[];end=[]
    for i in range(depth):
        obj=shape=="object"or(shape=="alternating"and i%2)
        start.append('{"x":'if obj else"[");end.append("}"if obj else"]")
    return "".join(start)+LEAVES[leaf][0]+"".join(reversed(end))
def constructed(shape,depth,leaf):
    raw,value=LEAVES[leaf]
    if leaf=="emptylist":value=[]
    elif leaf=="emptydict":value={}
    elif leaf=="large":value=int("257")
    elif leaf=="string":value="".join(("val","ue"))
    elif leaf=="half":value=float("0.5")
    elif leaf=="nan":
        from json.decoder import NaN
        value=NaN
    elif leaf=="inf":
        from json.decoder import PosInf
        value=PosInf
    elif leaf=="overflow":value=float("1e999")
    elif leaf in("invalid","unicode","missing"):raise ValueError("no object for malformed JSON")
    for i in reversed(range(depth)):
        obj=shape=="object"or(shape=="alternating"and i%2)
        value={"x":value}if obj else[value]
    return value
def recipes(group):
    group=int(group)
    if group not in range(6):raise ValueError("undeclared original profile")
    mode=("parse","dump","equal")[group%3];boundary=group>=3
    for shape in SHAPES:
        depths=range(1400,1521)if boundary else range(1601)
        leaves=tuple(k for k in LEAVES if k!="zero")if boundary and mode=="parse"else(
            tuple(k for k in LEAVES if k not in("zero","invalid","unicode","missing"))if boundary else("zero",))
        for leaf in leaves:
            for depth in depths:
                if not boundary and ((depth==0 and shape!="array")or(depth==1 and shape=="alternating")):continue
                yield dict(mode=mode,shape=shape,leaf=leaf,depth=depth)
def cases(group):
    for number,row in enumerate(recipes(group)):
        yield dict(case_id=int(group)*1000000+number,label=":".join(str(row[k])for k in("mode","shape","leaf","depth")),**row)
def domain():
    rows=[dict(group=i,cases=sum(1 for _ in recipes(i)))for i in range(6)]
    return dict(schema="hepta.runtime.python-json-value.original-depth-domain.v1",groups=rows,
        calls=sum(x["cases"]for x in rows),one_target_operation_per_case=True,
        parse_mode="actual json.loads(bytes)",dump_mode="actual json.dumps(sort_keys=True)",
        equal_mode="actual Python == on freshly constructed JSON-value trees",
        native_applications=0,application_replay=False)
