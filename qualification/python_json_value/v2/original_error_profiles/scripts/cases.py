"""Frozen new malformed inputs resolving C-error construction at the parse bound."""
LEAVES={
 "control":('"a\n"',None),"escape_q":('"\\q"',None),"unicode_short":('"\\u123"',None),
 "property":('{x:0}',None),"colon":('{"x",0}',None),"array_comma":('[0 1]',None),
 "object_comma":('{"x":0 "y":1}',None),"array_badvalue":('[tru]',None),
 "object_badvalue":('{"x":nul}',None),"integer4301":("1"+"0"*4300,None),
 "negative_integer4301":("-"+"1"+"0"*4300,None),"key_unterminated":('{"x:',None),
 "string_backslash":('"x\\',None),"key_unicode":('{"\\uQ000":0}',None),
 "array_trailing":('[0,]',None),"object_trailing":('{"x":0,}',None)}
SHAPES=("array","object","alternating")
def text(shape,depth,leaf):
    start=[];end=[]
    for i in range(depth):
        obj=shape=="object"or(shape=="alternating"and i%2)
        start.append('{"x":'if obj else"[");end.append("}"if obj else"]")
    return "".join(start)+LEAVES[leaf][0]+"".join(reversed(end))
def constructed(*args):raise AssertionError("malformed parse profiles have no constructed operand")
def recipes(group):
    group=int(group)
    if group not in range(3):raise ValueError("undeclared error-depth original profile")
    for leaf in LEAVES:
        for depth in[0,*range(9989,9999)]:
            if depth==0 and group!=0:continue
            yield dict(mode="parse",shape=SHAPES[group],leaf=leaf,depth=depth)
def cases(group):
    for number,row in enumerate(recipes(group)):
        yield dict(case_id=int(group)*1000000+number,label=":".join(str(row[k])for k in("mode","shape","leaf","depth")),**row)
def domain():
    rows=[dict(group=i,cases=sum(1 for _ in recipes(i)))for i in range(3)]
    return dict(schema="hepta.runtime.python-json-value.original-error-depth-domain.v1",groups=rows,
        calls=sum(x["cases"]for x in rows),one_target_operation_per_case=True,
        parse_mode="actual json.loads(bytes)",dump_mode="not called",equal_mode="not called",
        native_applications=0,application_replay=False)
