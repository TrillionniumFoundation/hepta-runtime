"""Complete iterative observation of actual JSON-value trees; no JSON parse/dump/compare."""
import struct
def scalar(value):
    kind=type(value)
    if value is None:return 0,b"",0
    if kind is bool:return(2 if value else 1),b"",0
    if kind is int:
        payload=str(value).encode("ascii");return 3,payload,len(payload)
    if kind is float:return 4,struct.pack("<d",value),8
    if kind is str:
        payload=value.encode("utf-32-le","surrogatepass");return 5,payload,len(value)
    if kind is list:return 6,b"",len(value)
    if kind is dict:return 7,b"",len(value)
    raise TypeError("non-JSON observed value")
def observe(value):
    out=bytearray();pending=[value]
    while pending:
        item=pending.pop();tag,payload,count=scalar(item)
        out.extend(struct.pack("<2Q",tag,count));out.extend(payload)
        if tag==6:pending.extend(reversed(item))
        elif tag==7:
            for key,value in reversed(list(item.items())):
                if type(key)is not str:raise TypeError("non-string observed JSON key")
                pending.extend((value,key))
    return bytes(out)
def describe(value):
    tag,payload,count=scalar(value)
    return dict(tag=tag,truth=bool(value),count=count,
        float_bits=payload.hex()if tag==4 else None),payload
def constructed(case):
    spec=case["constructed"];shape,depth,kind=spec["shape"],spec["depth"],spec["kind"]
    def deep():
        value="".join(("val","ue"))
        for _ in range(depth):value={"x":value}if shape=="object"else[value]
        return value
    if kind=="false_first":return{"z":0,"a":deep()},{"z":1,"a":deep()}
    if kind=="deep_first":return{"z":deep(),"a":0},{"z":deep(),"a":1}
    if kind=="missing_after_deep":return{"z":deep(),"a":1},{"z":deep(),"b":1}
    if kind=="missing_before_deep":return{"z":1,"a":deep()},{"b":1,"a":deep()}
    if kind=="length_diff":return{"z":deep()},{"z":deep(),"a":1}
    if kind=="duplicate_position":
        left={"z":None,"a":0};left["z"]=deep()
        return left,{"z":deep(),"a":1}
    raise ValueError("unknown frozen constructed comparison")
