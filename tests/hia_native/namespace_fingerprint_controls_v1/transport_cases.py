"""Fixed native admission controls; only owned allocations/NULL and trusted libc capabilities."""
import struct
from common import ROOT,require
from protocol import domain
from callable_contract import initial
INVALID=0xffffffff
CAPACITY=0xfffffffe
BUSY=0xfffffffd
MECHANICAL=0xfffffffc
def u64(value):return struct.pack("<Q",value).hex()
SPECS=[
    ("initialize","short-context",{"capacity":32767},(),CAPACITY),
    ("initialize","empty-context",{"capacity":0},(),CAPACITY),
    ("initialize","null-context",{"context":0},(),INVALID),
    ("initialize","unaligned-context",{"context":"context+1"},(),INVALID),
    ("initialize","null-table",{"table":0},(),INVALID),
    ("initialize","unaligned-table",{"table":"table+1"},(),INVALID),
    ("initialize","out-of-range-root",{"directory":1<<31},(),INVALID),
    ("initialize","reserved-table-word",{},(("table",48,u64(1)),),INVALID),
    ("initialize","dirty-context-head",{},(("context",0,"01"),),INVALID),
    ("initialize","dirty-context-middle",{},(("context",16384,"01"),),INVALID),
    ("initialize","dirty-context-tail",{},(("context",32767,"01"),),INVALID),
    ("initialize","user-without-callback",{"user":1},(),INVALID),
    ("initialize","overlapping-table",{"table":"context"},(),INVALID),
]
for at in range(0,48,8):SPECS.append(("initialize","zero-function-%d"%at,{},(("table",at,u64(0)),),INVALID))
SPECS+=[
    ("entry","empty-input",{"input_bytes":0},(),INVALID),
    ("entry","short-input",{"input_bytes":63},(),INVALID),
    ("entry","oversized-input",{"input_bytes":65},(),INVALID),
    ("entry","empty-output",{"output_capacity":0},(),CAPACITY),
    ("entry","output-31",{"output_capacity":31},(),CAPACITY),
    ("entry","output-127",{"output_capacity":127},(),CAPACITY),
    ("entry","empty-context",{"capacity":0},(),CAPACITY),
    ("entry","short-context",{"capacity":32767},(),CAPACITY),
    ("entry","null-input",{"input":0},(),INVALID),
    ("entry","null-output",{"output":0},(),INVALID),
    ("entry","null-context",{"context":0},(),INVALID),
    ("entry","unaligned-context",{"context":"context+1"},(),INVALID),
    ("entry","overlapping-input-output",{"output":"input"},(),INVALID),
    ("entry","overlapping-input-context",{"input":"context"},(),INVALID),
    ("entry","overlapping-output-context",{"output":"context"},(),INVALID),
    ("entry","bad-context-magic",{},(("context",0,"00"),),INVALID),
    ("entry","busy-context",{},(("context",8,u64(1)),),BUSY),
    ("entry","poisoned-context",{},(("context",8,u64(2)),),MECHANICAL),
    ("entry","invalid-life",{},(("context",8,u64(3)),),MECHANICAL),
    ("entry","borrowed-errno-live",{},(("context",48,u64(1)),),INVALID),
    ("entry","owned-fd-live",{},(("context",112,u64(0)),),INVALID),
    ("entry","owned-dir-live",{},(("context",120,u64(1)),),INVALID),
    ("entry","ambient-errno-live",{},(("context",136,u64(1)),),INVALID),
    ("entry","poison-marker",{},(("context",160,u64(1)),),INVALID),
    ("entry","root-overflow",{},(("context",24,u64(1<<31)),),INVALID),
    ("entry","user-without-callback",{},(("context",40,u64(1)),),INVALID),
    ("entry","zero-generation",{},(("input",16,u64(0)),),INVALID),
    ("entry","stale-generation",{},(("context",16,u64(1)),),INVALID),
    ("entry","later-prior-generation",{},(("context",16,u64(2)),),INVALID),
    ("entry","wrong-operation",{},(("input",8,u64(2)),),INVALID),
    ("entry","zero-root-capability",{},(("input",24,u64(0)),),INVALID),
    ("entry","wrong-root-capability",{},(("input",24,u64(2)),),INVALID),
]
for at in range(8):SPECS.append(("entry","input-magic-%d"%at,{},(("input",at,"00"),),INVALID))
for at in range(64,112,8):SPECS.append(("entry","zero-copied-function-%d"%at,{},(("context",at,u64(0)),),INVALID))
for at in range(192,256,8):SPECS.append(("entry","context-reserved-%d"%at,{},(("context",at,u64(1)),),INVALID))
for at in range(32,64,8):SPECS.append(("entry","input-reserved-%d"%at,{},(("input",at,u64(1)),),INVALID))
SPECS+=[
    ("dispose","empty-context",{"capacity":0},(),CAPACITY),
    ("dispose","short-context",{"capacity":32767},(),CAPACITY),
    ("dispose","null-context",{"context":0},(),INVALID),
    ("dispose","unaligned-context",{"context":"context+1"},(),INVALID),
    ("dispose","wrong-magic",{},(("context",0,"00"),),INVALID),
    ("dispose","busy-context",{},(("context",8,u64(1)),),BUSY),
    ("dispose","bad-life",{},(("context",8,u64(3)),),INVALID),
    ("dispose","live-errno",{},(("context",48,u64(1)),),INVALID),
    ("dispose","owned-fd",{},(("context",112,u64(0)),),INVALID),
    ("dispose","owned-dir",{},(("context",120,u64(1)),),INVALID),
]
SPECS=tuple(SPECS)
def source_case():
    rows=[r for r in domain(ROOT)["cases"]if r["name"]=="regular-file-root"and r["root_kind"]=="file"]
    require(len(rows)==1,"one original regular-file-root case");return rows[0]
def wire():return initial(1)
def defaults(function):
    if function=="initialize":return dict(context="context",capacity=32768,directory="root",table="table",observer=0,user=0)
    if function=="entry":return dict(input="input",input_bytes=64,output="output",output_capacity=128,context="context",capacity=32768)
    require(function=="dispose","fixed actual export");return dict(context="context",capacity=32768)
def argv(function,parameters,addresses):
    order={"initialize":("context","capacity","directory","table","observer","user"),
           "entry":("input","input_bytes","output","output_capacity","context","capacity"),
           "dispose":("context","capacity")}[function]
    values=[]
    for name in order:
        value=parameters[name]
        if type(value)is str:
            parts=value.split("+");require(len(parts)in(1,2)and parts[0]in addresses,"only actual owned allocation")
            value=addresses[parts[0]]+(int(parts[1])if len(parts)==2 else 0)
        require(type(value)is int and 0<=value<1<<64,"exact real native ABI argument");values.append(value)
    return values
def mutate(buffers,changes):
    result={k:bytearray(v)for k,v in buffers.items()}
    for key,offset,hexadecimal in changes:
        raw=bytes.fromhex(hexadecimal);require(0<=offset<=len(result[key])and len(raw)<=len(result[key])-offset,"owned mutation extent")
        result[key][offset:offset+len(raw)]=raw
    return{k:bytes(v)for k,v in result.items()}
def sequence(spec):
    function,name,overrides,changes,expected=spec;rows=[]
    if function!="initialize":rows.append(("before-init","initialize",defaults("initialize"),(),0))
    rows.append(("refusal",function,dict(defaults(function),**overrides),changes,expected))
    if function=="initialize":rows.append(("recovery-init","initialize",defaults("initialize"),(),0))
    rows+=[("recovery-run","entry",defaults("entry"),(),128),("recovery-dispose","dispose",defaults("dispose"),(),0)]
    return rows
