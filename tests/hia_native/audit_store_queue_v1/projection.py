"""Frozen observable original projection; remaining native boundaries remain model-only."""
import struct
COUNTS=(1,2,3,32,65,257)
FIFO_ROWS=(0,4,5,6,7,8,9,10,13,14,15,19,20,23,24,25)
def selected(scenario,ordinal,row):
    if "request_hex" not in row:return False
    op=struct.unpack_from("<Q",bytes.fromhex(row["request_hex"]),8)[0]
    return (scenario<6 and op in (0,3,5,8)) or (scenario==6 and ordinal in FIFO_ROWS)
def project(scenario,output,workspace):
    values=struct.unpack("<8s15Q",output)
    assert values[0]==b"HAUDLR01"
    op,result=values[1:3]
    if op in (3,4):
        assert result==3
        result=0
    state=struct.unpack_from("<8s15Q",workspace)
    assert state[0]==b"HAUDLS01"
    waiting=[]
    for offset in range(128,state[8],80):
        ticket,access,phase=struct.unpack_from("<3Q",workspace,offset)
        if phase==1:waiting.append((ticket,access))
    assert len(waiting)==values[12]
    return struct.pack("<8s10Q",b"HAUDOR01",scenario,op,result,*values[6:13])+b"".join(
        struct.pack("<2Q",*pair) for pair in waiting)
def expected(domain):
    result=[]
    assert [s["name"] for s in domain["scenarios"][:6]]==["adjacent-readers-"+str(n) for n in COUNTS]
    assert domain["scenarios"][6]["name"]=="writer-reader-writer-reader-fifo"
    for scenario,case in enumerate(domain["scenarios"]):
        for ordinal,row in enumerate(case["rows"]):
            if selected(scenario,ordinal,row):
                result.append(project(scenario,bytes.fromhex(row["output_hex"]),bytes.fromhex(row["state_hex"])))
    assert len(result)==748
    return b"".join(result)
