"""Complete finite serial state corpus; expected observations are not inputs."""
from __future__ import annotations
import struct

TOKEN = b"X" * 32
OTHER = b"Y" * 32
GOOD = [(b"x-hepta-runtime-token", TOKEN)]
INVALID = 0xffffffff
CAPACITY = 0xfffffffe
FORBIDDEN = 0xffffffdf
UNAUTHORIZED = 0xffffffde
MISSING = 0xffffffdd
OWNER = 0xffffffdc
CHANGED = 0xffffffdb
CRYPTO = 0xffffffda
LEGACY_COUNTS={"native_entries":[333,0,18,95,0,15,77,84,164],"native_public_requests":112,
    "native_lifecycle_calls":23,"native_contexts":20,"synthetic_entropy_contexts":20,
    "synthetic_ack_controls":1,"fixture_os_effects":133,"trusted_extension_fixture_transfers":2,
    "original_rust_replays":0}

def wire(op=3, headers=GOOD, payload=b""):
    value = b"HRAUTR01" + struct.pack("<3Q", op, len(headers), len(payload))
    for name, data in headers:
        value += struct.pack("<2Q", len(name), len(data)) + name + data
    return (value + payload).hex().encode()

def plan():
    rows = []
    def add(context, operation, **fields):
        rows.append(dict(context=context, operation=operation, **fields))
    def start(context, mode=2, token=TOKEN, entropy_fail=0, owner_error=0):
        add(context, "start", mode=mode, token_file_hex=(token+b"\n").hex(), file_mode=0o600,
            entropy_seed=7, entropy_fail=entropy_fail, owner_error=owner_error, owner_failure=bool(owner_error),
            missing_file=False, direct_missing_extension_fixture=mode==3)
    def query(context=1, op=3, headers=GOOD, payload=b"", code=0, capacity=256):
        add(context, "request", request_op=op, headers=[[n.hex(),v.hex()] for n,v in headers],
            payload_hex=payload.hex(), expected_semantic_code=code, capacity=capacity)
    start(1)
    query(op=0)
    # Malformed qualification transport is a native ABI domain, not Rust HTTP.
    good = wire()
    malformed = [b"", b"0", b"gg", good.upper(), b"00"+good[2:], good[:-2], good+b"00",
        wire(4), wire(3,payload=b"x"), wire(1,payload=b"x"), wire(0,payload=b"x")]
    raw = bytearray.fromhex(good.decode())
    for offset in (16,24,32,40):
        changed=bytearray(raw);struct.pack_into("<Q",changed,offset,(1<<64)-1);malformed.append(bytes(changed).hex().encode())
    for i, value in enumerate(malformed):
        add(1,"abi-control",name="malformed-%02d"%i,wire_hex=value.hex(),expected_code=INVALID)
    query()
    query(op=1)
    query(op=2,payload=b"complete current target owner binding")
    for cap in (0,7,8,167,168,169,256,8<<20):
        query(capacity=cap)
    query(headers=[] ,code=UNAUTHORIZED)
    for index in range(32):
        value=bytearray(TOKEN);value[index]=ord('Y')
        query(headers=[(b"x-hepta-runtime-token",bytes(value))],code=UNAUTHORIZED)
    for value in (b"",b"wrong",TOKEN+b" ",b" "+TOKEN,b"\xff"*32,b"z"*((1<<20)+1)):
        query(headers=[(b"x-hepta-runtime-token",value)],code=UNAUTHORIZED)
    for value in (b"",b"null",b"https://fixture.invalid",b"\t"):
        query(headers=GOOD+[(b"OrIgIn",value)],code=FORBIDDEN)
    query(headers=[(b"X-HePtA-RuNtImE-ToKeN",TOKEN)])
    query(headers=GOOD+[(b"x-hepta-runtime-token",b"wrong")])
    query(headers=[(b"x-hepta-runtime-token",b"wrong")]+GOOD,code=UNAUTHORIZED)
    start(2,token=OTHER)
    query(2,headers=[(b"x-hepta-runtime-token",OTHER)])
    add(1,"replace_verified_extension",source_context=2,adapter_only=True)
    query(code=CHANGED)
    add(1,"restore_verified_extension",adapter_only=True)
    query()
    add(1,"reconnect")
    query(op=0)
    query()
    for i,fields in [(3,dict(mode=1)),(4,dict(mode=1,owner_error=5)),
                     (5,dict(mode=1,entropy_fail=1)),(6,dict(mode=3)),(7,dict(owner_error=5))]:
        start(i,**fields)
        code=OWNER if i==4 else MISSING if i==6 else 0
        query(i,headers=[],code=UNAUTHORIZED if i==7 else code)
        if i==7:query(i)
        query(i,op=1,headers=GOOD if i==7 else [],code=code)
        if i==5:query(i,op=2,headers=[],payload=b"unchanged crypto selection",code=CRYPTO)
        query(i,headers=GOOD if i==7 else [],code=code)
    # Capacity on the very first resolve must not roll back owner binding.
    start(8)
    query(8,capacity=0)
    query(8)
    add(8,"replace_verified_extension",source_context=2,adapter_only=True)
    query(8,code=CHANGED)
    add(8,"restore_verified_extension",adapter_only=True)
    query(8)
    for i in range(1,9):add(i,"shutdown")
    return rows
