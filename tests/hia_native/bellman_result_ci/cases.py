"""Deterministic serializer observations; numerical results always come from HIA."""
import importlib.util
import math
from pathlib import Path
import random
import struct
import sys

def load_core(source):
    path=source/'tests/hia_native/bellman/qualify_bellman.py'
    spec=importlib.util.spec_from_file_location('bellman_result_core_cases',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def from_bits(bits):
    return struct.unpack('<d',struct.pack('<Q',bits))[0]

ELAPSED=(0,1,0x3e112e0be826d695,0x3ff0000000000000,0x3ff0000000000001,
         0x403dffffffffffff,0x403e000000000000,0x0010000000000000,0x7fefffffffffffff)
assert all(0<=value<(1<<63) and ((value>>52)&2047)!=2047 for value in ELAPSED)

def corpus(source: Path):
    core=load_core(source)
    index=0
    for name,graph,error in core.corpus():
        if error is not None:continue
        yield name,core.pack_graph(graph),ELAPSED[index%len(ELAPSED)]
        index+=1
    for mask in range(1,64):
        graph=[[core.terminal(-0. if j%2 else 0.) if mask&(1<<j) else None for j in range(6)]]
        yield f'all-action-masks-{mask}',core.pack_graph(graph),ELAPSED[mask%len(ELAPSED)]
    # Exercise finite extrema and exponent transitions through the exact imported formatter.
    patterns=[0,1,2,(1<<52)-1,1<<52,(1<<52)+1,0x3fefffffffffffff,
              0x3ff0000000000000,0x3ff0000000000001,0x7fefffffffffffff]
    rng=random.Random(678019)
    for _ in range(64):
        bits=rng.getrandbits(64)
        if (bits>>52)&2047==2047:bits^=1<<52
        patterns.append(bits)
    for i,bits in enumerate(patterns):
        for sign in (0,1<<63):
            value=from_bits(bits^sign)
            assert math.isfinite(value)
            graph=[[core.terminal(value)]+[None]*5]
            yield f'float-{i}-{sign>>63}',core.pack_graph(graph),ELAPSED[i%len(ELAPSED)]
    wide=[core.terminal(value) for value in (sys.float_info.max,-sys.float_info.max,
                                          from_bits(1),-from_bits(1),-0.,0.)]
    yield 'maximum-4096-wide-finite',core.pack_graph([wide]*4096),ELAPSED[5]

def malformed(base):
    yield 'empty',b''
    yield 'header-short',base[:63]
    yield 'truncated',base[:-1]
    yield 'trailing',base+b'X'
    def edit(*changes):
        raw=bytearray(base)
        for at,value in changes:struct.pack_into('<Q',raw,at,value)
        return bytes(raw)
    core=struct.unpack_from('<Q',base,16)[0]
    count=struct.unpack_from('<Q',base,72)[0]
    commit=64+core
    for name,at,value in [
        ('magic',0,0),('operation',8,2),('core-extent',16,199),('commitment-extent',24,127),
        ('elapsed-nan',32,0x7ff8000000000001),('elapsed-infinity',32,0x7ff0000000000000),
        ('elapsed-negative',32,0xbff0000000000000),('elapsed-negative-zero',32,1<<63),
        ('header-reserved-0',40,1),('header-reserved-1',48,1),('header-reserved-2',56,1),
        ('core-magic',64,0),('zero-count',72,0),('large-count',72,4097),('legal-count',80,0),
        ('continuing-count',88,count*2+1),('branch-count',96,24577),('zero-branches',104,24577),
        ('probability-nan',112,0x7ff8000000000000),('work-charge',120,0),
        ('exact-ties',128,count+1),('near-ties',136,count+1),('minimum-flag',144,2),
        ('minimum-nan',152,0x7ff8000000000000),('residual-infinity',160,0x7ff0000000000000),
        ('core-reserved-0',168,1),('core-reserved-1',176,1),('core-reserved-2',184,1),
        ('state-mask-zero',192,0),('state-mask-high',192,64),('state-action-high',200,6),
        ('state-action-absent',200,1),('state-value-different',208,0),
        ('state-q-nan',216,0x7ff8000000000000),('state-absent-q',224,1),
        ('commitment-magic',commit,0),('commitment-size',commit+8,8388609),
        ('commitment-reserved-0',commit+112,1),('commitment-reserved-1',commit+120,1),
    ]:yield name,edit((at,value))
    yield 'minimum-absent-nonzero',edit((144,0),(152,1))
