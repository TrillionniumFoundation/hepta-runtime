"""Two-state signed-zero diagnostic permutations for original Rust replay."""
import argparse
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
from qualify_bellman import terminal,pack_graph,reference

def main():
    p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();sys.dont_write_bytecode=True;sys.path.insert(0,str(a.runtime/'scripts'))
    from hia_native_loader import NativeModule
    raw=a.manifest.read_bytes();module=NativeModule(a.manifest,manifest_sha256=hashlib.sha256(raw).hexdigest())
    patterns=list(itertools.product((-0.,0.),repeat=3));inputs=bytearray();outputs=bytearray();count=0
    for first,second in itertools.product(patterns,repeat=2):
        graph=[[terminal(x)for x in pattern]+[None]*3 for pattern in (first,second)]
        wire=pack_graph(graph);expected=reference(graph)
        actual=module.invoke(wire,output_capacity=len(expected),workspace_capacity=len(expected))
        assert actual==expected,(first,second)
        inputs.extend(struct.pack('<Q',len(wire))+wire)
        outputs.extend(struct.pack('<QQ',0,len(actual))+actual);count+=1
    a.output.mkdir();(a.output/'inputs.bin').write_bytes(inputs);(a.output/'native.bin').write_bytes(outputs)
    (a.output/'inputs.bin.gz').write_bytes(gzip.compress(inputs,mtime=0))
    report={'status':'PASS','native_graph_cases':count,'reference':'Python hardware; original Rust replay separately required',
        'manifest_sha256':hashlib.sha256(raw).hexdigest(),
        'files':{f.name:{'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in a.output.iterdir()}}
    (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
