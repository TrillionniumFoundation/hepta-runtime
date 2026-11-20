"""Read exact source edits and reconstruct their original published bytes."""
from pathlib import Path
import argparse,hashlib,json

def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())

def read(root,record):
    root=Path(root).resolve(strict=True)
    assert record['schema']=='hepta.runtime.shell-consumer-source-change.v1'
    assert record['parent_commit']=='43426460fda1f7576127281a114306f4ae95e64b'
    assert len(record['modified'])==5 and len(record['added'])==2
    for name,row in record['modified'].items():
        raw=(root/name).read_bytes();assert pin(raw)==row['candidate'],name
        current=raw.decode().splitlines(True);original=current[:]
        for edit in reversed(row['edits']):
            start,end=edit['candidate_range'];assert original[start:end]==edit['candidate'],name
            original[start:end]=edit['original']
        assert pin(''.join(original).encode())==row['original'],name
        for edit in reversed(row['edits']):
            start,end=edit['original_range'];assert original[start:end]==edit['original'],name
            original[start:end]=edit['candidate']
        assert original==current,name
    for group in ('added','unchanged_hia_assembly_and_outcome'):
        for name,expected in record[group].items():assert pin((root/name).read_bytes())==expected,name
    assert record['original_native_timeout_seconds']==180 and record['modified_workflows']==[]
    for name in ('live_allocator_gate_removed','whole_runtime_replaced','public_binary_write_registered','old_stack_removal_qualified'):
        assert record[name] is False,name
    return dict(status='EXACT_SHELL_CONSUMER_SOURCE_INVERSE_PASS',modified=5,added=2,
                unchanged=len(record['unchanged_hia_assembly_and_outcome']),native_executions=0,
                compiler_executions=0,rust_executions=0,whole_runtime_replaced=False)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args()
    record=json.loads((Path(__file__).resolve().parent/'v1/SOURCE_CHANGE.json').read_bytes())
    print(json.dumps(read(args.root,record),sort_keys=True))

if __name__=='__main__':main()
