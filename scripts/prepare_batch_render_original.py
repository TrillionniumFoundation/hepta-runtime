"""Assemble unchanged Rust owner blocks inside a byte-only reference envelope."""
from pathlib import Path
import argparse
import hashlib
import json


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original_blocks(reference):
    text = (reference / 'src/mcp/fs/text_editing.rs').read_text()
    delta = (reference / 'src/mcp/fs/delta.rs').read_text()
    line = (reference / 'src/utils/line_hash.rs').read_text()
    def section(raw, start, end):
        first = raw.index(start)
        return raw[first:raw.index(end, first)]
    return {
        'line_ids': section(line, 'fn fnv1a_8', '/// Verify a composite id'),
        'batch_operation': section(text, '#[derive(Debug, Clone)]\nstruct BatchOperation', '// Unresolved batch operation'),
        'operation_types': section(text, '#[derive(Debug, Clone, PartialEq)]\nenum OperationType', '#[derive(Debug, Clone)]\nenum UnresolvedLineRange'),
        'incoming': section(text, 'fn incoming_content_lines', 'fn sanitize_incoming_content'),
        'added_lines': section(text, 'const ECHO_WHOLE_MAX:', '// NEW REVOLUTIONARY BATCH_EDIT'),
        'shift_note': section(text, 'pub(crate) fn shift_note', '/// Atomic write:'),
        'removed_marker': section(delta, 'pub fn removed_marker', '/// One step of a line diff'),
        'batch_result': section(text, '\t// Build annotated diff for each operation', '\n\tOk(diff_output)\n}') + '\n\tOk(diff_output)\n',
    }


ROOT=Path(__file__).resolve().parents[1]

def inputs(reference, source_root=ROOT):
    from prepare_batch_body_original import PINS
    reference,source_root=Path(reference),Path(source_root)
    originals={}
    files={}
    for path in ('src/mcp/fs/text_editing.rs','src/mcp/fs/delta.rs','src/utils/line_hash.rs'):
        raw=(reference/path).read_bytes();assert sha(raw)==PINS[path],path
        name=Path(path).name;files[name]=raw
        originals[path]={'file':name,'bytes':len(raw),'sha256':sha(raw)}
    blocks=original_blocks(reference)
    source=(source_root/'tests/hia_native/oracle_batch_render.rs').read_bytes()
    assert all(source.count(value.encode())==1 for value in blocks.values())
    files['oracle_batch_render.rs']=source
    report={'schema':'hepta.runtime.batch-render-original-source.v1',
      'original_commit':'a0dcdda1991ec536d5e2d252c006a778993fa566',
      'sources':originals,'blocks':{name:{'bytes':len(value.encode()),'sha256':sha(value.encode())} for name,value in blocks.items()},
      'oracle_sha256':sha(source),'actual_execution':'PENDING'}
    files['original-sources.json']=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
    return files,report

def prepare(reference,destination,source_root=ROOT):
    files,report=inputs(reference,source_root);destination=Path(destination)
    destination.mkdir(parents=True,exist_ok=False)
    for name,data in files.items():
        with (destination/name).open('xb') as handle:handle.write(data)
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(prepare(args.reference,args.output),sort_keys=True))
