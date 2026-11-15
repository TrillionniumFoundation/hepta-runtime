"""Extract original Rust bodies byte-for-byte into a test-only replay carrier."""
from pathlib import Path
import argparse
import hashlib
import json

HERE = Path(__file__).resolve().parent
ORIGINAL_SOURCES={
    'src/mcp/fs/text_editing.rs':('e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590','4a8114e72a51238608201e108288294c6282ab20'),
    'src/mcp/fs/delta.rs':('a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1','76681c01b571536e80f5bd1b93d79053d9df8985'),
    'src/utils/line_hash.rs':('904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57','0e521656ba24869dbc05afc51d62aa4af79b5e44'),
    'tests/hia_native/oracle_batch_apply.rs':('f437e4272035abeea35d6f50bda66870ff4292aae93c031e8db041060749a2db','8d9099216de2eadf346536a6161727c63deaa3ce'),
}


def assemble(runtime, output):
    for name,(sha,blob) in ORIGINAL_SOURCES.items():
        raw=(runtime/name).read_bytes()
        assert hashlib.sha256(raw).hexdigest()==sha,name
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==blob,name
    original=(runtime/'src/mcp/fs/text_editing.rs').read_text()
    delta=(runtime/'src/mcp/fs/delta.rs').read_text()
    line_hash=(runtime/'src/utils/line_hash.rs').read_text()
    apply=(runtime/'tests/hia_native/oracle_batch_apply.rs').read_text()
    def between(text,start,end):
        assert text.count(start)==1,(start,text.count(start))
        at=text.index(start);stop=text.index(end,at)
        return text[at:stop]
    blocks={
      'batch_operation':between(original,'#[derive(Debug, Clone)]\nstruct BatchOperation','// Unresolved batch operation'),
      'operation_types':between(original,'#[derive(Debug, Clone, PartialEq)]\nenum OperationType','#[derive(Debug, Clone)]\nenum UnresolvedLineRange'),
      'editable_and_incoming':between(original,'const LF_ENDING:','fn sanitize_incoming_content'),
      'guards_and_apply':between(original,'fn is_structural_noise',"// Parse an operation's `start`"),
      'batch_guards':between(original,'\t// Check for conflicts between operations','\n\tlet edited = apply_batch_operations'),
      'line_ids':between(line_hash,'fn fnv1a_8','/// Verify a composite id'),
      'push_added_lines':between(original,'const ECHO_WHOLE_MAX:','// NEW REVOLUTIONARY BATCH_EDIT'),
      'shift_note':between(original,'pub(crate) fn shift_note','/// Atomic write:'),
      'removed_marker':between(delta,'pub fn removed_marker','/// One step of a line diff;'),
      'post_write_render':between(original,'\t// Build annotated diff for each operation','\n\tOk(diff_output)\n}')+'\n\tOk(diff_output)\n',
    }
    # The existing original carrier already contains unchanged original apply
    # and duplicate/conflict helpers. Only its test-owned transport is replaced.
    prefix=apply[:apply.index('pub fn evaluate(raw: &str, rows:')]
    for name in ('batch_operation','operation_types','editable_and_incoming','guards_and_apply','batch_guards','line_ids'):
        assert prefix.count(blocks[name])==1,name
    source=prefix+blocks['push_added_lines']+blocks['shift_note']
    source+='fn render_diff(original_content: &str, final_content: &str, batch_operations: Vec<BatchOperation>) -> Result<String> {\n\tlet original_lines: Vec<&str> = original_content.lines().collect();\n'
    source+=blocks['post_write_render']+'}\n'+(HERE/'src/carrier.rs').read_text()
    source+='\nmod delta {\nuse crate::original::line_id_at;\n'+blocks['removed_marker']+'}\n'
    source+='\nmod utils { pub mod line_hash { pub use crate::original::line_id; } }\n'
    sha=lambda b:hashlib.sha256(b).hexdigest()
    record={'schema':'hepta.runtime.batch-diff-original-source.v1',
            'runtime_root':str(runtime),'sources':{},'blocks':{},
            'generated_source_sha256':sha(source.encode()),'filesystem_effects_executed':False}
    for name in ('src/mcp/fs/text_editing.rs','src/mcp/fs/delta.rs','src/utils/line_hash.rs','tests/hia_native/oracle_batch_apply.rs'):
        raw=(runtime/name).read_bytes()
        record['sources'][name]={'bytes':len(raw),'sha256':sha(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    for name,value in blocks.items():
        assert source.count(value)==1,name
        record['blocks'][name]={'bytes':len(value.encode()),'sha256':sha(value.encode())}
    if output is None:
        return source,record
    output.mkdir(parents=True,exist_ok=False)
    (output/'main.rs').write_text(source)
    (output/'source-manifest.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    return record


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(assemble(args.runtime,args.output),sort_keys=True))

