"""Complete relocated record-I/O readback. No HIA, Rust, syscall effect or process execution."""
from pathlib import Path
from common import ROOT,encoded,loads,pin,read,require,sha,source,files
from protocol import cases
import read_build
import read_native
import read_original

def semantic(root):
    root=Path(root).resolve(strict=True)
    m=loads(read(root/'CAPTURE.json'))
    require(m['schema']=='hepta.audit-record-io.capture.v1' and m['status']=='PASS'
        and m['source_manifest_sha256']==source()
        and m['public_handler_qualified'] is False and m['whole_runtime_replaced'] is False,
        'successful fixed private record-I/O capture')
    require(files(root,('CAPTURE.json',))==m['files'],'every retained physical capture file')
    require(files(root/'source')==files(ROOT),'complete source set equals the admitted current frozen package')
    require(files(root/'reference')==files(ROOT/'reference'),'all fresh original source bytes')
    full=read(ROOT/'reference/request_audit.rs.txt')
    registry=loads(read(ROOT/'reference/ORIGINAL_SPANS.json'))
    require(pin(full)=={k:registry['source'][k] for k in ('bytes','sha256')}
        and registry['source']['target']=='d3d75c30719db966b004756f610007a7c723729e',
        'exact current target whole request_audit source')
    parts=[]
    for row in registry['functions']:
        raw=full[row['start_byte']:row['end_byte']]
        require(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'each unchanged full original function')
        parts.append(raw)
    exact=b'\n\n'.join(parts)+b'\n'
    require(len(parts)==16 and exact==read(ROOT/'reference/original_io.rs.txt')
        ==read(ROOT/'reference/mcp/runtime/original_io.rs.txt'),'all sixteen original function bodies unchanged')
    types=read(ROOT/'reference/mcp/runtime/original_types.rs.txt')
    require(types.rstrip() in full,'unchanged complete original Record and DurableState declarations')
    rows=read_build.custody(root,m)
    compiled=read_build.compilation(root)
    dependencies=read_build.dependencies(root)
    native=read_native.verify(root/'native',cases(ROOT))
    original=read_original.verify(root,m,native)
    require(loads(read(root/'native/NATIVE.json'))['source_manifest_sha256']==source()
        and loads(read(root/'original/ORIGINAL.json'))['source_manifest_sha256']==source(),
        'both actual processes bound to the same final source')
    return dict(schema='hepta.audit-record-io.readback.v1',status='PASS',source_manifest_sha256=source(),
        processes=len(rows),compiler=compiled,dependencies=dependencies,
        native={k:v for k,v in native.items() if k not in ('observations','events')},original=original,
        complete_filesystem_and_durable_order_equal=True,native_or_rust_executions=0,reader_writes=0,
        qualified_scope='four private record I/O functions with actual ordinary Linux effects',
        exact_serde_diagnostic_replacement=False,whole_audit_caller_qualified=False,
        public_handler_qualified=False,whole_runtime_replaced=False)

def verify(root,controls=None):
    result=semantic(root)
    if controls is not None:
        import reader_controls
        result=dict(result,controls=reader_controls.verify(controls,result))
    return result
