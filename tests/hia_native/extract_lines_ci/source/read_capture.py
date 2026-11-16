"""Inert complete frozen graph admission, independent of producer path layout."""
from pathlib import Path
from common import ROOT, encoded, envelope, loads, pin, read, require, source
import read_builds
import read_paired
import read_capabilities


def semantic(root):
    root=Path(root);identity=source();capture=envelope(root);domain=loads(read(ROOT/'DOMAIN.json'))
    require(capture['schema']=='hepta.extract-lines.capture.v1' and capture['status']=='PASS'
            and capture['source_manifest_sha256']==identity and capture['domain']==pin(read(ROOT/'DOMAIN.json'))
            and not any(capture[k] for k in ('full_body_async_qualified','public_handler_qualified','whole_runtime_replaced')),
            'complete frozen Local body capture binding')
    rows=read_builds.processes(root/'processes',[(n,domain['process_budgets'][n]) for n in
        ('native-build','original-build','ordinary-pairs','capability-controls')])
    producer=Path(capture['producer_root']);old_source=Path(capture['source_root']);python=capture['python']
    recipes=[['native-build',[python,'-B',str(old_source/'build_native.py'),'--hepta',capture['compiler_root'],'--output',str(producer/'native')]],
        ['original-build',[python,'-B',str(old_source/'build_reference.py'),'--rust-bin',capture['rust_bin'],'--output',str(producer/'original')]],
        ['ordinary-pairs',[python,'-B',str(old_source/'run_paired.py'),'--original-build',str(producer/'original'),
            '--native-build',str(producer/'native'),'--output',str(producer/'paired')]],
        ['capability-controls',[python,'-B',str(old_source/'qualify_capabilities.py'),'--manifest',str(producer/'native/BUILD.json'),
            '--source-root',str(old_source),'--output',str(producer/'capabilities')]]]
    require(all(row['name']==name and row['argv']==argv and row['cwd']==str(old_source)
                for row,(name,argv) in zip(rows,recipes,strict=True)),'actual process command and original budget')
    native=read_builds.native(root/'native');original=read_builds.original(root/'original')
    paired=read_paired.verify(root/'paired',original['executable'],native['executable'])
    capability=read_capabilities.verify(root/'capabilities',native)
    return dict(schema='hepta.extract-lines.readonly.v1',status='COMPLETE_LOCAL_EXTRACT_BODY_READONLY_PASS',
        source_manifest_sha256=identity,native=native,original=original,paired=paired,capabilities=capability,
        native_or_rust_executions=0,reader_writes=0,full_body_async_qualified=False,
        public_handler_qualified=False,remote_qualified=False,whole_runtime_replaced=False)


def verify(output,require_controls=False):
    output=Path(output);result=semantic(output/'semantic')
    if require_controls:
        import reader_controls
        result=dict(result,reader_controls=reader_controls.verify(output,result))
    return result
