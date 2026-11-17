"""Exact original retained-build reader; no source or validation weakening."""
from pathlib import Path
import hashlib,json,stat,zipfile
from receipt_support import PIN,regular,require
import legacy_restore as restore
def ready(root):
    root=Path(root);r=json.loads(regular(root/'READY.json'));require(r['status']=='RETAINED_NATIVE118_AND_ORIGINAL_REFERENCE_READY' and r['runtime_recompiled'] is False and r['native_or_rust_executions']==0 and (r['runtime_hia_images'],r['physical_images'],r['installed_handlers'])==(118,111,10),'retained actual graph identity')
    for role,pin in restore.PINS.items():
        meta=json.loads(regular(root/(role+'.artifact.json')));require(meta['id']==pin['artifact'] and meta['digest']=='sha256:'+pin['sha256'] and meta['workflow_run']['id']==pin['run'] and meta['workflow_run']['head_sha']==pin['source'],'immutable input artifact identity')
        if role in ('native','original'):
            folder=root/role;selection=json.loads(regular(folder/'SELECTION.json'));require(selection['status']=='COMPLETE_RETAINED_ARCHIVE_STREAM_READ_PASS' and selection['zip']=={k:pin[k] for k in ('bytes','sha256')} and selection['native_or_rust_executions']==0,'complete prior archive read identity');receipt=selection['archive_receipt'];manifest_raw=regular(folder/'artifact-manifest.json');manifest=json.loads(manifest_raw);require(PIN(manifest_raw)==receipt['manifest'] and receipt['git_head']==pin['source'] and receipt['run_id']==str(pin['run']),'complete prior member inventory')
            allrows=dict(manifest['files']);allrows['artifact-manifest.json']={**receipt['manifest'],'mode':0o600};selected={n:v for n,v in allrows.items() if restore.selected(role,n)};require(selection['selected']==selected and selection['files']==len(allrows),'exact full selector inventory')
            require({p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}==set(selected)|{'SELECTION.json'},'selected retained file closure')
            for name,row in selected.items():
                path=folder/name;require(PIN(regular(path))=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE(path.stat().st_mode)==row['mode'],'complete retained member bytes/mode '+name)
            if role=='native':require(hashlib.sha256(regular(folder/'ci-package/graph/source/native/runtime_mcp_sources.json')).hexdigest()=='2c423747b2827c3a6d0993b89583c47691640ea44fcf5f77e6c0ed2aaaf0dc70','exact 425-source public graph binding')
            else:require(PIN(regular(folder/'ci-package/PACKAGE.json'))['sha256']=='fec98075c21e5761ae344d786d457144c5fb01aa48ab7427bb65748b26ea9e22','exact original reference source')
        else:
            archive=root/(role+'.zip');require(PIN(regular(archive))=={k:pin[k] for k in ('bytes','sha256')},'complete independent proof ZIP');folder=root/role
            with zipfile.ZipFile(archive) as z:
                require(z.testzip() is None and set(z.namelist())=={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()},'complete proof member set/CRC')
                for info in z.infolist():require(regular(folder/info.filename)==z.read(info.filename),'complete independently retained proof file')
            names=list(folder.rglob('READONLY.json')) if role=='native-proof' else list(folder.rglob('extract-reference-retained-read.stdout'));require(len(names)==1,'one original guarded proof');g=json.loads(regular(names[0]));require(g['before']==g['after'] and len(g['probes'])==11 and g['reader_writes']==g['native_or_rust_executions']==0 and g['source_bound_guard'] is True,'complete prior independent guarded read')
            if role=='native-proof':require(g['evidence']['status']=='COMPLETE_PUBLIC118_ARCHIVE_STREAM_READ_PASS' and g['evidence']['artifact']==14286335670,'actual native producer proof')
            else:require(g['evidence']['status']=='RETAINED_EXTRACT_REFERENCE_COMPLETE_READ_PASS' and g['evidence']['producer_conclusion_retained']=='FAIL' and g['evidence']['qualification']['controls']['refusals']==4,'actual recovered reference and original failure')
    for name,row in restore.BINARIES.items():require(PIN(regular(root/row['source']/row['path']))=={k:row[k] for k in ('bytes','sha256')},'exact executed retained binary '+name)
    return r

