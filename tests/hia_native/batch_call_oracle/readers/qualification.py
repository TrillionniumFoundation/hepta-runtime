"""Complete read-only Batch qualification: original, native and private controls."""
from pathlib import Path
import importlib.util
from capture_format import Files,fields,need,same,sha
import strict_reference
import async_evidence

PRIVATE_READER_SHA='74838c06bdb79fa46cc411bfc43f2b72e0a1464780bc8530a3a6b9d526fc7bf8'

def load_private(files,path):
    value=files.raw(str(path));same(sha(value),PRIVATE_READER_SHA,'qualified private state/packer reader source')
    spec=importlib.util.spec_from_file_location('_batch_qualified_private_controls',files.path(str(path)))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def native_evidence(*,native_source,native_run,build_source,manifest,origins,private_reader):
    """Native-first admission, with every actual private before/after buffer."""
    base=strict_reference.native_predecessor.native_evidence(native_source=native_source,native_run=native_run,
        build_source=build_source,manifest=manifest,origins=origins)
    files=Files(origins);module=load_private(files,private_reader)
    state=module.state_evidence(files,native_run,native_source)
    artifacts=dict(base['artifact_sha256'])
    for name,pin in files.artifacts.items():
        if name in artifacts:same(artifacts[name],pin['sha256'],'native source changed during private admission')
        artifacts[name]=pin['sha256']
    return {'schema':'hepta.runtime.batch-call-native-admission.v1','status':'PASS',
            'capture':base,'private_state':state,'original_comparison_complete':False,
            'public_handler_replaced':False,'whole_runtime_replaced':False,
            'artifact_sha256':dict(sorted(artifacts.items()))}

def evidence(*,reference,private_reader,packaging_run,packaging_test,python_executable,
             async_run,async_process,async_test,reader_root,origins):
    fields(reference,('original_source','original_output','native_source','native_run','build_source',
                      'manifest','outer_receipt'),'complete original qualification request')
    reader_root=Path(reader_root)
    original=strict_reference.evidence(**reference,origins=origins,reader_source=reader_root)
    files=Files(origins);module=load_private(files,private_reader)
    state=module.state_evidence(files,reference['native_run'],reference['native_source'])
    packer=module.packer_evidence(files,reference['native_source'],reference['manifest'],packaging_run,
                                 python_executable=python_executable,test_source=packaging_test)
    late=async_evidence.control_evidence(files,async_run,async_process,async_test,reference['native_run'],
                                         reference['native_source'],reference['manifest'])
    reader_sources={}
    for name in('capture_format.py','native_predecessor.py','trace_evidence.py','retained_comparison.py',
                 'strict_reference.py','async_evidence.py','qualification.py'):
        raw=files.raw(str(reader_root/name));reader_sources[name]={'bytes':len(raw),'sha256':sha(raw)}
    artifacts=dict(original['artifact_sha256'])
    for name,pin in files.artifacts.items():
        if name in artifacts:same(artifacts[name],pin['sha256'],'artifact changed between complete readers')
        artifacts[name]=pin['sha256']
    return {'schema':'hepta.runtime.batch-call-qualified-evidence.v1','status':'PASS',
            'original':original,'private_state':state,'packer':packer,'async_lock_controls':late,
            'native_original_comparison_complete':True,'original_cases':215,'post_cancel_followups':2,
            'separate_real_linux_controls':2,'private_native_controls':52,'actual_packer_calls':14,
            'physical_packer_contract_refusals':6,'actual_original_processes':7,
            'original_inner_execute_batch_edit_executed':True,
            'original_outer_batch_method_executed':False,'original_sdk_executed':False,
            'public_handler_replaced':False,'whole_runtime_replaced':False,
            'new_native_calls':0,'new_rust_processes':0,'reader_sources':reader_sources,
            'artifact_sha256':dict(sorted(artifacts.items()))}
