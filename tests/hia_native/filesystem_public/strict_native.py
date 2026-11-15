"""Independent admission of the source-bound fresh FS public/native pair.

The public build freshly compiles the shared 58 members exactly once; the
private fixture reuses those exact images. Cold bootstrap is a separate gate.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import stat
import sys
sys.dont_write_bytecode = True

BUILD_READER_SHA = '44850ccdd0e63c50b3f04cb45ba80d2266ca64710ae24f2aa46e96cc031d2afa'
BUILD_PRIMITIVE_SHA = '2271320cf5d8f114d4496f773285cbd94d9cc4cc9eb931d35b37d24e94d84e5e'


def load(path, name, expected=None):
    path = Path(path).absolute()
    for item in [*reversed(path.parents), path]:
        if item.is_symlink(): raise ValueError('FS native admission: source symlink')
    if not stat.S_ISREG(path.stat().st_mode): raise ValueError('FS native admission: source not regular')
    raw = path.read_bytes()
    if expected is not None and hashlib.sha256(raw).hexdigest() != expected: raise ValueError('FS native admission: frozen reader changed')
    spec = importlib.util.spec_from_file_location(name, path); module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__); return module


def _bound(*, native_capture, original_reader, native_source, build_reader, build_primitive, artifact_reader):
    here = Path(__file__).absolute().parent
    observation = load(here/'strict_observations.py','_fs_final_observation')
    reference = load(here/'strict_original.py','_fs_final_original'); q = reference.bootstrap(original_reader)
    captured = q.Binder(native_capture); binding = captured.json('SOURCE.json'); corpus = captured.json('INPUTS.json')
    graph = load(build_reader,'_fs_final_dual_build',BUILD_READER_SHA)
    primitive = Path(build_primitive).absolute()
    q.same(q.sha(primitive.read_bytes()),BUILD_PRIMITIVE_SHA,'frozen link/compile reader identity')
    public_manifest = Path(binding['builds']['public']['path']); private_manifest = Path(binding['builds']['fixture']['path'])
    build = graph.dual_build_evidence(Path(native_source),public_manifest,private_manifest,
        read_bytes=artifact_reader,reader_path=primitive)
    q.need(build['shared_fresh_member_qualification'] is True and build['fresh_cold_qualified'] is False,
           'shared member compilation and cold-bootstrap domains')
    provenance = load(here/'strict_native_provenance.py','_fs_final_provenance').provenance(q,native_capture,corpus,reference,build)
    # Source/reader physical locations may change. Their admitted identities are
    # stable logical names; actual execution paths inside every receipt stay intact.
    current_source = Path(native_source).absolute(); old_source = Path(binding['native_source_root'])
    remap = {str(Path(build_reader).absolute()):'build-reader/dual_build_evidence.py',
             str(primitive):'build-reader/qualification-reader-v1.py'}
    normalized = {}
    for name,pin in build['artifacts'].items():
        path = Path(name)
        if name in remap: logical = remap[name]
        elif path.is_relative_to(current_source): logical = str(old_source/path.relative_to(current_source))
        else: logical = name
        q.need(logical not in normalized,'colliding relocated artifact identity'); normalized[logical] = pin
    build = dict(build,artifacts=dict(sorted(normalized.items())),artifact_sha256={k:v['sha256'] for k,v in sorted(normalized.items())})
    sources = {}
    for name in ('strict_native.py','strict_native_provenance.py','strict_observations.py','strict_trace.py','strict_original.py','strict_fixture.py','strict_transport.py'):
        sources[name] = q.pin(q.inside(here,name))
    return q,observation,binding,corpus,build,provenance,sources


def _artifact_index(q, binding, sources, build, observation, original_reader):
    result={'native-capture/'+name:value for name,value in observation['artifact_sha256'].items()}
    result.update({'build/'+name:value for name,value in build['artifact_sha256'].items()})
    result.update({'reference-source/'+name:digest for name,(size,digest) in q.SOURCES.items()})
    result.update({'producer-source/'+name:pin['sha256'] for name,pin in binding['driver_sources'].items()})
    result.update({'admission-source/'+name:pin['sha256'] for name,pin in sources.items()})
    result['reference-reader/strict_reference.py']=q.pin(original_reader)['sha256']
    return dict(sorted(result.items()))


def native_evidence(*, native_capture, reference_source, original_reader, producer_source,
                    native_source, build_reader, build_primitive, artifact_reader=None):
    """Admit native data only; no original capture, replay, or live-file access."""
    q,observation,binding,corpus,build,provenance,sources=_bound(native_capture=native_capture,
        original_reader=original_reader,native_source=native_source,build_reader=build_reader,
        build_primitive=build_primitive,artifact_reader=artifact_reader)
    _,observed,_,_=observation.observation_evidence(original_reader,reference_source,producer_source,native_capture)
    trace=load(Path(__file__).absolute().parent/'strict_trace.py','_fs_native_only_trace').trace_evidence(
        q,native_capture,corpus,None,None,observation)
    report=q.Binder(native_capture).json('NATIVE.json')
    return {'schema':'hepta.runtime.filesystem-sdk-native-evidence.v1','status':'PASS',
        'native_execution_complete':True,'original_comparison_complete':False,'original_capture_read':False,
        'native_observed_processes':28,'native_ordinary_processes':26,'public_attempts':323,'private_controls':9,
        'formal_fresh_member_qualification':True,'fresh_cold_qualification':False,
        'source_graph_admitted':True,'syscall_and_continuation_evidence_admitted':True,
        'provenance':provenance,'build':build,'observations':observed,'trace':trace,
        'admission_source_files':sources,'artifact_sha256':_artifact_index(q,binding,sources,build,observed,original_reader),
        'fixture_origin':report['fixture_root'],'transient_fixture_directories':['fixtures'],
        'fixture_directories_relative_to':'supplied native_capture','live_fixture_required':False,
        'new_native_processes':0,'new_rust_processes':0}


def evidence(*, native_capture, original_capture, reference_source, original_reader,
             producer_source, original_driver_source, native_source, build_reader,
             build_primitive, artifact_reader=None):
    # Re-admit the entire native predecessor from the actual artifact bytes.
    # Comparing two hosts' monotonic clocks cannot establish this causality.
    prior=native_evidence(native_capture=native_capture,reference_source=reference_source,original_reader=original_reader,
        producer_source=producer_source,native_source=native_source,build_reader=build_reader,build_primitive=build_primitive,
        artifact_reader=artifact_reader)
    q,observation,binding,corpus,build,provenance,sources=_bound(native_capture=native_capture,
        original_reader=original_reader,native_source=native_source,build_reader=build_reader,
        build_primitive=build_primitive,artifact_reader=artifact_reader)
    recorded=q.Binder(original_capture).json('NATIVE-ADMISSION.json')
    q.same(recorded,prior,'complete native admission must precede and bind fresh original replay')
    comparison=observation.compare_original(original_reader,reference_source,producer_source,native_capture,original_capture,original_driver_source)
    trace=load(Path(__file__).absolute().parent/'strict_trace.py','_fs_final_trace').trace_evidence(
        q,native_capture,corpus,original_capture,comparison['original_evidence'],observation)
    provenance=dict(provenance,native_before_original_proved_by_original_reader=True)
    artifacts=_artifact_index(q,binding,sources,build,comparison['native_observations'],original_reader)
    artifacts.update({'original/'+name:value for name,value in comparison['original_evidence']['artifact_sha256'].items()})
    return {'schema':'hepta.runtime.filesystem-sdk-native-original-evidence.v1','status':'PASS',
        'scope':'frozen 323 public attempts plus 9 separate fixture/cache controls',
        'native_execution_before_fresh_original':True,'native_observed_processes':28,'native_ordinary_processes':26,
        'native_predecessor_admission_sha256':q.sha(q.canonical(prior)),
        'source_graph_admitted':True,'whole_original_response_and_state_comparison_complete':True,
        'syscall_and_continuation_evidence_admitted':True,'formal_fresh_member_qualification':True,'fresh_cold_qualification':False,
        'original_full_router_executed':False,'original_config_loader_executed':False,
        'full_configured_fence_acquisition_executed':False,'new_wide_remote_policy_domain_admitted':False,
        'remote_io_executed':False,'lease_full_record_array_observed':False,
        'native_fence_has_individual_effect_receipts':False,'ordinary_silent_request_intervals_observed':False,
        'physical_refusal_suite_is_separate':True,'provenance':provenance,'build':build,'comparison':comparison,'trace':trace,
        'admission_source_files':sources,'artifact_sha256':dict(sorted(artifacts.items())),
        'live_fixture_required':False,'new_native_processes':0,'new_rust_processes':0}
