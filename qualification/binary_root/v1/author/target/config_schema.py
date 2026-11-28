"""Build-time closed schema copied from the original RuntimeConfig closure.

This table authors native HIA constants. It is never a runtime parser.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT.parent / 'hepta-runtime'

# scalar: 1 UTF8 String, 2 bool, 3 u64/usize, 4 u8, 5 u32, 6 Unix PathBuf.
# enums: 10..13; structs 100..108; sequence 200+scalar; map 300+index;
# options 1000+underlying type. Fields are (name,type,default,skip_if_empty).
# None denotes REQUIRED; zero is a genuine default (including Option::None).
ENUMS = {
    10: ['linux', 'macos'], 11: ['isolated', 'operator'],
    12: ['gnu_readelf', 'gnu_objdump', 'jadx', 'ghidra'],
    13: ['headers', 'sections', 'symbols', 'notes', 'relocations', 'classes',
         'sources', 'inventory', 'functions', 'function', 'decompile', 'xrefs'],
}
MAPS = {300: 101, 301: 102, 302: 103, 303: 105, 304: 1}
SCHEMAS = {
 100: ('RuntimeConfig', False, [
  ('state_dir',6,'admin_default',False),
  ('controller_workspace_roots',206,0,False), ('hosts',300,0,False),
  ('weight_workers',302,0,True), ('rea_static_profiles',303,0,True),
  ('hia_worker',1108,0,True)]),
 101: ('HostConfig', False, [
  ('checkpoint_binary',1001,0,False),('checkpoint_binary_sha256',1001,0,False),
  ('execution_mode',11,0,False),('ssh_target',1,None,False),('platform',10,0,False),
  ('remote_state_dir',1,None,False),('allow_execute',2,0,False),
  ('allow_pty',2,0,False),('allow_write',2,0,False),('allow_job_network',2,0,False),
  ('allow_detached_fallback',2,0,False),('allowed_cwd_prefixes',201,0,False),
  ('allowed_read_path_prefixes',201,0,False),('allowed_write_path_prefixes',201,0,False),
  ('protected_path_prefixes',201,0,False),('protected_argument_substrings',201,0,False),
  ('denied_executables',201,0,False),('allowed_dangerous_executables',201,0,False),
  ('privileged_actions',301,0,False)]),
 102: ('PrivilegedAction', False, [
  ('executable',1,None,False),('fixed_args',201,0,False),('allow_extra_args',2,0,False),
  ('extra_arg_patterns',201,0,False),('timeout_seconds',3,30,False)]),
 103: ('WeightWorkerProfile', True, [
  ('host',1,None,False),('python_executable',1,None,False),('worker_path',1,None,False),
  ('worker_sha256',1,None,False),('worker_package_sha256',1001,0,False),
  ('native_client',1104,0,True),('session_root',1,None,False),
  ('input_roots',201,None,False),('allowed_providers',201,None,False),
  ('max_memory_bytes',3,4<<30,False),('max_cpu_threads',4,2,False),
  ('max_lifetime_seconds',3,1800,False),('max_request_ms',3,120000,False),
  ('max_active_sessions',3,1,False),('max_requests_per_session',3,128,False)]),
 104: ('WeightNativeClientProfile', True, [
  ('executable',1,None,False),('sha256',1,None,False)]),
 105: ('ReaStaticProfile', True, [
  ('host',1,None,False),('runtime_executable',1,None,False),('runtime_sha256',1,None,False),
  ('provider',12,None,False),('backend_executable',1,None,False),('backend_sha256',1,None,False),
  ('backend_version',1,None,False),('working_directory',1,None,False),
  ('input_roots',201,None,False),('allowed_operations',213,None,False),
  ('max_artifact_bytes',3,64<<20,False),('max_output_bytes',3,32768,False),
  ('timeout_seconds',3,30,False),('memory_max_bytes',3,512<<20,False),
  ('java_engine',1106,0,True),('ghidra_engine',1107,0,True)]),
 106: ('JavaEngineProfile', True, [
  ('java_home',1,None,False),('jar_path',1,None,False),('jar_sha256',1,None,False),
  ('engine_version',1,None,False),('release_archive_sha256',1,None,False),
  ('runtime_files',304,None,False)]),
 107: ('GhidraEngineProfile', True, [
  ('bridge_revision',1005,0,True),('java_home',1,None,False),
  ('installation_root',1,None,False),('manifest_path',1,None,False),
  ('manifest_sha256',1,None,False),('engine_version',1,None,False),
  ('release_archive_sha256',1,None,False),('runtime_files',304,None,False)]),
 108: ('HiaWorkerProfile', True, [
  ('host',1,None,False),('python_executable',1,None,False),
  ('working_directory',1,None,False),('state_root',1,None,False),
  ('artifact_roots',201,0,False),('worker_sha256',1,None,False),
  ('backend_sha256',1,None,False),('catalog_sha256',1,None,False),
  ('native_helpers_manifest',1001,0,True),('native_helpers_sha256',1001,0,True),
  ('timeout_seconds',3,120,False),('memory_max_bytes',3,1<<30,False)]),
}

SOURCE_PATHS = [
 'Cargo.toml','Cargo.lock','src/main.rs','src/mcp/runtime/config.rs',
 'src/mcp/runtime/config_tests.rs','src/mcp/runtime/inspect.rs',
 'src/mcp/runtime/inspect_tests.rs','src/mcp/runtime/effective_config.rs',
 'src/mcp/runtime/effective_config_tests.rs','src/mcp/weight_config.rs',
 'src/mcp/rea_provider.rs','src/mcp/rea_engine_profile.rs','src/mcp/hia_provider.rs',
 'src/mcp/hia_contract.rs','src/mcp/hia_tool_catalog.json',
 'src/utils/json_size.rs',
]

def pin_sources():
    import subprocess
    result = {'schema':'hepta.runtime.config-source-closure.v1',
              'baseline_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ORIGINAL,text=True).strip(),
              'files':{}}
    for name in SOURCE_PATHS:
        data=(ORIGINAL/name).read_bytes()
        result['files'][name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
          'git_blob':subprocess.check_output(['git','hash-object','--stdin'],cwd=ORIGINAL,input=data).decode().strip()}
    (ROOT/'reference/source-pins.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    (ROOT/'reference/typed-schema.json').write_text(json.dumps({'structs':SCHEMAS,'enums':ENUMS,'maps':MAPS},indent=2)+'\n')
    return result

if __name__=='__main__':
    print(json.dumps(pin_sources(),sort_keys=True))
