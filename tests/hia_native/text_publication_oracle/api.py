"""Import-safe pure API for the frozen Text original proof."""
from pathlib import Path
import builtins,hashlib,sys,types
SOURCE_FILES={'ordinary/Cargo.lock': {'bytes': 5070, 'sha256': 'b7e3bd136133883bff99d542ae984ca7ae7c35a0dd1186d1c1808be98f03c2d5'}, 'ordinary/common.py': {'bytes': 6132, 'sha256': 'dbcc268859c10b39aadbafda3196cfd47265673db409ee5a2ed8661ebb605fd5'}, 'ordinary/driver.rs': {'bytes': 3128, 'sha256': '4bcc65aa7006d76444c2eef0fa58aa5221f2219244d67a813df9b2709db698f3'}, 'ordinary/hia_native_text_publication_fixtures.py': {'bytes': 15120, 'sha256': '444145bdbb842da038d18d04f18484782fad7d5e50b213ef6dd78a8ac0e8b1b1'}, 'ordinary/native_predecessor.py': {'bytes': 12205, 'sha256': 'c8dedc99f6334d580dff1063f28c21cc264d78f465258257b10471e2b672665d'}, 'ordinary/original/Cargo.lock': {'bytes': 90148, 'sha256': '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43'}, 'ordinary/original/text_file_write.rs': {'bytes': 13948, 'sha256': 'f502197e7409c5d565b1c3328816dceb9cacac8031fb4fbadd20b473286facfc'}, 'ordinary/run.py': {'bytes': 14247, 'sha256': '25c7d7e8bc1c7d85372ed539f4c85126f6ef562fb6a8446ac4faeda8b1dc71a0'}, 'ordinary/verify_sources.py': {'bytes': 5000, 'sha256': '0adba009fd7aec00e3c6be59ce84e354988006425400c06eaf7c43971b9ee096'}, 'qualification_evidence.py': {'bytes': 11108, 'sha256': '32afd2c4f3a51c4bf097ded55c84a2f4c2a8183b2044607e7c8e13287858ceff'}, 'races/GENERATOR-SOURCE.json': {'bytes': 396, 'sha256': 'ec858f8d91e6353db0b0b0494e2e71c69e81d5202eae7e764f3ff07d978902a0'}, 'races/original/native_races.py': {'bytes': 19050, 'sha256': '550cf160469171fda477dc5f7fdae070a094727a04f7ce6085d0fff3e190a421'}, 'races/ptrace_capture.py': {'bytes': 11988, 'sha256': 'fd796b8ffca32c6a94eec53d8ea9869a63f57b90df73c9c890386fbc3dc1fe18'}, 'races/race_cases.py': {'bytes': 3374, 'sha256': '337aebcf57b9f7998813f3c1b154722083397a660172c477875988037c0f32cc'}, 'races/race_native_predecessor.py': {'bytes': 6327, 'sha256': 'a7af1aeec6d94121dd256f3c15cb7553f099af0d86a9f3ae425ed56c177942a9'}, 'races/run_races.py': {'bytes': 17119, 'sha256': '2e89ff4e0c656691f3e9531ee28078ab23195dfb15ae34dac551912744e56aa9'}, 'readers/ptrace_evidence.py': {'bytes': 9686, 'sha256': 'bb361884992816492075c6b71d83253463ae01503416b130cf90faa3652c6b9d'}, 'readers/strict_races.py': {'bytes': 26776, 'sha256': 'eb99ace0649ff2e747b221d26d88f7599d9375f2224100c6e4d5e1f989552418'}, 'readers/strict_reference.py': {'bytes': 22488, 'sha256': 'f797b9e1e7e1e337adf33367d7f76391930adce36b71bf7674fa601a10d2b81b'}, 'readers/trace_evidence.py': {'bytes': 10447, 'sha256': '01586d600bd23761c08141c80912e80184859484a2147aaeb6f5bd99a8ee4407'}, 'test_original_evidence.py': {'bytes': 16097, 'sha256': '154a886643457367e45f7cb90de7949e41fd12e953ab79e04bc8e96ee2ed547d'}, 'test_race_evidence.py': {'bytes': 13645, 'sha256': '3d494a0fa451ca93494415dc66444a4b8baca4abb34c65b747476839d1ba51fe'}}
MODULE_FILES={'common':'ordinary/common.py','verify_sources':'ordinary/verify_sources.py','native_predecessor':'ordinary/native_predecessor.py','hia_native_text_publication_fixtures':'ordinary/hia_native_text_publication_fixtures.py','trace_evidence':'readers/trace_evidence.py','strict_reference':'readers/strict_reference.py','race_cases':'races/race_cases.py','race_native_predecessor':'races/race_native_predecessor.py','ptrace_evidence':'readers/ptrace_evidence.py','strict_races':'readers/strict_races.py','qualification_evidence':'qualification_evidence.py'}
def load(source_root):
    root=Path(source_root).absolute();raws={}
    for name,expected in SOURCE_FILES.items():
        path=root/name
        for p in [*reversed(path.parents),path]:
            if p.is_symlink():raise ValueError('symlink in original API source')
        raw=path.read_bytes()
        if {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}!=expected:raise ValueError('changed original API source: '+name)
        raws[name]=raw
    namespace='_hepta_text_original_'+hashlib.sha256(str(root).encode()).hexdigest();loaded={}
    def importer(name,globals=None,locals=None,fromlist=(),level=0):
        if level==0 and name in MODULE_FILES:return module(name)
        return builtins.__import__(name,globals,locals,fromlist,level)
    def module(name):
        if name in loaded:return loaded[name]
        full=namespace+'.'+name;path=root/MODULE_FILES[name]
        m=types.ModuleType(full);m.__file__=str(path);m.__package__=namespace
        m.__dict__['__builtins__']={**vars(builtins),'__import__':importer};loaded[name]=m;sys.modules[full]=m
        exec(compile(raws[MODULE_FILES[name]],str(path),'exec'),m.__dict__)
        return m
    selected=module('qualification_evidence')
    return {'qualification_evidence':selected.qualification_evidence,'ordinary_evidence':module('strict_reference').evidence,'race_evidence':module('strict_races').evidence,'source_sha256':dict(SOURCE_FILES)}
