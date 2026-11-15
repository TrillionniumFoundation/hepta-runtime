"""Execute all fifteen frozen configuration/regex suites with actual receipts.

This focused run requires its real build below OUTPUT/build. It does not claim a
fresh compiler cold gate. No original Rust executes on the local machine.
"""
from pathlib import Path
import argparse,hashlib,json,os,signal,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_config_qualification as q
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--build',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    output=a.output.resolve(strict=True);build=a.build.resolve(strict=True);assert build==output/'build/config-build.json'
    data=json.loads(build.read_bytes());report={'compiler_commit':data['compiler_commit'],'compiler_image_sha256':data['compiler_sha256'],'modules':{'runtime_config':{'builder':'runtime_config','manifest':'build/config-build.json','sha256':sha(build.read_bytes())}},'checks':[]}
    assert not(output/'focused-processes.json').exists();before=q.source_pins(ROOT);q.build_evidence(ROOT,output,report)
    env={k:v for k,v in os.environ.items()if not k.startswith(('HIA_','PYTHON'))}
    env.update(HIA_CONFIG_BUILD=str(build),HIA_REGEX_OUTPUT_DIR=str(output/'regex-native'),HIA_CONFIG_JSON_CORPUS_DIR=str(output/'config-native/typed-corpus'),HIA_CONFIG_SEMANTICS_CORPUS_DIR=str(output/'config-native/semantics-corpus'))
    for name,command in q.test_commands(ROOT,output,report).items():
        start=time.monotonic();code=None;timed=False;cleanup=False;error=None
        with (output/(name+'.stdout')).open('xb')as stdout,(output/(name+'.stderr')).open('xb')as stderr:
            try:
                process=subprocess.Popen(command,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
                try:code=process.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    timed=True
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    try:code=process.wait(timeout=3)
                    except subprocess.TimeoutExpired:cleanup=True
            except OSError as exc:error={'type':type(exc).__name__,'message':str(exc)}
        row={'name':name,'command':command,'cwd':str(ROOT),'exit_code':code,'elapsed_seconds':time.monotonic()-start,'timed_out':timed,'cleanup_timed_out':cleanup,'start_error':error,'timeout_seconds':180,'cleanup_seconds':3,'stdout_sha256':sha((output/(name+'.stdout')).read_bytes()),'stderr_sha256':sha((output/(name+'.stderr')).read_bytes())}
        report['checks'].append(row);(output/'focused-processes.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(row,sort_keys=True),flush=True)
        if code!=0 or timed or cleanup or error is not None:raise AssertionError(('native suite incomplete',name,code,timed,error))
    def completed(folder,aggregate,name):
        rows=[r for r in aggregate['checks']if r['name']==name];assert len(rows)==1
        return rows[0],json.loads((Path(folder)/(name+'.stdout')).read_bytes())
    assert before==q.source_pins(ROOT)
    evidence=q.native_evidence(ROOT,output,report,completed,create=True)
    (output/'focused-native-evidence.json').write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n')
    report.update(status='PASS',source_unchanged=True,actual_suites=15,fresh_cold_qualified=False,native_evidence_sha256=sha((output/'focused-native-evidence.json').read_bytes()))
    (output/'focused-result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print('ALL_FOCUSED_NATIVE_PASS',len(report['checks']),flush=True)

if __name__=='__main__':main()
