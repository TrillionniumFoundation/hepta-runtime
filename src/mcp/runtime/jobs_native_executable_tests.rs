// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Execute the real executable pinning path, including a sealed venv interpreter.

use super::*;
use std::io::Write;
use std::process::{Command, Stdio};

const FIXTURE: &str = r#"
import json,os,pathlib,shutil,stat,subprocess,sys,tempfile
from unittest import mock
q=json.load(sys.stdin)
namespace={}
exec(q['private'],namespace)
namespace['stat']=stat
exec(q['pin'],namespace)
pin=namespace['pin_native_workload_executable']
with tempfile.TemporaryDirectory(prefix='hia-native-executable-') as temporary:
    root=pathlib.Path(temporary)
    if q['case']=='venv':
        venv=root/'venv'
        subprocess.run([sys.executable,'-m','venv','--without-pip','--symlinks',str(venv)],
                       check=True,capture_output=True,timeout=20)
        selected=venv/'bin/python3'
        assert selected.is_symlink()
        workload,anchor=pin(str(selected))
        try:
            code=('import json,os,sys;print(json.dumps({'
                  '"executable":sys.executable,"prefix":sys.prefix,"base_prefix":sys.base_prefix,'
                  '"argv":sys.argv,"entry_inode":os.fstat(int(os.environ["HEPTA_RUNTIME_WORKER_ENTRY_FD"])).st_ino}))')
            arguments=[str(selected),'-B','-E','-s','-c',code,'original-argument']
            environment=os.environ.copy()
            environment['HEPTA_RUNTIME_WORKER_ENTRY_FD']=str(anchor)
            result=subprocess.run(arguments,executable='/proc/self/fd/'+str(workload.fileno()),
                                  pass_fds=(workload.fileno(),anchor),env=environment,
                                  check=True,capture_output=True,timeout=10)
            observed=json.loads(result.stdout)
            assert result.stderr==b''
            assert observed['executable']==str(selected)
            assert observed['prefix']==str(venv) and observed['base_prefix']!=str(venv)
            assert observed['argv']==['-c','original-argument']
            assert observed['entry_inode']==os.stat(selected).st_ino==os.fstat(anchor).st_ino
            print(json.dumps({'case':'venv','sealed_exec':True,'original_argv':True,
                              'venv_prefix':True,'entry_inode_bound':True}))
        finally:
            workload.close()
            os.close(anchor)
    elif q['case']=='refusals':
        original=pathlib.Path(sys.executable).resolve().read_bytes()
        target=root/'target'
        selected=root/'selected'
        selected.symlink_to(target)
        failures=[]
        def reset():
            target.write_bytes(original)
            target.chmod(0o755)
        def refused(name,path=selected):
            try:
                workload,anchor=pin(str(path))
            except (OSError,SystemExit):
                failures.append(name)
                return
            workload.close();os.close(anchor)
            raise AssertionError('accepted unsafe executable: '+name)
        reset()
        for mode in (0o777,0o775,0o757,0o644):
            target.chmod(mode)
            refused('mode-'+oct(mode))
        reset()
        target.write_bytes(b'not-ELF'+b'\0'*100)
        refused('not-elf')
        target.write_bytes(b'\x7fELF\x02\x01\x01'+b'\0'*56)
        refused('too-small')
        with target.open('wb') as stream:stream.truncate((64<<20)+1)
        refused('too-large')
        refused('directory',root)
        fifo=root/'fifo';os.mkfifo(fifo,0o700)
        refused('fifo',fifo)
        reset()
        substitute=root/'substitute'
        substitute.write_bytes(original);substitute.chmod(0o755)
        real_fdopen=os.fdopen
        class MutatingReader:
            def __init__(self,stream,mutation):self.stream,self.mutation=stream,mutation
            def __enter__(self):return self
            def __exit__(self,*arguments):return self.stream.__exit__(*arguments)
            def fileno(self):return self.stream.fileno()
            def read(self,*arguments):
                data=self.stream.read(*arguments)
                self.mutation()
                return data
        def changed(name,mutation):
            def opened(fd,*arguments,**keywords):
                return MutatingReader(real_fdopen(fd,*arguments,**keywords),mutation)
            with mock.patch.object(os,'fdopen',opened):refused(name)
        def retarget():
            selected.unlink();selected.symlink_to(substitute)
        changed('symlink-retarget',retarget)
        selected.unlink();selected.symlink_to(target)
        reset()
        changed('target-replaced',lambda:os.replace(substitute,target))
        reset()
        changed('fd-mode-changed',lambda:target.chmod(0o700))
        reset()
        def rewrite():
            with target.open('r+b') as stream:
                stream.seek(32);stream.write(b'changed')
        changed('fd-bytes-changed',rewrite)
        assert len(failures)==13,failures
        print(json.dumps({'case':'refusals','refused':failures,'workloads_started':0}))
    else:raise AssertionError('unknown fixture case')
"#;

fn executable_fixture(case: &str) -> Value {
	let source = START_CODE
		.split_once("def pin_native_workload_executable")
		.unwrap()
		.1
		.split_once("\ndef exec_native_job_owner")
		.unwrap()
		.0;
	let input = json!({"case":case,"private":PRIVATE_DIRECTORY_CODE,
		"pin":format!("def pin_native_workload_executable{source}")});
	let mut child = Command::new("python3")
		.args(["-I", "-B", "-c", FIXTURE])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(&serde_json::to_vec(&input).unwrap())
		.unwrap();
	let output = child.wait_with_output().unwrap();
	assert!(
		output.status.success(),
		"{case}: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn native_workload_symlinked_venv_preserves_original_argv_prefix_and_entry_inode() {
	let result = executable_fixture("venv");
	for field in [
		"sealed_exec",
		"original_argv",
		"venv_prefix",
		"entry_inode_bound",
	] {
		assert_eq!(result[field], true, "{field}");
	}
}

#[test]
fn native_workload_refuses_unsafe_targets_and_mid_read_retargeting() {
	let result = executable_fixture("refusals");
	assert_eq!(result["refused"].as_array().unwrap().len(), 13);
	assert_eq!(result["workloads_started"], 0);
}
