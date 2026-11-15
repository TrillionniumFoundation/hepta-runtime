#!/usr/bin/env python3
"""Source-bound prepublication focused gates; full suites remain GitHub CI gates."""
from pathlib import Path
import hashlib, importlib.util, json, os, signal, sys, traceback

repo=Path('/home/qian-qi/hepta-runtime-rea-full-20261103-r1')
target=Path('/home/qian-qi/work/hepta-rea-full-20261103-r1-target')
out=repo/'docs/qualification/rea-final-focused-20261103-r1'
spec=importlib.util.spec_from_file_location('rea_final_focus_helpers',repo/'scripts/rea_full_qualification.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
env=os.environ.copy()
env.update({'CARGO_HOME':'/home/qian-qi/work/hepta-rea-full-20261103-r1-cargo','CARGO_TARGET_DIR':str(target),'CARGO_BUILD_JOBS':'4','CARGO_NET_OFFLINE':'true','CARGO_TERM_COLOR':'never','RUSTUP_TOOLCHAIN':'1.95.0','RUSTC':'/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc','NEXTEST_TEST_THREADS':'1','NEXTEST_RETRIES':'0'})
cargo='/home/qian-qi/.cargo/bin/cargo'
filter_expr='test(rea_) | test(config::) | test(state_root) | test(effect_owner_fence) | binary(/rea/) | test(large_pending_view_) | test(metadata_deadline_does_not_leave_a_blocking_query_behind_the_store_lock)'
common=['--locked','--offline','--all-targets']
test_control=['--build-jobs','4','--test-threads','1','--retries','0','--no-fail-fast','--profile','default','--ignore-default-filter','--no-tests','fail','-E',filter_expr]
commands=[
 ('fmt-check',[cargo,'fmt','--all','--','--check']),
 ('clippy-all-features',[cargo,'clippy']+common+['--all-features','--jobs','4','--','-D','warnings']),
 ('clippy-no-default-features',[cargo,'clippy']+common+['--no-default-features','--jobs','4','--','-D','warnings']),
 ('focused-all-features',[cargo,'nextest','run']+common+['--all-features']+test_control),
 ('focused-no-default-features',[cargo,'nextest','run']+common+['--no-default-features']+test_control)]
selection=m.Selection(repo,target,out)
cancel=m.Cancellation()
handlers={n:signal.getsignal(n) for n in (signal.SIGINT,signal.SIGTERM)}
for n in handlers:signal.signal(n,cancel.receive)
report={'schema':'hepta.rea.prepublication-focused-qualification.v1','status':'running','qualified':False,'full_suite_qualified':False,'child_launch_umask':'0022','started_at':m.utc_now(),'scope':'Targeted source-bound prepublication gates. Complete all-target suites for both feature configurations are required separately in GitHub exact-head and prospective-merge CI. This receipt does not replace or relabel the interrupted full r3 run.','filter':filter_expr,'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'helper_sha256':hashlib.sha256((repo/'scripts/rea_full_qualification.py').read_bytes()).hexdigest(),'stages':[],'binaries':[],'invalid_reasons':[]}
lock=None;monitor=None;before=None;after=None
try:
 lock=m.pin_target(target,repo)
 monitor=m.SourceMonitor(selection);monitor.start()
 before=selection.snapshot()
 report['source_before']=m.save_json(out/'source-before.json',before)
 report['source_before']['tree_sha256']=before['tree_sha256']
 m.save_json(out/'summary.json',report)
 for idx,(name,argv) in enumerate(commands,1):
  if cancel.signal is not None:break
  stage=m.run_stage(idx,name,argv,repo,out,env,cancel,'gate')
  report['stages'].append(stage)
  if name.startswith('focused-'):
   obs=m.observe_binary(target,Path('debug/hepta-runtime'))
   obs['stage']=name
   report['binaries'].append(obs)
  m.save_json(out/'summary.json',report)
  if stage['exit_code']!=0:break
except BaseException as e:
 report['invalid_reasons'].append(type(e).__name__+': '+str(e))
 (out/'driver-error.log').write_text(traceback.format_exc())
finally:
 try:
  after=selection.snapshot()
  report['source_after']=m.save_json(out/'source-after.json',after)
  report['source_after']['tree_sha256']=after['tree_sha256']
 except BaseException as e:report['invalid_reasons'].append('source-after: '+str(e))
 event={'event_count':0,'errors':['monitor not established']}
 if monitor is not None:
  try:event=monitor.stop()
  except BaseException as e:event['errors']=['monitor shutdown: '+str(e)]
 report['source_events']=m.save_json(out/'source-events.json',event)
 report['source_monitor_complete']=not event['errors']
 report['source_changed']=before is None or after is None or before!=after or event['event_count']>0
 if report['source_changed'] or not report['source_monitor_complete']:
  report['invalid_reasons'].append('source changed or monitor coverage incomplete')
 for stage in report['stages']:
  for log in stage.get('logs',{}).values():
   current=m.hash_file(Path(log['path']))
   log['sha256']=current
   if current!=log['sha256_at_stage_exit']:report['invalid_reasons'].append('log changed: '+log['path'])
 report['qualified']=len(report['stages'])==len(commands) and all(s['exit_code']==0 and s['child_launch_umask']=='0022' for s in report['stages']) and not report['invalid_reasons'] and cancel.signal is None
 report['status']='passed' if report['qualified'] else 'failed'
 report['interrupted_by_signal']=cancel.signal
 report['finished_at']=m.utc_now()
 m.save_json(out/'summary.json',report)
 if lock is not None:lock.close()
 for n,h in handlers.items():signal.signal(n,h)
print(json.dumps({'event':'final_focused_finished','qualified':report['qualified'],'full_suite_qualified':False,'source_changed':report['source_changed'],'summary':str(out/'summary.json'),'binaries':report['binaries']}),flush=True)
sys.exit(0 if report['qualified'] else 1)
