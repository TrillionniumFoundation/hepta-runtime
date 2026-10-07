#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only maintenance and process-resource inventory; never authorizes a reboot.
No sudo, signals, checkpoint capture, credentials, file-content copying or hidden
execution hooks. Incomplete permissions and unstable process IDs remain explicit.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import time

MAX_PROCESSES=8192
MAX_MEMBERS=64
MAX_FDS=50000


def safe_text(value):
    return ''.join(c if c.isprintable() else '?' for c in value)[:160]


def process_identity(pid,proc=pathlib.Path('/proc')):
    if not isinstance(pid,int) or isinstance(pid,bool) or pid<=1:raise ValueError('positive non-system PID required')
    path=proc/str(pid);raw=(path/'stat').read_text();end=raw.rfind(')')
    if end<0:raise ValueError('invalid proc stat')
    parts=raw[end+2:].split()
    uids=list(map(int,next(line for line in (path/'status').read_text().splitlines() if line.startswith('Uid:')).split()[1:]))
    return {'pid':pid,'ppid':int(parts[1]),'start_ticks':int(parts[19]),'state':parts[0],
            'uids':uids,'comm':safe_text(raw[raw.find('(')+1:end])}


def process_table(proc=pathlib.Path('/proc')):
    entries=sorted((p for p in proc.iterdir() if p.name.isdigit() and int(p.name)>1),key=lambda p:int(p.name))
    if len(entries)>MAX_PROCESSES:raise ValueError('process enumeration budget exceeded')
    records={};unavailable=[]
    for entry in entries:
        try:records[int(entry.name)]=process_identity(int(entry.name),proc)
        except FileNotFoundError:continue
        except (OSError,ValueError,StopIteration,IndexError) as exc:unavailable.append({'pid':int(entry.name),'error':type(exc).__name__})
    return records,unavailable


def family(records,pid):
    if pid not in records:raise ValueError('selected process absent')
    members=[];queue=[pid]
    while queue:
        current=queue.pop(0)
        if current in members:raise ValueError('cyclic process topology')
        members.append(current)
        if len(members)>MAX_MEMBERS:raise ValueError('process-tree inventory budget exceeded')
        queue.extend(sorted(p for p,v in records.items() if v['ppid']==current))
    return members


def descriptor_inventory(pid,proc=pathlib.Path('/proc')):
    root=proc/str(pid);result=[]
    for entry in sorted((root/'fd').iterdir(),key=lambda p:int(p.name)):
        try:
            link=os.readlink(entry);fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in (root/'fdinfo'/entry.name).read_text().splitlines() if ':' in line}
            access=int(fields['flags'],8)&3
            if link.startswith('pipe:['):kind='pipe';resource=link
            elif link.startswith('socket:['):kind='socket';resource=link
            elif link.startswith('anon_inode:'):kind='anonymous_kernel_object';resource=None
            elif link in ('/dev/null','/dev/zero','/dev/random','/dev/urandom'):kind='basic_device';resource=None
            elif link.startswith('/dev/pts/') or link=='/dev/tty':kind='terminal';resource=None
            elif link.startswith('/dev/nvidia') or link.startswith('/dev/dri/'):kind='gpu_device';resource=None
            else:
                mode=entry.stat().st_mode
                kind='regular_file' if stat.S_ISREG(mode) else ('directory' if stat.S_ISDIR(mode) else 'other')
                resource=None
            snapshot=entry.stat()
            row={'fd':int(entry.name),'kind':kind,'access':access,'position':int(fields.get('pos','0')),'device':snapshot.st_dev,'inode':snapshot.st_ino}
            if resource:row['resource']=resource
            if link.endswith(' (deleted)'):row['unlinked']=True
            result.append(row)
        except (OSError,ValueError,KeyError) as error:
            # A racing single descriptor must not erase already observed owners.
            result.append({'fd':int(entry.name),'kind':'unavailable','error':type(error).__name__})
        if len(result)>1024:raise ValueError('per-process descriptor budget exceeded')
    return result


def resource_report(pid,proc=pathlib.Path('/proc'),uid=None):
    uid=os.getuid() if uid is None else uid
    records,unavailable=process_table(proc);members=family(records,pid)
    if any(v!=uid for p in members for v in records[p]['uids']):raise PermissionError('inventory requires a uniformly owned process tree')
    own=[];unknown=list(unavailable);all_fds={};fd_total=0
    for number,record in records.items():
        try:
            descriptors=descriptor_inventory(number,proc);fd_total+=len(descriptors)
            if fd_total>MAX_FDS:raise ValueError('global descriptor scan budget exceeded')
            all_fds[number]=descriptors
            missing=sum(row['kind']=='unavailable' for row in descriptors)
            if missing:unknown.append({'pid':number,'error':'partial_descriptor_inventory','unavailable_fds':missing})
        except FileNotFoundError:unknown.append({'pid':number,'error':'process_changed'})
        except OSError as exc:unknown.append({'pid':number,'error':type(exc).__name__})
    resources={d['resource'] for p in members for d in all_fds.get(p,[]) if d.get('resource')}
    external=[]
    for number,descriptors in all_fds.items():
        if number in members:continue
        for descriptor in descriptors:
            if descriptor.get('resource') in resources:
                external.append({'identity':records[number],**descriptor})
    stable=True;descriptor_stable=True
    for number in members+sorted({x['identity']['pid'] for x in external}):
        try:
            now=process_identity(number,proc)
            if any(now[key]!=records[number][key] for key in ('pid','ppid','start_ticks','uids')):stable=False
            if number in all_fds:
                def descriptor_key(rows):
                    return [{k:v for k,v in row.items() if k!='position'} for row in rows
                            if row['kind']!='unavailable' and (number in members or row.get('resource') in resources)]
                if descriptor_key(descriptor_inventory(number,proc))!=descriptor_key(all_fds[number]):descriptor_stable=False
        except (OSError,ValueError):stable=False;descriptor_stable=False
    current,_=process_table(proc)
    try:stable=stable and family(current,pid)==members
    except ValueError:stable=False
    for number in members:own.append({'identity':records[number],'descriptors':all_fds.get(number,[]),'descriptors_available':number in all_fds})
    limits=[]
    if len(members)>1:limits.append('native_process_tree_capture_not_implemented')
    if external:limits.append('external_resource_owners_require_explicit_coordination')
    if unknown:limits.append('resource_ownership_scan_incomplete')
    if not stable:limits.append('process_topology_changed_during_observation')
    if not descriptor_stable:limits.append('descriptor_binding_changed_during_observation')
    kinds={v['kind'] for row in own for v in row['descriptors']}
    if kinds & {'socket','gpu_device','terminal','anonymous_kernel_object','other'}:limits.append('unsupported_or_unclassified_external_kernel_resources')
    if any(v.get('unlinked') for row in own for v in row['descriptors']):limits.append('unlinked_open_resource')
    return {'mode':'observe_only','selected_pid':pid,'members':own,'external_descriptor_owners':external,
            'process_count':len(members),'observation_stable':stable,'descriptor_bindings_stable':descriptor_stable,'ownership_scan_complete':not unknown,
            'unavailable_processes':unknown[:128],'unavailable_count':len(unknown),'limitations':limits,
            'resource_bytes_read':False,'processes_signalled':False,'migration_authorized':False}


def command_json(argv):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=8)
        if p.returncode:return {'available':False,'exit_code':p.returncode}
        try:value=json.loads(p.stdout)
        except ValueError:
            value=[json.loads(line) for line in p.stdout.splitlines() if line.strip()]
        return {'available':True,'value':value}
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc:return {'available':False,'error':type(exc).__name__}


def maintenance_report(proc=pathlib.Path('/proc')):
    records,unknown=process_table(proc);uid=os.getuid();work=[];interactive=[];h3=[]
    # The report lists evidence, not an exception list or an authorization policy.
    for pid,value in records.items():
        if value['uids'][0]!=uid or pid in (os.getpid(),os.getppid()):continue
        name=value['comm']
        if name.lower().startswith(('python','cargo','rustc','make','ninja','cc1','ffmpeg','codex','qemu','heptabao','heptatrader','llama')):
            item=dict(value)
            try:
                cwd=os.readlink(proc/str(pid)/'cwd')
                item['workload_category']=next((label for token,label in [('h3-','H3'),('heptabao','HeptaBao'),('heptatrader','HeptaTrader'),('hepta-runtime','runtime')] if token in cwd.lower()),'unclassified')
                arguments=(proc/str(pid)/'cmdline').read_bytes().split(b'\0')
                if any(b'/h3-neural-vsr-' in arg and arg.endswith(b'.py') for arg in arguments):item['workload_category']='H3'
            except OSError:item['workload_category']='unavailable'
            work.append(item)
            if item['workload_category']=='H3':h3.append(pid)
        if name in ('chrome','firefox','ChatGPT','gnome-shell','code'):interactive.append(pid)
    services=command_json(['systemctl','list-units','--state=running','--type=service','--no-pager','--output=json'])
    relevant=[]
    if services['available']:
        relevant=[{key:item.get(key) for key in ('unit','active','sub')} for item in services['value'] if any(token in item.get('unit','').lower() for token in ('hepta','postgres','docker','waydroid','openbao','openclaw','ollama','runner'))]
    containers=command_json(['docker','ps','--format','json'])
    blockers=[]
    if work:blockers.append('active_workloads_need_completion_or_verified_checkpoint')
    if interactive:blockers.append('interactive_application_state_not_attested')
    if relevant:blockers.append('stateful_services_need_verified_restart_contract')
    if not services['available'] or unknown:blockers.append('inventory_incomplete')
    container_count=len(containers['value']) if containers['available'] and isinstance(containers['value'],list) else (1 if containers['available'] else None)
    if container_count is None:blockers.append('container_state_unavailable')
    elif container_count:blockers.append('running_containers_need_verified_restart_contract')
    return {'mode':'observe_only','hostname':os.uname().nodename,'boot_id':(proc/'sys/kernel/random/boot_id').read_text().strip(),
            'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'monotonic_ns':time.monotonic_ns(),
            'workloads':work,'observed_H3_pids':h3,'interactive_process_count':len(interactive),
            'stateful_services':relevant,'service_inventory_available':services['available'],
            'container_query_available':containers['available'],'running_container_count':container_count,'unavailable_process_count':len(unknown),
            'blockers':blockers,'safe_reboot_proven':False,'power_action_authorized':False,
            'reason':'Absence of a process-name match is not evidence that business state is durable.'}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--pid',type=int);ap.add_argument('--out',required=True);a=ap.parse_args()
    result=resource_report(a.pid) if a.pid is not None else maintenance_report()
    data=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode();fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    print(json.dumps({'report':a.out,'sha256':hashlib.sha256(data).hexdigest(),'mode':'observe_only','mutation_performed':False}))


if __name__=='__main__':main()
