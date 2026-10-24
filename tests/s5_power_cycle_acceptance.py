#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit X230 S5 shutdown/wake test, NOT removal of AC/battery (G3).
The controller stays on. Require an idle target, no existing RTC alarm, an actual
received magic packet and readback of temporary WOL+RTC settings before shutdown.
"""
import argparse
import datetime
import json
import os
import pathlib
import re
import shlex
import socket
import subprocess
import time

HOST='x230-ts';RUNNER='actions.runner.TrillionniumFoundation-Trillionnium-Chain.p4-x230.service'
MAC='3c:97:0e:71:c9:ca';BROADCAST='192.168.0.255';INTERFACE='enp0s25'
BASE=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5',HOST]
GUARD=r'''
import pathlib,os,json,subprocess
blocked=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name) in (os.getpid(),os.getppid()):continue
 try:
  name=(p/'comm').read_text().strip();cg=(p/'cgroup').read_text()
  if name.startswith(('cargo','rustc','cc1','make','ninja','Runner.Worker','codex','llama','ffmpeg','qemu','criu')) or (name.startswith('python') and '/wired-fallback-guard.service' not in cg):blocked.append({'pid':int(p.name),'name':name})
 except (FileNotFoundError,PermissionError):pass
r=subprocess.run(['/usr/bin/docker','ps','-q'],capture_output=True,text=True,timeout=8)
if r.returncode or r.stdout.strip():blocked.append({'containers':'not proven empty'})
print(json.dumps({'blocked':blocked}));raise SystemExit(2 if blocked else 0)
'''


def main():
 ap=argparse.ArgumentParser();ap.add_argument('--execute-s5',action='store_true');ap.add_argument('--out',required=True);a=ap.parse_args()
 if not a.execute_s5:raise SystemExit('Requires explicit --execute-s5; no shutdown requested')
 report={'complete':False,'performed':False,'target':HOST,'cold_g3_power_removal':False,'checks':[],'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
 def ssh(command,check=True,timeout=20):
  p=subprocess.run([*BASE,command],capture_output=True,text=True,timeout=timeout)
  if check and p.returncode:raise RuntimeError(p.stderr[-1500:] or p.stdout[-1500:])
  return p
 def passed(name):report['checks'].append(name);save();print('PASS '+name,flush=True)
 packet=b'\xff'*6+bytes.fromhex(MAC.replace(':',''))*16
 def magic():
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);s.sendto(packet,(BROADCAST,9))
 identity=ssh('hostname; cat /proc/sys/kernel/random/boot_id; cat /sys/class/net/'+INTERFACE+'/address; cat /sys/class/rtc/rtc0/wakealarm; systemctl is-enabled '+RUNNER+' ssh tailscaled wired-fallback-guard.service').stdout.splitlines()
 assert identity[:1]==['qian-ThinkPad-X230'] and identity[2]==MAC
 assert identity[3:]==['enabled','enabled','enabled','enabled'],identity
 report['boot_before']=identity[1]
 report['preflight']=json.loads(ssh('sudo -n /usr/bin/python3 -c '+shlex.quote(GUARD)).stdout)
 passed('physical identity, no existing RTC alarm, enabled recovery services, no business workload')
 # Prove that this controller's wake packet reaches the selected wired target.
 capture="import socket,json,time;expected=bytes.fromhex("+repr(packet.hex())+");s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('enp0s25',0));s.settimeout(8);end=time.monotonic()+8\nwhile time.monotonic()<end:\n data=s.recv(65535)\n if expected in data:print(json.dumps({'matching_magic_packet_received':True}),flush=True);break\nelse:raise SystemExit(2)"
 p=subprocess.Popen([*BASE,'sudo -n /usr/bin/python3 -c '+shlex.quote(capture)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 time.sleep(1);magic();out,err=p.communicate(timeout=12)
 assert p.returncode==0 and json.loads(out)['matching_magic_packet_received'],err
 passed('actual controller-originated magic packet received on target wired interface')
 paused=False;wake_changed=False
 try:
  ssh('sudo -n systemctl stop '+RUNNER);paused=True
  ssh('sudo -n /usr/bin/python3 -c '+shlex.quote(GUARD))
  settings=ssh('sudo -n ethtool '+INTERFACE).stdout
  match=re.search(r'^\s*Wake-on:\s*(\S+)',settings,re.M);assert match
  report['wol_before']=match.group(1)
  ssh('sudo -n ethtool -s '+INTERFACE+' wol g');wake_changed=True
  assert re.search(r'^\s*Wake-on:\s*g\s*$',ssh('sudo -n ethtool '+INTERFACE).stdout,re.M)
  ssh('sudo -n rtcwake --utc --mode no --seconds 180')
  alarm=int(ssh('cat /sys/class/rtc/rtc0/wakealarm').stdout.strip());now=int(ssh('date +%s').stdout)
  assert 130<=alarm-now<=190
  report['rtc_alarm_epoch']=alarm
  passed('idle runner paused; temporary magic wake and independent RTC fallback armed and read back')
  ssh('sudo -n /usr/bin/python3 -c '+shlex.quote(GUARD))
  report['shutdown_requested_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save()
  ssh('sync; sudo -n systemctl poweroff',check=False,timeout=20);report['performed']=True;save()
  start=time.monotonic();first_down=None;returned=None;sent=0
  while time.monotonic()-start<300:
   age=time.monotonic()-start
   if age>=30:magic();sent+=1
   try:
    result=ssh('cat /proc/sys/kernel/random/boot_id',check=False,timeout=8)
    if result.returncode==0 and result.stdout.strip()!=report['boot_before']:
     returned=result.stdout.strip();break
    if result.returncode and first_down is None:first_down=age
   except subprocess.TimeoutExpired:
    if first_down is None:first_down=age
   time.sleep(3)
  report.update(boot_after=returned,first_unreachable_after_seconds=first_down,return_after_seconds=time.monotonic()-start,magic_packets_sent=sent)
  if not returned:raise RuntimeError('S5 target has not returned within 300 seconds; retained recovery evidence, do not claim success')
  assert first_down is not None and returned!=report['boot_before']
  passed('target disappeared after poweroff and returned from firmware boot with a different kernel identity')
  report['previous_shutdown_journal']=ssh('journalctl -b -1 -u systemd-poweroff.service -u systemd-logind.service --no-pager -n 15',check=False).stdout[-6000:]
  states=ssh('systemctl is-active '+RUNNER+' ssh tailscaled wired-fallback-guard.service').stdout.splitlines();assert states==['active']*4
  paused=False;report['postboot_services']=states
  passed('runner, SSH, tailnet and wired recovery services returned automatically')
  report['complete']=True;report['completed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 finally:
  if report.get('boot_after') or not report['performed']:
   if wake_changed:
    ssh('sudo -n ethtool -s '+INTERFACE+' wol '+report['wol_before'],check=False)
    ssh('sudo -n rtcwake --mode disable',check=False)
   if paused:ssh('sudo -n systemctl start '+RUNNER,check=False)
   report['wake_cleanup']=ssh('cat /sys/class/rtc/rtc0/wakealarm; sudo -n ethtool '+INTERFACE+' | grep "Wake-on:"',check=False).stdout
  save()
 print('S5_POWER_CYCLE_PASS '+json.dumps({'boot_after':report['boot_after'],'return_seconds':report['return_after_seconds'],'G3_claimed':False}),flush=True)


if __name__=='__main__':main()
