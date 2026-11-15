"""Matched actual scheduling barriers for the native owner and locked Tokio."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import struct
import sys

from owned_trace import Trace,u64

CHUNK=2<<20


def result(raw,mode):
    if len(raw)<8:return None
    extent=u64(raw,0)
    if len(raw)<8+extent:return None
    assert len(raw)==8+extent
    body=bytes(raw[8:])
    if body[:8]==b'HLCRER01':
        assert extent==48 and u64(body,8)==48 and u64(body,40)==0
        return dict(outcome='result',kind=u64(body,16),error=u64(body,24),written=u64(body,32))
    if mode=='rust':assert body==b'HLCCAN01'+struct.pack('<Q',16)
    else:
        assert body[:8]==b'HLCASR01' and extent==128 and u64(body,8)==128 and u64(body,16)==6
        assert u64(body,24)in (4,6)and u64(body,120)==0
    return dict(outcome='cancelled')


class Policy:
    def __init__(self,scenario,content,*,normal_kind=0,normal_error=0,expected_bytes=None):
        self.scenario=scenario;self.content=content;self.normal_kind=normal_kind;self.normal_error=normal_error
        self.expected_bytes=expected_bytes;self.matched=set();self.witnesses=[];self.phase='start'
        self.bootstrap=False;self.poll_cancel=False;self.abort_returned=False
        self.bootstrap_write=False;self.target_write_held=False;self.close_barrier=False
        self.worker_start=False;self.pending_gate=False;self.ready_forwarded=False
        self.repeat_wakes=0;self.repeat_last_poll=None;self.repeat_initial_poll=None

    def marker(self,trace,event):
        if event.get('owner')=='rust':
            if event['event']==9:self.abort_returned=True
            if event['event']==5:self.ready_forwarded=True
            if event['event']==16:return 'worker_start'
            if event['event']==4:return 'ready'
            if event['event']==1:return 'poll'
            if event['event']==2:return 'pending'
            if event['event']==15:return 'unpolled'
        elif event.get('owner')=='native':
            if event['action']==9 and event['life']==3:return 'ready'
            if event['tid']==trace.root_pid and event['action']==3 and event['life']==3:return 'pending'
            if self.scenario=='nul_ready_poll_cancel'and event['tid']==trace.root_pid and event['action']==11 and event['life']==2:return 'poll'
            if event['tid']==trace.root_pid and event['life']==2 and event['action']in (2,4):return 'poll'
            if event['tid']==trace.root_pid and event['action']==10 and event['life']==1:return 'unpolled'
        return None

    def observe(self,trace,event):
        scene=self.scenario;mark=self.marker(trace,event)if event['kind']=='marker_entry'else None
        if scene.startswith('nul_')and not self.worker_start:
            if mark=='worker_start'or (trace.mode=='native'and event['kind']=='child_first_syscall'):
                self.worker_start=True;self.matched.add('worker_start')
                return 'nul_effect'if scene=='nul_inflight_cancel'else 'bootstrap_worker'
        if scene=='completion_before_wait'and mark=='pending'and not self.pending_gate:
            self.pending_gate=True;self.matched.add('pending_gate');return 'pending_gate'
        if scene=='unpolled_cancel' and mark=='unpolled' and 'unpolled'not in self.matched:
            self.matched.add('unpolled');return 'unpolled'
        if scene.startswith('open_ready') or scene in ('empty_ready_poll_cancel','last_ready_poll_cancel','completion_before_wait'):
            if event['kind']=='syscall_entry'and event['operation']=='open'and not self.bootstrap:
                self.bootstrap=True;return 'bootstrap_open'
        if scene.startswith('write_ready')or scene=='last_ready_poll_cancel':
            if event['kind']=='syscall_entry'and event['operation']=='write'and not self.bootstrap_write:
                self.bootstrap_write=True;return 'bootstrap_write'
        if scene in ('open_ready_cancel','open_ready_close_cancel') and mark=='ready'and trace.completed==0 and 'ready'not in self.matched:
            self.matched.add('ready');return 'ready'
        if scene=='nul_ready_cancel'and mark=='ready'and 'ready'not in self.matched:
            self.matched.add('ready');return 'ready'
        if scene=='write_ready_cancel'and mark=='ready'and trace.completed>=CHUNK and 'ready'not in self.matched:
            self.matched.add('ready');return 'ready'
        if mark=='poll'and not self.poll_cancel:
            candidate=False
            if trace.mode=='rust':
                after_open=event['poll']>1 and trace.calls['open']>=1
                candidate=(scene=='open_ready_poll_cancel'and after_open and trace.completed==0
                           or scene=='write_ready_poll_cancel'and trace.completed>=CHUNK
                           or scene=='empty_ready_poll_cancel'and after_open and not self.content
                           or scene=='last_ready_poll_cancel'and trace.completed==len(self.content)and self.content
                           or scene=='nul_ready_poll_cancel'and event['poll']>1)
            else:
                candidate=(scene=='open_ready_poll_cancel'and event['action']==2 and event['ticket_start']==0
                           or scene=='write_ready_poll_cancel'and event['action']==2 and event['ticket_start']==CHUNK
                           or scene in ('empty_ready_poll_cancel','last_ready_poll_cancel')and event['action']==4)
                if scene=='nul_ready_poll_cancel'and event['action']==11:candidate=True
            if candidate:self.poll_cancel=True;self.matched.add('poll');return 'poll'
        if event['kind']=='syscall_entry':
            operation=event['operation']
            repeated=(scene=='repeat_pending_open'and operation=='open'
                      or scene=='repeat_pending_write'and operation=='write')
            if repeated and 'repeat_effect'not in self.matched:
                self.matched.add('repeat_effect');return 'repeat_effect'
            if scene=='open_inflight_cancel'and operation=='open'and 'effect'not in self.matched:
                self.matched.add('effect');return 'effect'
            if operation=='write'and not self.target_write_held:
                threshold=CHUNK if scene in ('write2_inflight_cancel','write_ready_poll_cancel')else 0
                wanted=scene in ('write1_inflight_cancel','write2_inflight_cancel','flush_inflight_cancel',
                                 'open_ready_poll_cancel','write_ready_poll_cancel')
                if wanted and trace.completed>=threshold:
                    self.target_write_held=True;self.matched.add('effect');return 'effect'
            if operation=='close'and scene=='open_ready_close_cancel'and trace.cancel_sent and not self.close_barrier:
                assert event['tid']==trace.root_pid
                self.close_barrier=True;self.matched.add('close');return 'close'
        return None

    def advance(self,trace):
        holds=list(trace.holds.items())
        repeated=next((hold for _,hold in holds if hold['reason']=='repeat_effect'),None)
        if repeated and trace.parent_pending and not trace.cancel_sent:
            if self.repeat_initial_poll is None:self.repeat_initial_poll=trace.polls
            if self.repeat_wakes<3 and self.repeat_last_poll!=trace.polls:
                self.repeat_last_poll=trace.polls;self.repeat_wakes+=1
                self.witnesses.append(dict(kind='force_actual_repoll',poll=trace.polls,ordinal=self.repeat_wakes))
                trace.force_wake('explicit wake while the actual worker remains held')
            elif self.repeat_wakes==3 and trace.polls>self.repeat_last_poll:
                self.witnesses.append(dict(kind='three_repeated_pending_turns',initial_poll=self.repeat_initial_poll,
                                          final_poll=trace.polls))
                trace.cancel('three actual Pending turns did not redispatch the held ticket')
                self.phase='cancel_sent'
        for pid,hold in holds:
            if hold['reason']in ('bootstrap_open','bootstrap_write','bootstrap_worker')and trace.parent_pending:
                trace.release(pid,'actual parent Pending was observed')
            elif hold['reason']=='pending_gate':
                completed=(self.ready_forwarded if trace.mode=='rust'else any(pid!=trace.root_pid for pid in trace.exit_codes))
                if completed:
                    self.witnesses.append(dict(kind='completion_before_pending_turn_released',event=hold['event']['index']))
                    trace.release(pid,'actual wake/worker completion preceded the wait boundary')
        holds=list(trace.holds.items())
        if not trace.cancel_sent:
            trigger=next((hold for _,hold in holds if hold['reason']in ('ready','poll','unpolled')),None)
            if trigger is None and trace.parent_pending:
                trigger=next((hold for _,hold in holds if hold['reason']in ('effect','nul_effect')),None)
            if trigger:
                self.witnesses.append(dict(kind='cancel_at',reason=trigger['reason'],event=trigger['event']['index']))
                trace.cancel(trigger['reason']);self.phase='cancel_sent'
        for pid,hold in list(trace.holds.items()):
            if hold['reason']in ('poll','unpolled') and trace.cancel_sent:
                if trace.mode=='native'or self.abort_returned:
                    trace.release(pid,'actual abort requested during held task turn')
            elif hold['reason']=='close':
                trace.pipe_events(0)
                assert not trace.stdout and not trace.publication_started
                self.witnesses.append(dict(kind='no_cancel_publication_while_inline_close_held',event=hold['event']['index']))
                trace.release(pid,'close-before-publication barrier verified')
        visible=result(trace.stdout,trace.mode)
        if visible is not None:
            for pid,hold in list(trace.holds.items()):
                if hold['reason']in ('ready','effect','nul_effect','repeat_effect'):
                    assert visible['outcome']=='cancelled'
                    self.witnesses.append(dict(kind='actual_cancel_visible_before_release',event=hold['event']['index']))
                    trace.release(pid,'complete cancellation frame is actually readable')
            self.phase='result_visible'

    def finish(self,trace):
        actual=result(trace.stdout,trace.mode);assert actual is not None
        normal=self.scenario in ('normal','empty_ready_poll_cancel','last_ready_poll_cancel','nul_ready_poll_cancel','completion_before_wait')
        if normal:
            assert actual['outcome']=='result' and (actual['kind'],actual['error'])==(self.normal_kind,self.normal_error)
            if self.normal_kind==0:assert actual['written']==len(self.content)
        else:assert actual=={'outcome':'cancelled'} and trace.cancel_sent
        if self.scenario!='normal':assert self.matched
        if self.scenario=='open_ready_close_cancel':assert self.close_barrier
        if self.scenario in ('open_ready_poll_cancel','write_ready_poll_cancel','empty_ready_poll_cancel','last_ready_poll_cancel','nul_ready_poll_cancel'):
            assert self.poll_cancel
        if self.scenario.startswith('repeat_pending_'):
            assert self.repeat_wakes==3 and trace.polls>=self.repeat_initial_poll+3
        expected=self.expected_bytes
        if expected is None:
            if self.scenario=='unpolled_cancel' or self.normal_kind==2 or self.scenario.startswith('nul_'):expected=None
            elif self.scenario=='repeat_pending_open'or self.scenario.startswith('open_')and self.scenario!='open_ready_poll_cancel':expected=0
            elif self.scenario in ('write1_inflight_cancel','open_ready_poll_cancel','write_ready_cancel','repeat_pending_write'):expected=min(CHUNK,len(self.content))
            elif self.scenario in ('write2_inflight_cancel','write_ready_poll_cancel'):expected=min(2*CHUNK,len(self.content))
            else:expected=len(self.content)
        path=Path(os.fsdecode(trace.target))
        if expected is None:
            assert b'\0'in trace.target or not path.exists()
            assert trace.calls=={'open':0,'write':0,'close':0}
        else:
            assert path.read_bytes()==self.content[:expected]
            assert trace.calls['close']==1
        assert not trace.holds
        self.actual=actual;self.expected_file_bytes=expected

    def result(self):
        return dict(scenario=self.scenario,matched=sorted(self.matched),witnesses=self.witnesses,
                    phase=self.phase,semantic_result=getattr(self,'actual',None),
                    expected_file_bytes=getattr(self,'expected_file_bytes',None),repeat_wakes=self.repeat_wakes)


def content(size):return (bytes(range(251))*((size+250)//251))[:size]


def run(binary,output,mode,scenario,size,*,injections=(),fd0=False,nul=False,expected_bytes=None,kind=0,error=0):
    output=Path(output);output.mkdir(exist_ok=False)
    work=output/'work';work.mkdir();path=os.fsencode(str((work/'created.bin').resolve()))
    if nul:path+=b'\0tail'
    body=content(size);wire=b'HLCARQ01'+struct.pack('<7Q',1,len(path),len(body),1,0,0,0)+path+body
    policy=Policy(scenario,body,normal_kind=kind,normal_error=error,expected_bytes=expected_bytes)
    return Trace(binary,work,struct.pack('<Q',len(wire))+wire,path,output/'trace',mode,policy,
                 injections=injections,fd0=fd0).run()


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--output',required=True)
    p.add_argument('--mode',choices=('native','rust'),required=True);p.add_argument('--scenario',default='normal')
    p.add_argument('--size',type=int,default=3);p.add_argument('--fd0',action='store_true');p.add_argument('--nul',action='store_true')
    p.add_argument('--injections',default='[]');p.add_argument('--expected-bytes',type=int);p.add_argument('--kind',type=int,default=0);p.add_argument('--error',type=int,default=0)
    a=p.parse_args();r=run(a.binary,a.output,a.mode,a.scenario,a.size,injections=json.loads(a.injections),fd0=a.fd0,nul=a.nul,
                         expected_bytes=a.expected_bytes,kind=a.kind,error=a.error)
    print(json.dumps({key:r[key]for key in ('status','mode','syscall_counts','completed_kernel_bytes','file','policy')},sort_keys=True))
