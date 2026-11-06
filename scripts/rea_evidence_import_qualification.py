#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual public REA/native import, complete history, atomic merge and recovery.

Inputs are built by the pinned original domain constructors, then both actual
MCP servers receive the same files and requests. Full replies, payload object
order, complete canonical export bytes and failed-merge session snapshots are
compared. This finite Linux profile never establishes complete replacement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
from pathlib import Path
import subprocess
import sys
import time

import rea_apk_export_qualification as a
import rea_operation_qualification as q
from rea_frame_mcp_qualification import CompressedMcp
from rea_full_qualification import Selection, SourceMonitor

ALIASES = {"import_evidence_bundle":"rea_import_evidence_bundle", "get_evidence_bundle":"rea_get_evidence_bundle",
           "export_evidence_bundle":"rea_export_evidence_bundle"}
OPEN_REQUIREMENTS = ["all-file-size-token-depth-and-platform-boundaries", "all-evidence-provider-profiles",
                     "complete-public-unknown-management-tools", "full-final-combination-build-receipt",
                     "real-multi-host-failure-recovery", "complete-reference-capability-and-cost-comparison"]


def orders(value):
    if value.get("isError") or "rpc_error" in value or "structuredContent" not in value:
        return []
    facts=[]
    def walk(item, path, representation):
        if isinstance(item,dict):
            facts.append({"representation":representation,"path":path,"keys":list(item)})
            for key, child in item.items(): walk(child,path+[key],representation)
        elif isinstance(item,list):
            for index,child in enumerate(item):walk(child,path+[index],representation)
    walk(value["content"][0]["text"],[],"text")
    walk(value["structuredContent"],[],"structured")
    return facts


def error(value):
    q.require(value.get("isError") is True and "rpc_error" not in value,"expected a public tool error")
    return value["content"][0]["text"]["error"]


def payload(value):
    q.require(not value.get("isError") and "rpc_error" not in value,"expected a successful public tool response")
    return value["content"][0]["text"]["result"]


class Session:
    def __init__(self,label,scenario,command,environment,workspace,output,report):
        self.label,self.scenario,self.output=label,scenario,output
        self.client=CompressedMcp(command,workspace,environment,output)
        self.client.initialize()
        self.rows=[]
        self.state={"rows":[],"checks":[]}
        report["sessions"][label+"/"+scenario]=self.state
    def observe(self,name,operation,arguments,response):
        value=q.tool_value(response)
        row={"id":name,"operation":operation,"arguments":arguments,"value":value,
             "orders":orders(value),"response":response}
        self.rows.append(row)
        path=self.output/f"call-{len(self.rows):03d}-{name}.json"
        q.write_json(path,row)
        self.state["rows"].append({"id":name,"path":str(path),"sha256":q.file_hash(path)})
        return value
    def call(self,name,operation,arguments):
        tool=ALIASES[operation] if self.label=="native" else operation
        return self.observe(name,operation,arguments,self.client.call(tool,arguments))
    def bundle(self,name):
        return payload(self.call(name,"get_evidence_bundle",{}))
    def read(self,name,fixtures,file=None):
        return self.call(name,"import_evidence_bundle",{"path":str(fixtures/((file or name)+".json"))})
    def close(self):
        self.state["close"]=self.client.close()
        q.require(a.closed_normally(self.state["close"]),"actual MCP owner did not drain")


def counts(value, imported, unknowns, total):
    q.require(payload(value)=={"imported":imported,"unknowns_added":unknowns,"total":total},"import counters differ from independently selected candidate")
    q.require(value.get("_meta")==q.TARGET_META,"public import lost original untrusted target-content provenance")


def compare_observation(old, new):
    """Keep payload semantics and the unparsed CallToolResult as separate gates.

    content.text is part of the public result. Parsing that string before the
    only comparison used to hide error-producer key-order differences. A
    cancellation notification has no response and remains a lifecycle fact;
    it must never be counted as an equal fabricated CallToolResult.
    """
    q.require(not a.differences(old['arguments'],new['arguments']),
              "producers received different inputs")
    semantic=a.differences(old['value'],new['value'])+a.differences(old['orders'],new['orders'],'$/orders')
    lifecycle=old.get('kind')=='observed-protocol-lifecycle'
    q.require(lifecycle==(new.get('kind')=='observed-protocol-lifecycle'),
              "producer observation kinds differ")
    if lifecycle:
        q.require('response' not in old and 'response' not in new,
                  "suppressed response must not be invented")
        full=None
    else:
        q.require('response' in old and 'response' in new,
                  "original public response is missing")
        q.require('result' in old['response'] and 'result' in new['response'],
                  "public tool response was replaced by an RPC error")
        full=a.differences(old['response']['result'],new['response']['result'],'$/CallToolResult')
    differences=semantic+(full or [])
    return {'status':'FAIL' if differences else 'PASS','differences':differences,
            'parsed_value_status':'FAIL' if semantic else 'PASS',
            'complete_call_tool_result_status':None if full is None else ('FAIL' if full else 'PASS')}


def check_bundle(bundle, records, revisions):
    q.require(set(bundle)==a.BUNDLE_KEYS and len(bundle["records"])==records and len(bundle["unknowns"])==revisions,"complete imported ledger counts differ")
    q.require([r["evidence_id"] for r in bundle["records"]]==sorted({r["evidence_id"] for r in bundle["records"]}),"records are not unique canonical IDs")
    for record in bundle["records"]:
        q.require(q.semantic_evidence_id(record)==record["evidence_id"],"imported complete record semantic ID differs")
    q.require([(u["unknown_id"],u["revision"]) for u in bundle["unknowns"]]==sorted({(u["unknown_id"],u["revision"]) for u in bundle["unknowns"]}),"unknown history is not canonical")


def same_after_failure(session,name,fixtures,before):
    error(session.read(name,fixtures))
    q.require(session.bundle(name+"-unchanged")==before,"failed import partially published records, metadata or revisions: "+name)


def exercise_main(session,fixtures,catalog,exported):
    schema={x["name"]:x for x in session.client.tools()}
    tool=ALIASES["import_evidence_bundle"] if session.label=="native" else "import_evidence_bundle"
    q.require(tool in schema,"public import handler is absent")
    session.state["contract"]={key:schema[tool][key] for key in ("inputSchema","outputSchema","annotations")}
    invalid=[{}, {"path":None},{"path":False},{"path":[]},{"path":""},{"path":"relative"},
             {"path":"/nul\0file"},{"path":"relative\0file"},{"path":"/missing","z":1,"a":2}]
    for index,arguments in enumerate(invalid):error(session.call("input-"+str(index),"import_evidence_bundle",arguments))
    counts(session.read("empty",fixtures),0,0,0)
    counts(session.read("record",fixtures),1,0,1)
    initial=session.bundle("record-complete");check_bundle(initial,1,0)
    counts(session.read("record-repeat",fixtures,"record"),0,0,1)
    counts(session.read("metadata",fixtures),0,0,1)
    metadata=session.bundle("metadata-complete");check_bundle(metadata,1,0)
    q.require(metadata["records"][0]["subject"]["name"]=="replacement-display-name" and "caller_input_path" in metadata["records"][0],"same-ID display metadata was not refreshed")
    counts(session.read("reordered-same-metadata",fixtures),0,0,1)
    q.require(session.bundle("same-metadata-complete")==metadata,"idempotent same-ID import changed semantic facts")
    counts(session.read("unknown-first",fixtures),1,1,2)
    first=session.bundle("unknown-first-complete");check_bundle(first,2,1)
    counts(session.read("unknown-repeat",fixtures,"unknown-first"),0,0,2)
    counts(session.read("unknown-second",fixtures),1,1,3)
    second=session.bundle("unknown-second-complete");check_bundle(second,3,2)
    same_after_failure(session,"unknown-conflict",fixtures,second)
    q.require(all(record["evidence_id"]!=catalog["ids"]["extra"] for record in second["records"]),"conflict rollback fixture already contained the new record")
    counts(session.read("unknown-verified",fixtures),0,1,3)
    verified=session.bundle("unknown-verified-complete");check_bundle(verified,3,3)
    q.require(verified["unknowns"][-1]["status"]=="resolved" and verified["unknowns"][-1]["resolution"]["disposition"]=="verified","qualified revision was not retained")
    counts(session.read("unknown-schema-trim",fixtures),0,0,3)
    before=session.bundle("trimmed-complete");check_bundle(before,3,3)
    negatives=[x["name"] for x in catalog["files"] if not x["valid"] and not x["name"].startswith(("proto-","capture-","exception-","labels-"))]
    for name in negatives:same_after_failure(session,name,fixtures,before)
    for name in ("invalid-json","bom","invalid-utf8"):
        same_after_failure(session,name,fixtures,before)
    for name,path in (("missing",fixtures/"absent.json"),("directory",fixtures)):
        error(session.call(name,"import_evidence_bundle",{"path":str(path)}))
        q.require(session.bundle(name+"-unchanged")==before,"file failure changed the ledger")
    summary=payload(session.call("summary","get_evidence_bundle",{"detail":"summary"}))
    q.require(summary["total_retained_records"]==3 and summary["unknown_revisions"]==3,"summary lost imported revisions")
    result=payload(session.call("export-complete","export_evidence_bundle",{"path":str(exported),"overwrite":True}))
    raw=exported.read_bytes()
    q.require(result=={"path":str(exported),"bytes":len(raw),"records":3,"unknowns":3},"export counts do not include complete history")
    q.require(q.parse_json(raw)==before,"canonical export differs from complete retained data")
    (session.output/"complete-export.json").write_bytes(raw)
    session.state["export"]={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    return raw


def exercise_union(session,fixtures):
    counts(session.read("union-cycle-seed",fixtures),3,3,3)
    before=session.bundle("union-before");check_bundle(before,3,3)
    failure=error(session.read("union-cycle-candidate",fixtures))
    q.require(failure["code"]=="evidence_integrity_mismatch" and failure["details"]["reason"]=="Evidence bundle unknown registry failed","union graph failure lost the upstream integrity reason")
    q.require(session.bundle("union-after")==before,"union graph failure committed a partial revision or new record")


def exercise_capture(session,fixtures,exported):
    counts(session.read('capture-valid',fixtures),1,0,1)
    before=session.bundle('capture-complete');check_bundle(before,1,0)
    record=before['records'][0]
    q.require(record['predicate_type']=='rea.process-capture' and before['captures']==[{'evidence_id':record['evidence_id'],'predicate_type':'rea.process-capture'}], 'capture manifest or complete retained record was lost')
    same_after_failure(session,'capture-id-mismatch',fixtures,before)
    same_after_failure(session,'capture-invalid-payload',fixtures,before)
    payload(session.call('capture-export','export_evidence_bundle',{'path':str(exported),'overwrite':True}))
    raw=exported.read_bytes();q.require(q.parse_json(raw)==before,'capture export changed complete data')
    (session.output/'capture-export.json').write_bytes(raw)
    session.state['export']={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    return raw


def exercise_proto(session,fixtures):
    counts(session.call('input-proto','import_evidence_bundle',{'path':str(fixtures/'empty.json'),'__proto__':{'marker':True}}),0,0,0)
    counts(session.read('proto-schema',fixtures),1,0,1)
    first=session.bundle('proto-schema-complete');check_bundle(first,1,0)
    record=first['records'][0]
    q.require(all('__proto__' not in item for item in (first,record,record['subject'],record['provider'],first['providers'][0])), 'fixed schema did not strip its __proto__ key')
    counts(session.read('proto-payload',fixtures),1,0,2)
    before=session.bundle('proto-payload-complete');check_bundle(before,2,0)
    record=next(r for r in before['records'] if r['operation']=='import_proto_payload')
    q.require(all(item.get('__proto__')=={'marker':'retained own data'} for item in (record['parameters'],record['raw_result'],record['normalized_result'])), 'free JSON lost its legitimate own __proto__ data')
    for name in ('proto-unknown-order','proto-constructor','proto-toString'):same_after_failure(session,name,fixtures,before)


def exercise_exception(session,fixtures):
    for name,arguments in (
        ('exception-record',{'path':str(fixtures/'exception-record.json')}),
        ('exception-unknown',{'path':str(fixtures/'exception-unknown.json')}),
        ('exception-bare',{'path':str(fixtures/'exception-bare.json')}),
        ('exception-path',{'path':{'length':{'toString':None}}}),
    ):
        value=session.call(name,'import_evidence_bundle',arguments)
        q.require(value=={'content':[{'type':'text','text':'Cannot convert object to primitive value'}],
                          'isError':True,'_meta':q.TARGET_META},
                  'unexpected original schema exception projection')
        check_bundle(session.bundle(name+'-unchanged'),0,0)


def exercise_labels(session,fixtures,catalog):
    arguments={'path':str(fixtures/'empty.json')}
    arguments.update({key:1 for key in catalog['label_keys']})
    error(session.call('input-labels','import_evidence_bundle',arguments))
    check_bundle(session.bundle('input-labels-unchanged'),0,0)
    for name in ('labels-single','labels-multiple'):
        error(session.read(name,fixtures))
        check_bundle(session.bundle(name+'-unchanged'),0,0)


def owned_read_counters(client):
    result={}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():continue
        pid=int(entry.name)
        try:
            if os.getpgid(pid)!=client.process.pid:continue
            fields=dict(line.split(':',1) for line in (entry/'io').read_text().splitlines())
            result[pid]={"rchar":int(fields['rchar']),"owner":q.process_identity(pid)}
        except (OSError,ValueError,KeyError):pass
    q.require(result,"owned MCP process I/O counters are unavailable")
    return result


def active_reader(client,path,baseline,seconds=15):
    """Observe the exact open file after >8 MiB of owned read progress.

    REA uses positional reads, which do not advance fdinfo.pos. A pre-request
    rchar snapshot is therefore compared while the selected inode stays open.
    The initialized, otherwise idle session receives only this file request.
    An already completed read or missing observation never becomes a PASS.
    """
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        for pid,initial in baseline.items():
            entry=Path('/proc')/str(pid)
            try:
                if os.getpgid(pid)!=client.process.pid:continue
                fields=dict(line.split(':',1) for line in (entry/'io').read_text().splitlines())
                current=int(fields['rchar']);progress=current-initial['rchar']
                if not 8*1024*1024 < progress < path.stat().st_size-1024*1024:continue
                for fd in (entry/'fd').iterdir():
                    try:
                        if os.readlink(fd)!=str(path):continue
                        info=(entry/'fdinfo'/fd.name).read_text()
                        position=int(next(line.split()[1] for line in info.splitlines() if line.startswith('pos:')))
                        owner=q.process_identity(pid)
                        q.require(owner==initial['owner'],"active parser process identity changed")
                        return {"pid":pid,"fd":fd.name,"fd_position":position,"rchar_before":initial['rchar'],
                                "rchar_observed":current,"read_progress":progress,"size":path.stat().st_size,
                                "owner":owner,"proof":"exact selected open file plus owned positional-read progress"}
                    except (OSError,StopIteration,ValueError):pass
            except (OSError,ValueError,KeyError):pass
        if client.process.poll() is not None:break
        time.sleep(0.001)
    raise q.QualificationError("did not observe active streaming parser; no cancellation PASS is inferred")


def exercise_cancel(session,fixtures,path):
    counts(session.read("cancel-seed",fixtures,"record"),1,0,1)
    before=session.bundle("cancel-before")
    tool=ALIASES["import_evidence_bundle"] if session.label=="native" else "import_evidence_bundle"
    arguments={"path":str(path)}
    baseline=owned_read_counters(session.client)
    identity=session.client.begin("tools/call",{"name":tool,"arguments":arguments})
    observed=active_reader(session.client,path,baseline)
    session.state["active_parser"]=observed
    session.client.send("notifications/cancelled",{"requestId":identity,"reason":"controlled active-parser import cancellation"})
    deadline=time.monotonic()+10
    while True:
        selected=[]
        for pid in baseline:
            try:
                if os.getpgid(pid)!=session.client.process.pid:continue
                for fd in (Path('/proc')/str(pid)/'fd').iterdir():
                    try:
                        if os.readlink(fd)==str(path):selected.append((pid,fd.name))
                    except OSError:pass
            except OSError:pass
        if not selected:break
        q.require(time.monotonic()<deadline,"cancelled import retained an open selected descriptor")
        time.sleep(0.005)
    # A cancellation notification suppresses the original request response in
    # the actual reference SDK. Record protocol observations, never a fabricated
    # cancelled CallToolResult, then require same-session queries and new work.
    fact={"id":"cancel-active","operation":"notifications/cancelled","arguments":arguments,
          "kind":"observed-protocol-lifecycle","value":{"cancel_notification_sent":True,
          "selected_descriptor_closed":True,"cancelled_request_response_suppressed":True},"orders":[]}
    session.rows.append(fact)
    fact_path=session.output/f"call-{len(session.rows):03d}-cancel-active.json"
    q.require(session.bundle("cancel-after")==before,"cancelled parser imported candidate records or revisions")
    counts(session.read("cancel-reuse",fixtures,"unknown-first"),1,1,2)
    check_bundle(session.bundle("cancel-reused-complete"),2,1)
    q.require(identity not in session.client.pending,"cancelled request unexpectedly delivered a response")
    try:
        extra=session.client.responses.get(timeout=0.25)
    except queue.Empty:extra=None
    q.require(extra is None,"unexpected response or connection failure after cancellation recovery")
    q.write_json(fact_path,{**fact,"cancelled_request_id":identity,"active_parser":observed,
                           "observation":"No cancelled-ID response through descriptor closure, three completed follow-up calls and the final 250 ms observation window."})
    session.state['rows'].insert(2,{"id":"cancel-active","path":str(fact_path),"sha256":q.file_hash(fact_path)})


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("binary","reference-package","reference-tarball","node","repo","output-dir"):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--binary-sha256',required=True)
    args=p.parse_args(argv)
    q.require(all(x.is_absolute() for x in vars(args).values() if isinstance(x,Path)),"all paths must be absolute")
    out=args.output_dir;out.mkdir(parents=True,exist_ok=False)
    report={"schema":"hepta.rea.public-import.v1","qualified":False,"status":"OPEN","open_requirements":OPEN_REQUIREMENTS,"sessions":{},"comparisons":[],"errors":[]}
    sessions={};monitor=selection=None;before=None
    try:
        report["binary_before"]=q.identity(args.binary)
        q.require(report["binary_before"]["sha256"]==args.binary_sha256,"frozen binary hash differs")
        report["reference_before"]=q.reference_package(args.reference_package,args.reference_tarball)
        report["node"]=q.identity(args.node.resolve())
        q.require(report["node"]["sha256"]==a.NODE_SHA256,"unexpected Node binary")
        selection=Selection(args.repo,out/'unused-target',out);monitor=SourceMonitor(selection);monitor.start()
        before=selection.snapshot();q.write_json(out/'producer-before.json',before)
        workspace=out/'workspace';workspace.mkdir(mode=0o700)
        fixtures=workspace/'fixtures'
        generator=args.repo/'scripts/rea_evidence_import_fixtures.mjs'
        q.require(generator.is_file(),"pinned source fixture generator is absent")
        run=subprocess.run([str(args.node),str(generator),str(args.reference_package),str(fixtures),str(args.repo/'tests/fixtures/rea_process_capture/minimal.json')],env={},capture_output=True,timeout=30)
        (out/'fixture-generation.stdout').write_bytes(run.stdout);(out/'fixture-generation.stderr').write_bytes(run.stderr)
        q.require(run.returncode==0,"original fixture construction failed")
        catalog=q.parse_json((fixtures/'catalog.json').read_bytes())
        report["fixtures"]=[q.identity(x) for x in sorted(fixtures.iterdir()) if x.is_file()]
        cancel=workspace/'cancel-active.json'
        with cancel.open('xb') as stream:
            value=(fixtures/'unknown-second.json').read_bytes();q.require(value.startswith(b'{'),"bundle is not an object")
            stream.write(b'{')
            for _ in range(96):stream.write(b' '*(1024*1024))
            stream.write(value[1:])
        report["cancel_input"]=q.identity(cancel)
        config=out/'runtime.json'
        q.write_json(config,{"controller_workspace_roots":[str(workspace)],"state_dir":str(out/'state'),
                            "hosts":{"never-connect":{"ssh_target":"never-connect-invalid","remote_state_dir":str(out/'unused-remote'),"allow_execute":False,"allow_pty":False,"allow_write":False,"allow_job_network":False}}})
        environment={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","REA_MCP_INPUT_SCHEMA_PROFILE":"full","REA_MCP_OUTPUT_SCHEMA_PROFILE":"full"}
        producers=(("reference",[str(args.node),str(args.reference_package/'scripts/rea.mjs'),'mcp'],environment),
                   ("native",[str(args.binary),'mcp','--runtime-config',str(config)],{}))
        exports={};capture_exports={}
        for label,command,env in producers:
            for scenario in ('main','cold','union','capture','proto','exception','labels','cancel'):
                s=Session(label,scenario,command,env,workspace,out/(label+'-'+scenario),report);sessions[(label,scenario)]=s
                if scenario=='main':exports[label]=exercise_main(s,fixtures,catalog,workspace/'export.json')
                elif scenario=='cold':
                    check_bundle(s.bundle('cold-empty'),0,0)
                    counts(s.call('cold-import','import_evidence_bundle',{"path":str(workspace/'export.json')}),3,3,3)
                    check_bundle(s.bundle('cold-complete'),3,3)
                elif scenario=='union':exercise_union(s,fixtures)
                elif scenario=='capture':capture_exports[label]=exercise_capture(s,fixtures,workspace/'capture-export.json')
                elif scenario=='proto':exercise_proto(s,fixtures)
                elif scenario=='exception':exercise_exception(s,fixtures)
                elif scenario=='labels':exercise_labels(s,fixtures,catalog)
                else:exercise_cancel(s,fixtures,cancel)
                s.close()
        for scenario in ('main','cold','union','capture','proto','exception','labels','cancel'):
            left,right=sessions[('reference',scenario)],sessions[('native',scenario)]
            q.require([r['id'] for r in left.rows]==[r['id'] for r in right.rows],"producer request sequence differs")
            for old,new in zip(left.rows,right.rows):
                report['comparisons'].append({'id':scenario+'/'+old['id'],**compare_observation(old,new)})
        for key in ('inputSchema','outputSchema','annotations'):
            differences=a.differences(sessions[('reference','main')].state['contract'][key],sessions[('native','main')].state['contract'][key])
            report['comparisons'].append({'id':'contract/'+key,'status':'FAIL' if differences else 'PASS','differences':differences})
        report['comparisons'].append({'id':'canonical-export-bytes','status':'PASS' if exports['reference']==exports['native'] else 'FAIL'})
        report['comparisons'].append({'id':'capture-export-bytes','status':'PASS' if capture_exports['reference']==capture_exports['native'] else 'FAIL'})
    except Exception as exc:
        report['errors'].append({'type':type(exc).__name__,'message':str(exc)})
    finally:
        for session in sessions.values():
            if not session.client.closed:
                try:session.close()
                except Exception as exc:report['errors'].append({'type':type(exc).__name__,'message':'cleanup: '+str(exc)})
        if monitor is not None:
            events=monitor.stop();q.write_json(out/'producer-events.json',events)
            after=selection.snapshot();q.write_json(out/'producer-after.json',after)
            report['source_unchanged']=before==after and events['event_count']==0 and not events['errors']
            if not report['source_unchanged']:report['errors'].append({'type':'SourceChanged','message':'selected producer sources changed'})
        try:
            report['binary_after']=q.identity(args.binary);report['reference_after']=q.reference_package(args.reference_package,args.reference_tarball)
            q.require(report['binary_before']==report['binary_after'] and report['reference_before']==report['reference_after'],'producer identity changed')
        except Exception as exc:report['errors'].append({'type':type(exc).__name__,'message':str(exc)})
    passed=sum(x['status']=='PASS' for x in report['comparisons'])
    expected={label+'/'+scenario:count for label in ('reference','native') for scenario,count in (('main',68),('cold',3),('union',4),('capture',7),('proto',11),('exception',8),('labels',6),('cancel',6))}
    observed={label+'/'+scenario:len(session.rows) for (label,scenario),session in sessions.items()}
    report['finite_status']='PASS' if not report['errors'] and observed==expected and len(report['comparisons'])==118 and passed==118 else 'FAIL'
    report['counts']={key:len(session.rows) for key,session in ((label+'/'+scenario,s) for (label,scenario),s in sessions.items())}
    full=[x for x in report['comparisons'] if x.get('complete_call_tool_result_status') is not None]
    report['complete_call_tool_results']={'compared':len(full),
        'matched':sum(x['complete_call_tool_result_status']=='PASS' for x in full),
        'raw_jsonrpc_bytes':'Not inferred from object equality; retained wire requires a separate comparison.'}
    q.write_json(out/'qualification.json',report)
    print(json.dumps({'finite_status':report['finite_status'],'qualified':False,'passed':passed,'comparisons':len(report['comparisons']),'errors':report['errors'],'receipt':q.identity(out/'qualification.json')}))
    return 0 if report['finite_status']=='PASS' else 1

if __name__=='__main__':sys.exit(main())
