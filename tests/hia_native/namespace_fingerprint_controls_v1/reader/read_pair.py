"""All complete same-tree inputs, processes, files, native buffers and original results."""
from pathlib import Path
import math,struct
from common import ROOT,encoded,files,loads,pin,read,require
from protocol import cases,line,require_semantic
from environment_policy import filters,GROUPS
from read_frames import equal
from read_filesystem import Tree
import read_native,read_trace
ROLES=("native-observed","native-off","original")
def bounded(value,limit):
    return type(value)in(int,float)and math.isfinite(value)and 0<value<=limit
def verify(root,metadata,group,producer,compiled,source_sha):
    folder=root/("paired-"+group);wanted=cases(group);report=loads(read(folder/"PAIRED.json"))
    require(report["schema"]=="hepta.namespace-fingerprint.same-tree-pair.v1"and report["status"]=="PASS"and
            report["source_manifest_sha256"]==source_sha and report["group"]==group and
            report["cases"]==len(wanted)and report["operations"]==sum(len(c["steps"])for c in wanted)and
            report["processes"]==3 and report["compared_complete_terminal_bytes"]is True and
            report["namespace_watch_qualified"]is False and report["public_handler_qualified"]is False,"whole frozen three-process domain")
    oldout=metadata["producer_root"]+"/paired-"+group;oldfixture=metadata["owned_fixture"]+"/"+group
    require(report["source_root"]==metadata["source_root"]and report["output_root"]==oldout and
            report["build_root"]==metadata["producer_root"]+"/build"and report["fixture_root"]==oldfixture and
            report["original_binary"]==metadata["original_binary"]and
            type(report["timeout_seconds"])is int and report["timeout_seconds"]==60 and bounded(report["elapsed_seconds"],60),
            "complete inert producer paths, binary and unchanged whole-group deadline")
    require(type(report["pid"])is int and report["pid"]>1 and
            report["parent_pid"]==report["pgid"]==producer["pid"]and report["pid"]!=report["parent_pid"]and
            report["uid"]==metadata["uid"]>0 and report["gid"]==metadata["gid"],"actual traced coordinator custody")
    names=("INITIALS.json","OBSERVATIONS.json","RETIREMENT.json","PROCESSES.json")
    require(set(report["files"])==set(names),"all whole paired report inputs")
    for name in names:equal(report["files"][name],pin(read(folder/name)),"whole paired file "+name)
    initials,observations,retirements,processes=[loads(read(folder/n))for n in names]
    require(len(initials)==len(retirements)==len(wanted)and len(observations)==report["operations"]and
            len(processes)==3,"complete paired case and process arrays")
    requests=[];responses=[[],[],[]];trees=[];errors=[];cursor=0
    environment=dict(group=group,installed=bool(GROUPS[group]),filters=[list(r)for r in filters(group)])
    for case,init,retired in zip(wanted,initials,retirements,strict=True):
        ci=case["case"];path=oldfixture+"/case-%04d"%ci
        require(set(init)=={"case","owned_root","snapshot","replies"}and init["case"]==ci and init["owned_root"]==path and
                len(init["replies"])==3,"exact physical case setup")
        tree=Tree(case,metadata["uid"],metadata["gid"]);tree.verify(init["snapshot"])
        rootrow=init["snapshot"]["entries"][0];identity={k:rootrow[k]for k in("device","inode")}
        identity["mode"]=rootrow["mode"]|rootrow["type"]
        wanted_init=dict(command="init",case=ci,root_fd=96,root_identity=identity,environment=environment)
        require(all(encoded(x)==encoded(wanted_init)for x in init["replies"]),"three actual same-root initial replies")
        requests.append(dict(cmd="init",case=ci,path_hex=path.encode().hex()))
        for seq in range(3):responses[seq].append(init["replies"][seq])
        previous=init["snapshot"]
        for si,step in enumerate(case["steps"]):
            row=observations[cursor];cursor+=1
            require(set(row)=={"case","step","generation","before","after","answers"}and
                    (row["case"],row["step"],row["generation"])==(ci,si,si+1)and len(row["after"])==len(row["answers"])==3,
                    "one complete physical triple per frozen operation")
            tree.apply(step["actions"]);tree.verify(row["before"])
            require(all(encoded(value)==encoded(row["before"])for value in row["after"]),
                    "every whole native/original before/after file tree, not a projected summary")
            for value in row["answers"]:require_semantic(value["semantic"])
            require(row["answers"][0]["semantic"]==row["answers"][1]["semantic"]==row["answers"][2]["semantic"]and
                    row["answers"][0]["native_frame_hex"]==row["answers"][1]["native_frame_hex"],"entire three-way result equality")
            original=row["answers"][2]
            require(set(original)=={"command","case","step","generation","semantic","original_error"}and
                    original["command"]=="run"and(original["case"],original["step"],original["generation"])==(ci,si,si+1),
                    "complete unchanged original answer")
            error=original["original_error"]
            if original["semantic"]["kind"]==0:require(error is None,"successful original has no hidden error")
            else:
                require(type(error)is dict and set(error)=={"display","debug","chain","raw_os_error"}and
                        type(error["raw_os_error"])is int and error["raw_os_error"]==original["semantic"]["errno"]and
                        all(type(error[k])is str and error[k]for k in("display","debug"))and type(error["chain"])is list and
                        error["chain"]==[error["display"]],"complete actual original OS error and chain")
                errors.append(dict(case=ci,step=si,**error))
            requests.append(dict(cmd="run",case=ci,step=si,generation=si+1))
            for seq in range(3):responses[seq].append(row["answers"][seq])
            previous=row["before"]
        requests.append(dict(cmd="dispose",case=ci))
        for seq in range(3):responses[seq].append(dict(command="dispose",case=ci,closed_root=True))
        require(set(retired)=={"case","complete_before","retired","root"}and retired["case"]==ci and
                retired["root"]==path and retired["retired"]is True and encoded(retired["complete_before"])==encoded(previous),
                "exact complete fixture retirement after all three actual disposals")
        trees.append(tree)
    require(cursor==len(observations),"no omitted or extra source operation")
    streams={};expected_names=set(names)|{"PAIRED.json"}
    for ri,(role,process)in enumerate(zip(ROLES,processes,strict=True)):
        part=folder/"roles"/role;equal(process,loads(read(part/"PROCESS.json")),"same complete child process row")
        require(set(process)=={"role","argv","cwd","group","pid","parent_pid","pgid","timeout_seconds","elapsed_seconds",
                "exit_code","success","failure","ready","exchanges","streams"}and
                process["role"]==role and process["cwd"]==metadata["source_root"]and process["group"]==group and
                type(process["pid"])is int and process["pid"]>1 and process["parent_pid"]==report["pid"]and
                process["pgid"]==producer["pid"]and type(process["timeout_seconds"])is int and process["timeout_seconds"]==60 and
                bounded(process["elapsed_seconds"],report["elapsed_seconds"])and process["success"]is True and process["failure"]is None and
                type(process["exit_code"])is int and process["exit_code"]==0 and process["exchanges"]==len(requests),
                "actual child PID/parent/PGID/whole deadline/exit")
        argv=process["argv"]
        if role=="original":expected=[metadata["producer_root"]+"/original.elf",group]
        else:
            require(argv[0]in(metadata["python"],"/usr/bin/python3.12")and Path(argv[0]).parent==Path(metadata["python"]).parent,
                    "actual resolved system Python in the frozen Ubuntu-24.04 fixture")
            expected=[argv[0],"-I","-B",metadata["source_root"]+"/native_child.py","--build",metadata["producer_root"]+"/build",
                "--output",oldout+"/roles/"+role+"/capture","--group",group,"--observer","on"if ri==0 else"off"]
        equal(argv,expected,"whole actual child command")
        raw={n:read(part/n)for n in("stdin","stdout","stderr")};streams[role]=raw
        require(set(process["streams"])==set(raw),"whole child stream set")
        for name,body in raw.items():equal(pin(body),process["streams"][name],"entire actual child stream")
        ready=process["ready"];require(type(ready)is dict and ready["command"]=="ready"and ready["role"]==role and
            ready["group"]==group and all(type(ready[k])is int and ready[k]==process[k]for k in("pid","parent_pid","pgid"))and
            ready["uid"]==metadata["uid"]and ready["gid"]==metadata["gid"],"real child ready and actual identity")
        require(raw["stdin"]==b"".join(line(x)for x in requests),"all original complete owned requests in source order")
        require(raw["stdout"]==line(ready)+b"".join(line(x)for x in responses[ri]),"all complete actual answers and ready")
        tags=(b"NFORGB01",b"NFORGE01")if ri==2 else(b"NFNATB01",b"NFNATE01")
        markers=b"".join(tag+struct.pack("<2Q",row["case"],row["generation"])for row in observations for tag in tags)
        require(raw["stderr"]==markers,"complete stderr contains exactly the actual binary syscall markers")
        xs=loads(read(part/"EXCHANGES.json"));require(len(xs)==len(requests),"all complete control exchanges")
        for index,(x,req,answer)in enumerate(zip(xs,requests,responses[ri],strict=True)):
            a,c=line(req),line(answer)
            equal(x,dict(index=index,request=pin(a),response=pin(c),request_hex=a.hex(),response_hex=c.hex()),
                "whole ordered captured exchange")
        for name in("stdin","stdout","stderr","PROCESS.json","EXCHANGES.json"):expected_names.add("roles/"+role+"/"+name)
        if ri<2:
            for name in files(part/"capture"):expected_names.add("roles/"+role+"/capture/"+name)
    require(len({p["pid"]for p in processes})==3 and set(files(folder))==expected_names,"all actual process and complete group file domains")
    observed=read_native.verify(folder/"roles/native-observed/capture",group,wanted,observations,initials,processes[0]["ready"],
        compiled["image"],source_sha,processes[0],observed=True)
    off=read_native.verify(folder/"roles/native-off/capture",group,wanted,observations,initials,processes[1]["ready"],
        compiled["image"],source_sha,processes[1],observed=False,observed_turns=observed["turns"])
    for value,role in((observed,"native-observed"),(off,"native-off")):
        require(value["report"]["build_root"]==metadata["producer_root"]+"/build"and
                value["report"]["output_root"]==oldout+"/roles/"+role+"/capture","whole native capture paths as inert identities")
    trace=read_trace.verify(read(root/("paired-"+group+".strace")),group,wanted,processes,observed["turns"],observations,streams)
    return dict(group=group,cases=len(wanted),operations=len(observations),processes=3,
        actual_owner_calls=observed["calls"],actual_boundary_calls=observed["boundaries"],
        observed_buffer_bytes=observed["logical_bytes"],observer_free_buffer_bytes=off["logical_bytes"],
        complete_original_errors=errors,kernel_trace=trace,whole_original_native_terminal_equality=True)
