"""All source-owned root, checkpoint, limit and EOF descriptor effects."""
from reader_common import require
from read_pairs import exact
POOL=list(range(32,320))+list(range(512,772))
def verify(trace,commands,role):
    original=role["report"]["role"]=="original";actual=trace["outside"];at=0
    queried=trace["descriptor_queries"];root_flags=trace["root_cloexec"]
    saved=trace["saved_limits"];require(len(saved)==1 and saved[0]["result"]==0 and saved[0]["errno"]==0,
        "one complete actual original saved descriptor limit")
    limit=saved[0]["value"];require(limit.startswith("{rlim_cur=")and", rlim_max="in limit and limit.endswith("}"),
        "complete actual saved descriptor-limit pair")
    roots={};queries=list(POOL);flags=[];opens=stats=closes=restores=0;last=None
    def take(wanted,message):
        nonlocal at
        require(at<len(actual),"no omitted outer actual syscall: "+message)
        row=actual[at];at+=1;exact(row,wanted,message);return row
    def open_root(path,index):
        nonlocal at,opens
        require(index not in roots and at<len(actual),"fresh source-owned root capability")
        row=actual[at];fd=row["result"];require(type(fd)is int and 32<=fd<320,"actual transient root descriptor")
        expected_flags="O_RDONLY|O_CLOEXEC"
        if original:expected_flags="O_RDONLY|O_CLOEXEC"
        # Linux's Rust File open may spell the ABI-zero O_LARGEFILE bit.
        wanted=dict(row);wanted["flags"]=wanted.get("flags","").replace("|O_LARGEFILE","")if original else wanted.get("flags")
        exact(wanted,dict(op="open-root",directory="AT_FDCWD",path=path,flags=expected_flags,result=fd,errno=0),
            "complete actual root open path/flags/result")
        at+=1;take(dict(op="root-slot",source=fd,target=512+index,result=512+index,errno=0),"actual root slot transfer")
        take(dict(op="close",fd=fd,result=0,errno=0),"actual transient root closed")
        roots[index]=512+index;queries.append(512+index);opens+=1
        if original:flags.append(dict(fd=512+index,value="FD_CLOEXEC",result=0,errno=0))
    def checkpoint(answer):
        nonlocal stats,last
        rows=answer["state"]["roots"];require([r["root"]for r in rows]==sorted(roots),"all real caller roots in actual state")
        for row in rows:
            take(dict(op="stat",fd=roots[row["root"]],identity=[row["device"],row["inode"],row["mode"]],result=0,errno=0),
                "complete real root metadata at the actual observer checkpoint")
            stats+=1
        last=answer["state"]
    def restore():
        nonlocal restores
        take(dict(op="limit",request=limit,result=0,errno=0),"actual restoration to the complete originally observed limit")
        restores+=1
    require(len(commands)==len(role["answers"]),"complete source control/response set")
    for command,answer in zip(commands,role["answers"]):
        kind=command["cmd"]
        if kind=="prepare":
            require(not roots,"all prior caller roots released")
            queries.extend(POOL)
            for i,row in enumerate(command["roots"]):
                if not row["late"]:open_root(row["path_hex"],i)
            checkpoint(answer)
        elif kind=="run":
            op=command["operation"];key=(command["case"],command["step"])
            if op["op"]=="open-root":
                require(op["root"]not in roots,"new explicitly late caller root")
                roots[op["root"]]=512+op["root"];queries.append(512+op["root"])
                if original:flags.append(dict(fd=512+op["root"],value="FD_CLOEXEC",result=0,errno=0))
            elif op["op"]=="release-root":
                require(op["root"]in roots,"existing caller reference released");del roots[op["root"]]
            elif op["op"]=="restore-limit":
                exact(trace["groups"][key],[dict(op="limit",request=limit,result=0,errno=0)],
                    "source restore operation uses the actual initial limit")
            checkpoint(answer)
        elif kind=="finish":
            require(last is not None and last["watchers"]==[]and
                all(row["strong_count"]==1 for row in last["roots"]),"last roots have no Watcher owners at finish")
            order=sorted(roots)if original else list(roots)
            for i in order:
                take(dict(op="close",fd=roots[i],result=0,errno=0),"all actual last caller references closed at finish")
                closes+=1
            roots.clear();restore();queries.extend(POOL);last=None
        else:raise ValueError("unlisted complete original control")
    queries.extend(POOL)
    if not original:restore()
    require(at==len(actual)and not roots,"no unclaimed outer kernel effects or caller references")
    expected_queries=[dict(fd=fd,result=-1,errno=9)for fd in queries]
    differences=[i for i,(a,b)in enumerate(zip(queried,expected_queries))if a!=b]
    first=differences[0]if differences else min(len(queried),len(expected_queries))
    exact(queried,expected_queries,
        "all original complete descriptor-vacancy scans, including actual EOF cleanup: "+
        repr(dict(role=role["report"]["role"],actual=len(queried),expected=len(expected_queries),
            at=first,actual_rows=queried[max(0,first-2):first+5],
            expected_rows=expected_queries[max(0,first-2):first+5])))

    exact(root_flags,flags,"every complete original root CLOEXEC installation")
    return dict(outer_syscalls=len(actual),root_opens=opens,root_closes=closes,
        checkpoint_stats=stats,restored_limits=restores,descriptor_vacancy_checks=len(queried),
        root_cloexec_sets=len(root_flags),original_file_close_checks=len(trace["typed_close_checks"]),remaining_roots=0)
