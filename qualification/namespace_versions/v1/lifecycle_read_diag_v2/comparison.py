"""Compare complete source results; nondeterministic constructors retain a witnessed bijection."""
import copy
from common import require
from protocol import require_semantic
HIGH=1<<63
class Comparison:
    def __init__(self,case):self.case=case;self.ids={};self.events={};self.witness=[]
    def bind(self,answers,operation):
        if operation["op"]!="parallel-new":return
        count=operation["workers"];base=operation["sid"]
        for role,a in enumerate(answers):
            sets=a["state"]["sets"];require(len(sets)==count and [s["sid"]for s in sets]==list(range(base,base+count)),
                "every actual concurrent constructor scope")
            ids={s["id"]:s["sid"]for s in sets};fds={s["watcher"]["event_fd"]:s["sid"]for s in sets}
            require(len(ids)==len(fds)==count and set(ids)==set(range(HIGH+1,HIGH+count+1))
                and set(fds)==set(range(32,32+count))and a["state"]["next"]==count+1,
                "actual constructor CAS serial range, unique event descriptors and final NEXT")
            self.ids[role]=ids;self.events[role]=fds
            self.witness.append(dict(role=role,scope_ids=[dict(raw=k,sid=v)for k,v in sorted(ids.items())],
                event_descriptors=[dict(raw=k,sid=v)for k,v in sorted(fds.items())],next=a["state"]["next"]))
    def normalize_semantic(self,role,semantic):
        result=copy.deepcopy(require_semantic(semantic))
        if result["kind"]==1 and result["version"][0]in self.ids.get(role,{}):
            result["version"][0]=HIGH|self.ids[role][result["version"][0]]
        return result
    def normalize_state(self,role,state):
        result=copy.deepcopy(state)
        if role in self.ids:
            for scope in result["sets"]:
                require(scope["id"]in self.ids[role]and self.ids[role][scope["id"]]==scope["sid"],
                    "actual scope keeps its witnessed allocated ID")
                scope["id"]=HIGH|scope["sid"]
                fd=scope["watcher"]["event_fd"];require(self.events[role].get(fd)==scope["sid"],"actual event ownership stays with its constructor")
                scope["watcher"]["event_fd"]=32+scope["sid"]-self.case["steps"][0]["operation"]["sid"]
        return result
    def normalize_parallel(self,role,rows):
        result=[]
        for r in rows:
            require(type(r["tid"])is int and r["tid"]>0,"actual raw worker TID retained")
            q={k:v for k,v in r.items()if k not in("tid","original_error","native_frame_hex")}
            if"semantic"in q:q["semantic"]=self.normalize_semantic(role,q["semantic"])
            result.append(q)
        return sorted(result,key=lambda x:(x["worker"],x.get("index",0)))
    def compare(self,answers,operation):
        self.bind(answers,operation)
        for name in("semantic","state","control","parallel"):
            values=[]
            for i,a in enumerate(answers):
                if name=="semantic":value=self.normalize_semantic(i,a[name])
                elif name=="state":value=self.normalize_state(i,a[name])
                elif name=="parallel":value=self.normalize_parallel(i,a[name])
                else:value=a[name]
                values.append(value)
            require(values[0]==values[1]==values[2],"complete actual original/native comparison: "+name)
        if not self.ids:
            require(answers[0]["native_frame_hex"]==answers[1]["native_frame_hex"],"entire observer-off native terminal")
        rows=answers[2]["parallel"]
        if operation["op"].startswith("parallel-"):
            require(len(rows)==operation["workers"]*operation.get("count",1)and
                {r["worker"]for r in rows}==set(range(operation["workers"])),"every complete actual parallel call")
            for role,a in enumerate(answers):
                by_worker={}
                for r in a["parallel"]:by_worker.setdefault(r["worker"],set()).add(r["tid"])
                require(len({next(iter(v))for v in by_worker.values()})==operation["workers"]
                    and all(len(v)==1 for v in by_worker.values()),"distinct real worker threads for every actual application")
        return dict(compared_fields=["semantic","state","control","parallel"],
            terminal_bytes_equal=answers[0]["native_frame_hex"]==answers[1]["native_frame_hex"],
            constructor_bijection_required=bool(self.ids))
    def relations(self,observations):
        for relation in self.case.get("relations",[]):
            if relation["kind"]=="concurrent_id_bijection":
                count=relation["count"];base=relation["sid_first"]
                require(self.case["steps"][0]["operation"]==dict(op="parallel-new",root=0,sid=base,workers=count)
                    and len(self.witness)==3 and all(len(w["scope_ids"])==len(w["event_descriptors"])==count and w["next"]==count+1
                    and {v["sid"]for v in w["scope_ids"]}==set(range(base,base+count))for w in self.witness),
                    "all actual concurrent IDs, event descriptors and NEXT have complete constructor witnesses")
                continue
            rows=[observations[i]["answers"][2]["semantic"]for i in relation["steps"]]
            if relation["kind"]=="same_token":require(all(x==rows[0]for x in rows),"source-level stable token relation")
            elif relation["kind"]=="different_tokens":require(len({str(x)for x in rows})==len(rows),"source-level changed token relation")
            else:raise ValueError("unlisted frozen relation")
        return self.case.get("relations",[])
