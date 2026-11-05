from pathlib import Path
import hashlib,json
base=Path(__file__).resolve().parent
def put(p,b):
    if p.exists():
        if p.read_bytes()!=b: raise ValueError(f"existing bytes differ: {p}")
    else:
        with p.open("xb") as f:f.write(b)
    return {"path":str(p),"size":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def dto(p):
    o=json.loads(p.read_bytes()); r=o["result"]
    if r.get("isError"): raise ValueError(str(p))
    t=r["content"][0]["text"]
    return t.encode(),json.loads(t)
records=[]
for campaign,status in [("lifecycle","status-01.json"),("observation","status-03.json")]:
    d=base/(campaign+"-operations-01")
    tb,t=dto(d/status); rb,r=dto(d/"read-complete-01.json")
    expected_exit=1 if campaign=="lifecycle" else 0
    assert t["job_id"]==r["job_id"] and t["state"]==("failed" if expected_exit else "succeeded")
    assert t["exit_code"]==expected_exit
    assert all(t[k] is True for k in ["output_complete","output_durable","terminal_publication_confirmed"])
    assert t["terminal_publication_protocol"]==1
    assert all(t[k] is False for k in ["cancelled","timed_out","automatic_retry"])
    records.append(put(d/"actual-native-terminal-01.json",tb))
    records.append(put(d/"actual-native-read-01.json",rb))
    for stream in ["stdout","stderr"]:
        s=r[stream]; b=bytes.fromhex(s["bytes_hex"])
        assert s["offset"]==0 and s["eof"] is True
        assert len(b)==s["size"]==s["next_offset"]==t["log_bytes"][stream]["seen"]==t["log_bytes"][stream]["stored"]
        assert t["log_synced"][stream] is True and t["log_truncated"][stream] is False and t["log_errors"][stream] is None
        assert b.decode()==s["text"]
        records.append(put(d/("complete-"+stream+"-01.log"),b))
    if campaign=="lifecycle":
        _,m=dto(d/"mac-receipts-read-01.json")
        assert m["truncated"] is False
        names={"report.json":"actual-mac-report-01.json","forwarded.stdout":"actual-forwarded-stdout-01.log","forwarded.stderr":"actual-forwarded-stderr-01.log","owned-agent.stderr":"actual-owned-agent-stderr-01.log"}
        assert len(m["files"])==len(names)
        for x in m["files"]:
            b=x["text"].encode()
            assert x["eof"] is True and len(b)==x["size"] and hashlib.sha256(b).hexdigest()==x["sha256"]
            records.append(put(d/names[Path(x["path"]).name],b))
receipt={"schema":"r29-original-holder-receipt-materialization/v1","native_actions":False,"measurement_retries":0,"records":records}
put(base/"holder-receipt-materialization-02.json",(json.dumps(receipt,indent=2)+"\n").encode())
print(json.dumps(receipt,indent=2))
