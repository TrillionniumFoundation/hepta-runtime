"""Recover exact ordinary request/response bytes from a fully verified archive."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json

def pin(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("source","failure","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();corpus=json.loads((a.source/"CORPUS.json").read_bytes())
    root=a.failure/"public/session-0/process";raw=(root/"exchanges.jsonl").read_bytes()
    assert pin(raw)==corpus["failure_exchanges"] and pin((root/"process.json").read_bytes())==corpus["failure_process"]
    exchanges=[json.loads(row) for row in raw.splitlines()]
    streams={n:gzip.decompress((root/(n+".bin.gz")).read_bytes()) for n in ("stdin","stdout")}
    def span(seq,stream):
        r=exchanges[seq];s=r["ranges"][stream];b=streams[stream][s["offset"]:s["offset"]+s["bytes"]]
        if stream=="stdin":assert pin(b)==r["accepted_input"]==r["attempted_input"]
        else:assert len(r["responses"])==(1 if b else 0) and (not b or pin(b)==r["responses"][0])
        return b
    a.output.mkdir(parents=True,exist_ok=False)
    for row in corpus["rows"]:
        assert row["frozen_failure_exchange"]==exchanges[row["sequence"]]
        inp=b"".join(span(i,"stdin") for i in row["input_sequences"])
        out=span(0,"stdout")+span(row["sequence"],"stdout")
        assert pin(inp)==row["input"] and pin(out)==row["expected"]
        (a.output/(row["name"]+".stdin")).write_bytes(inp)
        (a.output/(row["name"]+".stdout")).write_bytes(out)
    print(json.dumps({"status":"EXACT_RETAINED_CORPUS_RECOVERED","rows":len(corpus["rows"]),"native_executions":0,"rust_executions":0},sort_keys=True))

if __name__=="__main__":main()
