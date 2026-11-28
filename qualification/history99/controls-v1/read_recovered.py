"""Fixed main99 roots and unchanged original report for pending evidence controls."""
from pathlib import Path
import hashlib,json
SOURCE=Path("/home/runner/work/_temp/hia-historical-public58")
CAPTURE=Path("/home/runner/work/_temp/hia-runtime-native")
PYTHON=Path("/home/runner/work/_temp/hia-native-python/bin/python3")
REPORT_SHA="83437daf7232222bf19025a2c4b395ec4da70179984f2a52763abb452fd98078"
def need(value,label):
    if not value:raise ValueError(label)
def pin(path):
    with path.open("rb") as f:
        h=hashlib.sha256();count=0
        while block:=f.read(1<<20):h.update(block);count+=len(block)
    return {"bytes":count,"sha256":h.hexdigest()}
def put(path,value):
    with path.open("xb") as f:f.write((json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode())
