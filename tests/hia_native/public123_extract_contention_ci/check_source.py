"""Pure source admission and complete input-only domain enumeration."""
from pathlib import Path
import json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import callable_common,wait_domain
result=callable_common.syntax(HERE)
rows=[]
for group in ("ordinary-a","ordinary-b","eof"):
    for era in ("legacy","modern"):
        name=group+"-"+era;value=wait_domain.domain(name,Path("/tmp")/("hia-extract-contention-"+name)/"work")
        assert len(value["cases"])==4 and value["expected_wire"] is None
        rows.append({"name":name,"cases":len(value["cases"]),"steps":sum(len(x["steps"]) for x in value["cases"])})
result.update(domains=rows,actual_input_cases=24,original_or_native_executions=0)
print(json.dumps(result,sort_keys=True))
