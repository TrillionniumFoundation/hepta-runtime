"""Previously unexecuted native C-depth cases using immutable completed originals."""
import importlib.util,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
GROUPS=tuple("high-"+str(i)for i in range(9))+tuple("error-"+str(i)for i in range(3))
MODULES={}
def profile(family):
    if family not in MODULES:
        path=ROOT/"trusted-profiles"/family/"scripts/cases.py"
        spec=importlib.util.spec_from_file_location("frozen_"+family+"_profile_cases",path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);MODULES[family]=module
    return MODULES[family]
def cases(group):
    if group not in GROUPS:raise ValueError("undeclared native depth boundary group")
    family,number=group.split("-");module=profile(family)
    for original in module.cases(number):
        depth=original["depth"]
        if family=="high"and not 9993<=depth<=9999:continue
        if family=="error"and depth==0:continue
        primary=module.text(original["shape"],depth,original["leaf"]);mode=original["mode"]
        command={"parse":1,"dump":3,"equal":5}[mode];auxiliary=primary if command==5 else""
        cp=len(primary)+len(auxiliary);body=(primary+auxiliary).encode("utf-32-le","surrogatepass")
        wire=struct.pack("<8Q",int.from_bytes(b"HPYJSQ01","little"),command,len(primary),len(auxiliary),
            9997 if command==1 else 20000,9997,9998 if command==5 else 0,len(body))+body
        cid=(100000000 if family=="error"else 0)+original["case_id"]
        yield dict(case_id=cid,label=family+":"+original["label"],original_id=original["case_id"],original=original,
            primary=primary,auxiliary=auxiliary,command=command,wire=wire,
            output_capacity=512+(4 if command==1 else 12)*len(primary),
            workspace_capacity=16480+40*cp,output_fill=(cid*37+23)%256,workspace_fill=(cid*61+53)%256)
def domain(group):
    return dict(schema="hepta.runtime.python-json-value.native-c-depth-domain.v1",group=group,
        family=group.split("-")[0],profile_group=group.split("-")[1],
        native_calls=sum(1 for _ in cases(group)),new_original_calls=0,original_application_replays=0)
def total():
    rows=[domain(g)for g in GROUPS]
    return dict(groups=rows,native_calls=sum(x["native_calls"]for x in rows),new_original_calls=0,original_application_replays=0)
