"""Select only a completely frozen original profile recipe module."""
import importlib.util
from pathlib import Path
from common import require
CURRENT=None
CURRENT_SOURCE=None
def set_source(source):
    global CURRENT,CURRENT_SOURCE
    path=Path(source)/"scripts/cases.py"
    if CURRENT is not None and CURRENT_SOURCE==path:return
    CURRENT_SOURCE=path
    spec=importlib.util.spec_from_file_location("frozen_original_profile_cases",path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);CURRENT=module
def cases(group):
    require(CURRENT is not None,"original profile cases admitted");return CURRENT.cases(group)
def domain():
    require(CURRENT is not None,"original profile domain admitted");return CURRENT.domain()
def text(shape,depth,leaf):
    require(CURRENT is not None,"original profile text recipe admitted");return CURRENT.text(shape,depth,leaf)
