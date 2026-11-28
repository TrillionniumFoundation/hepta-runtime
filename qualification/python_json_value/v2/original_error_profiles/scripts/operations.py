"""Actual target operations used for original call-site calibration and value qualification."""
import json
def parse(primary):
    return json.loads(b"\xff\xfe\0\0"+primary.encode("utf-32-le","surrogatepass"))
def dump(value):
    return json.dumps(value,sort_keys=True)
def equal(left,right):
    return left==right
def operate(command,primary,auxiliary):
    value=parse(primary)
    if command==1:return value
    if command==2:return value[auxiliary]
    if command==6:return value.get(auxiliary)
    if command==3:return dump(value)
    other=parse(auxiliary)
    if command==4:
        value.update(other)
        return dump(value)
    if command==5:return equal(value,other)
    raise ValueError("undeclared JSON operation")
