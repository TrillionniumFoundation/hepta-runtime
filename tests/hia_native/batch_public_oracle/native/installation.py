"""Explicit reachable startup envelope for both actual implementations.

The retained 133-step generator declares only local roots and no hosts because
its reference installation fixture does not run CLI validation. This companion
adds the same unused, validated host already used by test_runtime_mcp.py.
It never changes a request, path, root order, fence environment or response.
"""
import copy
HOST={'h':{'ssh_target':'private-target','remote_state_dir':'/private-state'}}
def installed_policy(value):
 if value is None:return None
 assert isinstance(value,dict) and value.get('hosts')=={}
 result=copy.deepcopy(value);result['hosts']=copy.deepcopy(HOST)
 assert {k:v for k,v in result.items() if k!='hosts'}=={k:v for k,v in value.items() if k!='hosts'}
 return result
