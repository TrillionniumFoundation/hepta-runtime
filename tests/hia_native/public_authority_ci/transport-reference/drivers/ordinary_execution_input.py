"""Exact ordinary input constructor only; no comparison oracle."""
def fixture(host='h'):
    return {'record':{'kind':'execution_intent','record':{'binding':{'schema_version':1,'run_id':'run-1','turn_id':'turn-1','cell_id':'cell-1','organ_id':None,'operation_id':'op-1','principal':'principal-1','objective_digest':'1'*64,'policy_digest':'2'*64,'candidate_digest':'3'*64,'host':host,'generation':1,'idempotency_key':'key-1','predecessor':None,'currentness':'current','final_use':{'state':'not_granted'},'rollback_reference':None},'class':'file_read','payload_digest':'4'*64}}}
