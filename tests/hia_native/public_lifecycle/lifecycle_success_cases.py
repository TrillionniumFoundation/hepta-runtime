# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Finite ordinary public Start/Cancel cases; no host process or network operations."""
def cases():
    items=[]
    def add(name,protocol,tool='host_list',hosts=1,fence=None,success=True,key=None):
        items.append(dict(name=name,protocol=protocol,operation=dict(tool=tool,arguments={}),
            hosts=hosts,fence=fence,success=success,key=key or ('public-success-'+name),
            expected_result='overflow'if tool=='effective_config'and hosts==128 else 'stored'))
    add('plain-host-list-old','2025-06-18',key='k')
    add('plain-host-list-new','2026-07-28',key='L'*128)
    add('plain-effective-eight','2025-06-18','effective_config',8)
    add('plain-effective-overflow','2026-07-28','effective_config',128)
    add('fence-v4-host-list','2025-06-18',fence='v4')
    add('fence-v4-effective-eight','2026-07-28','effective_config',8,'v4')
    add('fence-v11-private-predecessor','2026-07-28',fence='v11')
    for i,kind in enumerate(('frozen','wrong_owner','wrong_state','missing_predecessor',
                             'zero_epoch','partial','invalid_required')):
        add('business-refusal-'+kind,('2025-06-18','2026-07-28')[i%2],fence=kind,success=False)
    assert len(items)==14 and sum(x['success']for x in items)==7
    return items
