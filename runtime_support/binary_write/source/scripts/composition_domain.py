"""Independent immutable domain projection used only by DATA readers."""
def query_from_case(case,fixture,observed):
    value=str(fixture)
    root=case['root'].replace('{R0}',value.lstrip('/')).replace('{R}',value)
    path=case['path'].replace('{R0}',value.lstrip('/')).replace('{R}',value)
    return dict(op='write',root=root,path=path,expected_version=case['expected_version'],data_base64=case['data_base64'],observer=observed)
