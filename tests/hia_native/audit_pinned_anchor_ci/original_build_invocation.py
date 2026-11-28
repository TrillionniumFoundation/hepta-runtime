"""Verbatim qualified full compiler invocation verifier, with only explicit pure imports."""
from common import loads, read, require, encoded, sha

CHILD_FIELDS={'status','result_u64','abi_status','return_encoding','core_u32','source_sha256',
    'image_sha256','output_sha256','source_unchanged','output_unchanged','workspace_header',
    'native_elapsed_ns','forbidden_compiler_modules_loaded','loader_operations','limits'}

def invocation(folder,label,input_raw,image_raw,expected_image,fmt):
    receipt=loads(read(folder/(label+'.receipt.json')))
    stdout=loads(read(folder/(label+'.stdout.log')))
    require(set(stdout)==CHILD_FIELDS and read(folder/(label+'.stderr.log'))==b'',
            'complete actual compiler child stdout/stderr')
    for key,value in stdout.items():
        require(encoded(receipt.get(key))==encoded(value),'actual compiler stdout equals retained receipt: '+key)
    full=read(folder/(label+'.output.bin'))
    request=loads(read(folder/(label+'.request.json')))
    require(read(folder/(label+'.input.bin'))==input_raw and sha(image_raw)==request['image_sha256']
            and request['source_sha256']==sha(input_raw) and request['format']==fmt
            and request['capacity']==request['workspace_size']==1<<20 and request['workspace_fill']==0,
            'actual complete compiler request')
    require(receipt['status']=='returned' and type(receipt['abi_status']) is int and receipt['abi_status']==0
        and type(receipt['core_u32']) is int and receipt['core_u32']==len(expected_image)
        and receipt['result_u64']==len(expected_image) and receipt['source_unchanged'] is True
        and receipt['input_bytes']==len(input_raw) and receipt['input_sha256']==sha(input_raw)
        and receipt['artifact_sha256']==sha(image_raw) and receipt['format']==fmt
        and receipt['source_sha256']==sha(input_raw) and receipt['image_sha256']==sha(image_raw)
        and receipt['output_sha256']==sha(full) and len(full)==1<<20
        and full[:len(expected_image)]==expected_image
        and full[len(expected_image):]==b'\xa5'*((1<<20)-len(expected_image))
        and receipt['forbidden_compiler_modules_loaded']==[]
        and receipt['produced_bytes']==len(expected_image) and receipt['produced_sha256']==sha(expected_image)
        and type(receipt['wall_elapsed_ns']) is int and 0<=receipt['wall_elapsed_ns']<=20_000_000_000,
        'actual HIA compiler complete output including unused tail')
    return receipt
