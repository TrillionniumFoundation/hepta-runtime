"""Exact two-owner source successor; retain every prior default124 check.

The new fixed graph is admitted only after whole-source inverses reconstruct
the complete op9 product, which the original op9 reader reverses to its frozen
536-path source. Pure DATA reads never import a native application loader.
"""
from pathlib import Path
import hashlib,json
from common import require
import binary_root_successor
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
PIN=lambda raw:dict(bytes=len(raw),sha256=SHA(raw))
COMPOSITION='native/runtime_mcp_binary_owners_integration.json'
CURRENT={'native/binary_write_params.hepta': {'bytes': 296970, 'sha256': 'f1779101f1edf27e0e8dd384f14f88b4ae877392b02b2c772105fbf5645e693b'}, 'native/binary_write_params_composition.json': {'bytes': 8554, 'sha256': 'ed4dbb5faa504402f9155fcc33d3440a081410d4de6c49370f1fd3d9a8f49318'}, 'native/binary_write_params_abi.md': {'bytes': 2998, 'sha256': 'd01deb04fe71798cda471707379abf89190ef2b02534b8c5e80f87d8f45a894f'}, 'native/binary_call_plan.hepta': {'bytes': 98825, 'sha256': 'fc8624cc760735a0fdaea46fb5c7434c09cc1fe96d8b218d510a3858fe3305bc'}, 'native/binary_call_plan_composition.json': {'bytes': 5012, 'sha256': '09439d395c4fc7e05e3829f423d04408a39377c53fcdf01c12fa3758d9a4cd69'}, 'native/binary_call_plan_abi.md': {'bytes': 3838, 'sha256': '2db7f1935d439c7c9369c5df3b5d9df41275a58685074faddf0a7f1a2e11ede7'}, 'native/runtime_mcp_binary_owners_integration.json': {'bytes': 13693, 'sha256': 'c51592550a6d3d2a52d6d8d7db4cf57cc972a7b3a7627662767247ee961e821b'}, 'scripts/public_nine_build.py': {'bytes': 37316, 'sha256': '10a9763e2dded295df4619217eaddc4787d18f71a2d7fbff445bcd1523e1a762'}, 'scripts/hia_native_runtime_mcp_build.py': {'bytes': 9179, 'sha256': '9480f9e41a09973e2898c0d102afbf1d1c094aba53353215a7cf96d19c72d50b'}, 'scripts/runtime_mcp_extra_engine.S': {'bytes': 62440, 'sha256': '5d3c8ed77e2e0eddf136a3490b4f6cf2110151a4ecd15604dd163fac32cbf406'}, 'scripts/runtime_mcp_transport.S': {'bytes': 12715, 'sha256': '70385401c053e98884c37907b99f3a2311b3cbc460a590928d0ca8f9a2f25555'}, 'scripts/runtime_mcp_filesystem_fixture.S': {'bytes': 11386, 'sha256': '677d4ed150c9b24570bcbec2c29e9a6ecabfab27080770c72d937dbca780e659'}, 'native/runtime_mcp_publication_graph_composition.json': {'bytes': 3122, 'sha256': '7224d952d0397a4efbf06038466b5e0f770520478ea1b2b3c23c97a949bd55ff'}, 'native/runtime_mcp_sources.json': {'bytes': 129644, 'sha256': '280261f2df19a9b0ba988b984ddf8d70e3c77efe68c7a908cb9348db952a1cb7'}}
BASE={'scripts/public_nine_build.py': {'bytes': 36712, 'sha256': '0bb7ce69a5d3fcda1e0ac31b27647cb02073a26a4ea022b5ce5c2ce7ecc7fb0e'}, 'scripts/hia_native_runtime_mcp_build.py': {'bytes': 9011, 'sha256': '506abc341094e97c8b83a121d08ba437d87adb29f21787e5684ee2f960546de3'}, 'scripts/runtime_mcp_extra_engine.S': {'bytes': 58697, 'sha256': '2850c36e059efbbcba47145303bcb371dbf6ca104f4fc1519c6a9c904467fc9a'}, 'scripts/runtime_mcp_transport.S': {'bytes': 12717, 'sha256': 'c68cb469ffa59293b12fe98229b3f5d42ec1b852bca42805e8ce8c783da0968b'}, 'scripts/runtime_mcp_filesystem_fixture.S': {'bytes': 11253, 'sha256': '25646badd28ffca3205a28d668e661ef61eb4615adddceb27103f828548841e0'}, 'native/runtime_mcp_publication_graph_composition.json': {'bytes': 3122, 'sha256': '7ee8e5664c93021e121aab9943679863ebb0d4c6bf9662b7e43a5d51843115d7'}, 'native/runtime_mcp_sources.json': {'bytes': 127962, 'sha256': '3b36dc20a77471c62b1cc12156ebcad6e2d6cd04701cdb5537b4bfa3638110be'}}
PUBLIC={'bytes': 26787840, 'sha256': 'd995069de6fa4f98f62a8e0412f90f7ff7cd3746706e6e0a91589569979952af'}

class OverlayFile:
    def __init__(self,path,raw=None):self.path,self.raw=path,raw
    def read_bytes(self):return self.path.read_bytes() if self.raw is None else self.raw
    def read_text(self):return self.read_bytes().decode()
    def __getattr__(self,key):return getattr(self.path,key)

class OverlayRoot:
    def __init__(self,root,originals):self.root,self.originals=root,originals
    def __truediv__(self,name):return OverlayFile(self.root/name,self.originals.get(str(name)))

def profile(root):
    if not (root/COMPOSITION).exists():
        return {**binary_root_successor.profile(root),'owners_active':False}
    current={name:binary_root_successor.ordinary(root,name)for name in CURRENT}
    require(all(PIN(current[name])==identity for name,identity in CURRENT.items()),'exact installed binary-owner source bytes')
    record=json.loads(current[COMPOSITION])
    require(record['base_commit']=='1f652e301f01bd8a99dc9b0c272b5037ac319515'
        and record['qualified_params_commit']=='0666613d8c3cad74f6eb192c287069988e813827'
        and record['qualified_call_plan_commit']=='5535171a52aa724f8c4b6974450deec9720dc210'
        and record['public_binary_write_registered'] is False and record['old_path_removed'] is False,
        'exact qualified component and scope binding')
    originals={}
    for row in record['mechanical_sources']:
        name=row['path'];raw=current[name].decode()
        require(PIN(current[name])==row['after'] and BASE[name]==row['before'],'whole mechanical source endpoints')
        for patch in reversed(row['replacements']):
            require(raw.count(patch['after'])==1,'one exact whole-source inverse')
            raw=raw.replace(patch['after'],patch['before'],1)
        originals[name]=raw.encode()
        require(PIN(originals[name])==BASE[name],'complete previous mechanical source bytes')
    added=[r['path']for r in record['imported_sources']]+[COMPOSITION]
    require(len(added)==7 and len(set(added))==7,'exact seven added source paths')
    binding=json.loads(current['native/runtime_mcp_sources.json'])
    require(len(binding['sources'])==543 and binding['binary_owners_extension']['write_params_slot']==69
        and binding['binary_owners_extension']['call_plan_slot']==70
        and binding['binary_owners_extension']['public_binary_write_registered'] is False,'complete new source graph')
    for name in added:del binding['sources'][name]
    del binding['binary_owners_extension']
    for row in record['mechanical_sources']:binding['sources'][row['path']]=row['before']
    originals['native/runtime_mcp_sources.json']=(json.dumps(binding,sort_keys=True,indent=2)+'\n').encode()
    require(PIN(originals['native/runtime_mcp_sources.json'])==BASE['native/runtime_mcp_sources.json'],
        'complete prior op9 source binding')
    prior=binary_root_successor.profile(OverlayRoot(root,originals))
    require(prior['active'] is True,'prior op9 graph remains installed')
    originals.update(prior['originals'])
    return {'active':True,'owners_active':True,'originals':originals,'additional_sources':added}

def verify_recipe(root):
    before=(root/'before-entry-op9.py.txt').read_bytes()
    require(PIN(before)==dict(bytes=10594,sha256='22c9a7660c8088941323f73ad3d7ae3fb61511cf8451fe7b58cec3e70aa4d97f'),
        'unaltered prior op9 complete reader')
    require(PIN((root/'binary_root_successor.py').read_bytes())==dict(bytes=5184,
        sha256='c88a077e18dc0461862e66e73aa4b68dd66b5e9ac06bf19e9b3e4297199be723'),'unaltered prior op9 inverse')
    proof=json.loads((root/'ENTRY_BINARY_OWNERS_SUCCESSOR.json').read_bytes())
    require(proof['schema']=='hepta.runtime.default126.binary-owners-reader-successor.v1','reader successor schema')
    raw=(root/'entry.py').read_text()
    for old,new in reversed(proof['exact_replacements']):
        require(raw.count(new)==1,'one exact new reader inverse');raw=raw.replace(new,old,1)
    require(raw.encode()==before,'whole previous op9 reader inverse')
    binary_root_successor.verify_recipe(OverlayRoot(root,{'entry.py':before}))
