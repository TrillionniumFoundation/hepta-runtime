"""Compose unchanged target extract/list functions into the exact retained SDK carrier.

This author only checks and transforms source bytes. It never executes Rust or HIA.
The full 136 raw Tool registry is retained original metadata; the exact original
policy runs before the explicit ten-member installed projection.
"""
from pathlib import Path
import hashlib,importlib.util,json
ROOT=Path(__file__).resolve().parents[1]
TARGET='d3d75c30719db966b004756f610007a7c723729e'
TARGET_GIT={
 'src/mcp/server.rs':'8167974425e01728432bffd5f0243087647061d6',
 'src/mcp/fs/core.rs':'0bf273858281618f51792c5663494f6ba37645ed',
 'src/utils/truncation.rs':'a14ad26adedbff7624c67f5b89672e54fe60918e',
 'src/mcp/hia_contract.rs':'f5a17e918d7b4fedf0bbc220c5e9fa8f42c69f09'}
INSTALLED=('directory_create','directory_move','effective_config','execution_shadow_admit','extract_lines','file_move','host_list','text_editor','view','workdir')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def encoded(data):return (json.dumps(data,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def take(targets,name,anchor,end,label,rows):
    raw=targets[name];assert raw.count(anchor)==1,(name,anchor)
    start=raw.index(anchor);finish=raw.index(end,start)+len(end);span=raw[start:finish]
    rows.append({'declaration':label,'target':name,'start':start,'end':finish,**pin(span)});return span
def from_base(files,baseproof,targets,catalog):
    out=dict(files);out.pop('SOURCE.json')
    assert pin(catalog)=={'bytes':776697,'sha256':'d150e2a180b9faaccb8f10414cbc83c9b3278efa39802c2e65123d0056c125fd','git_blob':'ef3cf5bb8d36cc569adc6f7dcf9648a4e2ff31d4'}
    tools=json.loads(catalog);assert isinstance(tools,list) and len(tools)==136 and len({t['name'] for t in tools})==136
    assert all(sum(t['name']==name for t in tools)==1 for name in INSTALLED)
    for name,digest in TARGET_GIT.items():
        assert pin(targets[name])['git_blob']==digest,name
        if name in baseproof['target_files']:assert pin(targets[name])==baseproof['target_files'][name]
    spans=[];server='src/mcp/server.rs';core='src/mcp/fs/core.rs';trunc='src/utils/truncation.rs'
    extract_params=take(targets,server,b'#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct ExtractLinesParams {',b'\n}\n','ExtractLinesParams',spans)
    gateway=take(targets,server,b'\tasync fn extract_lines(',b'\n\t}\n','extract_lines',spans)
    optional=take(targets,core,b'fn parse_optional_endpoint(',b'\n}\n','parse_optional_endpoint',spans)
    execute=take(targets,core,b'pub async fn execute_extract_lines(',b'\n}\n','execute_extract_lines',spans)
    render=take(targets,trunc,b'fn render_line(',b'\n}\n','render_line',spans)
    formatter=take(targets,trunc,b'pub fn format_extracted_content_smart(',b'\n}\n','format_extracted_content_smart',spans)
    strip_null=take(targets,server,b'fn strip_null_variants(',b'\n}\n','strip_null_variants',spans)
    strip_noise=take(targets,server,b'fn strip_generator_noise(',b'\n}\n','strip_generator_noise',spans)
    supports=take(targets,server,b'fn supports_cache_hints(',b'\n}\n','supports_cache_hints',spans)
    list_tools=take(targets,server,b'\tasync fn list_tools(',b'\n\t}\n','list_tools',spans)
    runtime=take(targets,server,b'const RUNTIME_TOOL_NAMES:',b'\n];\n','RUNTIME_TOOL_NAMES',spans)
    weight=take(targets,server,b'const WEIGHT_WORKER_TOOL_NAMES:',b'\n];\n','WEIGHT_WORKER_TOOL_NAMES',spans)
    hia=take(targets,'src/mcp/hia_contract.rs',b'pub(super) const TOOLS:',b'\n];\n','hia_contract::TOOLS',spans)
    out['src/types.rs']+=b'\n'+extract_params
    out['src/original_extract_gateway.rs']=b'impl OctofsServer {\n'+gateway+b'}\n'
    out['src/original_extract_dispatch.rs']=optional+b'\n'+execute
    out['src/original_extract_truncation.rs']=b'use crate::utils::line_hash::line_id;\n'+render+b'\n'+formatter
    out['src/original_list_tools.rs']=(runtime+weight+b'mod hia_contract {\n'+hia+b'}\n'+strip_null+strip_noise+supports+
        b'trait OriginalList { async fn list_tools(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>) -> Result<ListToolsResult, ErrorData>; }\n'+
        b'impl OriginalList for OctofsServer {\n'+list_tools+b'}\n')
    out['raw-catalog-input.json']=catalog
    out['src/fixture_catalog_registry.rs']=('''// Fixture-owned metadata supply and explicit installed projection; all policy is original.
const INSTALLED_TOOLS: &[&str] = &'''+json.dumps(list(INSTALLED))+''';
struct FixtureToolRouter;
impl FixtureToolRouter {
    fn list_all(&self) -> Vec<Tool> {
        let tools: Vec<Tool> = serde_json::from_str(include_str!("../raw-catalog-input.json")).expect("retained original Tool array");
        assert_eq!(tools.len(), 136);
        tools
    }
}
impl OctofsServer { fn tool_router() -> FixtureToolRouter { FixtureToolRouter } }
''').encode()
    changes=[];main=out['src/main.rs'].decode()
    def change(old,new):
        nonlocal main
        assert main.count(old)==1,old
        main=main.replace(old,new);changes.append({'before':old,'after':new,'count':1})
    change('//! Only Batch/Text and the declared View parameter refusal are routed. It does not','//! Extract/Batch/Text, original list policy, and the declared View refusal are routed. It does not')
    change('    Implementation, JsonObject, ProtocolVersion, ServerCapabilities, ServerConfig};','    Implementation, JsonObject, ProtocolVersion, ServerCapabilities, ServerConfig,\n    CacheScope, ListToolsResult, PaginatedRequestParams, Tool};')
    change('            use super::remote::{io_exists, io_read_to_string, resolve_path_source, PathSource};','            use super::remote::{io_exists, io_read_to_string, io_create_dir_all, resolve_path_source, PathSource};\n            use crate::utils::line_hash::{self, Endpoint, resolve_line_index};\n            use crate::utils::truncation::format_extracted_content_smart;')
    change('            include!("original_batch_dispatch.rs");','            include!("original_batch_dispatch.rs");\n            include!("original_extract_dispatch.rs");')
    change('        pub use core::{execute_batch_edit, execute_text_editor};','        pub use core::{execute_batch_edit, execute_text_editor, execute_extract_lines};')
    change('mod utils { pub mod line_hash { include!("../original/line_hash.rs"); } }','mod utils { pub mod line_hash { include!("../original/line_hash.rs"); } pub mod truncation { include!("original_extract_truncation.rs"); } }')
    change('include!("original_batch_gateway.rs");','include!("original_batch_gateway.rs");\ninclude!("original_extract_gateway.rs");\ninclude!("original_list_tools.rs");\ninclude!("fixture_catalog_registry.rs");')
    change('impl OctofsServer {\n    fn sdk_batch', '''impl OctofsServer {
    fn sdk_extract(&self, context: RequestContext<RoleServer>, params: Parameters<ExtractLinesParams>)
        -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<String, String>> + Send + '_>> {
        Box::pin(self.extract_lines(context, params))
    }
    fn sdk_batch''')
    change('    fn get_info(&self) -> ServerConfig { OriginalInfo::get_info(self) }', '''    fn get_info(&self) -> ServerConfig { OriginalInfo::get_info(self) }
    async fn list_tools(&self, request: Option<PaginatedRequestParams>, context: RequestContext<RoleServer>)
        -> Result<ListToolsResult, ErrorData> {
        let mut result = OriginalList::list_tools(self, request, context).await?;
        result.tools.retain(|tool| INSTALLED_TOOLS.contains(&tool.name.as_ref()));
        Ok(result)
    }''')
    change('        match request.name.as_ref() {','''        match request.name.as_ref() {
            "extract_lines" => ToolCallContext::new(self, request, context)
                .invoke::<_, AsyncMethodAdapter<(RequestContext<RoleServer>, Parameters<ExtractLinesParams>), Result<String, String>>>(Self::sdk_extract).await,''')
    change('    if let Some(path) = first_argument.filter(|_| fixture_sessions == 2) {','''    let fixture_config = if fixture_sessions == 1 { std::env::args().nth(2) } else { first_argument };
    if let Some(path) = fixture_config {''')
    out['src/main.rs']=main.encode()
    for row in spans:
        raw=targets[row['target']][row['start']:row['end']]
        placements=[]
        for name,value in out.items():
            if name.endswith('.rs') and raw in value:
                assert value.count(raw)==1,(row['declaration'],name)
                at=value.index(raw);placements.append({'container':name,'start':at,'end':at+len(raw)})
        assert placements,row['declaration'];row['compiled_spans']=placements
    proof=dict(baseproof)
    preserved=[]
    for old in baseproof['preserved_original_items']:
        first=old['compiled_spans'][0];raw=files[first['container']][first['start']:first['end']]
        assert pin(raw)=={k:old[k] for k in ('bytes','sha256','git_blob')}
        placements=[]
        for name,value in out.items():
            if name.endswith('.rs') and raw in value:
                assert value.count(raw)==1,(old['declaration'],name)
                at=value.index(raw);placements.append({'container':name,'start':at,'end':at+len(raw)})
        assert placements,old['declaration'];preserved.append({**old,'compiled_spans':placements})
    proof.update(schema='hepta.extract-sdk-current.original-source.v1',base_source=pin(files['SOURCE.json']),
        target_files={**baseproof['target_files'],**{n:pin(b) for n,b in targets.items()}},
        preserved_original_items=preserved,extract_exact_spans=spans,extract_original_span_count=len(spans),
        original_list_policy_before_installed_projection=True,raw_tool_registry=pin(catalog),raw_tool_count=136,
        installed_tools=list(INSTALLED),wrapper_adapters=changes,new_wrapper=pin(out['src/main.rs']),
        files={n:pin(raw) for n,raw in out.items()},public_extract_qualified=False,
        fixture_registry_is_full_original_dispatch=False,full_runtime_audit_router_qualified=False,
        private_history_fixture_uses_original_owner=True,reference_binaries_executed=False)
    out['SOURCE.json']=encoded(proof);return out,proof
def compose(baseline,core):
    spec=importlib.util.spec_from_file_location('retained_batch_public_author',ROOT/'retained/authoring/author_public_reference.py')
    old=importlib.util.module_from_spec(spec);exec(compile((ROOT/'retained/authoring/author_public_reference.py').read_bytes(),str(ROOT/'retained/authoring/author_public_reference.py'),'exec',dont_inherit=True),old.__dict__)
    files,baseproof=old.compose(Path(baseline),Path(core))
    for n,b in files.items():assert (ROOT/'base-project'/n).read_bytes()==b,n
    actual={p.relative_to(ROOT/'base-project').as_posix() for p in (ROOT/'base-project').rglob('*') if p.is_file()}
    assert actual==set(files)
    targets={n:(ROOT/'target'/n).read_bytes() for n in TARGET_GIT}
    result,proof=from_base(files,baseproof,targets,(ROOT/'target/catalog-input.json').read_bytes())
    assert result['src/main.rs']==(ROOT/'authoring/public_reference_main.rs').read_bytes()
    return result,proof
