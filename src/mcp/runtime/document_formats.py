# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Rich document rendering and legacy XLS reads; fixed worker code, no network fetches.
Called inside the existing bounded document worker. Source assets must be named,
policy-checked and SHA256-bound; stylesheets cannot escape to local files or URLs.
"""
import io
import json
import pathlib
import re


def render_rich_document(q):
    import hashlib
    import logging
    import mimetypes
    from lxml import html as lhtml
    from markdown_it import MarkdownIt
    import weasyprint
    from weasyprint import HTML, CSS
    from weasyprint.urls import URLFetcher, URLFetcherResponse, FatalURLFetchingError
    target=checked(q,q['path'])
    if target.suffix.lower()!='.pdf':raise ValueError('rich render output must be PDF')
    content=q['content'];kind=q['input_format']
    if not isinstance(content,str) or len(content.encode())>1024*1024:raise ValueError('render content limit exceeded')
    if kind=='markdown':
        content=MarkdownIt('commonmark',{'html':True}).enable(['table','strikethrough']).render(content)
    elif kind=='svg':content='<html><body>'+content+'</body></html>'
    elif kind!='html':raise ValueError('unsupported rich input format')
    if re.search(r'<!\s*(?:ENTITY|DOCTYPE\s+(?!html\s*>))',content,re.I):raise ValueError('external document declarations are not accepted')
    tree=lhtml.document_fromstring(content)
    for node in tree.iter():
        if not isinstance(node.tag,str):continue
        tag=node.tag.rsplit('}',1)[-1].lower()
        if tag in ('script','iframe','object','embed','base','form','input','textarea','button'):
            raise ValueError('active or externally based document element is unsupported: '+tag)
        if any(name.lower().startswith('on') for name in node.attrib):raise ValueError('event handlers are not accepted')
        if 'attachment' in node.get('rel','').lower().split():raise ValueError('implicit PDF attachments are not accepted')
    assets={};asset_evidence=[];total=0
    for item in q.get('assets',[]):
        key=item['name']
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',key) or key in assets:raise ValueError('invalid or duplicate asset name')
        path=checked(q,item['path']);data,sha=read_bytes(path)
        if sha!=item['sha256']:raise ValueError('asset fingerprint changed')
        mime={'.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.css':'text/css'}.get(path.suffix.lower())
        if mime is None:raise ValueError('asset type not allowed; use raster, SVG or CSS assets')
        if mime=='image/svg+xml' and re.search(br'<!\s*(?:DOCTYPE|ENTITY)',data,re.I):raise ValueError('SVG entities/declarations rejected')
        total+=len(data)
        if total>16*1024*1024:raise ValueError('combined asset budget exceeded')
        assets['asset:'+key]=(data,mime)
        asset_evidence.append({'name':key,'sha256':sha,'size':len(data)})
    # Validate declared resource references even when the rendering engine would
    # ignore an unsupported element. Silent missing images are not a valid PDF.
    def allowed_reference(value):
        if value.startswith('#'):return
        if value not in assets:raise ValueError('undeclared document resource reference')
    import tinycss2
    def inspect_css(tokens):
        for token in tokens:
            if token.type=='url':allowed_reference(token.value)
            elif token.type=='function' and token.lower_name=='url':
                significant=[t for t in token.arguments if t.type not in ('whitespace','comment')]
                if len(significant)!=1 or significant[0].type!='string':raise ValueError('ambiguous CSS URL')
                allowed_reference(significant[0].value)
            if token.type=='at-rule' and token.lower_at_keyword=='import':
                significant=[t for t in token.prelude if t.type not in ('whitespace','comment')]
                if significant and significant[0].type=='string':allowed_reference(significant[0].value)
            for attr in ('arguments','content','prelude','value'):
                nested=getattr(token,attr,None)
                if isinstance(nested,list):inspect_css(nested)
    for node in tree.iter():
        if not isinstance(node.tag,str):continue
        tag=node.tag.rsplit('}',1)[-1].lower()
        for key,value in node.attrib.items():
            if key.rsplit('}',1)[-1].split(':')[-1].lower() in ('src','href','poster','background'):
                if tag=='a' and key=='href':continue  # Navigation is not resource fetching.
                allowed_reference(value)
        if node.get('style'):inspect_css(tinycss2.parse_declaration_list(node.get('style')))
        if tag=='style':inspect_css(tinycss2.parse_stylesheet(node.text or ''))
    inspect_css(tinycss2.parse_stylesheet(q.get('css') or ''))
    for content,mime in assets.values():
        if mime=='text/css':inspect_css(tinycss2.parse_stylesheet(content.decode('utf-8')))
    class ClosedFetcher(URLFetcher):
        def __init__(self):
            super().__init__(allowed_protocols={'asset'},allow_redirects=False,fail_on_errors=True)
            self.calls=0
        def fetch(self,url,headers=None):
            self.calls+=1
            if self.calls>128:raise FatalURLFetchingError('resource fetch budget exceeded')
            if url not in assets:raise FatalURLFetchingError('undeclared resource; only explicit asset:name references are allowed')
            data,mime=assets[url]
            return URLFetcherResponse(url,body=data,headers={'Content-Type':mime})
    fetcher=ClosedFetcher();messages=[]
    class Capture(logging.Handler):
        def emit(self,record):
            if len(messages)<128:messages.append(record.getMessage()[:512])
    logger=logging.getLogger('weasyprint');handler=Capture();logger.addHandler(handler)
    try:
        css=q.get('css') or ''
        if len(css.encode())>256*1024:raise ValueError('CSS budget exceeded')
        defaults='@page {size:A4;margin:18mm} body {font-family: sans-serif;font-size:11pt} table {border-collapse:collapse} th,td {padding:4px;border:1px solid #aaa} pre {white-space:pre-wrap} img,svg {max-width:100%}'
        document=HTML(string=lhtml.tostring(tree,encoding='unicode'),url_fetcher=fetcher).render(
            stylesheets=[CSS(string=defaults+'\n'+css,url_fetcher=fetcher)],presentational_hints=True)
        if not 1<=len(document.pages)<=100:raise ValueError('rendered page count exceeds limit')
        data=document.write_pdf()
    except FatalURLFetchingError as error:
        raise ValueError('render resource refused: '+str(error)) from error
    finally:logger.removeHandler(handler)
    result=publish(q,str(target),data,q['expected_sha256'])
    result.update({'renderer':'weasyprint','renderer_version':weasyprint.__version__,'page_count':len(document.pages),
                   'input_format':kind,'asset_fingerprints':asset_evidence,'network_resources_fetched':False,
                   'render_warnings':messages,'pixel_identical_to_browser':False})
    return [{'type':'text','text':json.dumps(result,ensure_ascii=False)}]


def read_legacy_xls(q,data,digest,path):
    import xlrd
    from openpyxl.utils.cell import range_boundaries
    book=xlrd.open_workbook(file_contents=data,formatting_info=True,on_demand=True)
    try:
        sheets=book.sheet_names();name=q.get('sheet') or sheets[0]
        if name not in sheets and name.isdigit() and int(name)<len(sheets):name=sheets[int(name)]
        if name not in sheets:raise ValueError('unknown legacy worksheet')
        sheet=book.sheet_by_name(name)
        offset=max(0,int(q.get('offset') or 0));length=max(1,min(100,int(q.get('length') or 20)))
        region=q.get('range') or f'A{offset+1}:T{offset+length}'
        c1,r1,c2,r2=range_boundaries(region)
        if not all(isinstance(v,int) and v>0 for v in (c1,r1,c2,r2)) or r2<r1 or c2<c1 or (r2-r1+1)*(c2-c1+1)>5000:
            raise ValueError('invalid legacy worksheet range')
        rows=[];formats=[]
        for r in range(r1-1,r2):
            values=[];row_formats=[]
            for c in range(c1-1,c2):
                if r>=sheet.nrows or c>=sheet.ncols:values.append(None);row_formats.append(None);continue
                cell=sheet.cell(r,c);value=cell.value
                if cell.ctype in (xlrd.XL_CELL_EMPTY,xlrd.XL_CELL_BLANK):value=None
                elif cell.ctype==xlrd.XL_CELL_DATE:value=xlrd.xldate_as_datetime(value,book.datemode).isoformat()
                elif cell.ctype==xlrd.XL_CELL_BOOLEAN:value=bool(value)
                elif cell.ctype==xlrd.XL_CELL_ERROR:value=xlrd.error_text_from_code.get(value,'#UNKNOWN!')
                values.append(value)
                xf=book.xf_list[cell.xf_index];row_formats.append(book.format_map[xf.format_key].format_str)
            rows.append(values);formats.append(row_formats)
        result={'path':str(path),'sha256':digest,'size':len(data),'format':'xls','sheets':sheets,'sheet':name,
                'range':region,'rows':rows,'number_formats':formats,'date_system':book.datemode,
                'formula_values':'stored_results_only','formula_source_available':False,
                'formulas_recalculated':False,'legacy_objects_executed':False}
        payload=json.dumps(result,ensure_ascii=False)
        if len(payload.encode())>TEXT_LIMIT:raise ValueError('legacy result too large; narrow range')
        return [{'type':'text','text':payload}]
    finally:book.release_resources()
