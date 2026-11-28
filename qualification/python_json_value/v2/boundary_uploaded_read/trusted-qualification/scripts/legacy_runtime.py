"""Read the pinned original JSON method AST; never load or execute its interpreter."""
import ast
NAMES=("json","json.decoder","json.encoder","json.scanner","codecs","encodings","encodings.aliases","encodings.utf_8",
    "encodings.utf_8_sig","encodings.utf_16","encodings.utf_16_le","encodings.utf_16_be",
    "encodings.utf_32","encodings.utf_32_le","encodings.utf_32_be","_json","_codecs")
METHODS={"json":("detect_encoding","loads","dumps"),"json.decoder":("JSONDecoder.decode","JSONDecoder.raw_decode"),
    "json.encoder":("JSONEncoder.encode","JSONEncoder.iterencode"),"json.scanner":("py_make_scanner",)}
def function(raw,name):
    node=ast.parse(raw)
    for part in name.split("."):
        node=next(n for n in node.body if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef))and n.name==part)
    return ast.dump(node,include_attributes=False)
