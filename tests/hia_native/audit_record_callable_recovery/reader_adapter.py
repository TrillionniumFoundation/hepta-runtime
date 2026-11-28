"""Install only the exact recovery-counter reader correction in an isolated source root."""
from pathlib import Path
import importlib.util,sys
from recovery_common import ROOT,BASE_SOURCE,source,read,pin,need

OLD_READER_SHA="bb9b91bad3b59717accf9332cb6309617ab6e2a0813a4a14add13ca695626b75"

def install(original):
    identity=source()
    need(pin(read(original/"SOURCE.json"))["sha256"]==BASE_SOURCE,"unchanged original callable source")
    sys.path[:0]=[str(original),str(original/"scripts")]
    import common
    need(common.ROOT==original and common.source()==BASE_SOURCE,"actual preserved original module namespace")
    import reader_callable_cli
    import read_transport_controls
    import reader_controls_callable
    before=read(original/"read_transport_controls.py")
    need(pin(before)["sha256"]==OLD_READER_SHA,"exact original control reader")
    replacement=read(ROOT/"corrected_transport.py")
    # The correction is a complete separately frozen function body; all producer source is unchanged.
    spec=importlib.util.spec_from_file_location("audit_callable_corrected_transport",ROOT/"corrected_transport.py")
    module=importlib.util.module_from_spec(spec)
    exec(compile(replacement,str(ROOT/"corrected_transport.py"),"exec"),module.__dict__)
    original_roots=reader_controls_callable.roots
    def roots(folder,prepared):
        return [*original_roots(folder,prepared),ROOT]
    def verify(folder,image,ordinary):
        need(source()==identity,"same frozen pure counter correction")
        return module.verify(folder,image,ordinary)
    reader_controls_callable.roots=roots
    read_transport_controls.verify=verify
    need(common.source()==BASE_SOURCE,"all original producer files still unchanged")
    return reader_callable_cli,reader_controls_callable
