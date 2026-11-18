"""Read exact compiled artifacts admitted by complete independent readers; never run an application."""
from common import ROOT,read,loads,encoded,pin,require,source
def native(retained):
    identity=source();d=loads(read(ROOT/"DEPENDENCIES.json"));a=loads(read(retained/"ADMISSION.json"))
    require(a["schema"]=="hepta.namespace-versions.actual-build-admission.v1"and a["status"]=="PASS"
        and a["source_manifest_sha256"]==identity and a["original_application_calls"]==a["native_application_calls"]==0,
        "complete current pre-application admission")
    build=retained/"native/run/build";proof=loads(read(build/"callable/BINDING.json"));raw=read(build/"callable/callable.image.bin")
    require(pin(raw)==d["native_image"]==proof["callable_image"]and proof["offsets"]==d["native_offsets"],
        "entire exactly qualified native image and exports")
    require(pin(read(retained/"original/run/original.elf"))==d["original_binary"],"entire exact unchanged compiled original")
    require(a["native"]["status"]=="COMPLETE_NAMESPACE_VERSIONS_CALLABLE_BUILD_READ_PASS"
        and a["native"]["image"]==d["native_image"]and a["native"]["guard_probes"]==12
        and a["original"]["status"]=="COMPLETE_ORIGINAL_NAMESPACE_BUILD_READ_PASS"
        and a["original"]["original_binary"]==d["original_binary"]and a["original"]["guard_probes"]==12,
        "whole actual independent original/native compiler evidence")
    return dict(schema="hepta.namespace-versions.actual-admission.v1",status="PASS",source_manifest_sha256=identity,
        native_image=pin(raw),original_binary=d["original_binary"],offsets=d["native_offsets"],
        admission=pin(read(retained/"ADMISSION.json")),native_applications=0,original_applications=0)
