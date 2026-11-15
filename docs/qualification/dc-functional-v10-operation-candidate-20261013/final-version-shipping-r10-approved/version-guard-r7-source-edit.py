import pathlib,hashlib,json,datetime
R=pathlib.Path("/home/qian-qi/hepta-runtime-operation-v10-20261013")
D=R/"docs/qualification/dc-functional-v10-operation-candidate-20261013/versioned-regression-r7-approved-guard"
D.mkdir(mode=0o700,exist_ok=False)
def sha(b):return hashlib.sha256(b).hexdigest()
def write(p,b):
 b=b.encode() if isinstance(b,str) else b
 with p.open("xb") as f:f.write(b)
 p.chmod(0o600)
p=R/"tests/dc_functional_v10_request_async_acceptance.py";old=p.read_bytes()
assert sha(old)=="803e36713b234f529ee5d2ae0c7c38100da252b429fe406ade5553d3f87a3a37"
write(D/"original-803e-request-async.py",old)
pkg=R/"docs/qualification/dc-functional-v10-operation-candidate-20261013/versioned-regression-package/manifest.json"
raw=pkg.read_bytes();assert sha(raw)=="48125a5832a18508bc78ce4a7e0ec6ff9cdfdbab35159278154cdd4b730fae6f";write(D/"original-48125-package.json",raw)
s=old.decode();anchor="def verify_catalog(tools, args, contract_path):\n"
guard='''APPROVED_V10_SHA256 = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"


def verify_approved_contract_pin(path, expected):
    # The caller cannot approve a recomputed catalog, even if structurally valid.
    if expected != APPROVED_V10_SHA256 or digest(path) != APPROVED_V10_SHA256:
        raise ValueError("unreviewed V10 contract; literal approved digest required")
    return APPROVED_V10_SHA256


'''
assert s.count(anchor)==1;s=s.replace(anchor,guard+anchor+"    if not args.export_contract:\n        verify_approved_contract_pin(contract_path, args.expected_contract_sha256)\n")
anchor="    args = parser.parse_args()\n";assert s.count(anchor)==1
s=s.replace(anchor,anchor+"    # Refuse unknown digests before ToolContract.load or any MCP controller work.\n    if args.contract:\n        verify_approved_contract_pin(args.contract, args.expected_contract_sha256)\n")
p.write_text(s);p.chmod(0o600)
t=R/"tests/dc_functional_v10_contract_approval_tests.py";orig=t.read_bytes()
assert sha(orig)=="9294d21e9a33ddb0de28ac987c9084f0f74836e85ff74c6ddb7881e26fa93446";write(D/"original-9294-approval-tests.py",orig)
ts=orig.decode().replace("import unittest\n","import unittest\nfrom unittest import mock\n")
anchor='    def test_operation_harness_alias_is_byte_exact_r4(self):\n'
extra='''    def test_async_unknown_self_consistent_new_definitions_refused_before_mcp_or_load(self):
        module_path = ROOT / "tests/dc_functional_v10_request_async_acceptance.py"
        spec = importlib.util.spec_from_file_location("_v10_async_guard_probe", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for tool_name in FOUR:
            with self.subTest(tool=tool_name), tempfile.TemporaryDirectory(prefix="hepta-v10-cold-approval-") as root:
                root = pathlib.Path(root)
                tools = copy.deepcopy(self.catalog.tools)
                next(tool for tool in tools if tool["name"] == tool_name)["description"] += " unknown recomputed approval"
                candidate = root / "unknown.json"
                candidate.write_text(json.dumps(make_contract(tools), indent=2)+"\\\\n")
                candidate.chmod(0o600)
                unknown_sha = digest(candidate)
                argv = ["async-guard", "--binary", str(root/"never-executed"), "--contract", str(candidate),
                        "--expected-contract-sha256", unknown_sha,
                        "--expected-binary-sha256", "0"*64, "--expected-source-fingerprint", "0"*64,
                        "--out", str(root/"never-created.json")]
                with mock.patch.object(sys, "argv", argv), mock.patch.object(module.Controller, "start") as controller_start, mock.patch.object(module.ToolContract, "load") as contract_load:
                    with self.assertRaisesRegex(ValueError, "literal approved digest"):
                        module.main()
                    controller_start.assert_not_called()
                    contract_load.assert_not_called()
                self.assertFalse((root/"never-created.json").exists())

    def test_async_original_approved_literal_positive_without_mcp(self):
        module_path = ROOT / "tests/dc_functional_v10_request_async_acceptance.py"
        spec = importlib.util.spec_from_file_location("_v10_async_guard_positive", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(module.Controller, "start") as controller_start, mock.patch.object(module.ToolContract, "load") as contract_load:
            self.assertEqual(module.verify_approved_contract_pin(self.path, V10_SHA256), V10_SHA256)
            controller_start.assert_not_called()
            contract_load.assert_not_called()

'''
assert ts.count(anchor)==1;ts=ts.replace(anchor,extra+anchor);t.write_text(ts);t.chmod(0o600)
manifest=json.loads(raw)
for copy in manifest["copies"]:
 if copy["new_path"]==str(p.relative_to(R)):copy["new_sha256"]=sha(p.read_bytes());copy["approved_guard_added_before_any_MCP_or_ToolContract_load"]=True
manifest["copy_whitelist"][str(p.relative_to(R))]={"sha256":sha(p.read_bytes()),"bytes":p.stat().st_size}
manifest["copy_whitelist"][str(t.relative_to(R))]={"sha256":sha(t.read_bytes()),"bytes":t.stat().st_size}
manifest["schema"]="hepta-v10-versioned-native-regression-copy-v2"
manifest["recorded_utc"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
manifest["superseded_source_package_sha256"]=sha(raw)
manifest["initial_all_package_peer_acceptance_withdrawn"]=True
manifest["peer_detected_P1"]="old new-copy803 accepted caller-approved self-consistent four-new-definition digest; CI literal129 actualrun valid but harness general approval gate insufficient"
manifest["execution_qualified"]=False
write(D/"manifest.json",json.dumps(manifest,indent=2,sort_keys=True)+"\n")
print(json.dumps({"manifest":str(D/"manifest.json"),"manifest_sha256":sha((D/"manifest.json").read_bytes()),"async_sha256":sha(p.read_bytes()),"approval_tests_sha256":sha(t.read_bytes()),"other_ten_package_files_unchanged":all((name==str(p.relative_to(R))) or sha((R/name).read_bytes())==meta["sha256"] for name,meta in json.loads(raw)["copy_whitelist"].items()),"business_assertions_unchanged":True},sort_keys=True))
