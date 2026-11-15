#!/usr/bin/env bash
set -u
cd /home/qian-qi/hepta-runtime-operation-v10-20261013 || exit 1
E=docs/qualification/dc-functional-v10-operation-engine-tests-20261013/export-r1
mkdir -m 700 "$E" || exit 1
python3 tests/dc_functional_v10_operation_async_acceptance.py \
  --binary /home/qian-qi/hepta-runtime-operation-v10-20261013/target/debug/hepta-runtime \
  --expected-binary-sha256 bc0d9f4766e0bb9af32075cea860ff82a3be89ba05a775512806be84fc9f1915 \
  --expected-source-fingerprint 3a9106b6fa774758590a94c2506eaded97d3e794cc34823767f93597d2ecdbb0 \
  --expected-head 50372629e0522d19b5bc4c1a800bfc311e4597f9 \
  --previous-contract deploy/contracts/hepta-runtime-full-operator-v9.json \
  --expected-previous-contract-sha256 3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761 \
  --export-contract "$E/contract.json" --out "$E/receipt.json" \
  >"$E/run.log" 2>&1
status=$?
printf '%s\n' "$status" >"$E/run.exit"
chmod 600 "$E"/run.*
printf '{"export_only_exit_code":%s}\n' "$status"
exit "$status"
