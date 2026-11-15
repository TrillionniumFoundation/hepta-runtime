#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""The public import gate preserves wire strings and JSON value categories."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import rea_evidence_import_qualification as h
import rea_operation_qualification as q


class PublicImportComparisonTests(unittest.TestCase):
    def setUp(self):
        fixture=json.loads((ROOT/'tests/fixtures/rea_evidence_import_errors.json').read_text())
        self.result=fixture['cases'][0]['original_result']
        self.row={'arguments':{},'orders':[],
                  'value':q.tool_value({'result':self.result}),
                  'response':{'result':self.result}}

    def test_complete_original_result_is_compared(self):
        result=h.compare_observation(self.row,copy.deepcopy(self.row))
        self.assertEqual(result['complete_call_tool_result_status'],'PASS')

    def test_sorted_embedded_text_is_not_full_result_equivalence(self):
        changed=copy.deepcopy(self.row)
        text=changed['response']['result']['content'][0]['text']
        changed['response']['result']['content'][0]['text']=json.dumps(
            json.loads(text),sort_keys=True,separators=(',',':'))
        result=h.compare_observation(self.row,changed)
        self.assertEqual(result['parsed_value_status'],'PASS')
        self.assertEqual(result['complete_call_tool_result_status'],'FAIL')
        self.assertEqual(result['status'],'FAIL')

    def test_boolean_arguments_cannot_bind_numeric_requests(self):
        changed=copy.deepcopy(self.row)
        self.row['arguments']={'flag':False}
        changed['arguments']={'flag':0}
        with self.assertRaises(q.QualificationError):
            h.compare_observation(self.row,changed)

    def test_boolean_result_metadata_is_not_a_number(self):
        changed=copy.deepcopy(self.row)
        changed['response']['result']['isError']=1
        self.assertEqual(h.compare_observation(self.row,changed)['status'],'FAIL')

    def test_cancelled_response_is_not_fabricated_or_counted(self):
        row={'arguments':{},'orders':[], 'kind':'observed-protocol-lifecycle',
             'value':{'cancel_notification_sent':True}}
        self.assertIsNone(h.compare_observation(row,row)['complete_call_tool_result_status'])
        changed=copy.deepcopy(row)
        changed['response']={'result':self.result}
        with self.assertRaises(q.QualificationError):
            h.compare_observation(row,changed)


    def original_error_row(self, result):
        response={'result':copy.deepcopy(result)}
        value=q.tool_value(response)
        return {'arguments':{},'value':value,'orders':h.orders(value),
                'raw_error_text':h.raw_error_text(response),'response':response}

    def test_full_result_comparison_keeps_the_raw_error_gate(self):
        row=self.original_error_row(self.result)
        changed=copy.deepcopy(row)
        changed['raw_error_text']['utf8_sha256']='0'*64
        result=h.compare_observation(row,changed)
        self.assertEqual(result['complete_call_tool_result_status'],'PASS')
        self.assertEqual(result['raw_error_text_status'],'FAIL')
        self.assertEqual(result['status'],'FAIL')

    def test_full_result_comparison_keeps_the_error_member_order_gate(self):
        row=self.original_error_row(self.result)
        changed=copy.deepcopy(row)
        error=next(x for x in changed['orders']
                   if x['representation']=='error-text' and x['path']==['error'])
        error['keys'].reverse()
        result=h.compare_observation(row,changed)
        self.assertEqual(result['complete_call_tool_result_status'],'PASS')
        self.assertEqual(result['error_text_order']['status'],'FAIL')
        self.assertEqual(result['status'],'FAIL')

    def test_original_plain_sdk_errors_remain_outside_json_error_gates(self):
        fixture=json.loads((ROOT/'tests/fixtures/rea_evidence_file/'
            'import-error-text-original-118-rea-6_8_0-679ccf.json').read_text())
        cases=[case for case in fixture['cases'] if case['kind']=='plain']
        self.assertEqual(len(cases),4)
        for case in cases:
            response=json.loads(bytes.fromhex(case['response_wire_hex']))
            row=self.original_error_row(response['result'])
            result=h.compare_observation(row,copy.deepcopy(row))
            self.assertEqual(result['status'],'PASS',case['id'])
            self.assertEqual(result['complete_call_tool_result_status'],'PASS')
            self.assertEqual(result['raw_error_text_status'],'NOT_APPLICABLE')
            self.assertEqual(result['error_text_order']['status'],'NOT_APPLICABLE')
            changed=copy.deepcopy(row)
            changed['response']['result']['content'][0]['text']+='!'
            self.assertEqual(h.compare_observation(row,changed)['status'],'FAIL')


if __name__=='__main__':
    unittest.main()
