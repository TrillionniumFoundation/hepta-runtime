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


if __name__=='__main__':
    unittest.main()
