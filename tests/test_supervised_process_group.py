"""Process-group routing tests use synthetic Python children, never PKCS#11."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('supervised_mu', ROOT/'adapters/pkcs11-mu.py')
MU = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MU)


@unittest.skipUnless(os.name == 'posix', 'POSIX process-group supervisor')
class SupervisedGroupTests(unittest.TestCase):
    def test_standalone_keeps_native_session_isolation(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(MU.native_process_options(), {'start_new_session': True})

    def test_supervised_opt_in_is_strict(self):
        for value in ('0', 'true', '', '2'):
            with mock.patch.dict(os.environ, {'PQMAIL_SUPERVISED_PROCESS_GROUP': value}, clear=True):
                with self.assertRaises(MU.AdapterError):
                    MU.native_process_options()
        with mock.patch.dict(os.environ, {'PQMAIL_SUPERVISED_PROCESS_GROUP': '1'}, clear=True):
            self.assertEqual(MU.native_process_options(), {'start_new_session': False})

    def test_real_descendant_group_matches_outer_supervisor_only_when_opted_in(self):
        # The outer synthetic supervisor owns a new group. Importing the real
        # option selector inside it checks actual spawn semantics, not merely
        # a mocked kwargs dictionary. Neither process loads a token module.
        code = '''import importlib.util,os,subprocess,sys,json
spec=importlib.util.spec_from_file_location('mu',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
child=subprocess.check_output([sys.executable,'-c','import os;print(os.getpgrp())'],**m.native_process_options())
print(json.dumps([os.getpgrp(),int(child)]))
'''
        for supervised in (False, True):
            env = {k:v for k,v in os.environ.items() if k != 'PQMAIL_SUPERVISED_PROCESS_GROUP'}
            if supervised:
                env['PQMAIL_SUPERVISED_PROCESS_GROUP'] = '1'
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(ROOT/'adapters/pkcs11-mu.py')],
                                    env=env, start_new_session=True, capture_output=True, timeout=10, check=True)
            outer, child = json.loads(result.stdout)
            self.assertEqual(outer == child, supervised)


if __name__ == '__main__':
    unittest.main()
