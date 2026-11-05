"""Dependency-free regression tests for the synchronous client's auth boundary."""
import ast
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, local
import unittest


def load_auth_options():
    # Exercise the actual class without importing optional tracing dependencies.
    source = Path(__file__).resolve().parents[1] / 'pynipap/pynipap/pynipap.py'
    tree = ast.parse(source.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                and n.name == 'AuthOptions')
    namespace = {'local': local, 'NipapMissingInputError': ValueError}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'),
         namespace)
    return namespace['AuthOptions']


class AuthOptionsIsolationTest(unittest.TestCase):
    def setUp(self):
        self.options = load_auth_options()

    def test_uninitialized_thread_fails_closed(self):
        self.options({'username': 'admin', 'readonly': False})
        with ThreadPoolExecutor(max_workers=1) as executor:
            with self.assertRaises(ValueError):
                executor.submit(self.options).result(timeout=5)

    def test_concurrent_identities_remain_isolated(self):
        barrier = Barrier(2)

        def request(username, readonly):
            held = self.options({'username': username, 'readonly': readonly})
            barrier.wait(timeout=5)
            return held.options, self.options().options

        with ThreadPoolExecutor(max_workers=2) as executor:
            admin = executor.submit(request, 'admin', False)
            reader = executor.submit(request, 'reader', True)
            for future, username, readonly in ((admin, 'admin', False),
                                               (reader, 'reader', True)):
                for result in future.result(timeout=5):
                    self.assertEqual(result, {'username': username,
                                              'readonly': readonly})

    def test_existing_instances_see_current_request(self):
        held = self.options({'username': 'admin', 'readonly': False})
        self.options({'username': 'reader', 'readonly': True})
        self.assertTrue(held.options['readonly'])
        self.assertEqual(held.options['username'], 'reader')

    def test_caller_dictionary_is_not_shared(self):
        original = {'username': 'reader', 'readonly': True}
        held = self.options(original)
        original['readonly'] = False
        self.assertTrue(held.options['readonly'])

    def test_clearing_thread_fails_closed_for_existing_instances(self):
        held = self.options({'username': 'admin', 'readonly': False})
        self.options.clear()
        self.options.clear()
        with self.assertRaises(ValueError):
            held.options


if __name__ == '__main__':
    unittest.main()
