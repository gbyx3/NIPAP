"""Request-local access-token and shared-cache isolation, without API calls."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch
import unittest

import pynipap
from pynipap import AuthOptions, XMLRPCConnection, VRF
import pynipap.pynipap as client


class BearerScopeTest(unittest.TestCase):
    def setUp(self):
        AuthOptions.clear()
        self.addCleanup(AuthOptions.clear)

    def test_concurrent_tokens_remain_in_their_own_threads(self):
        barrier = Barrier(2)
        def request(token):
            try:
                AuthOptions.set_bearer_token(token)
                barrier.wait(timeout=5)
                return AuthOptions.get_bearer_token()
            finally:
                AuthOptions.clear()
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(request, 'synthetic-first-token')
            second = executor.submit(request, 'synthetic-second-token')
            self.assertEqual(first.result(timeout=5), 'synthetic-first-token')
            self.assertEqual(second.result(timeout=5), 'synthetic-second-token')

    def test_clear_restores_single_identity_compatibility(self):
        with patch.object(pynipap, 'bearer_token', 'synthetic-legacy-token'):
            AuthOptions.set_bearer_token('synthetic-request-token')
            self.assertEqual(AuthOptions.get_bearer_token(), 'synthetic-request-token')
            AuthOptions.clear()
            self.assertEqual(AuthOptions.get_bearer_token(), 'synthetic-legacy-token')
            AuthOptions.set_bearer_token(None)
            self.assertIsNone(AuthOptions.get_bearer_token())

    def test_xmlrpc_transport_uses_request_token_not_global(self):
        with patch.object(pynipap, 'xmlrpc_uri', 'https://api.example.test/RPC2'), \
             patch.object(pynipap, 'bearer_token', 'synthetic-global-token'), \
             patch.object(client.xmlrpclib, 'ServerProxy') as proxy:
            AuthOptions.set_bearer_token('synthetic-request-token')
            XMLRPCConnection()
            headers = proxy.call_args.kwargs['transport']._headers
            self.assertEqual(list(headers), [('Authorization', 'Bearer synthetic-request-token')])
            AuthOptions.set_bearer_token(None)
            XMLRPCConnection()
            self.assertEqual(list(proxy.call_args.kwargs['transport']._headers), [])

    def test_request_scoped_credentials_neither_read_nor_populate_shared_cache(self):
        sentinel, fresh = object(), object()
        previous = dict(client._cache['VRF'])
        self.addCleanup(lambda: (client._cache['VRF'].clear(), client._cache['VRF'].update(previous)))
        client._cache['VRF'][123456] = sentinel
        with patch.object(pynipap, 'CACHE', True), patch.object(VRF, 'list', return_value=[fresh]):
            AuthOptions.set_bearer_token('synthetic-request-token')
            self.assertIs(VRF.get(123456), fresh)
            self.assertIs(client._cache['VRF'][123456], sentinel)
            AuthOptions.clear()
            self.assertIs(VRF.get(123456), sentinel)

    def test_bearer_and_basic_uri_credentials_cannot_be_mixed(self):
        with patch.object(pynipap, 'xmlrpc_uri', 'https://example:synthetic@api.example.test/RPC2'), \
             patch.object(client.xmlrpclib, 'ServerProxy') as proxy:
            AuthOptions.set_bearer_token('synthetic-request-token')
            with self.assertRaises(pynipap.NipapMissingInputError):
                XMLRPCConnection()
            proxy.assert_not_called()

    def test_bearer_tokens_are_not_sent_over_plain_http(self):
        with patch.object(pynipap, 'xmlrpc_uri', 'http://api.example.test/RPC2'), \
             patch.object(client.xmlrpclib, 'ServerProxy') as proxy:
            AuthOptions.set_bearer_token('synthetic-request-token')
            with self.assertRaises(pynipap.NipapMissingInputError):
                XMLRPCConnection()
            proxy.assert_not_called()
