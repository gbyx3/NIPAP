"""HTTP authentication dispatch without a database or live tokens."""
import configparser
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from flask import Flask
from werkzeug.datastructures import Authorization
from werkzeug.exceptions import HTTPException
from nipap.authlib import AuthFactory
from nipap import nipap_xmlrpc, rest


class ApiAuthTest(unittest.TestCase):
    def setUp(self):
        config = configparser.ConfigParser()
        self.config_patch = patch('nipap.authlib.NipapConfig', return_value=config)
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.app = Flask(__name__)
        self.receiver = SimpleNamespace(logger=Mock())
        self.account = SimpleNamespace(authenticate=lambda: True, readonly=True)

    def invoke(self, header, operation):
        headers = {'Authorization': header, 'NIPAP-Authoritative-Source': 'test'}
        with self.app.test_request_context('/test', headers=headers):
            xmlrpc = nipap_xmlrpc.requires_auth(operation)(
                self.receiver, {'auth': {'authoritative_source': 'test'}})
        with self.app.test_request_context('/test', headers=headers):
            response = rest.requires_auth(operation)(self.receiver)
        return xmlrpc, response

    def test_bearer_uses_bearer_backend(self):
        with patch.object(AuthFactory, 'get_auth_bearer_token', return_value=self.account) as bearer, \
             patch.object(AuthFactory, 'get_auth') as basic:
            result = self.invoke('Bearer synthetic-token', lambda receiver, args: args['auth'].readonly)
        self.assertEqual(result, (True, True))
        self.assertEqual(bearer.call_count, 2)
        basic.assert_not_called()

    def test_basic_preserves_backend_suffix(self):
        header = Authorization('basic', {'username': 'reader@directory', 'password': 'test-only'}).to_header()
        with patch.object(AuthFactory, 'get_auth', return_value=self.account) as basic, \
             patch.object(AuthFactory, 'get_auth_bearer_token') as bearer:
            self.invoke(header, lambda receiver, args: args['auth'].readonly)
        self.assertEqual(basic.call_count, 2)
        for call in basic.call_args_list:
            self.assertEqual(call.args[:2], ('reader@directory', 'test-only'))
        bearer.assert_not_called()

    def test_missing_or_malformed_credentials_do_not_reach_operation(self):
        operation = Mock()
        for header in ['', 'Bearer', 'Bearer a=b', 'Digest username=test']:
            headers = {'Authorization': header, 'NIPAP-Authoritative-Source': 'test'}
            with self.app.test_request_context('/test', headers=headers):
                with self.assertRaises(nipap_xmlrpc.Fault):
                    nipap_xmlrpc.requires_auth(operation)(
                        self.receiver, {'auth': {'authoritative_source': 'test'}})
            with self.app.test_request_context('/test', headers=headers):
                with self.assertRaises(HTTPException) as error:
                    rest.requires_auth(operation)(self.receiver)
                self.assertEqual(error.exception.get_response().status_code, 401)
        operation.assert_not_called()

    def test_rejected_token_does_not_reach_operation(self):
        operation = Mock()
        self.account.authenticate = lambda: False
        headers = {'Authorization': 'Bearer synthetic-token', 'NIPAP-Authoritative-Source': 'test'}
        with patch.object(AuthFactory, 'get_auth_bearer_token', return_value=self.account):
            with self.app.test_request_context('/test', headers=headers):
                with self.assertRaises(nipap_xmlrpc.Fault):
                    nipap_xmlrpc.requires_auth(operation)(
                        self.receiver, {'auth': {'authoritative_source': 'test'}})
            with self.app.test_request_context('/test', headers=headers):
                with self.assertRaises(HTTPException) as error:
                    rest.requires_auth(operation)(self.receiver)
                response = error.exception.get_response()
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers['WWW-Authenticate'], 'Bearer')
        operation.assert_not_called()
