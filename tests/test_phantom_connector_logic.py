# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


class _ActionResult:
    def __init__(self, parameters):
        self.parameters = parameters
        self.data = []
        self.summary = {}

    def add_data(self, value):
        self.data.append(value)

    def get_data(self):
        return self.data

    def get_data_size(self):
        return len(self.data)

    def get_message(self):
        return ""

    def set_status(self, status, message=None):
        self.status = status
        self.message = message
        return status

    def update_param(self, _value):
        pass

    def update_summary(self, value):
        self.summary.update(value)
        return self.summary

    def set_summary(self, value):
        self.summary = value


def _load_connector_module():
    beautiful_soup = types.ModuleType("bs4")
    beautiful_soup.BeautifulSoup = lambda *_args, **_kwargs: None
    magic = types.ModuleType("magic")
    magic.from_file = lambda *_args, **_kwargs: ""
    phantom_package = types.ModuleType("phantom")
    phantom_package.__path__ = []
    app = types.ModuleType("phantom.app")
    app.APP_SUCCESS = 0
    app.APP_ERROR = 1
    app.is_fail = lambda value: value != 0
    action_result = types.ModuleType("phantom.action_result")
    action_result.ActionResult = _ActionResult
    base_connector = types.ModuleType("phantom.base_connector")
    base_connector.BaseConnector = object
    cef = types.ModuleType("phantom.cef")
    cef.CEF_JSON = {}
    cef.CEF_NAME_MAPPING = {}
    rules = types.ModuleType("phantom.rules")
    utils = types.ModuleType("phantom.utils")
    utils.CONTAINS_VALIDATORS = {}
    vault = types.ModuleType("phantom.vault")
    vault.Vault = object
    requests = types.ModuleType("requests")
    requests.get = Mock()
    requests.post = Mock()
    requests.put = Mock()
    requests.delete = Mock()
    request_exceptions = types.ModuleType("requests.exceptions")
    request_exceptions.SSLError = type("SSLError", (Exception,), {})
    request_exceptions.Timeout = type("Timeout", (Exception,), {})

    sys.modules.update(
        {
            "bs4": beautiful_soup,
            "magic": magic,
            "phantom": phantom_package,
            "phantom.app": app,
            "phantom.action_result": action_result,
            "phantom.base_connector": base_connector,
            "phantom.cef": cef,
            "phantom.rules": rules,
            "phantom.utils": utils,
            "phantom.vault": vault,
            "requests": requests,
            "requests.exceptions": request_exceptions,
        }
    )

    connector_path = Path(__file__).parents[1] / "phantom_connector.py"
    spec = importlib.util.spec_from_file_location("phantom_connector_under_test", connector_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONNECTOR = _load_connector_module()


class PhantomConnectorLogicTest(unittest.TestCase):
    def test_remote_requests_verify_but_local_peer_requests_do_not(self):
        connector = object.__new__(CONNECTOR.PhantomConnector)
        connector._auth = "basic-auth"
        connector._base_uri = "https://peer.example"
        connector._verify_cert = True
        connector.get_config = lambda: {"auth_token": "token"}
        connector._process_response = lambda response, _result: (0, response, {})
        action_result = _ActionResult({})
        response = Mock()

        with patch.object(CONNECTOR.requests, "get", return_value=response) as request:
            connector._make_rest_call("/rest/version", action_result)
            connector._make_rest_call("/rest/container", action_result, ignore_auth=True)

        remote_call, local_call = request.call_args_list
        self.assertTrue(remote_call.kwargs["verify"])
        self.assertEqual(remote_call.kwargs["auth"], "basic-auth")
        self.assertEqual(remote_call.kwargs["headers"]["ph-auth-token"], "token")
        self.assertFalse(local_call.kwargs["verify"])
        self.assertIsNone(local_call.kwargs["auth"])
        self.assertNotIn("ph-auth-token", local_call.kwargs["headers"])

    def test_exact_match_defaults_to_true_with_a_substring_opt_out(self):
        connector = object.__new__(CONNECTOR.PhantomConnector)
        connector._base_uri = "https://peer.example"
        connector.save_progress = lambda _message: None
        connector.get_action_identifier = lambda: "find_artifacts"
        connector.add_action_result = lambda result: result
        connector.get_container_id = lambda: 1
        response_data = {"data": [{"id": 1, "container": 1, "_pretty_container": "test", "cef": {"name": "foobar"}}]}
        connector._make_rest_call = lambda *_args, **_kwargs: (0, None, response_data)

        connector.add_action_result = lambda result: setattr(connector, "last_result", result) or result
        connector._find_artifacts({"values": "foo"})
        self.assertEqual(connector.last_result.get_data()[0]["found in"], "N/A")

        connector._find_artifacts({"values": "foo", "exact_match": False})
        self.assertEqual(connector.last_result.get_data()[0]["found in"], "name")

    def test_custom_list_exact_match_defaults_to_true(self):
        connector = object.__new__(CONNECTOR.PhantomConnector)
        connector._base_uri = "https://peer.example"
        connector.save_progress = lambda _message: None
        connector.get_action_identifier = lambda: "find_listitem"
        connector.debug_print = lambda _message: None
        connector.add_action_result = lambda result: setattr(connector, "last_result", result) or result
        connector._validate_integer = lambda _result, value, _key, allow_zero=False: (0, value)
        connector._make_rest_call = lambda *_args, **_kwargs: (0, None, {"id": 1, "content": [["foobar"]]})

        connector._find_listitem({"list": "allowlist", "values": "foo"})
        self.assertEqual(connector.last_result.get_data_size(), 0)

        connector._find_listitem({"list": "allowlist", "values": "foo", "exact_match": False})
        self.assertEqual(connector.last_result.get_data(), [["foobar"]])


if __name__ == "__main__":
    unittest.main()
