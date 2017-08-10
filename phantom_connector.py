# --
# File: phantom_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from phantom.cef import CEF_NAME_MAPPING
from phantom.utils import CONTAINS_VALIDATORS

import ast

import json
import requests
from requests.exceptions import Timeout, SSLError

import urlparse
import socket

TIMEOUT = 120
INVALID_RESPONSE = 'Server did not return a valid JSON response.'
GET = 'get'
POST = 'post'

def determine_contains(value):
    for c, f in CONTAINS_VALIDATORS.items():
        if f(value):
            return c
    return None

class PhantomConnector(BaseConnector):

    def _do_request(self, url, method=GET, payload=None):
        try:
            if method == GET:
                response = requests.get(url, verify=self.verify_cert, auth=self.use_auth, headers=self.headers, timeout=TIMEOUT)
            elif method == POST:
                response = requests.post(url, data=payload, verify=self.verify_cert, auth=self.use_auth, headers=self.headers, timeout=TIMEOUT)
            else:
                raise ValueError('Invalid method {}'.format(method))
        except Timeout as e:
            raise Exception('HTTP GET request timed out: ' + str(e))
        except SSLError as e:
            raise Exception('HTTPS SSL validation failed: ' + str(e))
        else:
            if response.status_code != 200:
                message = INVALID_RESPONSE
                try:
                    message = response.json()['message']
                except:
                    pass
                return False, (response, message)
        return True, response.json()

    def _test_connectivity(self, param):
        url = self.base_uri + '/rest/version'
        success, output = self._do_request(url)
        if not success:
            response, message = output
            self.set_status(phantom.APP_ERROR, 'Failed to connect: {}'.format(message))
            return self.get_status()
        version = output['version']
        self.save_progress("Connected to Phantom appliance version {}".format(version))
        self.save_progress("Test connectivity PASSED.")
        self.set_status(phantom.APP_SUCCESS, 'Request succeeded')
        return self.get_status()

    def _find_artifacts(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)
        values = param.get('values', '')
        if param.get('is_regex'):
            flt = 'iregex'
        else:
            flt = 'icontains'
        exact_match = param.get('exact_match')
        if exact_match:
            values = '"{}"'.format(values)
        url = self.base_uri + '/rest/artifact?_filter_cef__{}={}&page_size=0&pretty'.format(flt, repr(values))
        success, output = self._do_request(url)
        if not success:
            response, message = output
            action_result.set_status(phantom.APP_ERROR, 'Error retrieving records: {}'.format(message))
            return action_result.get_status()

        records = output['data']
        values = values.lower()
        for rec in records:
            key, value = None, None

            for k, v in rec['cef'].iteritems():
                if values in v.lower() or (exact_match and values.strip('"') == v.lower()):
                    key = k
                    value = v
                    break
            result = {
                "id": rec['id'],
                "container": rec['container'],
                "container_name": rec['_pretty_container'],
                "name": rec.get('name'),
                "found in": key if key else "N/A",
                "matched": value if value else "",
            }
            action_result.add_data(result)
        action_result.update_summary({'artifacts found': len(records)})
        action_result.update_summary({'server': self.base_uri})
        action_result.set_status(phantom.APP_SUCCESS, 'Request succeeded')
        return action_result.get_status()

    def _add_artifact(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        name = param.get('name')
        container_id = param.get('container_id', self.get_container_id())
        label = param.get('label', 'event')
        contains = param.get('contains', '').strip().split(',')
        cef_name = param.get('cef_name')
        cef_value = param.get('cef_value')

        url = self.base_uri + '/rest/artifact'

        artifact = {}
        artifact['name'] = name
        artifact['label'] = label
        artifact['container_id'] = container_id
        artifact['cef'] = {
            cef_name: cef_value,
        }
        if contains:
            artifact['cef_types'] = {'cef_name': contains}
        elif cef_name not in CEF_NAME_MAPPING:
            contains = determine_contains(cef_value)
            if contains:
                artifact['cef_types'] = {'cef_name': [contains]}

        success, output = self._do_request(url, method=POST, payload=json.dumps(artifact))
        if not success:
            response, message = output
            result = response.json()
            artifact_id = result.get('existing_artifact_id')
            if not artifact_id:
                action_result.set_status(phantom.APP_ERROR, 'Error adding artifact: {}'.format(message))
                return action_result.get_status()
        else:
            result = output
            artifact_id = result.get('id')
            message = 'Request succeeded'
        action_result.add_data(result)
        action_result.update_summary({'artifact id': artifact_id})
        action_result.update_summary({'container id': container_id})
        action_result.update_summary({'server': self.base_uri})
        action_result.set_status(phantom.APP_SUCCESS, message)
        return action_result.get_status()

    def _find_listitem(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        values = param.get('values')
        list_name = param.get('list')
        exact_match = param.get('exact_match')
        column_index = int(param.get('column_index', -1))
        if column_index == '':
            column_index = -1

        url = self.base_uri + '/rest/decided_list/{}'.format(list_name)

        success, output = self._do_request(url)
        if not success:
            response, message = output
            action_result.set_status(phantom.APP_ERROR, 'Error loading list: {}'.format(message))
            return action_result.get_status()

        j = output
        list_id = j['id']
        content = j.get('content')
        coordinates = []
        found = 0
        for rownum, row in enumerate(content):
            for cid, value in enumerate(row):
                if column_index < 0 or cid == column_index:
                    if exact_match and value == values:
                        found += 1
                        action_result.add_data(row)
                        coordinates.append((rownum, cid))
                    elif value and values in value:
                        found += 1
                        action_result.add_data(row)
                        coordinates.append((rownum, cid))

        action_result.update_summary({'server': self.base_uri})
        action_result.update_summary({'found matches': found})
        action_result.update_summary({'locations': coordinates})

        action_result.set_status(phantom.APP_SUCCESS, 'Request succeeded')
        return action_result.get_status()
        
    def _create_list(self, list_name, row, action_result):
        if type(row) in (str, unicode):
            row = [row]
        payload = {
            'content': [row],
            'name': list_name,
        }
        url = self.base_uri + '/rest/decided_list'
        success, output = self._do_request(url, method=POST, payload=json.dumps(payload))
        if not success:
            response, message = output
            action_result.set_status(phantom.APP_ERROR, 'Error creating list: {}'.format(message))
            return action_result.get_status()
        result = output
        action_result.add_data(result)
        action_result.update_summary({'server': self.base_uri})
        action_result.set_status(phantom.APP_SUCCESS, 'Request succeeded')
        return action_result.get_status()

    def _add_listitem(self, param):
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        list_name = param.get('list')
        row = param.get('new_row')
        try:
            row = ast.literal_eval(row)
        except:
            #its just a string
            pass

        url = self.base_uri + '/rest/decided_list/{}'.format(list_name)

        payload = {
            'append_rows': [
                row,
            ]
        }

        success, output = self._do_request(url, method=POST, payload=json.dumps(payload))
        if not success:
            response, message = output
            if response.status_code == 404:
                if param.get('create'):
                    self.save_progress('List "{}" not found, creating'.format(list_name))
                    return self._create_list(list_name, row, action_result)
            action_result.set_status(phantom.APP_ERROR, 'Error appending to list: {}'.format(message))
            return action_result.get_status()
        result = output
        action_result.add_data(result)
        action_result.update_summary({'server': self.base_uri})
        action_result.set_status(phantom.APP_SUCCESS, 'Request succeeded')
        return action_result.get_status()

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()
        self.config = config = self.get_config()
        host = self.config.get('phantom_server')
        try:
            unpacked = socket.gethostbyname(host)
        except:
            packed = socket.inet_aton(host)
            unpacked = socket.inet_ntoa(packed)

        if unpacked.startswith('127.'):
            self.set_status(phantom.APP_ERROR, 'Accessing 127.0.0.1 is not allowed')
            return self.get_status()
        if '127.0.0.1' in host or 'localhost' in host:
            self.set_status(phantom.APP_ERROR, 'Accessing 127.0.0.1 is not allowed')
            return self.get_status()
        self.base_uri = 'https://{}'.format(self.config.get('phantom_server'))
        self.verify_cert = config.get('verify_certificate', False)

        self.use_auth = None
        if config.get('username') and config.get('password'):
            self.use_auth = (config['username'], config['password'])
        headers = param.get('headers', {})
        if headers:
            try:
                headers = json.loads(headers)
            except Exception as e:
                raise Exception(u'Failed to parse headers as JSON object. error: {}, headers: {}'.format(str(e), unicode(headers)))
        if config.get('auth_token'):
            if 'ph-auth-token' not in headers:
                headers['ph-auth-token'] = config.get('auth_token')
        self.headers = headers and headers or None

        if (action == 'find_artifacts'):
            result = self._find_artifacts(param)
        elif (action == 'add_artifact'):
            result = self._add_artifact(param)
        elif (action == 'add_listitem'):
            result = self._add_listitem(param)
        elif (action == 'find_listitem'):
            result = self._find_listitem(param)
        elif (action == 'test_asset_connectivity'):
            result = self._test_connectivity(param)

        return result

if __name__ == '__main__':

    import sys
    # import simplejson as json
    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = PhantomConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(ret_val), indent=4)

    exit(0)
