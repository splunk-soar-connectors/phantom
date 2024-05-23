# File: phantom_connector.py
#
# Copyright (c) 2016-2024 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom imports
import ast
import bz2
import datetime
import gzip
import json
import os
import pathlib
import random
import socket
import string
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Tuple

import requests
from bs4 import BeautifulSoup
from requests.exceptions import SSLError, Timeout

import magic
import phantom.app as phantom
import phantom.rules as ph_rules
import phantom.utils as ph_utils
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.cef import CEF_JSON, CEF_NAME_MAPPING
from phantom.utils import CONTAINS_VALIDATORS
from phantom.vault import Vault
# Constants imports
from phantom_consts import *

try:
    from urllib.parse import quote
except Exception:
    from urllib import quote


def determine_contains(value):
    valid_contains = list()
    for c, f in list(CONTAINS_VALIDATORS.items()):
        try:
            if f(value):
                valid_contains.append(c)
        except Exception:
            continue

    return valid_contains


class RetVal3(tuple):
    def __new__(cls, val1, val2=None, val3=None):
        return tuple.__new__(RetVal3, (val1, val2, val3))


class PhantomConnector(BaseConnector):

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_INVALID_INT.format(msg="", param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_INVALID_INT.format(msg="", param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_INVALID_INT.format(msg="non-negative", param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_INVALID_INT.format(msg="non-zero positive", param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = PHANTOM_ERR_CODE_UNAVAILABLE
        error_msg = PHANTOM_ERR_MSG_UNAVAILABLE
        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as e:
            self.debug_print("Error occurred while fetching exception information. Details: {}".format(str(e)))

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _get_error_details(self, resp_json):

        # The device that this app talks to does not sends back a simple message,
        # so this function does not need to be that complicated
        message = resp_json.get('message')
        if not message:
            message = "Error message is unavailable"
        return message

    def _process_html_response(self, response, action_result):

        # An html response, is bound to be an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        # In 2.0 the platform does not like braces in messages, unless it's format parameters
        message = message.replace('{', ' ').replace('}', ' ')

        return RetVal3(action_result.set_status(phantom.APP_ERROR, message), response)

    def _process_json_response(self, response, action_result):

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                        PHANTOM_ERR_PARSE_JSON_RESPONSE.format(self._get_error_message_from_exception(e))), response)

        if isinstance(resp_json, list):
            # Let's not parse it here
            return RetVal3(phantom.APP_SUCCESS, response, resp_json)

        failed = resp_json.get('failed', False)

        if failed:
            return RetVal3(
                    action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_SERVER.format(response.status_code,
                        self._get_error_details(resp_json))), response)

        if 200 <= response.status_code < 399:
            return RetVal3(phantom.APP_SUCCESS, response, resp_json)

        return RetVal3(
                action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_SERVER.format(response.status_code,
                    self._get_error_details(resp_json))), response, None)

    def _process_response(self, response, action_result):

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if response is not None:
                action_result.add_debug_data({'r_text': response.text})
                action_result.add_debug_data({'r_headers': response.headers})
                action_result.add_debug_data({'r_status_code': response.status_code})
            else:
                action_result.add_debug_data({'r_text': 'response is None'})

        # There are just too many differences in the response to handle all of them in the same function
        if (('json' in response.headers.get('Content-Type', '')) or ('javascript' in response.headers.get('Content-Type'))):
            return self._process_json_response(response, action_result)

        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not an html or json, handle if it is a successful empty response
        if (200 <= response.status_code < 399) and (not response.text):
            return RetVal3(phantom.APP_SUCCESS, response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                response.status_code, response.text.replace('{', ' ').replace('}', ' '))

        return RetVal3(action_result.set_status(phantom.APP_ERROR, message), response, None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", ignore_auth=False):

        config = self.get_config()

        # Create the headers
        if headers is None:
            headers = {}

        if headers:
            try:
                headers = json.loads(headers)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                            "Unable to load headers as JSON: {}".format(self._get_error_message_from_exception(e)))

        # auth_token is a bit tricky, it can be in the params or config
        auth_token = config.get('auth_token')

        if ((auth_token) and ('ph-auth-token' not in headers)):
            headers['ph-auth-token'] = auth_token

        if 'Content-Type' not in headers:
            headers.update({'Content-Type': 'application/json'})

        request_func = getattr(requests, method)

        if not request_func:
            action_result.set_status(phantom.APP_ERROR, "Unsupported HTTP method '{0}' requested".format(method))

        auth = self._auth

        # To avoid '//' in the URL(due to self._base_uri + endpoint)
        self._base_uri = self._base_uri.strip('/')

        if ignore_auth:
            auth = None
            if 'ph-auth-token' in headers:
                del headers['ph-auth-token']

        try:
            url = '{0}{1}'.format(self._base_uri, endpoint)
            response = request_func(url,
                    auth=auth,
                    json=data,
                    headers=headers if headers else None,
                    verify=False if ignore_auth else self._verify_cert,
                    params=params,
                    timeout=TIMEOUT)

        except Timeout as e:
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                        "Request timed out: {}".format(self._get_error_message_from_exception(e))), None, None)
        except SSLError as e:
            return (action_result.set_status(phantom.APP_ERROR,
                        "HTTPS SSL validation failed: {}".format(self._get_error_message_from_exception(e))), None, None)
        except Exception as e:
            return (action_result.set_status(phantom.APP_ERROR,
                        "Error connecting to server. Error Details: {}".format(self._get_error_message_from_exception(e))), None, None)

        return self._process_response(response, action_result)

    def _test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response, resp_data = self._make_rest_call('/rest/version', action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return action_result.set_status(phantom.APP_ERROR, 'Failed to connect: {}'.format(action_result.get_message()))

        version = resp_data['version']
        self.save_progress("Connected to Phantom appliance version {}".format(version))
        self.save_progress("Test connectivity passed")

        return action_result.set_status(phantom.APP_SUCCESS, 'Request succeeded')

    def load_dirty_json(self, dirty_json, action_result, parameter):
        import re
        regex_replace = [
            (r"([ \{,:\[])(u?\\?)?'([^']*)'([^'])", r'\1"\3"\4'),   # Replace single quotes with double quotes
            (r" False([, \}\]])", r' false\1'),                     # Replace python "False" with json "false"
            (r" True([, \}\]])", r' true\1'),                       # Replace python "True" with json "true"
            (r" None([, \}\]])", r' null\1')                        # Replace python "None" with json "null"
        ]
        for r, s in regex_replace:
            dirty_json = re.sub(r, s, dirty_json)
        dirty_json = dirty_json.replace(": ''", ': ""')

        try:
            clean_json = json.loads(dirty_json)
            if not clean_json:
                action_result.set_status(phantom.APP_ERROR,
                        "Please provide a non-empty JSON in {parameter} parameter".format(parameter=parameter))
                return None
            if not isinstance(clean_json, dict):
                action_result.set_status(phantom.APP_ERROR, "Please provide {parameter} parameter in JSON format".format(parameter=parameter))
                return None
        except Exception as e:
            action_result.set_status(phantom.APP_ERROR,
                        "Could not load JSON from {parameter} parameter".format(parameter=parameter), self._get_error_message_from_exception(e))
            return None

        return clean_json

    def _update_artifact(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        artifact_id = param['artifact_id']

        name = param.get('name')
        label = param.get('label')
        severity = param.get('severity')
        cef_json = param.get('cef_json')
        cef_types_json = param.get('cef_types_json')
        tags = param.get('tags')
        art_json = param.get('artifact_json')

        overwrite = param.get('overwrite', False)

        # Check if at least one of the following parameters have been supplied:
        if not any((name, label, severity, cef_json, cef_types_json, tags, art_json)):
            req_params = 'name, label, severity, cef_json, cef_types_json, tags, artifact_json'
            return action_result.set_status(phantom.APP_ERROR,
                    'At least one of the following parameters are required to update an artifact: {}'.format(req_params))

        endpoint = "/rest/artifact/{}".format(artifact_id)

        output_artifact = {}

        # name, label, and severity should always be overwritten, if provided
        if name:
            output_artifact['name'] = name

        if label:
            output_artifact['label'] = label

        if severity:
            output_artifact['severity'] = severity

        existing_artifact = {}  # If overwriting, this will be used.

        # //// Start workaround for PPS-18970 ////
        ''' Use this once PPS-18970 is fixed
        if overwrite is False:
            # Get the existing artifact to append provided parameters to existing values
            ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

            if phantom.is_fail(ret_val):
                self.save_progress(PHANTOM_ERR_FIND_ARTIFACT)
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_ARTIFACT.format(action_result.get_message()))

            existing_artifact = resp_data
        '''

        # First get the artifacts json
        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(PHANTOM_ERR_FIND_ARTIFACT)
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_ARTIFACT.format(action_result.get_message()))

        if overwrite is False:
            existing_artifact = resp_data
        if 'label' not in output_artifact:
            output_artifact['label'] = resp_data.get('label')
            if not output_artifact['label']:
                output_artifact['label'] = 'event'

        # Get the CEF JSON and update the artifact
        myData = existing_artifact.get('cef', {})

        if cef_json:
            try:
                clean_json = json.loads(cef_json)
            except Exception:
                clean_json = self.load_dirty_json(cef_json, action_result, "cef_json")

            if clean_json is None:
                return action_result.get_status()

            try:
                myData = dict((k, v) for k, v in myData.iteritems() if v)
            except Exception:
                myData = dict((k, v) for k, v in myData.items() if v)
            myData.update(clean_json)

        try:
            myData = dict((k, v) for k, v in myData.iteritems() if v)
        except Exception:
            myData = dict((k, v) for k, v in myData.items() if v)

        # //// End workaround for PPS-18970 ////

        output_artifact['cef'] = myData

        if cef_types_json:
            # If overwrite is False, need to update existing cef_types verses replacing whole thing
            contains = existing_artifact.get('cef_types', {})
            cef_types_json = self.load_dirty_json(cef_types_json, action_result, "cef_types_json")
            if cef_types_json is None:
                return action_result.get_status()
            contains.update(cef_types_json)
            output_artifact['cef_types'] = contains

        if tags:
            # If overwrite is False, need to add to the existing tags. Otherwise replace list of tags.
            cleaned_tags = [tag.strip().strip('\'"') for tag in tags.strip('[]').split(',')]
            output_artifact['tags'] = list(set(existing_artifact.get('tags', []) + cleaned_tags))  # make sure any duplicates are removed

        # This will always overwrite any existing fields provided.
        if art_json:
            art_json = self.load_dirty_json(art_json, action_result, "art_json")
            if art_json is None:
                return action_result.get_status()
            output_artifact.update(art_json)

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result, data=output_artifact, method="post")

        action_result.add_data({
            'requested_artifact': output_artifact,
            'response': resp_data
        })

        if phantom.is_fail(ret_val):
            self.save_progress('Unable to update artifact.')
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_UPDATE_ARTIFACT.format(action_result.get_message()))

        return action_result.set_status(phantom.APP_SUCCESS, 'Artifact updated successfully.')

    def _tag_artifact(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        artifact_id = param['artifact_id']
        add_tags = param.get('add_tags', '')
        remove_tags = param.get('remove_tags', '')

        # These come in as str, so split, then convert to set
        add_tags = set([x.strip() for x in add_tags.split(',')])
        remove_tags = set([x.strip() for x in remove_tags.split(',')])

        endpoint = "/rest/artifact/{}".format(artifact_id)
        # First get the artifacts json
        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress("Unable to get artifact, please check the artifact id")
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_ARTIFACT.format(action_result.get_message()))

        resp_label = resp_data.get("label")

        if not resp_label:
            self.debug_print("The provided aritfact does not have any label")

        # Label has to be included or it gets clobbered in POST
        fields = ['tags', 'label']
        art_data = {f: response.json().get(f) for f in fields}

        # In case the label is None empty string will be passed
        if not art_data.get("label"):
            art_data["label"] = ""

        current_tags = set(art_data['tags'])
        tags_already_added = set()
        tags_already_removed = set()

        # Find tags which are already present
        for tag in add_tags:
            if tag in current_tags:
                tags_already_added.add(tag)

        # Find tags that are to be removed but are not present
        for tag in remove_tags:
            if tag not in current_tags:
                tags_already_removed.add(tag)

        # Set union first to add, then difference to remove, then cast back to list to update
        _tags = (current_tags | add_tags) - remove_tags
        art_data['tags'] = list(_tags)

        # Post our changes
        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result, data=art_data, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress("Unable to modify artifact")
            msg = PHANTOM_ERR_UPDATE_ARTIFACT.format(action_result.get_message())
            if not resp_label:
                msg = "{}. {}".format("The reason of the failure can be the unavailability of the label in the provided artifact", msg)
            return action_result.set_status(phantom.APP_ERROR, msg)

        action_result.set_summary({'tags_added': ', '.join((list(add_tags - tags_already_added))),
                                'tags_removed': ', '.join((list(remove_tags - tags_already_removed))),
                                'tags_already_present': ', '.join((list(tags_already_added))),
                                'tags_already_absent': ', '.join((list(tags_already_removed)))})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_note(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        phase_id = param.get('phase_id', None)

        ret_val, phase_id = self._validate_integer(action_result, phase_id, 'phase_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        container_id = param.get('container_id', self.get_container_id())
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = '/rest/note'

        note_data = {
            'container_id': container_id,
            'title': param.get('title', ''),
            'content': param.get('content', ''),
            'note_type': "general",
            'phase': phase_id
        }

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result, data=note_data, method="post")

        if phantom.is_fail(ret_val):
            self.save_progress('Unable to create note')
            return action_result.set_status(phantom.APP_ERROR, "Failed to create note: {}".format(action_result.get_message()))
        return action_result.set_status(phantom.APP_SUCCESS, "Note created")

    def _find_artifacts(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        limit_search = param.get("limit_search", False)
        container_ids = param.get("container_ids", "current")
        values = param.get('values', '')
        if limit_search:
            container_ids = list(
                set([
                    a for a in [
                        int(z) if isinstance(z, int) or z.isdigit() else None for z in [
                            self.get_container_id() if y == "current" else y for y in
                            [x.strip() for x in container_ids.replace(",", " ").split()]
                        ]
                    ] if a
                ])
            )
            action_result.update_param({"container_ids": str(sorted(container_ids)).strip("[]")})

        if limit_search and not container_ids:
            action_result.update_summary({'artifacts_found': 0, 'server': self._base_uri})
            return action_result.set_status(phantom.APP_SUCCESS)

        cef_key = param.get("cef_key")

        exact_match = param.get('exact_match', False)

        if exact_match and not cef_key:
            values = '"{}"'.format(values)

        url_enc_values = quote(values, safe='')

        if cef_key and exact_match:
            endpoint = '/rest/artifact?_filter_cef__{}={}&page_size=0&pretty'.format(quote(cef_key, safe=''), repr(url_enc_values))
        elif cef_key:
            endpoint = '/rest/artifact?_filter_cef__{}__{}={}&page_size=0&pretty'.format(quote(cef_key, safe=''),
                                                                                        "icontains", repr(url_enc_values))
        else:
            endpoint = '/rest/artifact?_filter_cef__{}={}&page_size=0&pretty'.format("icontains", repr(url_enc_values))

        if limit_search:
            endpoint += '&_filter_container__in={}'.format(container_ids)

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, 'Error retrieving records: {0}'.format(action_result.get_message()))

        records = resp_data['data']

        values = values.lower()

        for rec in records:
            key, value = None, None

            try:
                cef_dict_items = rec['cef'].iteritems()
            except Exception:
                cef_dict_items = rec['cef'].items()

            for k, v in cef_dict_items:

                curr_value = v

                try:
                    # if we convert this if/elif statement to if/else, then it will try to
                    # perform str() operation on even the already string/basestring data.
                    # This works for every situation except for the unicode characters for which it will fail.
                    # Hence, we are avoiding the str() on already string/basestring formatted data.
                    if isinstance(curr_value, dict):
                        curr_value = json.dumps(curr_value)
                    if not isinstance(curr_value, str):  # For python 3
                        curr_value = str(curr_value)
                except Exception as e:
                    self.debug_print('Error occurred while processing the artifacts data')
                    return action_result.set_status(phantom.APP_ERROR,
                            'Error occurred while processing the artifacts data: {}'.format(self._get_error_message_from_exception(e)))

                if values in curr_value.lower() or (exact_match and values.strip('"') == curr_value.lower()):
                    key = k
                    value = curr_value
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

        action_result.update_summary({'artifacts_found': len(records), 'server': self._base_uri})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_artifact(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param.get('name')
        container_id = param.get('container_id', self.get_container_id())
        sdi = param.get('source_data_identifier')
        label = param.get('label', 'event')
        contains = param.get('contains')
        cef_name = param.get('cef_name')
        cef_value = param.get('cef_value')
        cef_dict = param.get('cef_dictionary')
        run_automation = param.get('run_automation', False)

        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        loaded_cef = {}
        loaded_contains = {}

        if cef_dict:

            try:
                loaded_cef = json.loads(cef_dict)
                if not isinstance(loaded_cef, dict):
                    return action_result.set_status(phantom.APP_ERROR, "Please provide cef_dictionary parameter in JSON format")
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                                "Could not load JSON from CEF parameter: {}".format(self._get_error_message_from_exception(e)))

        if contains:
            try:
                loaded_contains = json.loads(contains)
                if isinstance(loaded_contains, list):
                    return action_result.set_status(phantom.APP_ERROR, "Please provide contains parameter in JSON or string format only")
                if not isinstance(loaded_contains, dict):
                    loaded_contains = {}
                    raise Exception
            except Exception:
                if cef_name and cef_value:
                    contains_list = [x.strip() for x in contains.split(",")]
                    contains_list = list(filter(None, contains_list))
                    loaded_contains[cef_name] = contains_list
                else:
                    self.debug_print("Please provide contains parameter in JSON format")
                    return action_result.set_status(phantom.APP_ERROR, "Please provide contains parameter in JSON format")

        if cef_name and cef_value:
            loaded_cef[cef_name] = cef_value

        artifact = {}
        artifact['name'] = name
        artifact['label'] = label
        artifact['container_id'] = container_id
        artifact['cef'] = loaded_cef
        artifact['cef_types'] = loaded_contains
        artifact['source_data_identifier'] = sdi
        artifact['run_automation'] = run_automation

        for cef_name in loaded_cef:

            if loaded_contains.get(cef_name):
                continue

            if cef_name not in CEF_NAME_MAPPING:
                determined_contains = determine_contains(loaded_cef[cef_name]) if loaded_cef[cef_name] else None
                if determined_contains:
                    artifact['cef_types'][cef_name] = determined_contains
            else:
                try:
                    artifact['cef_types'][cef_name] = CEF_JSON[cef_name]['contains']
                except Exception:
                    pass

        success, response, resp_data = self._make_rest_call('/rest/artifact', action_result, method='post', data=artifact)

        if not resp_data:
            return action_result.get_status()

        if phantom.is_fail(success):
            artifact_id = resp_data.get('existing_artifact_id')
            if not artifact_id:
                return action_result.get_status()
        else:
            artifact_id = resp_data.get('id')

        action_result.add_data(resp_data)

        action_result.update_summary({'artifact_id': artifact_id, 'container_id': container_id, 'server': self._base_uri})
        self.debug_print("Successfully executed the action")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_file_to_vault(self, action_result, data_stream, file_name, recursive, container_id):

        save_as = file_name or '_invalid_file_name_'

        # PAPP-9543 append a random string to the filename to make concurrent action runs succeed
        random_suffix = '_{}'.format(''.join(random.SystemRandom().choice(string.ascii_lowercase) for _ in range(16)))
        save_as = '{0}{1}'.format(save_as, random_suffix)

        # if the path contains a directory
        if os.path.dirname(save_as):
            save_as = '-'.join(save_as.split(os.sep))

        if hasattr(Vault, 'get_vault_tmp_dir'):
            vault_tmp_dir = Vault.get_vault_tmp_dir()
        else:
            vault_tmp_dir = '/opt/phantom/vault/tmp'

        try:
            save_path = os.path.join(vault_tmp_dir, save_as)
            with open(save_path, 'wb') as uncompressed_file:
                uncompressed_file.write(data_stream)
        except IOError as e:
            error_message = self._get_error_message_from_exception(e)
            try:
                if "File name too long" in error_message:
                    new_file_name = "ph_long_file_name_{}{}".format(self._level, random_suffix)
                    save_path = os.path.join(vault_tmp_dir, new_file_name)
                    self.debug_print("Original filename: {}".format(file_name))
                    self.debug_print("Modified filename: {}".format(new_file_name))
                    with open(save_path, 'wb') as uncompressed_file:
                        uncompressed_file.write(data_stream)
                else:
                    return (action_result.set_status(phantom.APP_ERROR, "Error occurred while adding file to Vault. Error Details:{}".format(
                        self._get_error_message_from_exception(e))))
            except Exception as e:
                return (action_result.set_status(phantom.APP_ERROR, "Error occurred while adding file to Vault. Error Details:{}".format(
                    self._get_error_message_from_exception(e))))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                            "Error occurred while adding file to Vault. Error Details:{}".format(self._get_error_message_from_exception(e)))

        try:
            success, message, vault_id = ph_rules.vault_add(container=container_id, file_location=save_path, file_name=file_name)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                        "Failed to add file into vault: {}".format(self._get_error_message_from_exception(e)))

        if not success:
            return action_result.set_status(phantom.APP_ERROR, "Failed to add file into vault: {0}".format(message))

        try:
            success, message, resp_data = ph_rules.vault_info(vault_id=vault_id.lower())

            if not success:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_VAULT_INFO.format(message))

            for resp_element in resp_data:
                resp_filename = resp_element['name']

                if file_name == resp_filename:
                    vault_info = resp_element
                    break

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                            "Failed to retrieve info about file added to vault {}".format(self._get_error_message_from_exception(e)))

        action_result.add_data(vault_info)

        if recursive:

            file_path = vault_info['path']

            file_name = vault_info['name']

            file_type, is_supported = self.is_deflation_supported_file(file_path)

            if not is_supported:
                return (phantom.APP_SUCCESS)

            self._extract_file(action_result, file_path, file_name, recursive, container_id)
            self._level -= 1

        return (phantom.APP_SUCCESS)

    @staticmethod
    def _has_allowed_archive_extension(file_name, allowed_extensions):
        if allowed_extensions:
            allowed_extension_suffixes = set(allowed_extensions.split(','))
            file_extension = Path(file_name).suffix.lstrip('.')
            if file_extension not in allowed_extension_suffixes:
                return False

        return True

    def _extract_file(self, action_result, file_path, file_name, recursive, container_id=None, password=None):

        self._level += 1
        if container_id is None:
            container_id = self.get_container_id()

        file_type, is_supported = self.is_deflation_supported_file(file_path)

        if not is_supported:
            return action_result.set_status(phantom.APP_ERROR, "Deflation of file type: {0} not supported".format(file_type))

        config = self.get_config()
        allowed_extensions = config.get('deflate_item_extensions', '')
        if not self._has_allowed_archive_extension(file_name, allowed_extensions):
            self.debug_print(f'Skipping extraction of {file_name} since it is not in the allowed extensions list: {allowed_extensions}')
            return phantom.APP_SUCCESS

        data = None
        if file_type == 'application/x-bzip2':
            # gz and bz2 don't provide a nice way to test, so trial and error
            try:
                with bz2.BZ2File(file_path, 'r') as f:
                    data = f.read()
            except IOError:
                return action_result.set_status(phantom.APP_ERROR, "Unable to deflate bz2 file")

            if data is None:
                return phantom.APP_SUCCESS

            ret_val = self._add_file_to_vault(action_result, data, os.path.splitext(file_name)[0], recursive, container_id)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_DECOMPRESSING_FILE.format(file_type, action_result.get_message()))

        elif file_type == 'application/x-gzip' or file_type == 'application/gzip':
            try:
                with gzip.GzipFile(file_path, 'r') as f:
                    data = f.read()
            except IOError:
                return action_result.set_status(phantom.APP_ERROR, "Unable to deflate gzip file")

            if data is None:
                return phantom.APP_SUCCESS

            ret_val = self._add_file_to_vault(action_result, data, os.path.splitext(file_name)[0], recursive, container_id)

            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_DECOMPRESSING_FILE.format(file_type, action_result.get_message()))

        elif file_type == 'application/zip':
            if not zipfile.is_zipfile(file_path):
                return action_result.set_status(phantom.APP_ERROR, "Unable to deflate zip file")

            try:
                compressed_file = ''
                with zipfile.ZipFile(file_path, 'r') as vault_file:
                    if password:
                        vault_file.setpassword(password.encode())

                    archived_files = vault_file.namelist()

                    for compressed_file in archived_files:

                        save_as = os.path.basename(compressed_file)

                        if not os.path.basename(save_as):
                            continue

                        ret_val = self._add_file_to_vault(action_result, vault_file.read(compressed_file), save_as,
                                                          recursive, container_id)

                        if phantom.is_fail(ret_val):
                            return ret_val
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                error_message = error_message.replace(compressed_file, file_name)
                return action_result.set_status(phantom.APP_ERROR, "Unable to open the zip file: {}. {}".format(file_path, error_message))

            return (phantom.APP_SUCCESS)

        # a tgz is also a tar file, so first extract it and add it to the vault
        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path, 'r') as vault_file:

                for member in vault_file.getmembers():

                    # Only interested in files, pass on dirs, links, etc.
                    if not member.isfile():
                        continue

                    ret_val = self._add_file_to_vault(action_result, vault_file.extractfile(member).read(),
                                                    os.path.basename(member.name), recursive, container_id)

                    if phantom.is_fail(ret_val):
                        return action_result.set_status(phantom.APP_ERROR, "Error decompressing tar file.")

            return (phantom.APP_SUCCESS)

        return action_result.set_status(phantom.APP_SUCCESS)

    @staticmethod
    def is_deflation_supported_file(file_path) -> Tuple[str, bool]:
        """
        Checks if the file is supported for deflation.

        This method patches invalid behavior of some Operating
        Systems recognizing MS Office files (eg. xslx) as zip
        files which lead to an enormous deflation process run
        hanging the service.
        """
        msooxml_magic_file_path = os.path.join(pathlib.Path(__file__).parent.resolve(), "magic", "msooxml")
        m = magic.Magic(mime=True, magic_file=msooxml_magic_file_path)
        file_type = m.from_file(file_path)

        if file_type not in OPEN_XML_FORMATS:
            # fallback to the default magic definitions
            file_type = magic.from_file(file_path, mime=True)

        return file_type, file_type in SUPPORTED_FILES

    def _deflate_item(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param['vault_id']

        container_id = param.get('container_id')
        password = param.get('password')
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            success, message, vault_info = ph_rules.vault_info(vault_id=vault_id)

            if not success:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_GET_VAULT_INFO.format(message))

            vault_info = list(vault_info)[0]

            file_path = vault_info['path']
            file_name = vault_info['name']
        except IndexError:
            return action_result.set_status(phantom.APP_ERROR,
                                "Error occurred while accessing the vault ID. Please verify the provided vault ID in the action parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                "Failed to get vault item info: {}".format(self._get_error_message_from_exception(e)))

        try:
            file_type, is_supported = self.is_deflation_supported_file(file_path)
        except IOError:
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_FILE_PATH_NOT_FOUND)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_FILE_PATH_NOT_FOUND)

        if not is_supported:
            return action_result.set_status(phantom.APP_ERROR, "Deflation of file type: {0} not supported".format(file_type))

        ret_val = self._extract_file(action_result, file_path, file_name, param.get('recursive', False),
                                     container_id, password=password)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        summary['total_vault_items'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _find_listitem(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        values = param.get('values')
        list_name = param['list']
        exact_match = param.get('exact_match', False)
        column_index = param.get('column_index')

        ret_val, column_index = self._validate_integer(action_result, column_index, 'column_index', True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Encode list_name to consider special url encoded characters like '\' in URL
        list_name = quote(list_name, safe='')

        endpoint = '/rest/decided_list/{}'.format(list_name)

        ret_val, response, resp_data = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        j = resp_data
        list_id = j['id']
        content = j.get('content')  # pylint: disable=E1101
        coordinates = []
        found = 0
        for rownum, row in enumerate(content):
            for cid, value in enumerate(row):
                if column_index is None or cid == column_index:
                    if exact_match and value == values:
                        found += 1
                        action_result.add_data(row)
                        coordinates.append((rownum, cid))
                    elif not exact_match and value and values in value:
                        found += 1
                        action_result.add_data(row)
                        coordinates.append((rownum, cid))

        action_result.update_summary({'server': self._base_uri, 'found_matches': found, 'locations': coordinates, 'list_id': list_id})
        self.debug_print("Successfully executed the action")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_list(self, list_name, row, action_result):

        try:
            if type(row) in (str, int, float, bool):
                row = [row]
        except Exception:
            if type(row) in (str, int, float, bool):
                row = [row]

        payload = {
            'content': [row],
            'name': list_name,
        }

        ret_val, response, resp_data = self._make_rest_call('/rest/decided_list', action_result, method='post', data=payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_data)

        action_result.update_summary({'server': self._base_uri})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_listitem(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        list_name = param['list']

        row = param.get('new_row')

        try:
            row = ast.literal_eval(row)
        except Exception:
            # it's just a string
            pass

        # Encode list_name to consider special url encoded characters like '\' in URL

        url_enc_list_name = quote(list_name, safe='')

        url = '/rest/decided_list/{}'.format(url_enc_list_name)

        payload = {
            'append_rows': [
                row,
            ]
        }

        ret_val, response, resp_data = self._make_rest_call(url, action_result, method='post', data=payload)

        if phantom.is_fail(ret_val):
            if response is not None and response.status_code == 404:
                if param.get('create', False):
                    self.save_progress('List "{}" not found, creating'.format(list_name))
                    return self._create_list(list_name, row, action_result)
            return action_result.set_status(phantom.APP_ERROR, 'Error appending to list: {0}'.format(action_result.get_message()))

        action_result.add_data(resp_data)
        action_result.update_summary({'server': self._base_uri})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_artifact_list(self, action_result, artifacts, ignore_auth=False):
        """ Add a list of artifacts """
        ret_val, response, resp_data = self._make_rest_call('/rest/artifact', action_result,
                                        method='post', data=artifacts, ignore_auth=ignore_auth)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Error adding artifact: {}".format(action_result.get_message()))
        failed = 0
        for resp in resp_data:  # is a list
            if resp.get('failed') is True:
                self.debug_print(resp.get('message'))
                failed += 1
        if failed:
            action_result.update_summary({'failed_artifact_count': failed})
            return action_result.set_status(phantom.APP_ERROR, "Failed to add one or more artifacts")
        return phantom.APP_SUCCESS

    def _create_container_copy(self, action_result, container_id, destination, source, source_local=False,
                               destination_local=False, keep_owner=False, run_automation=True, label=None):
        """ destination: where new container is being made """
        """ source: where the original container is """
        """ Create a copy of this existing container, including all of its artifacts """

        # Retrieve original container
        self._base_uri = source
        url = '/rest/container/{}'.format(container_id)

        ret_val, response, resp_data = self._make_rest_call(url, action_result, ignore_auth=source_local)

        if phantom.is_fail(ret_val):
            return ret_val

        container = resp_data
        # Remove data from original we dont want
        container.pop('asset', None)
        container.pop('artifact_count', None)
        container.pop('start_time', None)
        container.pop('source_data_identifier', None)
        container.pop('ingest_app')
        container.pop('tenant')
        container.pop('id')
        if label:
            container['label'] = label
        if keep_owner:
            container['owner_id'] = container.pop('owner')
        else:
            container.pop('owner')

        if destination_local:
            container['asset_id'] = int(self.get_asset_id())
        # container['ingest_app_id'] = container.pop('ingest_app', None)

        self._base_uri = destination
        ret_val, response, resp_data = self._make_rest_call('/rest/container', action_result,
                                method='post', data=container, ignore_auth=destination_local)

        if phantom.is_fail(ret_val):

            act_message = action_result.get_message()

            if 'ingesting asset_id' in act_message:
                act_message += 'If Multi-tenancy is enabled, please make sure the asset is assigned a tenant'
                action_result.set_status(ret_val, act_message)

            elif '"owner_id" Not found' in act_message:
                act_message += '. Try setting the keep_owner parameter to false.'
                action_result.set_status(ret_val, act_message)

            return ret_val

        try:
            new_container_id = resp_data['id']
        except KeyError:
            # The newly created container wont get cleaned up
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_UNABLE_RETRIEVE_ID)

        # Retrieve artifacts from old container
        url = '/rest/container/{}/artifacts'.format(container_id)
        params = {'sort': 'id', 'order': 'asc', 'page_size': 0}
        self._base_uri = source
        ret_val, response, resp_data = self._make_rest_call(url, action_result, params=params, ignore_auth=source_local)

        artifacts = resp_data['data']
        if artifacts:
            for artifact in artifacts:
                # Remove data from artifacts that we dont want
                artifact.pop('update_time', None)
                artifact.pop('create_time', None)
                artifact.pop('start_time', None)
                artifact.pop('end_time', None)
                artifact.pop('asset_id', None)
                artifact.pop('container', None)
                artifact.pop('id', None)
                artifact['run_automation'] = False
                artifact['container_id'] = new_container_id
                artifact['owner_id'] = artifact.pop('owner')
            artifacts[-1]['run_automation'] = run_automation

            self._base_uri = destination
            ret_val = self._add_artifact_list(action_result, artifacts, ignore_auth=destination_local)
            if phantom.is_fail(ret_val):
                return action_result.set_status(ret_val, "Container created:{0}. {1}".format(new_container_id, action_result.get_message()))

        action_result.update_summary({'container_id': new_container_id, 'artifact_count': len(artifacts)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_container_new(self, action_result, container_json, artifact_json_list):
        try:
            container = json.loads(container_json)
            if not isinstance(container, dict):
                return action_result.set_status(phantom.APP_ERROR, "Please provide json formatted dictionary in container_json action parameter")

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                    "Error parsing container JSON: {}".format(self._get_error_message_from_exception(e)))

        if artifact_json_list:
            try:
                artifacts = json.loads(artifact_json_list)
                if not isinstance(artifacts, list):
                    return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_CONTAINER_ARTIFACT)
                else:
                    for artifact in artifacts:
                        if not isinstance(artifact, dict):
                            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_CONTAINER_ARTIFACT)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR,
                                "Error parsing artifacts list JSON: {}".format(self._get_error_message_from_exception(e)))
        else:
            artifacts = []

        ret_val, response, resp_data = self._make_rest_call('/rest/container', action_result, method='post', data=container)
        if phantom.is_fail(ret_val):
            return ret_val

        try:
            new_container_id = resp_data['id']
        except KeyError:
            # The newly created container wont get cleaned up
            return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_UNABLE_RETRIEVE_ID)

        if artifacts:
            for artifact in artifacts:
                artifact['run_automation'] = False
                artifact['container_id'] = new_container_id
            artifacts[-1]['run_automation'] = True

            ret_val = self._add_artifact_list(action_result, artifacts)
            if phantom.is_fail(ret_val):
                return action_result.set_status(ret_val, "Container created:{0}. {1}".format(new_container_id, action_result.get_message()))

        action_result.update_summary({'container_id': new_container_id, 'artifact_count': len(artifacts)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_container(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_json = param['container_json']
        container_artifacts = param.get('container_artifacts')
        return self._create_container_new(action_result, container_json, container_artifacts)

    def _export_container(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        label = param.get('label')
        run_automation = param.get('run_automation', False)

        container_id = param.get('container_id')
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        destination = self._base_uri
        source = self.get_phantom_base_url()

        return self._create_container_copy(action_result, container_id, destination,
                    source, source_local=True, keep_owner=param.get('keep_owner', False),
                    run_automation=run_automation, label=label)

    def _import_container(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param.get('container_id')
        ret_val, container_id = self._validate_integer(action_result, container_id, 'container_id')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        destination = self.get_phantom_base_url()
        source = self._base_uri

        return self._create_container_copy(action_result, container_id, destination,
                source, destination_local=True, keep_owner=param.get('keep_owner', False))

    def _get_action(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        url_params = {
                '_filter_action': '"{0}"'.format(param['action_name']),
                'include_expensive': '',
                'sort': 'start_time',
                'order': 'desc',
            }

        parameters = {}
        if 'parameters' in param:

            try:
                parameters = json.loads(param.get('parameters'))
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Could not load JSON from 'parameters' parameter")

            search_key, search_value = parameters.popitem()

            try:
                is_not_string = isinstance(search_value, (float, int, bool))
                formatted_search_value = json.dumps(search_value) if is_not_string else '\\"{}\\"'.format(search_value)
                url_params['_filter_result_data__regex'] = '\'parameter.*\\"{0}\\": {1}\''.format(search_key, formatted_search_value)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while creating filter string to search action results data")

        if 'time_limit' in param:
            hours = param.get('time_limit')
            ret_val, hours = self._validate_integer(action_result, hours, 'time_limit')
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            time_str = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            url_params['_filter_start_time__gt'] = '"{0}"'.format(time_str)

        if 'max_results' in param:
            limit = param.get('max_results')
            ret_val, limit = self._validate_integer(action_result, limit, 'max_results')
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            url_params['page_size'] = limit

        if 'app' in param:

            app_name = param.get('app')
            app_params = {'_filter_name__iexact': '"{0}"'.format(app_name)}
            ret_val, response, resp_json = self._make_rest_call('/rest/app', action_result, params=app_params)

            if phantom.is_fail(ret_val):
                return ret_val

            if resp_json['count'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Could not find app with name '{0}'".format(app_name))

            url_params['_filter_app'] = resp_json['data'][0]['id']

        if 'asset' in param:

            asset = param.get('asset')
            asset_params = {'_filter_name__iexact': '"{0}"'.format(asset)}
            ret_val, response, resp_json = self._make_rest_call('/rest/asset', action_result, params=asset_params)

            if phantom.is_fail(ret_val):
                return ret_val

            if resp_json['count'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Could not find asset with name '{0}'".format(asset))

            url_params['_filter_asset'] = resp_json['data'][0]['id']

        ret_val, response, resp_json = self._make_rest_call('/rest/app_run', action_result, params=url_params)

        if phantom.is_fail(ret_val):
            return ret_val

        count = 0
        if len(parameters) > 0:

            for action_run in resp_json['data']:

                for result in action_run['result_data']:

                    cur_params = result['parameter']

                    found = True

                    try:
                        parameters_items = parameters.iteritems()
                    except Exception:
                        parameters_items = parameters.items()

                    for k, v in parameters_items:
                        if cur_params.get(k) != v:
                            found = False
                            break

                    if found:
                        count += 1
                        action_result.add_data(action_run)

            if count == 0:
                return action_result.set_status(phantom.APP_SUCCESS, PHANTOM_ERR_ACTION_RESULT_NOT_FOUND)
            else:
                action_result.set_summary({'num_results': count})
                return action_result.set_status(phantom.APP_SUCCESS)

        elif resp_json['count'] == 0:
            return action_result.set_status(phantom.APP_SUCCESS, PHANTOM_ERR_ACTION_RESULT_NOT_FOUND)

        for action_run in resp_json['data']:
            action_result.add_data(action_run)

        action_result.set_summary({'num_results': len(resp_json['data'])})
        self.debug_print("Successfully executed the action.")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_list(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        row_number = param.get('row_number')
        ret_val, row_number = self._validate_integer(action_result, row_number, 'row_number', True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        row_values_as_list = param['row_values_as_list']

        list_name = param.get('list_name')
        list_id = param.get('id')

        if not list_name and not list_id:
            return action_result.set_status(phantom.APP_ERROR, "Either the custom list's name or id must be provided")

        if list_name:
            # Encode list_identifier to consider special url encoded characters like '\' in URL
            list_identifier = quote(list_name, safe='')
        else:
            ret_val, list_identifier = self._validate_integer(action_result, list_id, 'id')
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        try:
            row_values = json.loads(row_values_as_list)
            if not isinstance(row_values, list):
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_NON_EMPTY_PARAM_VALUE)
            if not row_values:
                return action_result.set_status(phantom.APP_ERROR, PHANTOM_ERR_NON_EMPTY_PARAM_VALUE)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                "Could not load JSON formatted list from the row_values_as_list parameter: {}".format(
                    self._get_error_message_from_exception(e)))

        data = {
            "update_rows": {
                str(row_number): row_values
            }
        }

        # make rest call
        ret_val, response, resp_data = self._make_rest_call('/rest/decided_list/{}'.format(list_identifier),
                                        action_result, data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(resp_data)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['success'] = True
        self.debug_print("Successfully executed the action.")
        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _no_op(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        sleep_seconds = param.get('sleep_seconds')
        ret_val, sleep_seconds = self._validate_integer(action_result, sleep_seconds, 'sleep_seconds', True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        remainder = sleep_seconds % 60

        self.send_progress("Sleeping...")
        for i in range(0, int(sleep_seconds / 60)):
            time.sleep(60)
            self.send_progress("Slept for {} minute{}...", i + 1, 's' if i else '')

        if remainder:
            time.sleep(remainder)

        return action_result.set_status(phantom.APP_SUCCESS, "Slept for {} seconds".format(sleep_seconds))

    def initialize(self):

        # Validate that it is not localhost or 127.0.0.1,
        # this needs to be done just once, so do it here instead of handle_action,
        # since handle_action gets called for every item in the parameters list

        config = self.get_config()

        host = config['phantom_server']

        if host.startswith('http:') or host.startswith('https:'):
            return self.set_status(phantom.APP_ERROR,
                    'Please specify the actual IP or hostname used by the Phantom instance in the Asset config wihtout http: or https:')

        # Split hostname from port
        host = host.split(':')[0]

        if ph_utils.is_ip(host):
            try:
                packed = socket.inet_aton(host)
                unpacked = socket.inet_ntoa(packed)
            except Exception as e:
                return self.set_status(phantom.APP_ERROR,
                            "Unable to do ip to name conversion on {0}".format(host), self._get_error_message_from_exception(e))
        else:
            try:
                unpacked = socket.gethostbyname(host)
            except Exception:
                return self.set_status(phantom.APP_ERROR, "Unable to do name to ip conversion on {0}".format(host))

        if unpacked.startswith('127.'):
            return self.set_status(phantom.APP_ERROR, PHANTOM_ERR_SPECIFY_IP_HOSTNAME)

        if '127.0.0.1' in host or 'localhost' in host:
            return self.set_status(phantom.APP_ERROR, PHANTOM_ERR_SPECIFY_IP_HOSTNAME)

        self._base_uri = 'https://{}'.format(config['phantom_server'])
        self._verify_cert = config.get('verify_certificate', False)

        self._auth = None

        if config.get('username') and config.get('password'):
            self._auth = (config.get('username'), config.get('password'))

        self._level = 0

        return (phantom.APP_SUCCESS)

    def handle_action(self, param):
        """Function that handles all the actions

        Args:

        Return:
            A status code
        """

        result = None
        action = self.get_action_identifier()

        if action == 'find_artifacts':
            result = self._find_artifacts(param)
        elif action == 'add_artifact':
            result = self._add_artifact(param)
        elif action == 'add_listitem':
            result = self._add_listitem(param)
        elif action == 'find_listitem':
            result = self._find_listitem(param)
        elif action == 'deflate_item':
            result = self._deflate_item(param)
        elif action == 'test_asset_connectivity':
            result = self._test_connectivity(param)
        elif action == 'create_container':
            result = self._create_container(param)
        elif action == 'export_container':
            result = self._export_container(param)
        elif action == 'import_container':
            result = self._import_container(param)
        elif action == 'get_action':
            result = self._get_action(param)
        elif action == 'update_list':
            result = self._update_list(param)
        elif action == 'no_op':
            return self._no_op(param)
        elif action == "update_artifact":
            return self._update_artifact(param)
        elif action == "add_note":
            return self._add_note(param)
        elif action == "tag_artifact":
            return self._tag_artifact(param)

        return result


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            login_url = '{}login'.format(BaseConnector._get_phantom_base_url())
            r = requests.get(login_url, verify=verify, timeout=TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: {}".format(str(e)))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PhantomConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
