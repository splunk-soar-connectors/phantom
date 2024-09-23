# File: phantom_consts.py
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
TIMEOUT = 120
INVALID_RESPONSE = 'Server did not return a valid JSON response.'

OPEN_XML_FORMATS = [
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-visio.drawing.main+xml",
    "application/x-silverlight-app",
]

# list of file types supported for deflation
SUPPORTED_FILES = ['application/zip', 'application/x-gzip', 'application/x-tar', 'application/x-bzip2', 'application/gzip']

# Consts for error messages
PHANTOM_ERR_INVALID_INT = "Please provide a valid {msg} integer value in the '{param}' action parameter"
PHANTOM_ERR_CODE_UNAVAILABLE = "Error code unavailable"
PHANTOM_ERR_MSG_UNAVAILABLE = "Unknown error occurred. Please check the asset configuration and|or action parameters."
PHANTOM_ERR_PARSE_JSON_RESPONSE = "Unable to parse response as JSON: {}"
PHANTOM_ERR_SERVER = "Error from server. Status code: {0}, Details: {1}"
PHANTOM_ERR_FIND_ARTIFACT = "Unable to find artifact, please check the artifact id."
PHANTOM_ERR_GET_ARTIFACT = "Failed to get artifact: {}"
PHANTOM_ERR_UPDATE_ARTIFACT = "Failed to update artifact: {}"
PHANTOM_ERR_DECOMPRESSING_FILE = "Error decompressing {0} file. Details: {1}"
PHANTOM_ERR_FILE_PATH_NOT_FOUND = "File path not found. Please check that the asset is pointing to the current(self) Phantom instance."
PHANTOM_ERR_CONTAINER_ARTIFACT = "Please provide container_artifacts as a list of artifact objects in JSON format"
PHANTOM_ERR_UNABLE_RETRIEVE_ID = "Unable to retrieve ID of newly created container"
PHANTOM_ERR_ACTION_RESULT_NOT_FOUND = "No action results found matching given criteria"
PHANTOM_ERR_NON_EMPTY_PARAM_VALUE = "Please provide row_values_as_list parameter as a non-empty JSON formatted list"
PHANTOM_ERR_SPECIFY_IP_HOSTNAME = ("Accessing 127.0.0.1 is not allowed."
" Please specify the actual IP or hostname used by the Phantom instance in the Asset config")
PHANTOM_ERR_GET_VAULT_INFO = "Failed to get the vault info: {}"

ARTIFACT_DEFAULT_MAX_RESULTS = 10
ARTIFACT_DEFAULT_PAGE = 0