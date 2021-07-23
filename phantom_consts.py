# File: phantom_consts.py
# Copyright (c) 2016-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# --

TIMEOUT = 120
INVALID_RESPONSE = 'Server did not return a valid JSON response.'
SUPPORTED_FILES = ['application/zip', 'application/x-gzip', 'application/x-tar', 'application/x-bzip2']

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
PHANTOM_ERR_SPECIFY_IP_HOSTNAME = "Accessing 127.0.0.1 is not allowed. Please specify the actual IP or hostname used by the Phantom instance in the Asset config"
