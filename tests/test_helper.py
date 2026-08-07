# Copyright (c) 2016-2026 Splunk Inc.
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

from unittest.mock import MagicMock, patch

from src.consts import TIMEOUT
from src.helper import PhantomClient, create_container_copy


def test_create_container_copy_import_posts_container_and_artifacts_to_destination():
    """Regression test for importing a container from a remote asset.

    destination (the local SOAR URL) differs from client.base_uri (the remote
    asset). Both the container POST and the artifact POST must target
    destination, not fall back to the remote client.base_uri.
    """
    client = MagicMock()
    client.base_uri = "https://remote-asset"
    client.make_rest_call.side_effect = [
        (MagicMock(), {"artifact_count": 1, "id": 7}),  # GET source container
        (MagicMock(), {"id": 42}),  # POST container to destination
        (MagicMock(), {"data": [{"id": 1, "name": "art"}]}),  # GET source artifacts
        (MagicMock(), [{"id": 1}]),  # POST artifacts to destination
    ]
    soar = MagicMock()

    destination = "https://local-soar"
    source = "https://remote-asset"

    new_container_id, artifact_count = create_container_copy(
        client, soar, 7, destination, source, destination_local=True
    )

    assert new_container_id == 42
    assert artifact_count == 1

    container_post_call = client.make_rest_call.call_args_list[1]
    artifact_post_call = client.make_rest_call.call_args_list[3]

    assert container_post_call.kwargs["base_uri"] == destination
    assert artifact_post_call.kwargs["base_uri"] == destination


def test_make_rest_call_threads_timeout_and_verify_cert_overrides():
    """Regression test for make_request: per-call timeout/verify_ssl parameters
    must reach requests.request instead of being silently dropped in favor of
    the asset-level default timeout and verify_certificate setting.
    """
    client = PhantomClient.__new__(PhantomClient)
    client.base_uri = "https://remote-asset"
    client.verify_cert = True
    client.auth = None
    client.auth_token = None

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.text = "{}"
    mock_response.json.return_value = {}

    with patch(
        "src.helper.requests.request", return_value=mock_response
    ) as mock_request:
        client.make_rest_call("/rest/version", timeout=5, verify_cert=False)

    assert mock_request.call_args.kwargs["timeout"] == 5
    assert mock_request.call_args.kwargs["verify"] is False


def test_make_rest_call_defaults_timeout_and_verify_cert_when_not_overridden():
    """Without explicit overrides, make_rest_call must keep using the global
    TIMEOUT constant and the asset's verify_certificate setting.
    """
    client = PhantomClient.__new__(PhantomClient)
    client.base_uri = "https://remote-asset"
    client.verify_cert = True
    client.auth = None
    client.auth_token = None

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/json"}
    mock_response.text = "{}"
    mock_response.json.return_value = {}

    with patch(
        "src.helper.requests.request", return_value=mock_response
    ) as mock_request:
        client.make_rest_call("/rest/version")

    assert mock_request.call_args.kwargs["timeout"] == TIMEOUT
    assert mock_request.call_args.kwargs["verify"] is True
