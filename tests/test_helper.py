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

from unittest.mock import MagicMock

from src.helper import create_container_copy


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
