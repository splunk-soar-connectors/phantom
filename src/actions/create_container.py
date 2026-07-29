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

import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import PHANTOM_ERR_CONTAINER_ARTIFACT, PHANTOM_ERR_UNABLE_RETRIEVE_ID
from ..helper import PhantomClient, PhantomClientError


class CreateContainerParams(Params):
    container_json: str = Param(description="JSON string of the container", required=True)
    container_artifacts: str = Param(
        description="List of artifact objects in JSON format", required=False
    )


class CreateContainerSummary(ActionOutput):
    container_id: int = OutputField(column_name="New Container")
    artifact_count: int


def _add_artifact_list(client: PhantomClient, artifacts: list, ignore_auth: bool = False) -> None:
    _response, resp_data = client.make_rest_call(
        "/rest/artifact", data=artifacts, method="post", ignore_auth=ignore_auth
    )
    failed = sum(1 for resp in resp_data if resp.get("failed") is True)
    if failed:
        raise PhantomClientError("Failed to add one or more artifacts")


@app.action(
    name="create container",
    identifier="create_container",
    description="Create a new container",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=CreateContainerSummary,
)
def create_container(params: CreateContainerParams, soar: SOARClient, asset: Asset) -> ActionOutput:
    client = get_client(asset)

    try:
        container = json.loads(params.container_json)
        if not isinstance(container, dict):
            raise PhantomClientError("Please provide json formatted dictionary in container_json action parameter")
    except json.JSONDecodeError as e:
        raise PhantomClientError(f"Error parsing container JSON: {e}") from e

    if params.container_artifacts:
        try:
            artifacts = json.loads(params.container_artifacts)
        except json.JSONDecodeError as e:
            raise PhantomClientError(f"Error parsing artifacts list JSON: {e}") from e
        if not isinstance(artifacts, list) or any(not isinstance(a, dict) for a in artifacts):
            raise PhantomClientError(PHANTOM_ERR_CONTAINER_ARTIFACT)
    else:
        artifacts = []

    _response, resp_data = client.make_rest_call("/rest/container", data=container, method="post")

    try:
        new_container_id = resp_data["id"]
    except KeyError as e:
        raise PhantomClientError(PHANTOM_ERR_UNABLE_RETRIEVE_ID) from e

    if artifacts:
        for artifact in artifacts:
            artifact["run_automation"] = False
            artifact["container_id"] = new_container_id
        artifacts[-1]["run_automation"] = True
        _add_artifact_list(client, artifacts)

    soar.set_summary(CreateContainerSummary(container_id=new_container_id, artifact_count=len(artifacts)))
    soar.set_message(f"Container id: {new_container_id}")
    return ActionOutput()
