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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..helper import CEF_JSON, CEF_NAME_MAPPING, PhantomClientError, determine_contains, validate_integer


class AddArtifactParams(Params):
    name: str = Param(description="Name of artifact", required=False, default="User created artifact")
    container_id: int = Param(
        description="Container to add the artifact to", required=False, cef_types=["phantom container id"]
    )
    label: str = Param(description="Artifact label", required=False, default="event")
    source_data_identifier: str = Param(description="Source data identifier", required=True)
    cef_name: str = Param(description="Name of a CEF field", required=False)
    cef_value: str = Param(description="Value for the CEF field", required=False, cef_types=["*"])
    cef_dictionary: str = Param(description="JSON string of CEF fields and values", required=False)
    contains: str = Param(description="Data type for the CEF field", required=False)
    run_automation: bool = Param(description="Run active playbooks", required=False, default=False)
    determine_contains: bool = Param(description="Determine the contains for the CEF fields", required=False, default=True)


class AddArtifactOutput(PermissiveActionOutput):
    id: int | None = None
    success: bool | None = None
    failed: bool | None = None
    existing_artifact_id: int | None = None


class AddArtifactSummary(ActionOutput):
    artifact_id: int
    container_id: int = OutputField(cef_types=["phantom container id"])
    server: str = OutputField(cef_types=["url"])


@app.view_handler(template="phantom_add_artifact.html")
def add_artifact_view(outputs: list[AddArtifactOutput]) -> dict:
    headers = ["Artifact ID", "Container ID"]
    data = [o.model_dump() for o in outputs]
    return {"results": [{"data": data}], "headers": headers}


@app.action(
    name="add artifact",
    identifier="add_artifact",
    description="Add an artifact to a container",
    action_type="generic",
    read_only=False,
    view_handler=add_artifact_view,
    summary_type=AddArtifactSummary,
)
def add_artifact(params: AddArtifactParams, soar: SOARClient, asset: Asset) -> list[AddArtifactOutput]:
    client = get_client(asset)

    container_id = params.container_id
    if container_id is None:
        container_id = soar.get_executing_container_id()
    container_id = validate_integer(container_id, "container_id")

    loaded_cef: dict = {}
    loaded_contains: dict = {}

    if params.cef_dictionary:
        try:
            loaded_cef = json.loads(params.cef_dictionary)
            if not isinstance(loaded_cef, dict):
                raise PhantomClientError("Please provide cef_dictionary parameter in JSON format")
        except json.JSONDecodeError as e:
            raise PhantomClientError(f"Could not load JSON from CEF parameter: {e}") from e

    if params.contains:
        try:
            loaded_contains = json.loads(params.contains)
            if isinstance(loaded_contains, list):
                raise PhantomClientError("Please provide contains parameter in JSON or string format only")
            if not isinstance(loaded_contains, dict):
                loaded_contains = {}
                raise ValueError
        except PhantomClientError:
            raise
        except Exception as e:
            if params.cef_name and params.cef_value:
                contains_list = list(filter(None, [x.strip() for x in params.contains.split(",")]))
                loaded_contains[params.cef_name] = contains_list
            else:
                raise PhantomClientError("Please provide contains parameter in JSON format") from e

    if params.cef_name and params.cef_value:
        loaded_cef[params.cef_name] = params.cef_value

    artifact = {
        "name": params.name,
        "label": params.label,
        "container_id": container_id,
        "cef": loaded_cef,
        "cef_types": loaded_contains,
        "source_data_identifier": params.source_data_identifier,
        "run_automation": params.run_automation,
    }

    if params.determine_contains:
        for cef_name in loaded_cef:
            if loaded_contains.get(cef_name):
                continue
            if cef_name not in CEF_NAME_MAPPING:
                determined = determine_contains(loaded_cef[cef_name]) if loaded_cef[cef_name] else None
                if determined:
                    artifact["cef_types"][cef_name] = determined
            else:
                try:
                    artifact["cef_types"][cef_name] = CEF_JSON[cef_name]["contains"]
                except Exception:
                    pass

    try:
        _response, resp_data = client.make_rest_call("/rest/artifact", method="post", data=artifact)
        artifact_id = resp_data.get("id")
    except PhantomClientError as e:
        # A conflicting artifact returns the existing id in the error payload response
        raise PhantomClientError(str(e)) from e

    soar.set_summary(AddArtifactSummary(artifact_id=artifact_id, container_id=container_id, server=client.base_uri))
    return [AddArtifactOutput(**resp_data)]
