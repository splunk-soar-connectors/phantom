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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    PHANTOM_ERR_FIND_ARTIFACT,
    PHANTOM_ERR_GET_ARTIFACT,
    PHANTOM_ERR_UPDATE_ARTIFACT,
)
from ..helper import PhantomClientError, load_dirty_json, validate_integer


class UpdateArtifactParams(Params):
    artifact_id: str = Param(
        description="Artifact ID to update",
        required=True,
        cef_types=["phantom artifact id"],
    )
    name: str = Param(description="Name of artifact", required=False)
    label: str = Param(description="Label of artifact", required=False)
    severity: str = Param(description="Severity of artifact", required=False)
    cef_json: str = Param(description="JSON string of CEF fields", required=False)
    cef_types_json: str = Param(
        description="JSON string of CEF data types (contains)", required=False
    )
    tags: str = Param(description="Comma separated list of tags", required=False)
    overwrite: bool = Param(
        description="Overwrite artifact with provided values",
        required=False,
        default=False,
    )
    artifact_json: str = Param(
        description="JSON string of the whole artifact to overwrite", required=False
    )


class UpdateArtifactResponse(PermissiveActionOutput):
    success: bool | None = OutputField(column_name="Success")


class UpdateArtifactOutput(PermissiveActionOutput):
    response: UpdateArtifactResponse | None = OutputField()


@app.action(
    name="update artifact",
    identifier="update_artifact",
    description="Update an artifact",
    action_type="generic",
    read_only=False,
    render_as="table",
)
def update_artifact(
    params: UpdateArtifactParams, soar: SOARClient, asset: Asset
) -> UpdateArtifactOutput:
    client = get_client(asset)

    artifact_id = validate_integer(params.artifact_id, "artifact_id")

    name = params.name
    label = params.label
    severity = params.severity
    cef_json = params.cef_json
    cef_types_json = params.cef_types_json
    tags = params.tags
    art_json = params.artifact_json
    overwrite = params.overwrite

    if not any((name, label, severity, cef_json, cef_types_json, tags, art_json)):
        req_params = (
            "name, label, severity, cef_json, cef_types_json, tags, artifact_json"
        )
        raise PhantomClientError(
            f"At least one of the following parameters are required to update an artifact: {req_params}"
        )

    endpoint = f"/rest/artifact/{artifact_id}"

    output_artifact: dict = {}
    if name:
        output_artifact["name"] = name
    if label:
        output_artifact["label"] = label
    if severity:
        output_artifact["severity"] = severity

    try:
        _response, resp_data = client.make_rest_call(endpoint)
    except PhantomClientError as e:
        raise PhantomClientError(
            f"{PHANTOM_ERR_FIND_ARTIFACT} {PHANTOM_ERR_GET_ARTIFACT.format(e)}"
        ) from e

    existing_artifact = resp_data if overwrite is False else {}
    if "label" not in output_artifact:
        output_artifact["label"] = resp_data.get("label") or "event"

    my_data = existing_artifact.get("cef", {})

    if cef_json:
        try:
            clean_json = json.loads(cef_json)
        except Exception:
            clean_json = load_dirty_json(cef_json, "cef_json")
        my_data = {k: v for k, v in my_data.items() if v}
        my_data.update(clean_json)

    my_data = {k: v for k, v in my_data.items() if v}
    output_artifact["cef"] = my_data

    if cef_types_json:
        contains = existing_artifact.get("cef_types", {})
        contains.update(load_dirty_json(cef_types_json, "cef_types_json"))
        output_artifact["cef_types"] = contains

    if tags:
        cleaned_tags = [tag.strip().strip("'\"") for tag in tags.strip("[]").split(",")]
        output_artifact["tags"] = list(
            set(existing_artifact.get("tags", []) + cleaned_tags)
        )

    if art_json:
        output_artifact.update(load_dirty_json(art_json, "art_json"))

    try:
        _response, resp_data = client.make_rest_call(
            endpoint, data=output_artifact, method="post"
        )
    except PhantomClientError as e:
        raise PhantomClientError(PHANTOM_ERR_UPDATE_ARTIFACT.format(e)) from e

    soar.set_message("Artifact updated successfully.")
    return UpdateArtifactOutput(requested_artifact=output_artifact, response=resp_data)
