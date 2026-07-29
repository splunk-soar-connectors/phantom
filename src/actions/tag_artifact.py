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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import PHANTOM_ERR_GET_ARTIFACT, PHANTOM_ERR_UPDATE_ARTIFACT
from ..helper import PhantomClientError, validate_integer


class TagArtifactParams(Params):
    artifact_id: str = Param(
        description="Artifact ID to update",
        required=True,
        cef_types=["phantom artifact id"],
    )
    add_tags: str = Param(
        description="Comma separated list of tags to add", required=False
    )
    remove_tags: str = Param(
        description="Comma separated list of tags to remove", required=False
    )


class TagArtifactSummary(ActionOutput):
    tags_added: str
    tags_removed: str
    tags_already_present: str
    tags_already_absent: str


@app.action(
    name="update artifact tags",
    identifier="tag_artifact",
    description="Add/remove tags from an artifact",
    action_type="generic",
    read_only=False,
    summary_type=TagArtifactSummary,
)
def tag_artifact(
    params: TagArtifactParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    client = get_client(asset)

    artifact_id = validate_integer(params.artifact_id, "artifact_id")

    add_tags = {x.strip() for x in (params.add_tags or "").split(",")}
    remove_tags = {x.strip() for x in (params.remove_tags or "").split(",")}

    endpoint = f"/rest/artifact/{artifact_id}"

    try:
        response, resp_data = client.make_rest_call(endpoint)
    except PhantomClientError as e:
        raise PhantomClientError(PHANTOM_ERR_GET_ARTIFACT.format(e)) from e

    resp_label = resp_data.get("label")

    fields = ["tags", "label"]
    art_data = {f: response.json().get(f) for f in fields}

    if not art_data.get("label"):
        art_data["label"] = ""

    current_tags = set(art_data["tags"])
    tags_already_added = {tag for tag in add_tags if tag in current_tags}
    tags_already_removed = {tag for tag in remove_tags if tag not in current_tags}

    art_data["tags"] = list((current_tags | add_tags) - remove_tags)

    try:
        client.make_rest_call(endpoint, data=art_data, method="post")
    except PhantomClientError as e:
        msg = PHANTOM_ERR_UPDATE_ARTIFACT.format(e)
        if not resp_label:
            msg = f"The reason of the failure can be the unavailability of the label in the provided artifact. {msg}"
        raise PhantomClientError(msg) from e

    soar.set_summary(
        TagArtifactSummary(
            tags_added=", ".join(list(add_tags - tags_already_added)),
            tags_removed=", ".join(list(remove_tags - tags_already_removed)),
            tags_already_present=", ".join(list(tags_already_added)),
            tags_already_absent=", ".join(list(tags_already_removed)),
        )
    )
    return ActionOutput()
