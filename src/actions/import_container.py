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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..helper import create_container_copy, validate_integer


class ImportContainerParams(Params):
    container_id: int = Param(
        description="Container ID on the configured Phantom asset to import",
        required=True,
        cef_types=["phantom container id"],
    )
    keep_owner: bool = Param(
        description="Attempt to keep the same container owner",
        required=False,
        default=False,
    )


class ImportContainerSummary(ActionOutput):
    container_id: int = OutputField(
        column_name="New Container", cef_types=["phantom container id"]
    )
    artifact_count: int


@app.action(
    name="import container",
    identifier="import_container",
    description="Import a container from another Phantom instance to this Phantom instance",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=ImportContainerSummary,
)
def import_container(
    params: ImportContainerParams, soar: SOARClient, asset: Asset
) -> ActionOutput:
    client = get_client(asset)

    container_id = validate_integer(params.container_id, "container_id")

    destination = soar.get_soar_base_url()
    source = client.base_uri

    new_container_id, artifact_count = create_container_copy(
        client,
        soar,
        container_id,
        destination,
        source,
        destination_local=True,
        keep_owner=params.keep_owner,
        run_automation=False,
    )

    soar.set_summary(
        ImportContainerSummary(
            container_id=new_container_id, artifact_count=artifact_count
        )
    )
    soar.set_message(f"Container id: {new_container_id}")
    return ActionOutput()
