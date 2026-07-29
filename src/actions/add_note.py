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
from ..helper import PhantomClientError, validate_integer


class AddNoteParams(Params):
    title: str = Param(description="Title of note", required=True)
    content: str = Param(description="Content of note", required=False)
    container_id: int = Param(description="Container ID", required=False, cef_types=["phantom container id"])
    phase_id: str = Param(description="Phase ID", required=False)


class AddNoteOutput(ActionOutput):
    message: str = OutputField(
        column_name="Status",
        example_values=["Note created"],
    )


@app.action(
    name="add note",
    identifier="add_note",
    description="Add a note to a container",
    action_type="generic",
    read_only=False,
    render_as="table",
)
def add_note(params: AddNoteParams, soar: SOARClient, asset: Asset) -> AddNoteOutput:
    client = get_client(asset)

    phase_id = validate_integer(params.phase_id, "phase_id")

    container_id = params.container_id
    if container_id is None:
        container_id = soar.get_executing_container_id()
    container_id = validate_integer(container_id, "container_id")

    note_data = {
        "container_id": container_id,
        "title": params.title or "",
        "content": params.content or "",
        "note_type": "general",
        "phase": phase_id,
    }

    try:
        client.make_rest_call("/rest/note", data=note_data, method="post")
    except PhantomClientError as e:
        raise PhantomClientError(f"Failed to create note: {e}") from e

    soar.set_message("Note created")
    return AddNoteOutput(message="Note created")
