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

import ast
from urllib.parse import quote

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..helper import PhantomClientError


class AddListitemParams(Params):
    list: str = Param(description="Name/ID of the list to append to", required=True)
    new_row: str = Param(description="Value(s) to append to the list", required=True)
    create: bool = Param(description="Create the list if it does not exist", required=False, default=False)


class AddListitemOutput(PermissiveActionOutput):
    status: str = OutputField(column_name="Status", example_values=["success", "failed"])


class AddListitemSummary(ActionOutput):
    server: str


def _create_list(client, list_name: str, row, soar: SOARClient) -> AddListitemOutput:
    if isinstance(row, (str, int, float, bool)):
        row = [row]
    payload = {"content": [row], "name": list_name}
    _response, resp_data = client.make_rest_call("/rest/decided_list", method="post", data=payload)
    soar.set_summary(AddListitemSummary(server=client.base_uri))
    resp_data.pop("status", None)
    return AddListitemOutput(status="success", **resp_data)


@app.action(
    name="add listitem",
    identifier="add_listitem",
    description="Add a new row to a list",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=AddListitemSummary,
)
def add_listitem(params: AddListitemParams, soar: SOARClient, asset: Asset) -> AddListitemOutput:
    client = get_client(asset)

    list_name = params.list
    row = params.new_row
    try:
        row = ast.literal_eval(row)
    except Exception:
        pass

    url = f"/rest/decided_list/{quote(list_name, safe='')}"
    payload = {"append_rows": [row]}

    try:
        _response, resp_data = client.make_rest_call(url, method="post", data=payload)
    except PhantomClientError as e:
        if "404" in str(e) and params.create:
            return _create_list(client, list_name, row, soar)
        raise PhantomClientError(f"Error appending to list: {e}") from e

    soar.set_summary(AddListitemSummary(server=client.base_uri))
    resp_data.pop("status", None)
    return AddListitemOutput(status="success", **resp_data)
