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
from urllib.parse import quote

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import PHANTOM_ERR_NON_EMPTY_PARAM_VALUE
from ..helper import PhantomClientError, validate_integer


class UpdateListParams(Params):
    list_name: str = Param(description="Name of the custom list", required=False)
    id: int = Param(description="ID of the custom list", required=False)
    row_number: int = Param(
        description="Row number of the list to update (index starts from 0)",
        required=True,
    )
    row_values_as_list: str = Param(
        description="Values to set the row to, as a JSON formatted list",
        required=True,
    )


class UpdateListOutput(ActionOutput):
    success: bool = OutputField(column_name="Status")


@app.action(
    name="update list",
    identifier="update_list",
    description="Update rows in an existing list",
    action_type="generic",
    read_only=False,
    render_as="json",
)
def update_list(
    params: UpdateListParams, soar: SOARClient, asset: Asset
) -> UpdateListOutput:
    client = get_client(asset)

    row_number = validate_integer(params.row_number, "row_number", allow_zero=True)

    list_name = params.list_name
    list_id = params.id

    if not list_name and list_id is None:
        raise PhantomClientError("Either the custom list's name or id must be provided")

    if list_name:
        list_identifier = quote(list_name, safe="")
    else:
        list_identifier = validate_integer(list_id, "id")

    try:
        row_values = json.loads(params.row_values_as_list)
        if not isinstance(row_values, list) or not row_values:
            raise PhantomClientError(PHANTOM_ERR_NON_EMPTY_PARAM_VALUE)
    except json.JSONDecodeError as e:
        raise PhantomClientError(
            f"Could not load JSON formatted list from the row_values_as_list parameter: {e}"
        ) from e

    data = {"update_rows": {str(row_number): row_values}}

    client.make_rest_call(
        f"/rest/decided_list/{list_identifier}", data=data, method="post"
    )

    soar.set_message("Success: True")
    return UpdateListOutput(success=True)
