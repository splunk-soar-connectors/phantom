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

from urllib.parse import quote

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..helper import validate_integer


class FindListitemParams(Params):
    list: str = Param(description="Name/ID of the list to search", required=True)
    column_index: int = Param(description="Column index to match against (indexing starts at 0)", required=False)
    values: str = Param(description="Value to search for", required=True)
    exact_match: bool = Param(description="List value must match exactly", required=False, default=True)


class FindListitemOutput(PermissiveActionOutput):
    row: list[str] | None = OutputField()


class FindListitemSummary(ActionOutput):
    server: str
    found_matches: int
    list_id: int
    locations: list[str]


@app.view_handler(template="phantom_find_listitem.html")
def find_listitem_view(outputs: list[FindListitemOutput]) -> dict:
    headers = ["List Name", "Matched Row", "Found at"]
    data = [o.model_dump() for o in outputs]
    return {"results": [{"data": data}], "headers": headers}


@app.action(
    name="find listitem",
    identifier="find_listitem",
    description="Find a value in a custom list",
    action_type="investigate",
    read_only=True,
    view_handler=find_listitem_view,
    summary_type=FindListitemSummary,
)
def find_listitem(params: FindListitemParams, soar: SOARClient, asset: Asset) -> list[FindListitemOutput]:
    client = get_client(asset)

    column_index = validate_integer(params.column_index, "column_index", allow_zero=True)

    endpoint = f"/rest/decided_list/{quote(params.list, safe='')}"
    _response, resp_data = client.make_rest_call(endpoint)

    list_id = resp_data["id"]
    content = resp_data.get("content")
    coordinates: list = []
    matched_rows: list = []
    found = 0
    for rownum, row in enumerate(content):
        for cid, value in enumerate(row):
            if column_index is None or cid == column_index:
                if params.exact_match and value == params.values:
                    found += 1
                    matched_rows.append(row)
                    coordinates.append((rownum, cid))
                elif not params.exact_match and value and params.values in value:
                    found += 1
                    matched_rows.append(row)
                    coordinates.append((rownum, cid))

    soar.set_summary(
        FindListitemSummary(
            server=client.base_uri,
            found_matches=found,
            list_id=list_id,
            locations=[f"Row {r}, Column {c}" for r, c in coordinates],
        )
    )
    return [FindListitemOutput(row=[str(v) for v in row]) for row in matched_rows]
