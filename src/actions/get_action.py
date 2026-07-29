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

import datetime
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import PHANTOM_ERR_ACTION_RESULT_NOT_FOUND
from ..helper import PhantomClientError, validate_integer


class GetActionParams(Params):
    action_name: str = Param(description="Name of action to search for", required=True)
    parameters: str = Param(description="Parameters to search for, in JSON format", required=False)
    app: str = Param(description="App to filter on", required=False)
    asset: str = Param(description="Asset to filter on", required=False)
    time_limit: int = Param(description="Hours to search back", required=False)
    max_results: int = Param(description="Max number of results to return", required=False, default=10)


class GetActionSummary(ActionOutput):
    num_results: int


class GetActionOutput(PermissiveActionOutput):
    pass


@app.action(
    name="get action result",
    identifier="get_action",
    description="Find the results of a previously run action",
    action_type="investigate",
    read_only=True,
    render_as="json",
    summary_type=GetActionSummary,
)
def get_action(params: GetActionParams, soar: SOARClient, asset: Asset) -> list[GetActionOutput]:
    client = get_client(asset)

    url_params: dict = {
        "_filter_action": f'"{params.action_name}"',
        "include_expensive": "",
        "sort": "start_time",
        "order": "desc",
    }

    parameters: dict = {}
    if params.parameters:
        try:
            parameters = json.loads(params.parameters)
        except Exception as e:
            raise PhantomClientError("Could not load JSON from 'parameters' parameter") from e

        search_key, search_value = parameters.popitem()
        is_not_string = isinstance(search_value, (float, int, bool))
        formatted_search_value = json.dumps(search_value) if is_not_string else f'\\"{search_value}\\"'
        url_params["_filter_result_data__regex"] = f"'parameter.*\\\"{search_key}\\\": {formatted_search_value}'"

    if params.time_limit is not None:
        hours = validate_integer(params.time_limit, "time_limit")
        time_str = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        url_params["_filter_start_time__gt"] = f'"{time_str}"'

    limit = validate_integer(params.max_results, "max_results", allow_zero=True)

    if params.app:
        app_params = {"_filter_name__iexact": f'"{params.app}"'}
        _response, resp_json = client.make_rest_call("/rest/app", params=app_params)
        if resp_json["count"] == 0:
            raise PhantomClientError(f"Could not find app with name '{params.app}'")
        url_params["_filter_app"] = resp_json["data"][0]["id"]

    if params.asset:
        asset_params = {"_filter_name__iexact": f'"{params.asset}"'}
        _response, resp_json = client.make_rest_call("/rest/asset", params=asset_params)
        if resp_json["count"] == 0:
            raise PhantomClientError(f"Could not find asset with name '{params.asset}'")
        url_params["_filter_asset"] = resp_json["data"][0]["id"]

    action_runs: list = []
    page = 0
    page_size = 10
    while True:
        page_params = dict(url_params)
        page_params["page"] = page
        page_params["page_size"] = min(page_size, limit - len(action_runs)) if limit else page_size

        _response, resp_json = client.make_rest_call("/rest/app_run", params=page_params)

        page_data = resp_json.get("data", [])
        action_runs.extend(page_data)
        if not page_data or (limit and len(action_runs) >= limit):
            break
        if page + 1 >= resp_json.get("num_pages", 1):
            break
        page += 1

    if limit:
        action_runs = action_runs[:limit]

    if len(parameters) > 0:
        matched = []
        for action_run in action_runs:
            for result in action_run["result_data"]:
                cur_params = result["parameter"]
                if all(cur_params.get(k) == v for k, v in parameters.items()):
                    matched.append(action_run)
                    break
        if not matched:
            soar.set_message(PHANTOM_ERR_ACTION_RESULT_NOT_FOUND)
            return []
        soar.set_summary(GetActionSummary(num_results=len(matched)))
        soar.set_message(f"Num results: {len(matched)}")
        return [GetActionOutput(**run) for run in matched]

    if not action_runs:
        soar.set_message(PHANTOM_ERR_ACTION_RESULT_NOT_FOUND)
        return []

    soar.set_summary(GetActionSummary(num_results=len(action_runs)))
    soar.set_message(f"Num results: {len(action_runs)}")
    return [GetActionOutput(**run) for run in action_runs]
