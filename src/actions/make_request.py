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

from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..app import Asset, app, get_client


class PhantomMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Phantom REST endpoint to call, appended to the asset base URL. "
            "Example: '/rest/version'"
        ),
        required=True,
    )


class PhantomMakeRequestOutput(ActionOutput):
    status_code: int = OutputField(example_values=[200])
    response_body: str = OutputField(example_values=['{"version": "6.0.0"}'])


@app.make_request()
def make_request(
    params: PhantomMakeRequestParams, asset: Asset
) -> PhantomMakeRequestOutput:
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL — "
            "it is derived from the asset configuration."
        )

    endpoint = (
        params.endpoint if params.endpoint.startswith("/") else f"/{params.endpoint}"
    )

    headers = None
    if params.headers:
        try:
            headers = json.loads(params.headers)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON headers: {params.headers}") from e

    query_params = None
    if params.query_parameters:
        try:
            query_params = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(
                f"Invalid JSON query_parameters: {params.query_parameters}"
            ) from e

    data = None
    if params.body:
        try:
            data = json.loads(params.body)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON body: {params.body}") from e

    client = get_client(asset)
    response, _resp_data = client.make_rest_call(
        endpoint,
        headers=headers,
        params=query_params,
        data=data,
        method=params.http_method.lower(),
    )

    return PhantomMakeRequestOutput(
        status_code=response.status_code, response_body=response.text
    )
