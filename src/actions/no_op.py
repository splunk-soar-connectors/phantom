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

import time

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import validate_integer


class NoOpParams(Params):
    sleep_seconds: int = Param(
        description="Number of seconds to wait",
        required=True,
    )


class NoOpOutput(ActionOutput):
    message: str = OutputField(
        column_name="Message",
        example_values=["Slept for 15 seconds"],
    )


@app.action(
    name="no op",
    identifier="no_op",
    description="Performs no action, and can be used to introduce a configurable delay in a playbook",
    action_type="investigate",
    read_only=True,
    render_as="table",
)
def no_op(params: NoOpParams, soar: SOARClient, asset: Asset) -> NoOpOutput:
    sleep_seconds = validate_integer(
        params.sleep_seconds, "sleep_seconds", allow_zero=True
    )

    remainder = sleep_seconds % 60

    for _ in range(int(sleep_seconds / 60)):
        time.sleep(60)

    if remainder:
        time.sleep(remainder)

    message = f"Slept for {sleep_seconds} seconds"
    soar.set_message(message)
    return NoOpOutput(message=message)
