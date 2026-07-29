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
from ..consts import ARTIFACT_ABSOLUTE_MAX_RESULTS, ARTIFACT_DEFAULT_MAX_RESULTS, PAGINATION_COMPLETE
from ..helper import PhantomClientError


class FindArtifactsParams(Params):
    cef_key: str = Param(description="CEF key to search on", required=False)
    values: str = Param(description="Value to search for", required=True)
    exact_match: bool = Param(description="Value must match exactly", required=False, default=True)
    limit_search: bool = Param(description="Limit search to given container IDs", required=False, default=False)
    container_ids: str = Param(description="Container IDs to limit the search to", required=False, default="current")
    max_results: int = Param(description="Max number of artifacts to return", required=False, default=ARTIFACT_DEFAULT_MAX_RESULTS)


class FindArtifactsOutput(ActionOutput):
    id: int = OutputField()
    container: int = OutputField()
    container_name: str = OutputField()
    name: str | None = OutputField()
    found_in: str = OutputField(alias="found in")
    matched: str = OutputField()


class FindArtifactsSummary(ActionOutput):
    artifacts_found: int
    server: str


@app.view_handler(template="phantom_find_artifacts.html")
def find_artifacts_view(outputs: list[FindArtifactsOutput]) -> dict:
    headers = ["Container ID", "Container", "Artifact ID", "Artifact Name", "Found in field", "Matched Value"]
    data = [o.model_dump(by_alias=True) for o in outputs]
    return {"results": [{"data": data}], "headers": headers}


@app.action(
    name="find artifacts",
    identifier="find_artifacts",
    description="Find all artifacts that have a certain value",
    action_type="investigate",
    read_only=True,
    view_handler=find_artifacts_view,
    summary_type=FindArtifactsSummary,
)
def find_artifacts(params: FindArtifactsParams, soar: SOARClient, asset: Asset) -> list[FindArtifactsOutput]:
    client = get_client(asset)

    limit_search = params.limit_search
    container_ids = params.container_ids
    values = params.values
    max_results = params.max_results

    if limit_search:
        resolved = []
        for token in container_ids.replace(",", " ").split():
            token = token.strip()
            candidate = soar.get_executing_container_id() if token == "current" else token
            if isinstance(candidate, int) or (isinstance(candidate, str) and candidate.isdigit()):
                resolved.append(int(candidate))
        container_ids = sorted(set(resolved))

        if not container_ids:
            soar.set_summary(FindArtifactsSummary(artifacts_found=0, server=client.base_uri))
            return []

    cef_key = params.cef_key
    exact_match = params.exact_match

    if exact_match and not cef_key:
        values = f'"{values}"'

    url_enc_values = quote(values, safe="")

    if cef_key and exact_match:
        endpoint = f"/rest/artifact?_filter_cef__{quote(cef_key, safe='')}={url_enc_values!r}&pretty"
    elif cef_key:
        endpoint = f"/rest/artifact?_filter_cef__{quote(cef_key, safe='')}__icontains={url_enc_values!r}&pretty"
    else:
        endpoint = f"/rest/artifact?_filter_cef__icontains={url_enc_values!r}&pretty"

    if limit_search:
        endpoint += f"&_filter_container__in={container_ids}"

    records: list = []
    page = 0
    page_size = 10
    while True:
        count = (page + 1) * 10
        if max_results != 0 and count > max_results:
            page_size = 10 if max_results - page * 10 == 0 else max_results - page * 10
        paginated_endpoint = f"{endpoint}&page_size={page_size}&page={page}"

        try:
            _response, resp_data = client.make_rest_call(paginated_endpoint)
        except PhantomClientError as e:
            if PAGINATION_COMPLETE in str(e):
                break
            raise PhantomClientError(f"Error retrieving records: {e}") from e

        page_records = resp_data["data"]
        if not page_records:
            break

        records += page_records
        if len(records) >= ARTIFACT_ABSOLUTE_MAX_RESULTS:
            records = records[:ARTIFACT_ABSOLUTE_MAX_RESULTS]
            break
        if max_results != 0 and count >= max_results:
            break
        page += 1

    values = values.lower()

    outputs: list[FindArtifactsOutput] = []
    for rec in records:
        key, value = None, None
        for k, v in rec["cef"].items():
            curr_value = v
            if isinstance(curr_value, dict):
                curr_value = json.dumps(curr_value)
            if not isinstance(curr_value, str):
                curr_value = str(curr_value)
            if (exact_match and values.strip('"') == curr_value.lower()) or (
                not exact_match and values in curr_value.lower()
            ):
                key = k
                value = curr_value
                break

        outputs.append(
            FindArtifactsOutput(
                id=rec["id"],
                container=rec["container"],
                container_name=rec["_pretty_container"],
                name=rec.get("name"),
                found_in=key if key else "N/A",
                matched=value if value else "",
            )
        )

    soar.set_summary(FindArtifactsSummary(artifacts_found=len(records), server=client.base_uri))
    return outputs
