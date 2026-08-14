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
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger

from .helper import PhantomClient, get_client


logger = getLogger()


class Asset(BaseAsset):
    phantom_server: str = AssetField(
        required=True,
        description="Phantom IP or Hostname (e.g. 10.1.1.10 or valid_phantom_hostname)",
        category=FieldCategory.CONNECTIVITY,
    )
    auth_token: str | None = AssetField(
        description="Phantom Auth token",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    username: str | None = AssetField(
        description="Username (for HTTP basic auth)",
        category=FieldCategory.CONNECTIVITY,
    )
    password: str | None = AssetField(
        description="Password (for HTTP basic auth)",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    verify_certificate: bool | None = AssetField(
        description="Verify HTTPS certificate (default: true)",
        default=True,
        category=FieldCategory.CONNECTIVITY,
    )
    deflate_item_extensions: str | None = AssetField(
        description=(
            "Only files with the specified extensions (comma-separated) will be deflated. "
            "If blank, file extension will not be checked"
        ),
        category=FieldCategory.ACTION,
    )


app = App(
    name="Phantom",
    app_type="information",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Phantom",
    product_name="Phantom",
    publisher="Splunk",
    appid="deb82aa9-22cc-4675-9cf1-534b8d006eb7",
    fips_compliant=True,
    asset_cls=Asset,
    min_phantom_version="8.6.0",
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    client = get_client(asset)
    _response, resp_data = client.make_rest_call("/rest/version")
    version = resp_data["version"]
    logger.info(f"Connected to Phantom appliance version {version}")
    soar.set_message("Test connectivity passed")
    logger.info("Test connectivity passed")


__all__ = ["Asset", "PhantomClient", "app", "get_client"]

# Register actions via import side effect. Custom-view actions register their
# view handler within the same module. Imports are at the bottom so the `app`
# instance exists first.
from .actions import (  # noqa: F401
    add_artifact,
    add_listitem,
    add_note,
    create_container,
    deflate_item,
    export_container,
    find_artifacts,
    find_listitem,
    get_action,
    import_container,
    make_request,
    no_op,
    tag_artifact,
    update_artifact,
    update_list,
)
