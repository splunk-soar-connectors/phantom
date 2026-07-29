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
import pathlib
import re

import requests
from bs4 import BeautifulSoup
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .consts import (
    OPEN_XML_FORMATS,
    PHANTOM_ERR_INVALID_INT,
    PHANTOM_ERR_PARSE_JSON_RESPONSE,
    PHANTOM_ERR_SERVER,
    PHANTOM_ERR_SPECIFY_IP_HOSTNAME,
    PHANTOM_ERR_UNABLE_RETRIEVE_ID,
    SUPPORTED_FILES,
    TIMEOUT,
)


logger = getLogger()

# The following identifiers are provided by the SOAR platform runtime but are not
# part of the SDK package, so guard the imports to keep the build/test venv happy.
try:
    from phantom.cef import CEF_JSON, CEF_NAME_MAPPING
except ImportError:
    CEF_JSON = {}
    CEF_NAME_MAPPING = {}

try:
    from phantom.utils import CONTAINS_VALIDATORS
except ImportError:
    CONTAINS_VALIDATORS = {}

try:
    from phantom.utils import is_ip
except ImportError:

    def is_ip(value: str) -> bool:
        import ipaddress  # noqa: PLC0415

        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


class PhantomClientError(ActionFailure):
    """Raised when the remote Phantom REST call fails."""


class PhantomClient:
    """REST client for the remote Phantom instance configured on the asset."""

    def __init__(self, asset):
        self.asset = asset
        _validate_phantom_server(asset.phantom_server)
        self.base_uri = f"https://{asset.phantom_server}".strip("/")
        self.verify_cert = (
            asset.verify_certificate if asset.verify_certificate is not None else True
        )
        self.auth = None
        if asset.username and asset.password:
            self.auth = (asset.username, asset.password)
        self.auth_token = asset.auth_token

    def _process_html_response(self, response) -> dict:
        status_code = response.status_code
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = [x.strip() for x in error_text.split("\n") if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"
        message = message.replace("{", " ").replace("}", " ")
        raise PhantomClientError(message)

    def _process_json_response(self, response):
        try:
            resp_json = response.json()
        except Exception as e:
            raise PhantomClientError(
                PHANTOM_ERR_PARSE_JSON_RESPONSE.format(str(e))
            ) from e

        if isinstance(resp_json, list):
            return resp_json

        failed = resp_json.get("failed", False)
        if failed:
            message = resp_json.get("message") or "Error message is unavailable"
            raise PhantomClientError(
                PHANTOM_ERR_SERVER.format(response.status_code, message)
            )

        if 200 <= response.status_code < 399:
            return resp_json

        message = resp_json.get("message") or "Error message is unavailable"
        raise PhantomClientError(
            PHANTOM_ERR_SERVER.format(response.status_code, message)
        )

    def _process_response(self, response):
        content_type = response.headers.get("Content-Type", "")
        if ("json" in content_type) or ("javascript" in content_type):
            return self._process_json_response(response)

        if "html" in content_type:
            return self._process_html_response(response)

        if (200 <= response.status_code < 399) and (not response.text):
            return {}

        message = "Can't process response from server. Status Code: {} Data from server: {}".format(
            response.status_code, response.text.replace("{", " ").replace("}", " ")
        )
        raise PhantomClientError(message)

    def make_rest_call(
        self,
        endpoint,
        headers=None,
        params=None,
        data=None,
        method="get",
        ignore_auth=False,
        base_uri=None,
    ):
        if headers is None:
            headers = {}
        elif isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except Exception as e:
                raise PhantomClientError(f"Unable to load headers as JSON: {e}") from e

        if self.auth_token and ("ph-auth-token" not in headers):
            headers["ph-auth-token"] = self.auth_token

        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        auth = self.auth
        base_uri = (base_uri or self.base_uri).strip("/")

        if ignore_auth:
            auth = None
            headers.pop("ph-auth-token", None)

        url = f"{base_uri}{endpoint}"
        try:
            response = requests.request(
                method,
                url,
                auth=auth,
                json=data,
                headers=headers if headers else None,
                verify=False if ignore_auth else self.verify_cert,
                params=params,
                timeout=TIMEOUT,
            )
        except requests.exceptions.Timeout as e:
            raise PhantomClientError(f"Request timed out: {e}") from e
        except requests.exceptions.SSLError as e:
            raise PhantomClientError(f"HTTPS SSL validation failed: {e}") from e
        except Exception as e:
            raise PhantomClientError(
                f"Error connecting to server. Error Details: {e}"
            ) from e

        return response, self._process_response(response)


def _validate_phantom_server(host: str) -> None:
    """Reject loopback/localhost targets. Ported from the connector's initialize()."""
    import ipaddress  # noqa: PLC0415
    import socket  # noqa: PLC0415

    if host.startswith("http:") or host.startswith("https:"):
        raise ActionFailure(
            "Please specify the actual IP or hostname used by the Phantom instance "
            "in the Asset config without http: or https:"
        )

    bare_host = host.split(":", 1)[0]

    if is_ip(bare_host):
        try:
            packed = socket.inet_aton(bare_host)
            unpacked = socket.inet_ntoa(packed)
        except Exception as e:
            raise ActionFailure(
                f"Unable to do ip to name conversion on {bare_host}"
            ) from e
    else:
        try:
            unpacked = socket.gethostbyname(bare_host)
        except Exception as e:
            raise ActionFailure(
                f"Unable to do name to ip conversion on {bare_host}"
            ) from e

    try:
        address = ipaddress.ip_address(unpacked)
    except ValueError as e:
        raise ActionFailure(
            f"Unable to parse resolved address {unpacked!r} for {bare_host}"
        ) from e

    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_link_local
        or address.is_reserved
    ):
        raise ActionFailure(PHANTOM_ERR_SPECIFY_IP_HOSTNAME)

    if "127.0.0.1" in bare_host or "localhost" in bare_host:
        raise ActionFailure(PHANTOM_ERR_SPECIFY_IP_HOSTNAME)


def get_client(asset) -> PhantomClient:
    return PhantomClient(asset)


def _add_artifact_list(
    client: "PhantomClient", artifacts: list, ignore_auth: bool = False
) -> None:
    try:
        _response, resp_data = client.make_rest_call(
            "/rest/artifact", data=artifacts, method="post", ignore_auth=ignore_auth
        )
    except PhantomClientError as e:
        raise PhantomClientError(f"Error adding artifact: {e}") from e
    failed = sum(1 for resp in resp_data if resp.get("failed") is True)
    if failed:
        raise PhantomClientError("Failed to add one or more artifacts")


def create_container_copy(
    client: "PhantomClient",
    soar,
    container_id: int,
    destination: str,
    source: str,
    source_local: bool = False,
    destination_local: bool = False,
    keep_owner: bool = False,
    run_automation: bool = True,
    label: str | None = None,
) -> tuple[int, int]:
    """Copy an existing container (and its artifacts) from source to destination.

    Returns (new_container_id, artifact_count). Raises PhantomClientError on failure.
    """
    url = f"/rest/container/{container_id}"
    _response, resp_data = client.make_rest_call(
        url, ignore_auth=source_local, base_uri=source
    )

    container = resp_data
    source_artifact_count = container.get("artifact_count")
    for key in (
        "asset",
        "artifact_count",
        "start_time",
        "source_data_identifier",
        "ingest_app",
        "closing_rule_run",
        "tenant",
        "id",
    ):
        container.pop(key, None)
    if label:
        container["label"] = label
    owner_name = container.pop("owner_name", None)
    container.pop("owner", None)
    if keep_owner and owner_name:
        container["owner_id"] = owner_name
    if destination_local:
        container["asset_id"] = int(soar.get_asset_id())

    try:
        _response, resp_data = client.make_rest_call(
            "/rest/container",
            data=container,
            method="post",
            ignore_auth=destination_local,
            base_uri=destination,
        )
    except PhantomClientError as e:
        act_message = str(e)
        if "ingesting asset_id" in act_message:
            act_message += "If Multi-tenancy is enabled, please make sure the asset is assigned a tenant"
        elif '"owner_id" Not found' in act_message:
            act_message += ". Try setting the keep_owner parameter to false."
        raise PhantomClientError(act_message) from e

    try:
        new_container_id = resp_data["id"]
    except KeyError as e:
        raise PhantomClientError(PHANTOM_ERR_UNABLE_RETRIEVE_ID) from e

    url = f"/rest/container/{container_id}/artifacts"
    params = {"sort": "id", "order": "asc", "page_size": 0}
    try:
        _response, resp_data = client.make_rest_call(
            url, params=params, ignore_auth=source_local, base_uri=source
        )
    except PhantomClientError as e:
        raise PhantomClientError(
            f"Container created:{new_container_id}. Failed to retrieve artifacts from the source: {e}"
        ) from e

    if not isinstance(resp_data, dict) or not isinstance(resp_data.get("data"), list):
        raise PhantomClientError(
            f"Container created:{new_container_id}. Failed to retrieve artifacts from the source"
        )

    artifacts = resp_data["data"]
    if (
        isinstance(source_artifact_count, int)
        and len(artifacts) < source_artifact_count
    ):
        raise PhantomClientError(
            f"Container created:{new_container_id}. Source reports {source_artifact_count} artifact(s) "
            f"but only {len(artifacts)} could be retrieved"
        )

    if artifacts:
        for artifact in artifacts:
            for key in (
                "update_time",
                "create_time",
                "start_time",
                "end_time",
                "asset_id",
                "container",
                "id",
                "owner",
            ):
                artifact.pop(key, None)
            artifact["run_automation"] = False
            artifact["container_id"] = new_container_id
            owner_name = artifact.pop("owner_name", None)
            if keep_owner and owner_name:
                artifact["owner_id"] = owner_name
        artifacts[-1]["run_automation"] = run_automation

        try:
            _add_artifact_list(client, artifacts, ignore_auth=destination_local)
        except PhantomClientError as e:
            raise PhantomClientError(
                f"Container created:{new_container_id}. {e}"
            ) from e

    return new_container_id, len(artifacts)


def validate_integer(value, key: str, allow_zero: bool = False) -> int | None:
    """Replicate the connector's _validate_integer. Returns int or raises ActionFailure."""
    if value is None:
        return None
    try:
        if not float(value).is_integer():
            raise ActionFailure(PHANTOM_ERR_INVALID_INT.format(msg="", param=key))
        value = int(value)
    except (TypeError, ValueError) as e:
        raise ActionFailure(PHANTOM_ERR_INVALID_INT.format(msg="", param=key)) from e

    if value < 0:
        raise ActionFailure(
            PHANTOM_ERR_INVALID_INT.format(msg="non-negative", param=key)
        )
    if not allow_zero and value == 0:
        raise ActionFailure(
            PHANTOM_ERR_INVALID_INT.format(msg="non-zero positive", param=key)
        )
    return value


def load_dirty_json(dirty_json: str, parameter: str) -> dict:
    """Best-effort load of loosely-formatted JSON. Raises ActionFailure on failure."""
    regex_replace = [
        (r"([ \{,:\[])(u?\\?)?'([^']*)'([^'])", r'\1"\3"\4'),
        (r" False([, \}\]])", r" false\1"),
        (r" True([, \}\]])", r" true\1"),
        (r" None([, \}\]])", r" null\1"),
    ]
    for r, s in regex_replace:
        dirty_json = re.sub(r, s, dirty_json)
    dirty_json = dirty_json.replace(": ''", ': ""')

    try:
        clean_json = json.loads(dirty_json)
    except Exception as e:
        raise ActionFailure(f"Could not load JSON from {parameter} parameter") from e

    if not clean_json:
        raise ActionFailure(f"Please provide a non-empty JSON in {parameter} parameter")
    if not isinstance(clean_json, dict):
        raise ActionFailure(f"Please provide {parameter} parameter in JSON format")

    return clean_json


def determine_contains(value) -> list:
    valid_contains = []
    for c, f in CONTAINS_VALIDATORS.items():
        try:
            if f(value):
                valid_contains.append(c)
        except Exception:  # noqa: S112
            continue
    return valid_contains


def has_allowed_archive_extension(file_name: str, allowed_extensions: str) -> bool:
    if allowed_extensions:
        allowed_extension_suffixes = set(allowed_extensions.split(","))
        file_extension = pathlib.Path(file_name).suffix.lstrip(".")
        if file_extension not in allowed_extension_suffixes:
            return False
    return True


def _detect_ooxml_mime(file_path: str) -> str | None:
    """Detects Open XML (MS Office 2007+) documents that are structurally ZIP archives.

    OOXML files (docx/pptx/xlsx/visio) are ZIP containers whose member entries live
    under a well-known top-level directory. Detecting them lets deflation skip these
    files, which otherwise look like plain ZIPs and trigger a runaway recursive
    deflation that can hang the service.
    """
    import zipfile  # noqa: PLC0415

    if not zipfile.is_zipfile(file_path):
        return None

    prefix_to_mime = {
        "word/": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "ppt/": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "xl/": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "visio/": "application/vnd.ms-visio.drawing.main+xml",
    }

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            names = archive.namelist()
    except zipfile.BadZipFile:
        return None

    for name in names:
        if name == "AppManifest.xaml":
            return "application/x-silverlight-app"
        for prefix, mime in prefix_to_mime.items():
            if name.startswith(prefix):
                return mime
    return None


def check_deflation_supported_file(file_path: str) -> tuple[str, bool]:
    """Checks if the file is supported for deflation.

    Patches invalid behavior of some Operating Systems recognizing MS Office
    files (eg. xlsx) as zip files which lead to an enormous deflation process
    run hanging the service.
    """
    import magic  # noqa: PLC0415

    file_type = _detect_ooxml_mime(file_path)

    if file_type not in OPEN_XML_FORMATS:
        file_type = magic.from_file(file_path, mime=True)

    return file_type, file_type in SUPPORTED_FILES
