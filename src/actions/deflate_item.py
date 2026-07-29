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

import bz2
import gzip
import os
import random
import string
import tarfile
import zipfile

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, app, get_client
from ..consts import (
    PHANTOM_ERR_DECOMPRESSING_FILE,
    PHANTOM_ERR_FILE_PATH_NOT_FOUND,
    PHANTOM_ERR_GET_VAULT_INFO,
)
from ..helper import (
    PhantomClientError,
    check_deflation_supported_file,
    has_allowed_archive_extension,
    validate_integer,
)


class DeflateItemParams(Params):
    vault_id: str = Param(
        description="Vault ID of the item to deflate",
        required=True,
        cef_types=["sha1", "vault id"],
    )
    container_id: int = Param(
        description="Container to add the deflated items to",
        required=False,
        cef_types=["phantom container id"],
    )
    password: str = Param(
        description="Password for the archive", required=False, sensitive=True
    )
    recursive: bool = Param(
        description="Recursively deflate the item", required=False, default=False
    )


class DeflateItemMetadata(PermissiveActionOutput):
    md5: str | None = OutputField(column_name="MD5", cef_types=["md5"])
    sha1: str | None = OutputField(cef_types=["sha1"])
    sha256: str | None = OutputField(column_name="SHA256", cef_types=["sha256"])


class DeflateItemOutput(PermissiveActionOutput):
    name: str | None = OutputField(column_name="Name")
    hash: str | None = OutputField(cef_types=["sha1"])
    container_id: int | None = OutputField(cef_types=["phantom container id"])
    vault_id: str | None = OutputField(
        column_name="Vault ID", cef_types=["sha1", "vault id"]
    )
    size: int | None = OutputField(column_name="Size")
    metadata: DeflateItemMetadata | None = OutputField()


class DeflateItemSummary(ActionOutput):
    total_vault_items: int


class _Deflater:
    def __init__(self, soar: SOARClient, asset: Asset) -> None:
        self.soar = soar
        self.deflate_item_extensions = asset.deflate_item_extensions or ""
        self.results: list[dict] = []

    def add_file_to_vault(
        self, data_stream: bytes, file_name: str, recursive: bool, container_id: int
    ) -> None:
        save_as = file_name or "_invalid_file_name_"
        random_suffix = "_{}".format(
            "".join(
                random.SystemRandom().choice(string.ascii_lowercase) for _ in range(16)
            )
        )
        save_as = f"{save_as}{random_suffix}"
        if os.path.dirname(save_as):  # noqa: PTH120
            save_as = "-".join(save_as.split(os.sep))  # noqa: PTH206

        vault_tmp_dir = self.soar.vault.get_vault_tmp_dir()
        save_path = os.path.join(vault_tmp_dir, save_as)  # noqa: PTH118
        with open(save_path, "wb") as uncompressed_file:
            uncompressed_file.write(data_stream)

        try:
            self.soar.vault.add_attachment(container_id, save_path, file_name)
        except Exception as e:
            raise PhantomClientError(f"Failed to add file into vault: {e}") from e

        attachments = self.soar.vault.get_attachment(
            file_name=file_name, container_id=container_id
        )
        if not attachments:
            raise PhantomClientError(
                PHANTOM_ERR_GET_VAULT_INFO.format("attachment not found")
            )

        vault_info = None
        for attachment in attachments:
            if attachment.name == file_name:
                vault_info = attachment
                break
        if vault_info is None:
            vault_info = attachments[0]

        self.results.append(vault_info.model_dump())

        if recursive:
            file_path = vault_info.path
            _file_type, is_supported = check_deflation_supported_file(file_path)
            if not is_supported:
                return
            self.extract_file(file_path, vault_info.name, recursive, container_id)

    def extract_file(
        self,
        file_path: str,
        file_name: str,
        recursive: bool,
        container_id: int,
        password: str | None = None,
    ) -> None:
        file_type, is_supported = check_deflation_supported_file(file_path)
        if not is_supported:
            raise PhantomClientError(
                f"Deflation of file type: {file_type} not supported"
            )

        if not has_allowed_archive_extension(file_name, self.deflate_item_extensions):
            return

        if file_type == "application/x-bzip2":
            try:
                with bz2.BZ2File(file_path, "r") as f:
                    data = f.read()
            except OSError as e:
                raise PhantomClientError("Unable to deflate bz2 file") from e
            self.add_file_to_vault(
                data,
                os.path.splitext(file_name)[0],  # noqa: PTH122
                recursive,
                container_id,
            )

        elif file_type in ("application/x-gzip", "application/gzip"):
            try:
                with gzip.GzipFile(file_path, "r") as f:
                    data = f.read()
            except OSError as e:
                raise PhantomClientError("Unable to deflate gzip file") from e
            self.add_file_to_vault(
                data,
                os.path.splitext(file_name)[0],  # noqa: PTH122
                recursive,
                container_id,
            )

        elif file_type == "application/zip":
            if not zipfile.is_zipfile(file_path):
                raise PhantomClientError("Unable to deflate zip file")
            compressed_file = ""
            try:
                with zipfile.ZipFile(file_path, "r") as vault_file:
                    if password:
                        vault_file.setpassword(password.encode())
                    for compressed_file in vault_file.namelist():
                        save_as = os.path.basename(compressed_file)  # noqa: PTH119
                        if not os.path.basename(save_as):  # noqa: PTH119
                            continue
                        self.add_file_to_vault(
                            vault_file.read(compressed_file),
                            save_as,
                            recursive,
                            container_id,
                        )
            except PhantomClientError:
                raise
            except Exception as e:
                error_message = str(e).replace(compressed_file, file_name)
                raise PhantomClientError(
                    f"Unable to open the zip file: {file_path}. {error_message}"
                ) from e

        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path, "r") as vault_file:
                for member in vault_file.getmembers():
                    if not member.isfile():
                        continue
                    try:
                        self.add_file_to_vault(
                            vault_file.extractfile(member).read(),
                            os.path.basename(member.name),  # noqa: PTH119
                            recursive,
                            container_id,
                        )
                    except PhantomClientError as e:
                        raise PhantomClientError(
                            PHANTOM_ERR_DECOMPRESSING_FILE.format(
                                file_type, "Error decompressing tar file."
                            )
                        ) from e


@app.action(
    name="deflate item",
    identifier="deflate_item",
    description="Deflate a compressed item in the vault, adding the deflated items back to the vault",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=DeflateItemSummary,
)
def deflate_item(
    params: DeflateItemParams, soar: SOARClient, asset: Asset
) -> list[DeflateItemOutput]:
    get_client(asset)

    container_id = validate_integer(params.container_id, "container_id")
    if container_id is None:
        container_id = soar.get_executing_container_id()

    try:
        attachments = soar.vault.get_attachment(vault_id=params.vault_id)
    except Exception as e:
        raise PhantomClientError(PHANTOM_ERR_GET_VAULT_INFO.format(e)) from e
    if not attachments:
        raise PhantomClientError(
            PHANTOM_ERR_GET_VAULT_INFO.format("vault item not found")
        )

    vault_info = attachments[0]
    file_path = vault_info.path
    file_name = vault_info.name

    try:
        file_type, is_supported = check_deflation_supported_file(file_path)
    except OSError as e:
        raise PhantomClientError(PHANTOM_ERR_FILE_PATH_NOT_FOUND) from e
    except Exception as e:
        raise PhantomClientError(PHANTOM_ERR_FILE_PATH_NOT_FOUND) from e

    if not is_supported:
        raise PhantomClientError(f"Deflation of file type: {file_type} not supported")

    deflater = _Deflater(soar, asset)
    deflater.extract_file(
        file_path, file_name, params.recursive, container_id, password=params.password
    )

    soar.set_summary(DeflateItemSummary(total_vault_items=len(deflater.results)))
    return [DeflateItemOutput(**item) for item in deflater.results]
