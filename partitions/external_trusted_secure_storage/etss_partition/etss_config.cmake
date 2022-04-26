#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#-------------------------------------------------------------------------------

set(TFM_PARTITION_EXTERNAL_TRUSTED_SECURE_STORAGE     ON          CACHE BOOL      "Enable ETSS partition")
set(ETSS_CREATE_FLASH_LAYOUT                          ON          CACHE BOOL      "Create flash FS if it doesn't exist for External Trusted Secure Storage partition")
set(ETSS_VALIDATE_METADATA_FROM_FLASH                 ON          CACHE BOOL      "Validate filesystem metadata every time it is read from external secure flash")
set(ETSS_MAX_ASSET_SIZE                               "2048"      CACHE STRING    "The maximum asset size to be stored in the External Trusted Secure Storage area")
set(ETSS_NUM_ASSETS                                   "10"        CACHE STRING    "The maximum number of assets to be stored in the External Trusted Secure Storage area")
set(ETSS_BUF_SIZE                                     ""          CACHE STRING    "Size of the ETSS internal data transfer buffer (defaults to ETSS_MAX_ASSET_SIZE if not set)")
set(PROV_BLOB_LEN_MAX                                 "2048"      CACHE STRING    "The maximum secure flash provision data size")
set(ETSS_SF_ASSET_BUF_SIZE                            "512"       CACHE STRING    "Size of secure Flash read/write buffer")

