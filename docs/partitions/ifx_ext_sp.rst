########################
IFX EXTENSIONS Partition
########################

Overview
********

The IFX EXTENSIONS partition provides a dedicated secure partition for
Infineon-specific secure services that are not part of the TF-M core service
set. It is intended to be an extensible integration point where platform
features can be exposed through a stable PSA-style entry point.

At the moment, the partition implements one service endpoint that dispatches
to MTB SRF handling logic when ``IFX_MTB_SRF`` is enabled.

What The Partition Is For
*************************

This partition exists to:

- Host Infineon extension services in a single secure boundary.
- Provide a stable Secure Function (SFN) based PSA service endpoint to
  non-secure clients.
- Keep Infineon feature integration out of TF-M core directories, while still
  following TF-M manifest and partition-generation flows.
- Offer an extensible place to add future IFX-specific service operations.

Services Provided
*****************

Service definition:

- Service name: ``IFX_EXT_SP_SERVICE``
- SID: ``0x00001001``
- Model: SFN (stateless)
- Non-secure clients: allowed
- Connection based: no

Current service operation:

- API selector ``IFX_EXT_SP_API_ID_MTB_SRF`` (value ``1001``)
  routes calls to MTB SRF request handling.

Client-facing API:

- ``ifx_mtb_srf_call(...)`` in
  ``partitions/ifx_ext_sp/interface/src/ifx_ext_sp_api.c`` performs
  ``psa_call(IFX_EXT_SP_SERVICE_HANDLE, IFX_EXT_SP_API_ID_MTB_SRF, ...)``.
- Public declarations are in
  ``partitions/ifx_ext_sp/interface/include/ifx_ext_sp_api.h`` and
  ``partitions/ifx_ext_sp/interface/include/ifx_ext_sp_defs.h``.

Design Overview
***************

High-level flow:

1. A client calls ``ifx_mtb_srf_call(...)``.
2. The call reaches ``ifx_ext_sp_service_sfn(const psa_msg_t *msg)``.
3. The SFN dispatches by ``msg->type``.
4. For MTB SRF requests, ``ifx_mtb_srf_handler(...)`` is executed.
5. The handler retrieves original IO vectors via
   ``ifx_call_platform_original_iovec(...)`` and executes
   ``mtb_srf_request_execute(...)``.

Key implementation behavior:

- ``ifx_ext_sp_init()`` performs partition initialization and optionally
  registers a user SRF module.
- ``mtb_srf_memory_validate(...)`` is overridden when ``IFX_MTB_SRF`` is
  enabled. The partition relies on PSA call-time memory checks and copies
  vector descriptors into SRF-owned buffers.
- Unsupported operation IDs return ``PSA_ERROR_NOT_SUPPORTED``.

Security And Access Model
*************************

- The partition is declared as ``PSA-ROT``.
- Calls arrive through TF-M PSA service mediation.
- The implementation expects PSA to enforce caller memory access constraints
  before secure service code executes.
- The service is currently accessible to non-secure clients by manifest
  policy.

Configuration
*************

Required configuration:

- ``IFX_EXT_SP=ON`` to include the partition.

Optional configuration:

- ``IFX_EXT_SP_STACK_SIZE`` configures stack size (default: ``0x600``).
- ``IFX_EXT_SP_REGISTER_USER_SRF_MODULE`` enables registration of a user SRF
  module at init time.
- If user SRF module registration is enabled, the build expects
  ``ifx_user_srf_module.c`` (same directory as partition ``CMakeLists.txt``)
  to provide ``ifx_user_srf_module``.

TF-M Extras integration knobs:

- ``TFM_EXTRA_MANIFEST_LIST_FILES``:
  ``<tf-m-extras-repo>/partitions/ifx_ext_sp/ifx_ext_sp_manifest_list.yaml``
- ``TFM_EXTRA_PARTITION_PATHS``:
  ``<tf-m-extras-repo>/partitions/ifx_ext_sp``

Code Structure
**************

Core partition code:

- ``partitions/ifx_ext_sp/ifx_ext_sp_mngr.c``
- ``partitions/ifx_ext_sp/ifx_ext_sp.yaml``

Interface code:

- ``partitions/ifx_ext_sp/interface/include/ifx_ext_sp_api.h``
- ``partitions/ifx_ext_sp/interface/include/ifx_ext_sp_defs.h``
- ``partitions/ifx_ext_sp/interface/src/ifx_ext_sp_api.c``

Manifest list files:

- ``partitions/ifx_ext_sp/ifx_ext_sp_manifest_list.yaml``

Design Notes And Limitations
****************************

- The partition currently exposes one operation (MTB SRF dispatch).
- When ``IFX_MTB_SRF`` is disabled, MTB SRF requests return
  ``PSA_ERROR_NOT_SUPPORTED``.
- The service-dispatch structure is intentionally simple so additional IFX
  operations can be added by extending ``ifx_ext_sp_service_sfn(...)`` and the
  public API identifiers.

--------------

*SPDX-License-Identifier: BSD-3-Clause*

*SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors*
