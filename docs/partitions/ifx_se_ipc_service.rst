#############################
IFX SE IPC SERVICE Partition
#############################

Overview
********

The IFX SE IPC SERVICE partition is the secure gateway between selected TF-M
secure partitions and the Infineon Secure Enclave (SE) runtime syscall
interface. It validates request shape and caller identity, then forwards the
request to the SE runtime backend.

This service is designed to centralize SE access policy and avoid direct,
unrestricted syscall exposure across secure partitions.

What The Partition Is For
*************************

This partition exists to:

- Expose a controlled SE IPC entry point to TF-M secure services.
- Enforce per-command-group access control based on the caller partition.
- Keep SPM initialization-time SE access and runtime partition SE access in a
  coherent integration model.
- Provide a reusable integration layer for IFX SE runtime syscall transport.

Services Provided
*****************

Service definition:

- Service name: ``IFX_SE_IPC_SERVICE``
- SID: ``0x00001000``
- Model: SFN (stateless)
- Non-secure clients: not allowed
- Connection based: no

Service behavior summary:

- Accepts one IPC packet input vector and one status output vector.
- Validates request type and buffer sizes.
- Decodes command/group identifiers from the packet.
- Checks caller authorization for the decoded command group.
- Executes ``ifx_se_syscall_builtin(...)`` for authorized callers.
- Returns SE status in the PSA output payload.

Design Overview
***************

Runtime request flow through partition path:

1. A secure caller reaches ``ifx_se_syscall(...)``.
2. During normal runtime, that path uses ``psa_call(...)`` to
   ``IFX_SE_IPC_SERVICE_HANDLE``.
3. The request is handled by ``ifx_se_ipc_service_sfn(...)``.
4. The service validates message type and payload sizes.
5. The service extracts command and group IDs from packet parameters.
6. Caller policy is evaluated against command/group.
7. Authorized requests are dispatched to ``ifx_se_syscall_builtin(...)``.
8. SE status is returned to the caller through PSA outvec.

Initialization-time flow:

- ``ifx_se_ipc_service_spm_init()`` and
  ``ifx_se_ipc_service_spm_shutdown()`` allow SPM to enable/disable SE runtime
  services in its initialization phase.
- During early init context, ``ifx_se_syscall(...)`` routes to
  ``ifx_se_ipc_service_spm_syscall(...)``.

Direct-call fallback flow:

- If the partition is not enabled, syscall integration can be built with the
  direct path (``ifx_se_ipc_service_syscall_direct.c``), which calls
  ``ifx_se_syscall_builtin(...)`` without PSA service mediation.

Access Control Model
********************

The partition enforces command-group aware client restrictions.

Current policy implemented in ``ifx_se_ipc_service_req_mngr.c``:

- ``IFX_SE_SYSCALL_PSA_GET_RANDOM``: allowed from any secure partition.
- PSA Crypto command group: allowed only from ``TFM_SP_CRYPTO``.
- Rollback counter command group: allowed only from ``TFM_SP_PLATFORM``.
- Attestation command group: allowed only from
  ``TFM_SP_INITIAL_ATTESTATION``.
- Any other command/group: denied.

If a request is not permitted, the service returns ``PSA_ERROR_NOT_PERMITTED``.

Input Validation And Robustness
*******************************

The service validates:

- PSA message type must be the expected call type.
- Input packet size must be within SE runtime min/max packet bounds.
- Output size must exactly match ``ifx_se_status_t`` size.
- Full packet read from PSA input vector must succeed.

After request handling, the local packet buffer is explicitly cleared.

Configuration
*************

Primary options:

- ``IFX_PARTITION_SE_IPC_SERVICE=ON`` enables the partition.
- ``IFX_SE_IPC_SERVICE_TYPE`` controls SE IPC integration mode used by SPM and
  syscall plumbing (``FULL`` or ``BASE`` in current CMake logic).

When partition is enabled:

- ``ifx_se_ipc_service_syscall_partition.c`` is compiled as the syscall route.

When partition is disabled:

- ``ifx_se_ipc_service_syscall_direct.c`` is compiled as the syscall route.

TF-M Extras integration knobs:

- ``TFM_EXTRA_MANIFEST_LIST_FILES``:
  ``<tf-m-extras-repo>/partitions/ifx_se_ipc_service/ifx_se_ipc_service_manifest_list.yaml``
- ``TFM_EXTRA_PARTITION_PATHS``:
  ``<tf-m-extras-repo>/partitions/ifx_se_ipc_service``

Code Structure
**************

Core partition sources:

- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_req_mngr.c``
- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service.yaml``

SPM and syscall integration sources:

- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_spm.c``
- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_spm.h``
- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_syscall_partition.c``
- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_syscall_direct.c``
- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_ipc.c``
- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_syscall.h``

Manifest list files:

- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_manifest_list.yaml``
- ``partitions/ifx_se_ipc_service/ifx_se_ipc_service_top_level_manifest.yaml``

Design Notes And Limitations
****************************

- The service is secure-partition-only by manifest policy.
- Command-group policy is hardcoded in the request manager and must be updated
  when new SE command groups are introduced.
- The partition deliberately separates SPM-init usage and normal runtime usage
  to avoid concurrent unsafe sharing of the same SE IPC path.

--------------

*SPDX-License-Identifier: BSD-3-Clause*

*SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors*