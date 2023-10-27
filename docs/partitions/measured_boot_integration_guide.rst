#######################################
Measured Boot Service Integration Guide
#######################################

Introduction
************
Measured Boot partition provides services to extend and read
measurements (hash values and metadata) during various stages of a power cycle.
These measurements can be extended and read by any application/service
(secure or non-secure).

************
Measurements
************
The initial attestation token (required by attestation service) is formed of
various claims. Each software component claim comprises of the following
measurements which are extended and read by Measured Boot services.

    - **Measurement type**: It represents the role of the
      software component. Value is encoded as a short(!) text string.

    - **Measurement value**: It represents a hash of the invariant software
      component in memory at start-up time. The value must be a cryptographic
      hash of 256 bits or stronger. Value is encoded as a byte string.

    - **Version**: It represents the issued software version. Value is encoded
      as a text string.

    - **Signer ID**: It represents the hash of a signing authority public key.
      Value is encoded as a byte string.

    - **Measurement description**: It represents the way in which the
      measurement value of the software component is computed. Value is
      encoded as text string containing an abbreviated description (name) of
      the measurement method.

**************
Code structure
**************

The TF-M Measured Boot Service source and header files are located in current
directory. The interfaces for the measured boot service are located in the
``interface/include``.  The headers to be included by applications that want
to use functions from the API is ``measured_boot_api.h`` and
``measured_boot_defs.h``.

Service source files
====================

- Measured Boot Service:
    - ``measured_boot.c`` : Implements core functionalities such as
      implementation of APIs, extension and reading of measurements.
    - ``measured_boot_api.c``: Implements the secure API layer to
      allow other services in the secure domain to request functionalities
      from the measured boot service using the PSA API interface.
    - ``measured_boot_req_mngr.c``: Includes the initialization entry of
      measured boot service and handles service requests in IPC model.

Measured Boot Interfaces
========================

The TF-M Measured Boot service exposes the following interfaces:

.. code-block:: c

    psa_status_t tfm_measured_boot_read_measurement(
                                              uint8_t index,
                                              uint8_t *signer_id,
                                              size_t signer_id_size,
                                              size_t *signer_id_len,
                                              uint8_t *version,
                                              size_t version_size,
                                              size_t *version_len,
                                              uint32_t *measurement_algo,
                                              uint8_t *sw_type,
                                              size_t sw_type_size,
                                              size_t *sw_type_len,
                                              uint8_t *measurement_value,
                                              size_t measurement_value_size,
                                              size_t *measurement_value_len,
                                              bool *is_locked);
    psa_status_t tfm_measured_boot_extend_measurement(
                                              uint8_t index,
                                              const uint8_t *signer_id,
                                              size_t signer_id_size,
                                              const uint8_t *version,
                                              size_t version_size,
                                              uint32_t measurement_algo,
                                              const uint8_t *sw_type,
                                              size_t sw_type_size,
                                              const uint8_t *measurement_value,
                                              size_t measurement_value_size,
                                              bool lock_measurement);

When reading measurement, the caller must allocate large enough
buffers to accommodate data for all the output measurement parameters.
The definitions ``SIGNER_ID_MAX_SIZE``, ``VERSION_MAX_SIZE``,
``SW_TYPE_MAX_SIZE``, and ``MEASUREMENT_VALUE_MAX_SIZE`` can be used to
determine the required size of the buffers.

System integrators might need to port these interfaces to a custom secure
partition manager implementation (SPM). Implementations in TF-M project can be
found in tf-m-extras repository.

-  ``partitions/measured_boot/interface/src/measured_boot_api.c``:
   non-secure as well as secure interface implementation

Related compile time options for out of tree build
--------------------------------------------------
- ``TFM_PARTITION_MEASURED_BOOT``: To include measured boot secure partition
  and its services, its value should be ON. By default, it is switched OFF.

- ``MEASURED_BOOT_HASH_ALG``: This option selects the hash algorithm used
  for extension of measurement hashes. Its default value is PSA_ALG_SHA_256.

- ``TFM_EXTRA_MANIFEST_LIST_FILES``: <tf-m-extras-repo>/partitions/
  measured_boot/measured_boot_manifest_list.yaml

- ``TFM_EXTRA_PARTITION_PATHS``: <tf-m-extras-repo>/partitions/measured_boot

************
Verification
************

Regression test
===============

To be implemented.

--------------

*Copyright (c) 2022, Arm Limited. All rights reserved.*
