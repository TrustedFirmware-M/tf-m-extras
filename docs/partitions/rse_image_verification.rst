################################
RSE Image Verification Partition
################################

Introduction
************

The RSE Image Verification partition provides a service to load and verify
images during the RSE runtime execution. It performs the following steps:

1. Copy the image to the provided load address.
2. Verify the image, using the verification structure that was constructed by
   the caller.
3. Create the image measurements, and optionally store them in the measured
   boot partition if it is requested.
4. Return the measurements to the caller.

The verification structure used in step 2 can contain chains of signatures.
Each chain can include NV counters and a root key ID. The root key ID is a PSA
key ID that refers to a key stored in the RSE.

A verification structure can be crafted for different image format types. The
caller constructs the verification structure and must be trusted. Some
example structures can be seen in the ``partitions/rse_image_verification/test``
directory.

Image authentication process
****************************

The following steps are performed to authenticate an image, using the provided
verification structure:

1. Hash the image buffer.
2. For each chain in the ``verification_data`` structure:

   a. Set the ``hash_to_be_verified`` to this hash of the image buffer.
   b. Set the ``signature_to_be_verified`` to the ``first_signature`` parameter.
   c. Validate the NV counter value from the image by comparing it to the stored
      NV counter value in the RSE.
   d. For each element in the chain (can be skipped if chain size is 0):

      i.   Set up the key from the ``chain_signature_and_data``.
      ii.  Validate the NV counter value from the image by comparing it to the
           stored NV counter value in the RSE.
      iii. Validate the ``hash_to_be_verified`` against
           ``signature_to_be_verified`` using the key and the algorithm it is
           specified for.
      iv.  Set ``signature_to_be_verified`` in the chain data to the
           ``chain_signature`` of size ``chain_signature_size``.
      v.   Set the ``hash_to_be_verified`` to the hash of data in the
           ``chain_signature_and_data`` buffer.
   e. Validate the ``hash_to_be_verified`` using the key specified by the
      ``root_key_id`` based on the type metadata of that key in the RSE crypto
      service. This validation can be a symmetric or asymmetric signature
      verification based on a key stored in OTP (or derived from one). More
      commonly, it can be a comparison to a hash value loaded from OTP into
      an unstructured type PSA keyslot.
   f. If all signature validations succeeded, create a struct
      ``rse_boot_verification_chain_measurement_t`` for this chain containing
      the root and intermediate hashes.
3. If any chains which had ``must_sign`` failed verification, erase the image
   and return an error code.
4. For each successful chain:

   a. Store the measurements in the caller-specified slot in the measured boot
      partition, if enabled.
   b. Populate the ``rse_image_verification_boot_measurement_t`` structure's
      ``measurement`` field with the measurement metadata and value fields.
5. Return the struct ``rse_image_verification_boot_measurement_t`` along with
   a success code.


**************
Code structure
**************

The code structure is similar to the other services of the TF-M extras
repository. The interface for the service is located in the
``partitions/rse_image_verification/interface``. The header to be included by
applications that want to use functions from the API is
``rse_image_verification_api.h``.

RSE Image Verification Interface
================================

The TF-M RSE Image Verification service exposes the following interface:

.. code-block:: c

    enum rse_verification_service_err_t
    rse_verify_and_load_image(const uint8_t *image,
                              uint32_t image_len,

                              const struct rse_image_verification_data_t *verification_data,
                              uint32_t verification_data_len,

                              struct rse_image_verification_boot_measurement_t *boot_measurement,
                              uint32_t boot_measurement_len,
                              uint32_t *boot_measurement_size,

                              uint8_t *destination,
                              uint32_t destination_len)


- The ``image`` parameter points to the source image that will be loaded to
  the ``destination`` address.
- The ``verification_data`` is the structure used for verifying the image. This
  structure is constructed by the caller, meaning the caller must be trusted to
  provide correct parameters.
- The ``boot_measurement`` is an input-output parameter. The caller provides
  information on how and where the measurement should be stored. The service
  populates the measurement data in this structure and returns it to the caller.
  The caller can use this structure to determine if image verification was
  successful.

Dependencies
============

The service depends on the following secure services:

- Crypto service: Required for performing cryptographic operations and using
  built-in keys for these operations.
- Measured boot service: Required for storing boot measurements of the loaded
  images.


.. note::
   The built-in keys used for verification must be accessible to the RSE Image
   Verification service. As an example, see the ``TFM_BUILTIN_RIV_TEST_KEY``
   setup and usage in TF-M.


The service only works with ``PSA_FRAMEWORK_HAS_MM_IOVEC`` enabled.


Related compile-time options for out-of-tree build
==================================================
- ``TFM_PARTITION_RSE_IMAGE_VERIFICATION``: To include the RSE Image
  verification secure partition and its service, its value should be ON. By
  default, it is switched OFF.

- ``TFM_EXTRA_MANIFEST_LIST_FILES``: <tf-m-extras-repo>/partitions/rse_image_verification/rse_image_verification_manifest_list.yaml

- ``TFM_EXTRA_PARTITION_PATHS``: <tf-m-extras-repo>/partitions/rse_image_verification


************
Verification
************

Regression test
===============

The regression test suite is implemented in
``partitions/rse_image_verification/test``. The tests verify images with MCUBoot
and ST signature formats. Test images are generated manually and included in the
``partitions/rse_image_verification/test/mcuboot_signed_test_image.c`` and
``partitions/rse_image_verification/test/st_signed_test_image.c`` files. The
signing script commands used to generate these images can be found as comments
in these files. The image signature information is manually parsed from these
images and used to construct the verification structures in the test cases.

The tests can be built similarly to other regression tests, by adding the
``-DEXTRA_S_TEST_SUITE_PATH=<tf-m-extras-repo>/partitions/rse_image_verification/test/secure``
and ``-DTEST_S_RSE_IMAGE_VERIFICATION=ON`` flags to the build, in addition to
the previously mentioned flags.

--------------

*SPDX-License-Identifier: BSD-3-Clause*

*SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors*
