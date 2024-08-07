######################
TF-M Example Partition
######################
The TF-M example partition is a simple Secure Partition implementation provided
to aid development of new Secure Partitions.

It is an Application RoT, SFN model Secure Partition and implements an
connection-based RoT Service.

Please refer to `PSA Firmware Framework 1.0`_
and `Firmware Framework for M 1.1 Extensions`_
for details of the attributes of Secure Partitions.

Please refer to :doc:`Adding Secure Partition <TF-M:integration_guide/services/tfm_secure_partition_addition>`
for more details of adding a new Secure Partition to TF-M.

.. file-structure:

**************
File structure
**************

.. code-block:: bash

   .
   ├── CMakeLists.txt
   ├── README.rst
   ├── tfm_example_manifest_list.yaml
   ├── tfm_example_partition_api.c
   ├── tfm_example_partition_api.h
   ├── tfm_example_partition.c
   └── tfm_example_partition.yaml

- ``CMakeLists.txt``

  The CMake file for building this example Secure Partitions.
  It is specific to the TF-M build system.

- ``README.rst``

  This document.

- ``tfm_example_partition.yaml``

  The manifest of this Secure Partition.

- ``tfm_example_manifest_list.yaml``

  The manifest list that describes the Secure Partition manifest of this Secure
  Partition. See `TF-M Manifest List`_ for details of manifest lists.

- ``tfm_example_partition.c``

  The core implementation of this Secure Partition.

- ``tfm_example_partition_api.c``

  The APIs for accessing the RoT Services provided by this Secure Partition.

- ``tfm_example_partition_api.h``

  The header file that declares the RoT Services APIs.

************
How to Build
************
It is recommended to build this example Secure Partition via out-of-tree build.
It can minimize the changes to TF-M source code for building and testing the
example.

To build, append the following extra build configurations to the CMake build
commands.

- ``-DTFM_PARTITION_EXAMPLE``

  This is the configuration switch to enable or disable building this example.
  Set to ``ON`` to enable or ``OFF`` to disable.

- ``-DTFM_EXTRA_PARTITION_PATHS``

  Set it to the absolute path of this directory.

- ``-DTFM_EXTRA_MANIFEST_LIST_FILES``

  Set it to the absolute path of the manifest list mentioned above -
  ``tfm_example_manifest_list.yaml``.

Refer to `Out-of-tree Secure Partition build`_ for more details.

**********************************************
Build steps for mps4/corstone315 platform
**********************************************
1. Build and install TF-M with the following command:

.. code-block:: bash

 $ cmake -S <TF-M Source Dir> \
         -B build/spe_test \
         -DTFM_PLATFORM=arm/mps4/corstone315 \
         -DTFM_TOOLCHAIN_FILE=<TF-M Source Dir>/toolchain_<toolchain>.cmake \
         -DTFM_PARTITION_INTERNAL_TRUSTED_STORAGE=ON \
         -DTFM_PARTITION_CRYPTO=ON \
         -DTEST_NS=ON
         -DTEST_S=ON \
 $ cmake --build build/spe_test -- -j$(nproc) install

2. Then build the example with the following:

.. code-block:: bash

 $ cmake -S <this_example_path> \
         -B build/nspe_test \
         -DTFM_TOOLCHAIN=<toolchain> \
         -DCONFIG_SPE_PATH=$(shell pwd)/<build_dir>/spe_test/api_ns
 $ cmake --build build/nspe_test -- -j$(nproc)

***********
How to Test
***********
To test the RoT Services, you need to build the APIs and call the service APIs
somewhere.

If you want to add comprehensive tests using the TF-M test framework, please
refer to :doc:`Adding TF-M Regression Test Suite <TF-M-Tests:tfm_test_suites_addition>`.

Testing in NSPE
===============
Any NSPE can be used to test the example RoT services.
If you are using the tf-m-tests repo as NSPE, you can:

- Add the ``tfm_example_partition_api.c`` to ``tfm_ns_api`` CMake library.
- Add the current directory in the include directory of ``tfm_ns_api``.
- Call the services APIs in the ``test_app`` function.

Testing in SPE
==============

Testing in SPE is to test requesting the RoT Services in any Secure Partition.

- Add the example services to the ``dependencies`` attribute in the target
  Secure Partition's manifest.
- Call the services APIs somewhere in the Secure Partition, for example, in the
  entry function.

Note that the API source file has already been added in the ``CMakeLists.txt``.
There are no extra steps to build the APIs for testing in SPE.

**********
References
**********

| `PSA Firmware Framework 1.0`_
| `Firmware Framework for M 1.1 Extensions`_
| `TF-M Manifest List`_
| `Out-of-tree Secure Partition build`_

.. _PSA Firmware Framework 1.0:
  https://developer.arm.com/documentation/den0063/latest/

.. _Firmware Framework for M 1.1 Extensions:
  https://developer.arm.com/documentation/aes0039/latest/

.. _TF-M Manifest List:
  https://trustedfirmware-m.readthedocs.io/en/latest/integration_guide/services/tfm_manifest_tool_user_guide.html#manifest-list

.. _Out-of-tree Secure Partition build:
  https://trustedfirmware-m.readthedocs.io/en/latest/integration_guide/services/tfm_secure_partition_addition.html#out-of-tree-secure-partition-build

--------------

*Copyright (c) 2020-2024, Arm Limited. All rights reserved.*
