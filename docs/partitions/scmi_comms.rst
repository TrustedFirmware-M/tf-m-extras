####################
SCMI Comms Partition
####################

Use the SCMI Comms partition to implement a minimal version of the SCMI [1]_
protocol that subscribes to system power state notifications from the SCP [2]_.


.. Note::

 - It currently supports only the shared memory based transport protocol.
   Refer to :doc:`Building Tests </building/tests_build_instruction>` on how to
   build TF-M regression tests and PSA Arch tests to verify TF-M.
 - It is designed to work primarily between RSE and a power control framework,
   such as the one implemented by the SCP-firmware (SCP).


***********************
Supported message types
***********************

The partition supports the System power management protocol [1]_. It can send
the following message types:

- SYSTEM_POWER_STATE_NOTIFY

It can receive the following message types:

- SYSTEM_POWER_STATE_SET
- SYSTEM_POWER_STATE_NOTIFIER

**************
Code structure
**************

Partition source files:

- ``scmi_comms.c``: Implements the core SCMI message handling.
- ``scmi_comms.h``: Common definitions used within the partition.
- ``scmi_hal.h``: Hardware abstraction layer that must be implemented by the
  platform to support the SCMI Comms partition.

TF-M-provided source and header files:

- ``scmi_protocol.h``: Defines values from the SCMI spec.
- ``scmi_system_power.c``: Provides the SCMI System Power Protocol
- ``scmi_system_power.h``: Provides the SCMI System Power Protocol definitions
- ``scmi_common.h``: Common definitions for SCMI protocols and messages

The target platform must provide:

- ``scmi_plat_defs.h``: Provides details for the shared memory

Build options for out of tree build
===================================

- ``TFM_PARTITION_SCMI_COMMS``: To build the SCMI Comms secure partition its
  value should be ``ON``. By default, it is switched ``OFF``.

- ``TFM_EXTRA_MANIFEST_LIST_FILES``: ``<tf-m-extras-repo>/partitions/scmi/scmi_comms_manifest_list.yaml``

- ``TFM_EXTRA_PARTITION_PATHS``: ``<tf-m-extras-repo>/partitions/scmi``

****************
Platform porting
****************

To use the SCMI Comms partition, a platform must supply an interface library
called ``scmi_hal`` for the partition to link against. The library must contain
implementations of all of the functions declared in ``scmi_hal.h``. It must also
contain a header called ``scmi_plat_defs.h``, with the following definitions:

- ``SCP_SHARED_MEMORY_BASE``: The base address of a memory area shared between
  SCP and the CPU running TF-M, which is used to pass messages via the SCMI
  shared memory transport protocol.
- ``SCP_SHARED_MEMORY_SIZE``: The size of the SCP shared memory area. The
  maximum SCMI message length that can be transported is the size of this area
  minus the ``24`` bytes used by the transport protocol.

Additionally, the platform must define ``SCP_DOORBELL_IRQ`` to be the IRQ number
triggered by the SCP doorbell in its ``config_tfm_target.h`` header. It must
also implement that IRQ's handler function to route the request to the SCMI
comms partition (see
:doc:`TF-M Secure IRQ integration guide<TF-M:integration_guide/tfm_secure_irq_integration_guide>`
for more details).

To successfully enable tests, the platform will need to link its targets to
``tfm_extras_test_secure_headers``.

***************************
Completion interrupt option
***************************

The SCMI specification describes a shared-memory–based transport that allows for
a completion interrupt. The completion interrupt option enables the caller to
receive an interrupt after the callee completes the message response.

Currently, the completion interrupt mode is not supported.
The code related to this feature is guarded by the
``TRANSPORT_COMPLETION_INTERRUPT_SUPPORTED`` macro.

*******
Testing
*******

A regression test suite for the Secure processing environment is provided in
``test/secure/scmi_s_testsuite.c``. To test the partition locally, the tests
rely on modifying the partition to use the ``TFM_TIMER0_IRQ`` IRQ source to
trigger its interrupt handler. The tests then use the ``tfm_plat_test.h`` APIs
to trigger the timer interrupt and cause the partition to handle an SCMI
message. They also reimplement the HAL so that the shared memory and doorbell
state are in local memory.

To run the tests, all of the following build options need to be supplied:

- ``TFM_EXTRA_MANIFEST_LIST_FILES``: Change to use
  ``<tf-m-extras-repo>/partitions/scmi/test/secure/scmi_comms_manifest_list.yaml``
  instead of the standard manifest.
- ``EXTRA_S_TEST_SUITE_PATH``: ``<tfm_extras_dir>/partitions/scmi/test/secure``
- ``TEST_S_SCMI_COMMS``: Set to ``ON`` to enable the tests and test HAL.

***********
Limitations
***********

Note that currently this partion:
- does not perform system discovery at initialization stage, thus the platform
  needs to ensure that the support required by this agent is in place.
  For example, the SCMI System Power protocol should be available and this agent
  can subscribe to notifications.
- is aligned with version 0x10000 of the System Power protocol.
- when acting as a receiver, it only supports
  SCMI_MESSAGE_ID_SYS_POWER_STATE_SET as input command.

**********
References
**********

.. [1] `Arm System Control and Management Interface (SCMI) <https://developer.arm.com/documentation/den0056/latest/>`_

.. [2] `SCP-Firmware (SCP) <https://developer.arm.com/Tools%20and%20Software/SCP%20Firmware>`_

--------------

*SPDX-License-Identifier: BSD-3-Clause*

*SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors*
