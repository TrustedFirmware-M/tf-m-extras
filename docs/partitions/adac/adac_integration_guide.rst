#########################################
ADAC (Authenticated Debug Access Control)
#########################################

.. toctree::
    :maxdepth: 1

    ADAC Implementation for RSE <adac_impl_for_rse>

************
Introduction
************

Background
==========
In order to make sure debug capabilities of any system do not become attack
vectors, PSA provides reference ADAC system architecture. It specifies
functional layers that reside above actual physical link.

Authenticated Debug Access Control (ADAC), also referred to as Secure Debug, is
a protocol that provides a way to use strong authentication to restrict device
debug access to only authorized entities. Across various life cycle states of
target device, it permits appropriate access to finely configured domains.

Requirements
============
Debug capabilities must achieve several safety goals to be fully resilient.
It requires

1. Strong authentication
2. Finely grained hardware and firmware domains
3. Enforcing debug limitations

ADAC protocol is fully flexible to meet the above goals.  But depending on the
system design and topology, it must be implemented so to meet varying attack
surface.

ADAC runtime services fulfills requirement #1 mentioned above and authenticates
incoming debug request by calling ADAC core protocol Secure debug manager API.

Secure debug policy
===================

Depending on hardware and system topology and security requirements, each
platform may have its own custom policy. It includes (but is not limited to)

1.  Classification of various debug zones
2.  Determination of appropriate debug permissions for each zone
3.  Appropriate life cycle states where debug request should be acknowledged
4.  Whether a new power cycle session is required to initiate and close a specific
    session

Implementation of policies (#1 and #2) is outside of scope of runtime ADAC
service and must be implemented and integrated into suitable layer of firmware.
However, depending on platform specific implementation, ADAC runtime service may
check for appropriate current device life cycle state. It may also request a
system reset to initiate and close a debug session.

************************************
Code structure & Service Integration
************************************

The ADAC Service source and header files are located in the current directory.
The interface for the ADAC runtime Service is located in ``interface/include``.
The only header to be included by applications that want to use functions from
the PSA API is ``tfm_adac_api.h``.

Service interface
=================
The ADAC Service exposes the following interface:

.. code-block:: c

   /*!
   * \brief  Authenticates the requested debug service.
   *
   * \param[in]  debug_request   Request identifier for the debug zone
   *                             (valid values vary based on the platform
   *                             Each  bit of the \p debug_request represents
   *                             debug request for corresponding zone.
   *                             e.g.
   *                             If no bits are set => no debug request
   *                             If bit0 is set     => start debug for zone1
   *                             If bit0 is cleared => end debug for zone1
   *                             If bit1 is set     => start debug for zone2
   *                             If bit1 is cleared => end debug for zone2
   *                             ...
   *
   *                             Enumeration of zones (zone1, zone2, etc.) is
   *                             done by ``tfm_debug_zones`` (platform specific)
   *
   * \return Returns PSA_SUCCESS on success,
   *         otherwise error as specified in \ref psa_status_t
   */
   psa_status_t tfm_adac_service(uint32_t debug_request)

Service source files
====================
-  ``tfm_adac_api.c``: Implements the secure API layer to allow
   other services in the secure domain to request functionalities
   from the adac service using the PSA API interface.

-  ``adac_req_mngr.c``: Includes the initialization entry of
   adac service and handles adac service requests in IPC model.

-  ``adac.c``: Implements core functionalities such as implementation
   of APIs, handling and processing of debug request.

Hardware abstraction layer
==========================
As mentioned above, classification of various debug zones is output of
platform/system specific debug policy formulation.

Below additional HAL interface MAY be required depending on platform policy.

- ``tfm_debug_zones``: enumerates various debug zones.

- ``tfm_platform_system_reset()``: Request system reset to initiate or terminate
  a debug session.

- ``tfm_plat_otp_read()``:  Reads the life cycle state as well as secure debug
  key required for authentication.

Bootloader Interface
====================
The ADAC runtime service requires to convey debug state information between
runtime service and bootloader. Implementation of this functionality is
dependant on platform hardware.

ADAC Protocol (SDA) integration
===============================
ADAC protocol which implements the Secure Debug Authenticator (SDA) component
is source in external github repository.

  ``git@github.com:ARMmbed/psa-adac.git``.

The API to initiate the connection with host debugger and to perform
authentication process is platform specific. It requires secure debug keys as
input for authentication.

For example for RSE platform, the API to integrate is:

- ``tfm_to_psa_adac_rse_secure_debug()``

Please follow the below link for further information on SDA implementation.

| `psa-adac read me`_

.. _psa-adac read me:
  https://developer.arm.com/documentation/den0101/latest

*********
Reference
*********

| `ADAC specification`_

.. _ADAC specification:
  https://developer.arm.com/documentation/den0101/latest

--------------

*Copyright (c) 2022-2023, Arm Limited. All rights reserved.*
