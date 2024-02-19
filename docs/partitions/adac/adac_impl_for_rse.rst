####################################
ADAC implementation for RSE platform
####################################

ADAC Requirements for RSE
=========================

For RSE, ADAC design and implementation must meet below requirements.

1. Since RSE is HES (Hardware Enforced Security) host for CCA (Confidential
   Compute Architecture) system, ADAC functionality must be implemented by RSE.
2. By default, CCA HES and other trusted subsystems debug should be disabled
   all the time.
3. When in a secured (trustworthy) state, no debug should be allowed to RSE,
   and other components of CCA System security Domain.
4. If life cycle is not in a secured state and if a CCA component debug is
   requested, a new debug session should be initiated.
5. Likewise at the end of debug session, all debug interfaces should be closed
   and a system reset is required to return to the previous state.
6. Depending on current policy, the debug start and stop request may require
   a system reset for the request to be processed in a distinct debug session.
   For RSE, a system reset is required for handling debug requests for any
   components of CCA security domain.
7. Finally, CCA Platform Attestation token should be different if any CCA debug
   is enabled.

Implementation Constraints
==========================

PSA ADAC protocol specifies use of asymmetric key cryptography for certificate
parsing and authentication. Ideally, authentication and application of
permissions should be done at the same time in boot so that they cannot be
tampered later on, but

*  BL1 is constrained on memory resources and
*  BL1 is immutable, so any flaw in the authentication scheme would result in
   a permanent security vulnerability.

Hence, authentication has to handled as runtime service while appropriate
permissions can be applied in the bootloader.

Design description
==================

As per the ADAC architecture, debug host must implement Secure Debug Manager
(SDM) component while debug target requires Secure Debug Authenticator (SDA)
as mentioned in architecture specification. Logical link is established
among the above two components to establish secure debug connection.

To meet the above requirements, ADAC protocol is integrated in TF-M as follows:

1. A new ADAC runtime service which calls SDA to authenticate any incoming debug
   request from other components.
2. Above service only acknowledges any incoming debug request if the device is
   in appropriate life cycle state. Else, it rejects any incoming debug request.
   Here the appropriate life cycle state is defined by the platform specific
   policy.
3. Once the service acknowledges the request, it sends the request to the
   core protocol API for authentication.  It also checks if the host has
   appropriate access rights permissions. If it authenticates the host
   successfully, it stores the debug state and may initiate the reset (depending
   on platform policy).
4. On immediate reset, the bootloader (BL1_2) retrieves the stored debug state
   and applies corresponding debug permissions.
5. It also locks the related DCU bits so that the applied permissions stays
   the same throughout the debug session.
6. Runtime service now waits for debug end signal to end debug session. To end
   current debug session, it stores the state again and initiates the reset
   (depending on platform policy).
7. On reset, BL1_2 resets the permission and locks the DCU to continue
   normal execution.
8. For debug request of any components where platform policy does not require a
   reset, ADAC service does not initiate any reset and enables the debug
   immediately.

Hardware abstraction layer Interface
====================================

Classification of various debug zones is platform/system specific.
For system with RSE subsystem, these are mainly classified into CCA security
domain debug and Non-CCA debug zones.

- ``tfm_debug_zones``: enumerates 2 CCA and 4 Non-CCA debug zones.

- ``tfm_platform_system_reset()``: Request system reset to initiate or terminate
  a debug session.

- ``tfm_plat_otp_read()``:  Reads the life cycle state as well as secure debug
  key required for authentication.

Bootloader Interface
====================

The ADAC runtime service requires to convey debug state information between
runtime service and bootloader. This needs be in platform specific
predefined persistent area as this information needs to be retained after reset.

For RSE platform, this functionality is provided by RESET_SYNDROME register.
8 bits field, SWSYN, of above register is allocated to convey debug state
information between bootloader and runtime service

- ``lcm_dcu_set_enabled()``: Apply appropriate debug zone permissions by setting
   the DCU register values.

- ``lcm_dcu_set_locked()``: Locks the DCU so permission cannot be modified
   during that power cycle.

ADAC Protocol (SDA) integration
===============================

- ``tfm_to_psa_adac_rse_secure_debug()``: Initiates the connection with the
  host debugger and performs secure debug authentication process.

Enable Secure Debug
===================

To enable ADAC on RSE, below options must be configured:

- ``-DPLATFORM_PSA_ADAC_SECURE_DEBUG=ON``

- ``-DTFM_PARTITION_ADAC=ON``

--------------

*Copyright (c) 2023, Arm Limited. All rights reserved.*
