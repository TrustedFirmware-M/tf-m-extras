################################################################
Trusted Firmware-M Voice Activity Detection Example Threat Model
################################################################

************
Introduction
************

This document extends the generic threat model of Trusted Firmware-M (TF-M).
This threat model provides an analysis of Voice Activity Detection (VAD) Example
in TF-M and identifies general threats and mitigation.

Scope
=====

TF-M supports diverse models and topologies. It also implements multiple
isolation levels. Each case may focus on different target of evaluation (TOE)
and identify different assets and threats.
TF-M implementation consists of several secure services, defined as
Root of Trust (RoT) service. Those RoT services belong to diverse RoT
(Application RoT or PSA RoT) and access different assets and hardware. Therefore
each RoT service may require a dedicated threat model.

This analysis only focuses on the assets and threats introduced by the VAD
example. The TF-M implementation, topologies, or other RoT services are out of
scope of this document.

Methodology
===========

The threat modeling in this document follows the process listed below to
build up the threat model.

- Target of Evaluation (TOE)
- Assets identification
- Data Flow Diagram (DFD)
- Threats prioritization
- Threats identification

TOE is the entity on which threat modeling is performed. The logic behind this
process is to firstly investigate the TOE which could be a system, solution or
use case. This first step helps to identify the assets to be protected in TOE.

According to TOE and assets, Trust Boundaries can be determined. The Data Flow
Diagram (DFD) across Trust Boundaries is then defined to help identify the
threats.

Those threats should be prioritized based on a specific group of principals and
metrics. The principals and metrics should also be specified.

********************
Target of Evaluation
********************

A typical TF-M system diagram can be seen on `Generic Threat Model <Generic-Threat-Model_>`_.
TF-M is running in the Secure Processing Environment (SPE) and NS software is
running in Non-secure Processing Environment (NSPE).

The TOE in this general model is the VAD Secure Partition and the interaction of
peripherals, and NSPE. The VAD algorithm itself and its possible flaws are not
in scope of this document, however the threats that such flaws can cause and its
mitigations are in scope.

********************
Asset identification
********************

In this threat model, assets include the items listed below:

- Software RoT data, e.g.

    - Secure partition code and data
    - NSPE data stored in SPE
    - Data generated in SPE as requested by NSPE
    - Data flowing from peripherals to SPE

- Availability of entire RoT service
- Result of a RoT service

*****************
Data Flow Diagram
*****************

The list and details of data flows are described in the `Generic Threat Model <Generic-Threat-Model_>`_.
In addition to the data flows above, this use-case introduces a new data flow
from a peripheral to the SPE. Although the peripheral resides within the SPE,
the data from it is external so must be considered as data crossing a trust
boundary. This Data flow will be labeled as DF7 from now on.

.. note::

  All the other data flows across the Trusted Boundary besides the valid ones
  mentioned in the `Generic Threat Model <Generic-Threat-Model_>`_ and above
  should be prohibited by default. Proper isolation must be configured to
  prevent NSPE directly accessing SPE.

  Although the data flows are covered in general in the TF-M Generic Threat
  Model, for DF2-DF5, given the inner workings and flow of control in VAD
  partition, additional threats are also considered. Threats identified in the
  Generic Threat Model still applies.

*********************
Threat identification
*********************

Threat priority
===============

Threat priority is indicated by the score calculated via Common Vulnerability
Scoring System (CVSS) Version 3.1 [CVSS]_. The higher the threat scores, the
greater severity the threat is with and the higher the priority is.

CVSS scores can be mapped to qualitative severity ratings defined in CVSS 3.1
specification [CVSS_SPEC]_. This threat model follows the same mapping between
CVSS scores and threat priority rating.

This document focuses on *Base Score* which reflects the constant and general
severity of a threat according to its intrinsic characteristics.

The *Impacted Component* defined in [CVSS_SPEC]_ refers to the assets listed in
`Asset identification`_.

Threats and mitigation list
===========================

This section lists generic threats and corresponding mitigation, based on the
the analysis of data flows in `Data Flow Diagram`_.

Threats are identified following ``STRIDE`` model. Please refer to [STRIDE]_ for
more details.

The field ``CVSS Score`` reflects the threat priority defined in
`Threat priority`_. The field ``CVSS Vector String`` contains the textual
representation of the CVSS metric values used to score the threat. Refer to
[CVSS_SPEC]_ for more details of CVSS vector string.

.. note::

  A generic threat may have different behaviors and therefore require different
  mitigation, in diverse TF-M models and usage scenarios.

  This threat model document focuses on threats specific to the VAD partition.
  Similar threats might exist in the generic threat model with different
  consequense or severity. For the details of generic threats in general usage
  scenario, please refer to the `Generic Threat Model <Generic-Threat-Model_>`_ document.

NSPE requests TF-M secure service
---------------------------------

This section identifies threats on ``DF2`` defined in `Data Flow Diagram`_.

.. table:: TFM-VAD-REQUEST-SERVICE-I-1
  :widths: 10 50

  +---------------+------------------------------------------------------------+
  | Index         | **TFM-VAD-REQUEST-SERVICE-I-1**                            |
  +---------------+------------------------------------------------------------+
  | Description   | A malicious NS application may extract result of a VAD     |
  |               | service request by measuring time while the service was    |
  |               | unavailable for further request.                           |
  +---------------+------------------------------------------------------------+
  | Justification | A malicious NS application may request VAD service to      |
  |               | perform voice activity detection, while another legit NS   |
  |               | app is doing so. By measuring how much time it takes for   |
  |               | the service to became available, it can be extracted if    |
  |               | there was voice activity or not.                           |
  +---------------+------------------------------------------------------------+
  | Category      | Information disclose                                       |
  +---------------+------------------------------------------------------------+
  | Mitigation    | Not yet. Service could use non-blocking or callback based  |
  |               | Implementation.                                            |
  +---------------+------------------------------------------------------------+
  | CVSS Score    | 2.9 (Low)                                                  |
  +---------------+------------------------------------------------------------+
  | CVSS Vector   | CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N               |
  | String        |                                                            |
  +---------------+------------------------------------------------------------+

.. table:: TFM-VAD-REQUEST-SERVICE-D-1
  :widths: 10 50

  +---------------+------------------------------------------------------------+
  | Index         | **TFM-VAD-REQUEST-SERVICE-D-1**                            |
  +---------------+------------------------------------------------------------+
  | Description   | A Malicious NS applications may frequently call secure     |
  |               | services to block secure service requests from other NS    |
  |               | applications.                                              |
  +---------------+------------------------------------------------------------+
  | Justification | TF-M runs on IoT devices with constrained resource. Even   |
  |               | though multiple outstanding NS PSA Client calls can be     |
  |               | supported in system, the number of NS PSA client calls     |
  |               | served by TF-M simultaneously are still limited.           |
  |               |                                                            |
  |               | Therefore, if a malicious NS application or multiple       |
  |               | malicious NS applications continue calling TF-M secure     |
  |               | services frequently, it may block other NS applications to |
  |               | request secure service from TF-M.                          |
  |               |                                                            |
  |               | For VAD service request, this can have more consequense as |
  |               | the current implementation is blocking Secure thread.      |
  +---------------+------------------------------------------------------------+
  | Category      | Denial of service                                          |
  +---------------+------------------------------------------------------------+
  | Mitigation    | TF-M is unable to manage behavior of NS applications.      |
  |               | Assets are not disclosed and TF-M is neither directly      |
  |               | impacted in this threat.                                   |
  |               |                                                            |
  |               | Repeatedly exploiting this vulnerability could distrupt    |
  |               | and decrease the availability of TF-M and other secure     |
  |               | servicese, but not completely. Because of this, the        |
  |               | availability vector of the threat is considered high.      |
  |               |                                                            |
  |               | It relies on NS OS to enhance scheduling policy and        |
  |               | prevent a single NS application to occupy entire CPU time. |
  |               | It is beyond the scope of this threat model.               |
  +---------------+------------------------------------------------------------+
  | CVSS Score    | 6.2 (Medium)                                               |
  +---------------+------------------------------------------------------------+
  | CVSS Vector   | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H               |
  | String        |                                                            |
  +---------------+------------------------------------------------------------+

NS interrupts preempts SPE execution
------------------------------------

This section identifies threats on ``DF5`` defined in `Data Flow Diagram`_.

.. table:: TFM-VAD-NS-INTERRUPT-T-D-1
  :widths: 10 50

  +---------------+------------------------------------------------------------+
  | Index         | **TFM-VAD-NS-INTERRUPT-T-D-1**                             |
  +---------------+------------------------------------------------------------+
  | Description   | An attacker may trigger spurious NS interrupts frequently  |
  |               | to block SPE execution.                                    |
  +---------------+------------------------------------------------------------+
  | Justification | In single Armv8-M core scenario, an attacker may inject a  |
  |               | malicious NS application or hijack a NS hardware to        |
  |               | frequently trigger spurious NS interrupts to keep          |
  |               | preempting SPE and block SPE to perform normal secure      |
  |               | execution.                                                 |
  |               |                                                            |
  |               | Blocking VAD service long enough can cause loss of input   |
  |               | data from peripherals to the service, possibly changing    |
  |               | the return value of the service request.                   |
  +---------------+------------------------------------------------------------+
  | Category      | Tampering / Denial of service                              |
  +---------------+------------------------------------------------------------+
  | Mitigation    | It is out of scope of TF-M.                                |
  |               |                                                            |
  |               | Assets protected by TF-M won't be leaked. TF-M won't be    |
  |               | directly impacted.                                         |
  +---------------+------------------------------------------------------------+
  | CVSS Score    | 5.1 (Medium)                                               |
  +---------------+------------------------------------------------------------+
  | CVSS Vector   | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L               |
  | String        |                                                            |
  +---------------+------------------------------------------------------------+

Data from peripherals to SPE
------------------------------------

This section identifies threats on ``DF7`` defined in `Data Flow Diagram`_.

.. table:: TFM-VAD-PERIPH-DATA-TO-SPE-T-D-1
  :widths: 10 50

  +---------------+------------------------------------------------------------+
  | Index         | **TFM-VAD-PERIPH-DATA-TO-SPE-T-D-1**                       |
  +---------------+------------------------------------------------------------+
  | Description   | An attacker may gain ability to artificially modify the    |
  |               | data and may trigger untested data paths within the voice  |
  |               | activity detection algorithm.                              |
  +---------------+------------------------------------------------------------+
  | Justification | TF-M is unable to prevent manipulation of external data,   |
  |               | attacker might inject malicious data through the           |
  |               | peripheral. The VAD algorithm is considered trusted, but   |
  |               | given its complexity, might be subject to vulnaribilities  |
  |               | within its data flow.                                      |
  |               |                                                            |
  |               | By carefully crafted data, an attacker might be able to    |
  |               | cause the failure of the VAD algorithm. It can also be     |
  |               | used or gain in-depth knowledge of the algorithm, possibly |
  |               | making it prone to adversarial attacks. The attacker might |
  |               | also be able to read data accessible within the secure     |
  |               | partition that the VAD algorithm is running in.            |
  +---------------+------------------------------------------------------------+
  | Category      | Tampering / Denial of service                              |
  +---------------+------------------------------------------------------------+
  | Mitigation    | It is out of scope of TF-M to mitigate vulnerabilities     |
  |               | within the VAD algorithm, however TF-M is responsible for  |
  |               | properly isolating the algorithm within the secure         |
  |               | partition, so vulnerabilities must not propagate.          |
  +---------------+------------------------------------------------------------+
  | CVSS Score    | 6.8 (Medium)                                               |
  +---------------+------------------------------------------------------------+
  | CVSS Vector   | CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H               |
  | String        |                                                            |
  +---------------+------------------------------------------------------------+

***************
Version control
***************

.. table:: Version control

  +---------+--------------------------------------------------+---------------+
  | Version | Description                                      | TF-M version  |
  +=========+==================================================+===============+
  | v1.0    | First version                                    | TF-M v1.6.0   |
  +---------+--------------------------------------------------+---------------+

*********
Reference
*********

.. [Security-Incident-Process] `Security Incident Process <https://developer.trustedfirmware.org/w/collaboration/security_center/reporting/>`_

.. [Generic-Threat-Model] `Generic Threat Model <https://tf-m-user-guide.trustedfirmware.org/docs/security/threat_models/generic_threat_model.html>`_

.. [FF-M] `Arm® Platform Security Architecture Firmware Framework 1.0 <https://developer.arm.com/-/media/Files/pdf/PlatformSecurityArchitecture/Architect/DEN0063-PSA_Firmware_Framework-1.0.0-2.pdf?revision=2d1429fa-4b5b-461a-a60e-4ef3d8f7f4b4>`_

.. [DUAL-CPU-BOOT] `Booting a dual core system <https://tf-m-user-guide.trustedfirmware.org/docs/technical_references/design_docs/dual-cpu/booting_a_dual_core_system.html>`_

.. [CVSS] `Common Vulnerability Scoring System Version 3.1 Calculator <https://www.first.org/cvss/calculator/3.1>`_

.. [CVSS_SPEC] `CVSS v3.1 Specification Document <https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf>`_

.. [STRIDE] `The STRIDE Threat Model <https://docs.microsoft.com/en-us/previous-versions/commerce-server/ee823878(v=cs.20)?redirectedfrom=MSDN>`_

.. [SECURE-BOOT] `Secure boot <https://tf-m-user-guide.trustedfirmware.org/docs/technical_references/design_docs/tfm_secure_boot.html>`_

.. [ROLLBACK-PROTECT] `Rollback protection in TF-M secure boot <https://tf-m-user-guide.trustedfirmware.org/docs/technical_references/design_docs/secure_boot_rollback_protection.html>`_

.. [STACK-SEAL] `Armv8-M processor Secure software Stack Sealing vulnerability <https://developer.arm.com/support/arm-security-updates/armv8-m-stack-sealing>`_

.. [ADVISORY-TFMV-1] `Advisory TFMV-1 <https://tf-m-user-guide.trustedfirmware.org/docs/security/security_advisories/stack_seal_vulnerability.html>`_

.. [ADVISORY-TFMV-2] `Advisory TFMV-2 <https://tf-m-user-guide.trustedfirmware.org/docs/security/security_advisories/svc_caller_sp_fetching_vulnerability.html>`_

--------------------

*Copyright (c) 2020-2022 Arm Limited. All Rights Reserved.*
