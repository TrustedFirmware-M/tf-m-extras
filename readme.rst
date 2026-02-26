#########################
Trusted Firmware-M Extras
#########################

This repository is a collection of additional components, integrations, and
experimental features for Trusted Firmware-M (TF-M).

The repository contains optional functionality that is not part of the
core TF-M tree but may be useful for evaluation, prototyping, platform
integration, or extended use cases.

.. important::
  - The `tf-m-extras` repository is primarily hosted at `git.trustedfirmware.org`_
    with a read-only mirror available on `GitHub`_.
  - The source code in this repository complements the main TF-M project, available at
    https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git

Overview
========

The purpose of ``tf-m-extras`` is to:

* Host optional or experimental features
* Provide integration examples
* Support platform-specific extensions
* Enable early evaluation of new concepts before potential upstreaming
* Offer additional utilities that build on top of TF-M

Content in this repository may be less stable than the core TF-M project
and may contain:

* Additional Secure Partitions
* Platform extensions
* Integration layers
* Example applications
* Experimental features
* Supporting build/configuration files

License
=======

This software is provided under the `BSD-3-Clause license <license.rst>`.
Contributions to this project are accepted under the same license,
with developer sign-off as described in the `Contribution guidelines`_.
Some files taken from external projects are licensed under `Apache-2.0 <apache-2.0.txt>`_

Links
=====

* `Trusted Firmware-M (TF-M) project homepage
  <https://www.trustedfirmware.org/projects/tf-m/>`_
* `TF-M documentation
  <https://trustedfirmware-m.readthedocs.io/en/latest/index.html>`_
* `TF-M Extras documentation (Read the Docs)
  <https://trustedfirmware-m.readthedocs.io/projects/tf-m-extras/en/latest>`_

Feedback and support
====================

Feedback can be submitted via email to the
`TF-M mailing list <tf-m@lists.trustedfirmware.org>`__.

.. _Contribution guidelines: https://trustedfirmware-m.readthedocs.io/en/latest/contributing/contributing_process.html
.. _trustedfirmware.org: https://www.trustedfirmware.org
.. _git.trustedfirmware.org: https://git.trustedfirmware.org/plugins/gitiles/TF-M/tf-m-extras
.. _GitHub: https://github.com/TrustedFirmware-M/tf-m-extras

*Copyright (c) 2026, Arm Limited. All rights reserved.*
