################################
Trusted Firmware-M Extras
################################

The Trusted Firmware-M (TF-M) Extras repository is the extension of the TF-M
main repository to host the examples, demonstrations, third-party modules,
third-party secure partitions, etc.

*******
License
*******

The default license of new source code in this repository is `BSD 3-clause <https://git.trustedfirmware.org/TF-M/tf-m-extras.git/tree/license.rst>`_.

Some source files are contributed by the third-parties or derived from the
external projects. A license file should be included in the root folder of these
source files if it has a different license.

****************
Folder Structure
****************

- `examples`: This folder hosts the examples and demos for TF-M.
- `partitions`: This folder hosts the supplementary or third-party secure
  partitions for TF-M.

*****************************
Contribute to this repository
*****************************

Refer to :doc:`contributing process <TF-M:contributing/contributing_process>`
for the TF-M general contribution guideline.

Please contact `TF-M development mailing list <https://lists.trustedfirmware.org/mailman3/lists/tf-m.lists.trustedfirmware.org>`_
for any question.

.. note::
   If your contribution consists of pre-bulit binaries, please upload your
   binary components to
   `Trusted Firmware binary repository (tf-binaries) <https://git.trustedfirmware.org/tf-binaries.git/about/>`_.
   This respository accepts source files only.

Additional requirements
=======================

- It is expected and strongly recommended to integrate and test your
  example/secure partition with TF-M latest release, to enable new features and
  mitigate known security vulnerabilities.

- List the example and secure partition in
  :doc:`example readme <examples/examples>` and
  :doc:`secure partition readme <partitions/partitions>` respectively.

   - Each example/secure partition shall specify the following information

      - A brief description
      - Maintainers with their contact emails
      - If the example/secure partition is not integrated or tested with the
        latest TF-M release, specify the TF-M version/commit ID tested with.

   - Each example/secure partition shall follow the structure below

     .. code-block:: rst

        Folder name
        ===========

        Description
        -----------
        Simple description

        Maintainers
        -----------
        Maintainer list and emails

        TF-M version
        ------------
        Optional. Specify the TF-M version/commit ID if it is not integrated or
        test with latest TF-M release.

.. toctree::
  :caption: Overview
  :titlesonly:
  :hidden:

  Partitions <partitions/index>
  Examples <examples/index>

.. toctree::
  :caption: Links
  :maxdepth: 1
  :hidden:

  Trusted Firmware-M <https://trustedfirmware-m.readthedocs.io/en/latest/>
  TF-M Tests <https://trustedfirmware-m.readthedocs.io/projects/tf-m-tests/en/latest/>
  TF-M Tools <https://trustedfirmware-m.readthedocs.io/projects/tf-m-tools/en/latest/>

--------------

*Copyright (c) 2021-2022, Arm Limited. All rights reserved.*
