##########
Partitions
##########

The list and simple introduction of 3rd-party Secure Partitions in this folder.

dma350_upriv_partition
======================

Description
-----------
DMA-350 Example unprivileged partition

Maintainers
-----------
- Bence Balogh `<bence.balogh@arm.com> <bence.balogh@arm.com>`_
- Mark Horvath `<mark.horvath@arm.com> <mark.horvath@arm.com>`_

measured_boot
=============

Description
-----------
Measured boot partition for extending and retrieving software component
measurements for RSS platform.

Maintainers
-----------
- Maulik Patel `<Maulik.Patel@arm.com>`_
- David Vincze `<David.Vincze@arm.com>`_

external_trusted_secure_storage
===============================

Description
-----------
ETSS partition for providing external trusted secure storage services
to protect assets stored in external secure Flash from a variety of
security attacks.

Maintainers
-----------
- Poppy Wu `<poppywu@mxic.com.cn>`_

TF-M version
------------
TF-M V1.4.0

delegated_attestation
=====================

Description
-----------
The aim of the partition is to support platforms/systems using a delegated
attestation model by providing services for delegated key generation and
platform attestation token creation.

Maintainers
-----------
- David Vincze `<David.Vincze@arm.com>`_

vad_an552_sp
============

Description
-----------
Secure partition for the AN552 FPGA image. It implements voice activity
detection on the microphone input of the MPS3 board, and if voice detected
(which can be any noise) a short sample (~100 ms) is recorded. Then it can be
calculated that which frequency component has the highest energy in the
recorded sample.

Maintainers
-----------
- Gabor Toth `<gabor.toth@arm.com> <gabor.toth@arm.com>`_
- Mark Horvath `<mark.horvath@arm.com> <mark.horvath@arm.com>`_

---------------------------

*Copyright (c) 2021-2022, Arm Limited. All rights reserved.*
