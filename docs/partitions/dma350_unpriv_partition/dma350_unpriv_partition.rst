######
Readme
######

TF-M application root of trust partition example for the unprivileged DMA-350
library. It is expected to be used in Isolation Level 2, as the unprivileged API
checks the access rights based on the MPU configuration.
The example demonstrates the proper, non-blocking usage of the library, as well
as some negative tests for invalid channel access, not allocated channel
access, and accesses for privileged memory.
For detailed description of how privilege separation can be achieved with
DMA-350, checkout :doc:`DMA-350 privilege separation <dma350_privilege_separation.rst>`
The partition requires a DMA350 peripheral in the platform with Channel 0 configured as
secure, like for example mps3/corstone310/fvp.

**********************************************
Build steps for mps3/corstone310/fvp platform
**********************************************
1. Run the following command in the tf-m directory:

.. code-block:: bash

 $ cmake -S . -B cmake_build -DTFM_PLATFORM=arm/mps3/corstone310/fvp -DTFM_TOOLCHAIN_FILE=toolchain_ARMCLANG.cmake -DTFM_ISOLATION_LEVEL=2 -DPLATFORM_SVC_HANDLERS=ON -DTFM_EXTRA_PARTITION_PATHS=<tf-m-extras root>/partitions/dma350_unpriv_partition -DTFM_PARTITION_LOG_LEVEL=TFM_PARTITION_LOG_LEVEL_INFO -DTFM_EXTRA_MANIFEST_LIST_FILES=<tf-m-extras root>/partitions/dma350_unpriv_partition/extra_manifest_list.yaml

2. Then:

.. code-block:: bash

 $ cmake --build cmake_build -- install


*Copyright (c) 2022, Arm Limited. All rights reserved.*
