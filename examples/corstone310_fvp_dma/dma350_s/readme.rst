######
Readme
######

Simple test suite to test basic DMA350 operations. Test suite requires a DMA350
peripheral in the platform with Channel 0 configured as secure and that the
DMA350 driver is linked for platform_s library, like for example
mps3/corstone310/fvp.

**********************************************
Build steps for mps3/corstone310/fvp platform
**********************************************
1. Run the following command in the tf-m directory:

.. code-block:: bash

 $ cmake -S . -B cmake_build -DTFM_PLATFORM=arm/mps3/corstone310/fvp -DTFM_TOOLCHAIN_FILE=toolchain_ARMCLANG.cmake -DEXTRA_S_TEST_SUITE_PATH=<tf-m-extras root>/examples/corstone310_fvp_dma/dma350_s

2. Then:

.. code-block:: bash

 $ cmake --build cmake_build -- install


*Copyright (c) 2022, Arm Limited. All rights reserved.*
