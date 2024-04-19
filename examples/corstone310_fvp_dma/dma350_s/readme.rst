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
1. Build and install the Secure side with the following command:

.. code-block:: bash

 $ cmake -S <tf-m-tests_source_directory>/tests_reg/spe \
    -B build/spe \
    -DTFM_PLATFORM=arm/mps3/corstone310/fvp \
    -DTFM_TOOLCHAIN_FILE=<tf-m_source_dir>/toolchain_<ARMCLANG,GNUARM,IARARM>.cmake \
    -DEXTRA_S_TEST_SUITE_PATH=<tf-m-extras_source_directory>/examples/corstone310_fvp_dma/dma350_s \
    -DCONFIG_TFM_SOURCE_PATH=<tf-m_source_dir> \
    -DTEST_S=ON
 $ cmake --build build/spe -- -j$(nproc) install

2. Then build the Non-Secure side with the following:

.. code-block:: bash

 $ cmake -S <tf-m-tests_source_directory>/tests_reg \
    -B build/nspe \
    -DCONFIG_SPE_PATH=<tf-m-extras_source_directory>/build/spe/api_ns \
    -DTFM_TOOLCHAIN_FILE=<tf-m-extras_source_directory>/build/spe/api_ns/cmake/toolchain_ns_<ARMCLANG,GNUARM,IARARM>.cmake
 $ cmake --build build/nspe -- -j$(nproc)


*Copyright (c) 2022-2024, Arm Limited. All rights reserved.*
