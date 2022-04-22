######################################
Privileged DMA350 example for FreeRTOS
######################################

FreeRTOS example to use DMA350 with command links from privileged task.

***********
Build steps
***********
1. Run the following command in the tf-m directory:

.. code-block::

 $ cmake -S . -B cmake_build -DTFM_PLATFORM=arm/mps3/corstone310_fvp -DTFM_TOOLCHAIN_FILE=toolchain_ARMCLANG.cmake -DNS_EVALUATION_APP_PATH=<tf-m-extras root>/examples/corstone310_fvp_dma/privileged_example

2. Then:

.. code-block::

 $ cmake --build cmake_build -- install

*Copyright (c) 2022, Arm Limited. All rights reserved.*
