########################################
Unprivileged DMA350 example for FreeRTOS
########################################

FreeRTOS example to use DMA350 from unprivileged task.
For detailed description of how privilege separation can be achieved with
DMA-350, checkout :doc:`DMA-350 privilege separation <dma350_privilege_separation.rst>`

***********
Build steps
***********
1. Run the following command in the tf-m directory:

.. code-block::

 $ cmake -S . -B cmake_build -DTFM_PLATFORM=arm/mps3/corstone310_fvp -DTFM_TOOLCHAIN_FILE=toolchain_ARMCLANG.cmake -DDEFAULT_NS_SCATTER=OFF -DNS_EVALUATION_APP_PATH=<tf-m-extras root>/examples/corstone310_fvp_dma/unprivileged_example

2. Then:

.. code-block::

 $ cmake --build cmake_build -- install

*Copyright (c) 2022, Arm Limited. All rights reserved.*
