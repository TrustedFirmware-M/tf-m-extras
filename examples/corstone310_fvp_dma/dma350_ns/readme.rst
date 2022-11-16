######################################
Non-Secure DMA350 example for FreeRTOS
######################################

FreeRTOS example to demonstrate the DMA-350 privileged and unprivileged APIs.
The privileged task demonstrates a way of using of command linking feature.
The unprivileged task demonstrates the usage of the unprivileged DMA API through
a simple 2D example.

For detailed description of how privilege separation can be achieved with
DMA-350, checkout :doc:`DMA-350 privilege separation <../../../partitions/dma350_unpriv_partition/dma350_privilege_separation.rst>`_

***********
Build steps
***********
1. Run the following command in the tf-m directory:

.. code-block::

 $ cmake -S . -B cmake_build -DTFM_PLATFORM=arm/mps3/corstone310/fvp -DTFM_TOOLCHAIN_FILE=toolchain_ARMCLANG.cmake -DDEFAULT_NS_SCATTER=OFF -DPLATFORM_SVC_HANDLERS=ON -DNS_EVALUATION_APP_PATH=<tf-m-extras root>/examples/corstone310_fvp_dma/dma350_ns

2. Then:

.. code-block::

 $ cmake --build cmake_build -- install

*Copyright (c) 2022, Arm Limited. All rights reserved.*
