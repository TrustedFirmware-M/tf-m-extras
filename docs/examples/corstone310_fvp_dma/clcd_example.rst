######################################
Non-Secure DMA350 example for FreeRTOS
######################################

.. toctree::
  :maxdepth: 1
  :titlesonly:

  DMA-350 Triggering interface <triggering_example>

FreeRTOS example to demonstrate the DMA-350 privileged and unprivileged APIs.
The privileged task demonstrates a way of using of command linking feature.
The unprivileged task demonstrates the usage of the unprivileged DMA API through
a simple 2D example.

For detailed description of how privilege separation can be achieved with
DMA-350, checkout :doc:`DMA-350 privilege separation <../../partitions/dma350_unpriv_partition/dma350_privilege_separation>`

***********
Build steps
***********
1. Build Secure TF-M with the following commands:

.. code-block::

 $ cmake -S <TF-M Source Dir> -B build/spe -DTFM_PLATFORM=arm/mps3/corstone310/fvp -DTFM_PROFILE=profile_small
 $ cmake --build build/spe -- -j$(nproc) install

2. Then to build the Non-Secure app:

.. code-block::

 $ cmake -S <path_to_this_example> -B build/nspe -DCONFIG_SPE_PATH=<absolute_path_to>/build/spe/api_ns
 $ cmake --build build/nspe -- -j$(nproc)

*Copyright (c) 2022-2024, Arm Limited. All rights reserved.*
