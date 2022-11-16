###################################
DMA350 Triggering interface example
###################################

Example usage of triggering flow control with DMA350. The DMA350 is configured to control
the data exchange with the UARTs. The CPU can enter into WFI() and the DMA will signal, when
the transactions are done. The CPU only wakes up to proccess the received data, then goes back
to sleep.

***********
Build steps
***********
1. Run the following command in the tf-m directory:

.. code-block::

 $ cmake -S . -B cmake_build -DTFM_PLATFORM=arm/mps3/corstone310/fvp -DTFM_TOOLCHAIN_FILE=toolchain_ARMCLANG.cmake -DNS_EVALUATION_APP_PATH=<tf-m-extras root>/examples/corstone310_fvp_dma/triggering_example

2. Then:

.. code-block::

 $ cmake --build cmake_build -- install

*********
Run steps
*********
The example can run only with 11.18.29 or later versions of Corstone SSE-310 AVH.
The ``mps3_board.uart1_adapter_tx.ENABLE`` and ``mps3_board.uart0_adapter_rx.ENABLE`` parameters have to be set, to enable the triggering interface of the UARTs.
The ``mps3_board.uart0.rx_overrun_mode=0`` parameter is needed. UART overrun can happen when the received data is not handled in time.
The UART overrun interrupt is turned off to prevent lock-up, but there might be data loss when the user sends data during data processing or UART transmitting.

1. Run the following command:

.. code-block::

 ./VHT_Corstone_SSE-310 -a cpu0*="bl2.axf" --data "tfm_s_ns_signed.bin"@0x11040000 -C mps3_board.uart1_adapter_tx.ENABLE=true  -C mps3_board.uart0_adapter_rx.ENABLE=true -C mps3_board.uart0.rx_overrun_mode=0


2. After the FVP starts the following message will be shown in the FVP telnetterminal0:

.. code-block::

 Starting DMA350 Triggering example


 ---------------------------------------------------------
 ---------------------------------------------------------
 Configure DMA350 for TX on UART1, then CPU goes to sleep.
 Type in 10 character to this terminal

Select the FVP telnetterminal0 and type in 10 characters. The 10 characters are going to be echoed back in reverse order to the FVP telnetterminal1.

*Copyright (c) 2022, Arm Limited. All rights reserved.*
