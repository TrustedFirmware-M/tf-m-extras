########################
TF-M Example Application
########################

This **tf-m-example-ns-app** directory provides a bare metal example NS application, demonstrating how to use the
artifacts exported by TF-M build.

The application outputs "Hello TF-M world" and uses a PSA service function to demonstrate
that a NS application can be successfully run.

*****************
The Build Process
*****************

1. Clone the TF-M repository at anywhere, assume the root directory is ``<TF-M Source Dir>``

2. Build the TF-M with the following command:

.. code-block:: bash

  cmake -S <TF-M Source Dir> -B build/spe -DTFM_PLATFORM=arm/mps2/an521 -DTFM_PROFILE=profile_small
  cmake --build build/spe -- install

3. The files necessary to build TF-M will appear in ``build/spe/api_ns``.
   The most important elements are:

   - Bootloader: ``/bin/bl2.*``
   - Secure (S) side binary image: ``/bin/tfm_s.*``
   - PSA API for Non-Secure application ``/interface/*``

4. Build this example TF-M application:

.. code-block:: bash

  cmake -S <path_to_this_example> -B build/nspe -DCONFIG_SPE_PATH=<absolute_path_to>/build/spe/api_ns
  cmake --build build/nspe

5. In output you will get:

   - Non-secure (NS) application in ``build/nspe/bin/tfm_ns.*``
   - Combined S + NS bianry ``build/nspe/bin/tfm_s_ns.bin``
   - Combined S + NS and signed bianry ``build/nspe/bin/tfm_s_ns.bin``

*******************
Run the Application
*******************
The application binary shall be loaded and launched on address ``0x10080000``.
The application can be run using the SSE-200 fast-model using FVP_MPS2_AEMv8M provided by Arm
Development Studio.
Add ``bl2.axf`` and ``tfm_s_ns_signed.bin`` to the symbol files in the Debug Configuration menu.
The following output you shall find in a serial terminal:

.. code-block:: console

  Non-Secure system starting...
  Hello TF-M world
  PSA Framework Version = 1.1
  Testing psa get random number...
  1: psa_generate_random() = 254
  2: psa_generate_random() = 214
  3: psa_generate_random() = 129
  4: psa_generate_random() = 226
  5: psa_generate_random() = 102
  End of TF-M example App

*Copyright (c) 2023, Arm Limited. All rights reserved.*
