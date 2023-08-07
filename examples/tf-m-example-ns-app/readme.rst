########################
TF-M Example Application
########################

This sub-directory provides a bare metal example NS application, demonstrating how to use the
artifacts exported by TF-M build.

The application outputs "Hello TF-M world" and uses a PSA service function to demonstrate
that a NS application can be successfully run.

*****************
The Build Process
*****************

1. Clone the TF-M repository at anywhere, assume the root directory is ``<TF-M Source Dir>``

2. Create a build folder, for example ``build``.

3. Build the TF-M with the following command:

..code-block::bash

  cmake -S <TF-M Source Dir> -B build/spe -DTFM_PLATFORM=arm/mps2/an521 -DTFM_PROFILE=profile_small
  cmake --build build/spe -- install

4. The files necessary to build TF-M will appear in ``build/spe/api_ns``

5. Build this example application:

..code-block::bash

  cmake -S <path_to_this_example> -B build/nspe \
        -DCONFIG_SPE_PATH=<absolute_path_to>/build/spe/api_ns
  cmake --build build/nspe

*******************
Run the Application
*******************
The output binary for the application will be located in ``build/spe/bin`` and ``build/nspe``.
The application can be run using the SSE-200 fast-model using FVP_MPS2_AEMv8M provided by Arm
Development Studio.
Add ``bl2.axf`` and ``tfm_s_ns_signed.bin`` to the symbol files in the Debug Configuration menu.

*Copyright (c) 2023, Arm Limited. All rights reserved.*
