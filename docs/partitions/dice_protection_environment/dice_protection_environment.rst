###########################
DICE Protection Environment
###########################

The DICE Protection Environment (DPE) service makes it possible to execute DICE
commands within an isolated execution environment. It provides clients with an
interface to send DICE commands, encoded as CBOR objects, that act on opaque
context handles. The DPE service performs DICE derivations and certification on
its internal contexts, without exposing the DICE secrets (private keys and CDIs)
outside of the isolated execution environment.

For a full description of DPE, see the
`DPE Specification <https://trustedcomputinggroup.org/wp-content/uploads/TCG-DICE-Protection-Environment-Specification_14february2023-1.pdf>`_.

A high level example of DPE commands usage is shown in the below diagram:

.. figure:: dpe_commands_example_usage.svg
  :align: center

DPE consists of both a runtime service and boot time integration. The DPE
service is currently a work in progress.

*********
Boot time
*********

A platform integrating DPE must perform the following boot-time functions:

- Derive a RoT CDI from the UDS (HUK) provisioned in OTP, lifecycle state and
  measurement of the first firmware stage after ROM (BL1_2), and store it via a
  platform-specific mechanism to be retrieved at runtime.

- Store boot measurements and metadata for all images loaded by the bootloaders
  in the TF-M shared boot data area.

*******************
Runtime DPE service
*******************

The runtime DPE service provides the following functionality.

Initialization
==============

At initialization, DPE completes the following tasks:

- Retrieves and processes offline measurements and metadata from the TF-M shared
  boot data area.

- Retrieves the RoT CDI generated at boot time by calling the
  ``dpe_plat_get_rot_cdi()`` platform function.

- Derives DICE contexts for the RoT certificate and platform certificate, using
  the values processed from boot data and the RoT CDI.

- Shares the initial context handle, corresponding to the newly-created child
  context, with the first client (AP BL1), via a platform-specific mechanism.

Context management
==================

The internal DICE contexts are referred to by clients of the DPE service using
opaque context handles. Each DPE command generates a new context handle that is
returned to the client to refer to the new internal state. Each context handle
can only be used once, so clients must use the "retain context" parameter of the
DPE commands if they wish to obtain a fresh handle to the same context.

The context handles are 32-bit integers, where the lower 16-bits is the index of
the context within the service and the upper 16-bits is a random nonce.

The internal contexts are associated with the 32-bit ID of the owner of the
context. The DPE service only permits the owner to access the context through
its context handle. In the TF-M integration, the ID is bound to the PSA Client
ID of the sender of the DPE message.

Client APIs
===========

The DPE partition in TF-M wraps the DPE commands into PSA messages. The request
manager abstracts PSA message handling, and the remainder of the service avoids
coupling to TF-M partition specifics.

The DPE commands themselves are CBOR-encoded objects that the DPE decode layer
decodes into calls to one of the following supported DICE functions.

DeriveContext
-------------

Adds a component context to the certificate context, consisting of:

- Context handle
- Parent context handle
- Linked certificate context
- Is leaf
- Client ID
- DICE input values

  - Code hash
  - Config value
  - Authority hash
  - Operating mode

When a certificate context is finalized (create_certificate=true), it:

- Computes the Attestation CDI and Sealing CDI.

- Derives an attestation keypair from the Attestation CDI.

- Creates the corresponding certificate and signs it with the previous certificate's
  attestation private key.

- Stores the finalized certificate in DPE partition SRAM.

Certificates are created in the CBOR Web Token (CWT) format, using the QCBOR
and t_cose libraries. CWT is specified in
`RFC 8392 <https://www.rfc-editor.org/rfc/rfc8392.html>`_,
with customization from
`Open DICE <https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#CBOR-UDS-Certificates>`_.

DeriveContext flow diagram
--------------------------

.. figure:: derive_context_flow.svg
  :align: center

GetCertificateChain
-------------------

Returns the full certificate chain leading to a given context.

- Returns the certificate chain (collection of individual certificates) as a
  CBOR array with format [+COSE_Sign1, COSE_Key]. The (pre-provisioned) root
  attestation public key is the first element in the CBOR array.

The following diagram shows a example certificate chain for RSE TC platform:

.. figure:: rse_dice_example_cert_chain.svg
  :align: center

CertifyKey
----------

Generates and returns a leaf certificate. If a public key is supplied,
then it certifies the key. If a public key is not supplied, then it derives key
pair from the accumulated context information for that certificiate and certifies
the public key.

- If the input certificate context (certificate linked to component context) is
  already finalised, then it creates a new leaf certficiate with no measurements.

- If the input certificate context is not finalised, then it creates a leaf certificate
  with all the measurements accumulated for that certificate context.

- Adds label (if supplied) to list of measurements.

- Returns the leaf certificate.

Seal
----

Encrypts and authenticates data using two keys derived from the Sealing CDI,
identifiers of the software components in the chain and a supplied label.

- Not currently implemented.

Unseal
------

Inverse of Seal.

- Not currently implemented.

**********
Host Build
**********

Tested only on Linux and RSE as build platform.

To enable the host build add this to the regular CMake command line:

.. code-block:: bash

    -DHOST_BUILD=ON

Example script (tf-m, tf-m-tests, tf-m-extras path need to be updated):

.. code-block:: bash

    #!/usr/bin/env bash
    ## Update this part ###
    TFM_PATH=<tf-m path>
    TFM_TEST_PATH=<tf-m-tests path>
    TFM_EXTRAS_PATH=<tf-m-extras path>
    CROSS_COMPILER_PATH=<cross-compiler path>
    # Create the build directory
    cd $TFM
    rm -rf build
    mkdir build
    # Execute CMake configuration step to generate the build files
    cmake \
    -S $TFM_PATH \
    -B $TFM_PATH/build \
    -DTFM_PLATFORM=arm/rse/tc/tc2 \
    -DTFM_TOOLCHAIN_FILE=$TF_M/toolchain_GNUARM.cmake \
    -DCMAKE_BUILD_TYPE=Debug \
    -DMCUBOOT_IMAGE_NUMBER=4 \
    -DRSS_GPT_SUPPORT=0 \
    -DTFM_EXTRAS_REPO_PATH=$TFM_EXTRAS_PATH \
    -DTFM_SPM_LOG_LEVEL=3 \
    -DRSE_LOAD_NS_IMAGE=OFF \
    -DTFM_ISOLATION_LEVEL=1 \
    -DCONFIG_TFM_SPM_BACKEND=IPC \
    -DTFM_TEST_PATH=$TFM_TEST_PATH \
    -DCROSS_COMPILE=$CROSS_COMPILER_PATH/gcc-arm-11.2-2022.02-x86_64-arm-none-eabi/bin/arm-none-eabi \
    -DHOST_BUILD=ON
    # Go to the build folder to execute only a partial build
    cd $TFM_PATH/build
    # Build only the host_app target and skip the rest
    make dpe_host

The compiled ``dpe_host`` app is installed to here:

.. code-block:: bash

    <TFM_PATH>/build/bin/host/dpe

There are two main operational modes of the ``dpe_host`` app:

- Regression mode: Invoking without any command line parameter results in
  executing the regular regression test suite.
- Fuzzer mode: Invoking with [-c, -d, -k -g, -r] options can be used to execute
  a single DPE command.

Code coverage
=============

The code coverage measurement is by default enabled in the DPE host build. The
coverage report can be generated as follows:

.. code-block:: bash

    # Find where the *.gcda files are created
    cd <TFM_BUILD_DIR>
    find . -name *.gcda
    lcov --capture --directory <LOCATION_OF_GCDA_FILES> --output-file ./dpe.info
    genhtml --output-directory=./dpe_coverage ./dpe.info

*********
Fuzz test
*********

Compile and install `AFL++ <https://github.com/AFLplusplus/AFLplusplus/>`_,

Read the `doc <https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md>`_
on how to use the fuzzer.

Create a symlink to ``afl-cc``:

.. code-block:: bash

    sudo ln -s afl-cc  afl-clang-lto

Export this environment variable to instrument only the relevant part of the
code:

.. code-block:: bash

    export AFL_LLVM_ALLOWLIST=<TFM_EXTRAS_PATH>/partitions/dice_protection_environment/test/fuzz/allowlist.txt

Add this argument to the CMake command in the Host Build section.

.. code-block:: bash

    -DAFL_CC=<OFF, afl-clang-lto, ..>

Recompile the ``dpe_host`` app with ``afl-cc``.

Execute fuzzing:

.. code-block:: bash

    # Fuzz DeriveContext (dc)
    afl-fuzz -i <TFM_EXTRAS_PATH>/partitions/dice_protection_environment/test/fuzz/input/raw/dc \
    -o <TFM_PATH>/fuzz_out \
    -- <TFM_PATH>/build/bin/host/dpe \
    -d @@
    # Fuzz CertifyKey (ck)
    afl-fuzz -i <TFM_EXTRAS_PATH>/partitions/dice_protection_environment/test/fuzz/input/raw/ck \
    -o <TFM_PATH>/fuzz_out \
    -- <TFM_PATH>/build/bin/host/dpe \
    -k @@
    # Fuzz GetCertificateChain (gcc)
    afl-fuzz -i <TFM_EXTRAS_PATH>/partitions/dice_protection_environment/test/fuzz/input/raw/gcc \
    -o <TFM_PATH>/fuzz_out \
    -- <TFM_PATH>/build/bin/host/dpe \
    -g @@
    # Fuzz CBOR parser (cbor)
    afl-fuzz -i <TFM_EXTRAS_PATH>/partitions/dice_protection_environment/test/fuzz/input/cbor \
    -o <TFM_PATH>/fuzz_out \
    -- <TFM_PATH>/build/bin/host/dpe \
    -c @@

Generate initial input for the fuzzer:

- Raw input means that a simplified subset (buffer related arguments are ignored)
  of the DPE command arguments are provided in a binary format and functions in
  ``<TFM_EXTRAS_PATH>/partitions/dice_protection_environment/test/host/cmd.c``
  turns those into real DPE commands through the DPE client API calls. As a
  result, the CBOR encoding of the commands is proper. The goal in to avoid error
  cases due to CBOR encoding in the command decoder part and be able to test the
  main functionality of the command. The raw binary input files can be generated
  based on these hexdump like files:
  ``<TFM_EXTRAS_PATH>/partitions/dice_protection_environment/test/fuzz/input/raw/*.txt``
  with the following commands:

.. code-block:: bash

    xxd -r dc.txt dc_cmd.bin
    xxd -r ck.txt ck_cmd.bin
    xxd -r gcc.txt gcc_cmd.bin

  Modifying the content of the ``*.txt`` files and generating the binary files
  results in the modification of the DPE command arguments.

  The first byte of the raw data is not strictly related to the DPE command. It
  meants to indicate which hard-coded command sequence to executes before executing
  the actual input. These hard-coded command sequences can be used to build a
  certain state (certificate chain) of the service. They can be found here:
  ``<TFM_EXTRAS_PATH>/partitions/dice_protection_environment/test/dpe_test_data.c``

  DPE command arguments are mostly boolean values. To ensure the normal
  distribution of these in the DPE commands, therefore odd value are converted
  to true and even values to false in the raw input.

- CBOR input means that the input provided through the command line is already a
  proper CBOR encoded DPE command. The input does not go through the DPE client
  API instead it is passed directly to the command parser. When the fuzzer
  modifies the CBOR input it is expected that a lot of CBOR encoding error will
  appear in the input. Therefore this is meant to mainly test the command parser
  part of the DPE service. This type of input is collected so that during the
  regression test the DPE commands are printed to the console and these are
  turned into binary files.


--------------

*Copyright (c) 2023-2024, Arm Limited. All rights reserved.*
