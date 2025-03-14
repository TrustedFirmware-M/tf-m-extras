#-------------------------------------------------------------------------------
# Copyright (c) 2024-2025, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

Project("DPE Host Build" LANGUAGES C)

set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0048 NEW)
set(ENABLE_TESTING OFF)
set(ENABLE_PROGRAMS OFF)
set(MBEDTLS_FATAL_WARNINGS OFF)
set(ENABLE_DOCS OFF)
set(INSTALL_MBEDTLS_HEADERS OFF)

################################## Fuzzing #####################################

if(FUZZ_TEST)
    if(NOT DEFINED ENV{AFL_LLVM_ALLOWLIST})
        message(FATAL_ERROR
            "The AFL_LLVM_ALLOWLIST environment variable is not defined. "
            "Define it as below to instrument only the DPE library:\n"
            "export AFL_LLVM_ALLOWLIST=<TF_M_EXTRAS_PATH>/partitions/dice_protection_environment/test/fuzz/allowlist.txt")
    endif()
endif()

############################### Crypto Library #################################

add_subdirectory(${MBEDCRYPTO_PATH} mbedtls)

############################### QCBOR Library ##################################

add_subdirectory(${QCBOR_PATH} qcbor)

# Entirely disable the floating-point support
target_compile_definitions(qcbor
    PRIVATE
        QCBOR_DISABLE_FLOAT_HW_USE
        QCBOR_OPT_DISABLE_FLOAT_PREFERRED
        QCBOR_OPT_DISABLE_FLOAT_ALL
)

############################### T_COSE Library #################################

# Empty target just to make build working
add_library(tfm_config INTERFACE)

# Empty target just to make build working
add_library(psa_crypto_config INTERFACE)

include(${TFM_PATH}/lib/ext/t_cose/tfm_t_cose.cmake)

add_library(t_cose STATIC EXCLUDE_FROM_ALL)

target_link_libraries(t_cose
    PUBLIC
        tfm_t_cose_defs
    PRIVATE
        tfm_t_cose_common
        qcbor
        mbedtls
)

############################### DPE Library ####################################

add_library(dpe_lib STATIC EXCLUDE_FROM_ALL)

target_sources(dpe_lib
    PUBLIC
        ../../interface/src/dpe_cmd_encode.c
    PRIVATE
        ../../dpe_certificate.c
        ../../dpe_cmd_decode.c
        ../../dpe_context_mngr.c
        ../../dpe_crypto_interface.c
        ../../dpe_log.c
)

target_include_directories(dpe_lib
    PUBLIC
        ../../interface/include
        ../..
        ${TFM_PATH}/platform/ext/target/arm/rse/common       # platform_locality.h
        ${TFM_PATH}/platform/ext/target/arm/rse/common/dpe   # dpe_plat.h
        ${TFM_PATH}/secure_fw/partitions/lib/runtime/include # tfm_sp_log.h
    PRIVATE
        ${TFM_PATH}/secure_fw/include                        # array.h

)

# Linked due to the headers
target_link_libraries(dpe_lib
    PUBLIC
        t_cose
        mbedtls
        qcbor
)

target_compile_definitions(dpe_lib
    PUBLIC
        TFM_PARTITION_LOG_LEVEL=${TFM_PARTITION_LOG_LEVEL}
    PRIVATE
        DPE_TEST_MODE
)

target_compile_options(dpe_lib
    PRIVATE
        --coverage
)

############################### Test framework #################################

add_subdirectory(${TFM_TEST_PATH}/tests_reg/test/framework/ test_framework)

target_compile_definitions(tfm_test_framework_common
    INTERFACE
        USE_STDIO
)

target_include_directories(tfm_test_framework_common
    INTERFACE
        ${TFM_TEST_PATH}/tests_reg/test/secure_fw/suites/extra/secure
)

############################# DPE Regression Test ##############################

# Empty target just to make build working
add_library(tfm_t_cose_s  INTERFACE)

add_library(tfm_test_suite_extra_s STATIC EXCLUDE_FROM_ALL)

add_subdirectory(../secure dpe_reg_test)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        t_cose
        mbedtls
        qcbor
        tfm_test_framework_common
)

target_include_directories(tfm_test_suite_extra_s
    PRIVATE
        ${TFM_PATH}/interface/include
       ../../interface/include
       ${TFM_PATH}/platform/ext/target/arm/rse/common
)

############################### DPE Host App ###################################

add_executable(dpe_host)

target_sources(dpe_host
    PRIVATE
        ./cmd.c
        ./main.c
        ./plat.c
        ./root_keys.c
        ./client.c
)

target_link_libraries(dpe_host
    PUBLIC
        dpe_lib
        tfm_test_suite_extra_s
        tfm_test_framework_common
)

target_include_directories(dpe_host
    PRIVATE
        .
        ../
)

target_compile_definitions(dpe_host
    PRIVATE
)

target_compile_options(dpe_host
    PRIVATE
        -Og
        -g
)

target_link_options(dpe_host
    PRIVATE
        --coverage
)
