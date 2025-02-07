#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited. All rights reserved.
# Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
# or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

if(${MEASURED_BOOT_HASH_ALG} STREQUAL "PSA_ALG_SHA_512")
    set(MEASUREMENT_VALUE_SIZE 64)
elseif(${MEASURED_BOOT_HASH_ALG} STREQUAL "PSA_ALG_SHA_256")
    set(MEASUREMENT_VALUE_SIZE 32)
else()
    message(FATAL_ERROR "Unknown hash algorithm")
endif()

target_sources(tfm_test_suite_extra_s
    PRIVATE
        ../measured_boot_tests_common.c
        ../measured_boot_common.c
        measured_boot_s_interface_testsuite.c
)

target_include_directories(tfm_test_suite_extra_s
    PRIVATE
        ..
)

target_compile_definitions(tfm_test_suite_extra_s
    PRIVATE
        MEASURED_BOOT_HASH_ALG=${MEASURED_BOOT_HASH_ALG}
        MEASUREMENT_VALUE_SIZE=${MEASUREMENT_VALUE_SIZE}
)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        tfm_sprt #for public header: tfm_measured_boot_api.h
        platform_region_defs
)
