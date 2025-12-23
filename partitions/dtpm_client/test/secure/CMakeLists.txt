#-------------------------------------------------------------------------------
# SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
# SPDX-License-Identifier: BSD-3-Clause
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

target_sources(tfm_test_suite_extra_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/dtpm_client_s_testsuite.c
)

target_include_directories(tfm_test_suite_extra_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../..
        ${CMAKE_CURRENT_SOURCE_DIR}/../../interface/include
)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        lib_tpm
        psa_crypto_config
        tfm_sprt
        tfm_helper_lib
        platform_region_defs
        dtpm_client_hal
)
