#-------------------------------------------------------------------------------
# SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
# SPDX-License-Identifier: BSD-3-Clause
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

target_sources(tfm_test_suite_extra_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/dtpm_client_s_testsuite.c
)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        psa_crypto_config
        tfm_sprt
        platform_region_defs
)
