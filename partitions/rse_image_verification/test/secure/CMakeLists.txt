#-------------------------------------------------------------------------------
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

if(NOT TEST_S_RSE_IMAGE_VERIFICATION)
    return()
endif()

target_sources(tfm_test_suite_extra_s
    PRIVATE
        rse_image_verification_s_interface_testsuite.c
        mcuboot_test_helpers.c
        st_test_helpers.c
        ../mcuboot_signed_test_image.c
        ../st_signed_test_image.c
)

target_include_directories(tfm_test_suite_extra_s
    PRIVATE
        ..
)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        psa_crypto_config
)

target_compile_definitions(tfm_test_suite_extra_s
    PRIVATE
        TEST_S_RSE_IMAGE_VERIFICATION
)
