#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

if ((NOT TFM_PARTITION_EXTERNAL_TRUSTED_SECURE_STORAGE))
    return()
endif()

####################### Non Secure #############################################

add_library(tfm_test_suite_etss_ns STATIC EXCLUDE_FROM_ALL)

target_sources(tfm_test_suite_etss_ns
    PRIVATE
        non_secure/ns_test_helpers.c
        non_secure/etss_ns_interface_testsuite.c
)

target_include_directories(tfm_test_suite_etss_ns
    PUBLIC
        non_secure
)

target_compile_definitions(tfm_test_suite_etss_ns
    PRIVATE
        DOMAIN_NS=1
        ETSS_MAX_ASSET_SIZE=${ETSS_MAX_ASSET_SIZE}
)

target_link_libraries(tfm_test_suite_etss_ns
    PRIVATE
        tfm_test_framework_ns
        platform_region_defs
        tfm_api_ns
)

target_link_libraries(tfm_ns_tests
    INTERFACE
        tfm_test_suite_etss_ns
)

####################### Secure #################################################

if (TEST_S)
    target_sources(tfm_test_suite_etss_s
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/secure/etss_s_interface_testsuite.c
            ${CMAKE_CURRENT_SOURCE_DIR}/secure/etss_s_reliability_testsuite.c
    )

    target_include_directories(tfm_test_suite_etss_s
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/secure
    )

    target_compile_definitions(tfm_test_suite_etss_s
        PRIVATE
            ETSS_MAX_ASSET_SIZE=${ETSS_MAX_ASSET_SIZE}
    )

    target_link_libraries(tfm_test_suite_etss_s
        PRIVATE
            tfm_test_framework_s
            platform_region_defs
            tfm_psa_rot_partition_etss
            tfm_psa_rot_partition_secure_client_service
            tfm_utilities
            platform_s
    )

    target_link_libraries(tfm_s_tests
        INTERFACE
            tfm_test_suite_etss_s
    )
endif()
