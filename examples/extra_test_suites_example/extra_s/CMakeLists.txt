#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/s_test_config.cmake)

####################### Secure #################################################

add_library(example_test_s STATIC EXCLUDE_FROM_ALL)

target_sources(example_test_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/s_test.c
)

target_include_directories(example_test_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Example test links tfm_test_suite_extra_common to use related interface
target_link_libraries(example_test_s
    PRIVATE
        tfm_test_suite_extra_common
)

# The example_test_s library is linked by tfm_test_suite_extra_s
target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        example_test_s
)
