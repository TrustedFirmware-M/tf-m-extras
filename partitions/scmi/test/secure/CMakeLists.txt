#-------------------------------------------------------------------------------
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

if(NOT TEST_S_SCMI_COMMS)
    return()
endif()

add_library(scmi_test_hal INTERFACE)

target_include_directories(scmi_test_hal
    INTERFACE
        hal
)

target_sources(scmi_test_hal
    INTERFACE
        hal/scmi_test_hal.c
        ${PLATFORM_DIR}/ext/common/scmi/scmi_hal_common.c
)

target_sources(tfm_test_suite_extra_s
    PRIVATE
        scmi_s_testsuite.c
)

target_include_directories(tfm_test_suite_extra_s
    PRIVATE
        ../..
)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        scmi_test_hal
        tfm_psa_rot_partition_scmi_comms # Required for psa_manifest/scmi_comms.h
)

# Add a header-only library for properties consumed in TF-M
add_library(tfm_extras_test_secure_headers INTERFACE)

target_include_directories(tfm_extras_test_secure_headers
    INTERFACE
        hal
)

target_include_directories(tfm_extras_test_secure_headers
    INTERFACE
        ../..
)
