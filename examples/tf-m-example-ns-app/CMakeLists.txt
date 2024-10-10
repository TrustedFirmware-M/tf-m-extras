#-------------------------------------------------------------------------------
# Copyright (c) 2023-2024, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.21)

if (NOT DEFINED CONFIG_SPE_PATH OR NOT EXISTS ${CONFIG_SPE_PATH})
    message(FATAL_ERROR "CONFIG_SPE_PATH = ${CONFIG_SPE_PATH} is not defined or incorrect. Please provide full path to TF-M build artifacts using -DCONFIG_SPE_PATH=")
endif()

list(APPEND CMAKE_MODULE_PATH ${CONFIG_SPE_PATH}/cmake)

# A platform specific MCPU and architecture flags for NS side
include(${CONFIG_SPE_PATH}/platform/cpuarch.cmake)
# Include common configs exported from TF-M
include(${CONFIG_SPE_PATH}/cmake/spe_config.cmake)

# Select toolchain file if it is not specified via command line or the absolute path
# is unavailable.
if (NOT DEFINED TFM_TOOLCHAIN_FILE)
    if (NOT DEFINED TFM_TOOLCHAIN)
        set(TFM_TOOLCHAIN "GNUARM")
        message(WARNING "TFM_TOOLCHAIN or TFM_TOOLCHAIN_FILE is not defined")
        message(WARNING "TFM_TOOLCHAIN is set to ${TFM_TOOLCHAIN}")
    endif()
    set(TFM_TOOLCHAIN_FILE    ${CONFIG_SPE_PATH}/cmake/toolchain_ns_${TFM_TOOLCHAIN}.cmake)
endif()

include(${TFM_TOOLCHAIN_FILE})
project("TF-M Example"  LANGUAGES C)

add_executable(tfm_ns)

# The exported TF-M interfaces
add_subdirectory(${CONFIG_SPE_PATH} ${CMAKE_BINARY_DIR}/spe)

target_sources(tfm_ns
    PRIVATE
        main.c
        ${CONFIG_SPE_PATH}/interface/src/os_wrapper/tfm_ns_interface_bare_metal.c
        # GNU Arm compiler version greater equal than *11.3.Rel1*
        # has a linker issue that required system calls are missing,
        # such as _read and _write. Add stub functions of required
        # system calls to solve this issue.
        $<$<BOOL:${CONFIG_GNU_SYSCALL_STUB_ENABLED}>:syscalls_stub.c>
)

target_link_libraries(tfm_ns
    PRIVATE
        tfm_api_ns
)

if (CONFIG_TFM_USE_TRUSTZONE)
    target_link_libraries(tfm_ns
        PRIVATE
            tfm_api_ns_tz
    )
endif()

set_target_properties(tfm_ns PROPERTIES
    SUFFIX ".axf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_add_scatter_file(tfm_ns ${CONFIG_SPE_PATH}/platform/linker_scripts)

target_link_options(tfm_ns
    PRIVATE
        $<$<C_COMPILER_ID:GNU>:-Wl,-Map=${CMAKE_BINARY_DIR}/bin/tfm_ns.map>
        $<$<C_COMPILER_ID:ARMClang>:--map>
        $<$<C_COMPILER_ID:IAR>:--map\;${CMAKE_BINARY_DIR}/bin/tfm_ns.map>
)

add_convert_to_bin_target(tfm_ns)
