#-------------------------------------------------------------------------------
# Copyright (c) 2021-2024, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

############################# Configuration ############################################

############################# External Dependencies ############################################

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

set(FREERTOS_SRC_PATH     "DOWNLOAD"  CACHE PATH  "Path to FreeRTOS kernel (or DOWNLOAD to fetch automatically")

add_subdirectory(ext/freertos-kernel freertos-kernel)

############################# TFM NS app #######################################

add_executable(tfm_ns)

# The exported TF-M interfaces
add_subdirectory(${CONFIG_SPE_PATH} ${CMAKE_BINARY_DIR}/spe)

target_sources(tfm_ns
    PRIVATE
        main_ns.c
        clcd_task.c
        draw_task.c
        shared_buffer.c
        pattern.c
        print_log.c
        clcd_dma_wrapper.c
        systimer_armv8-m_timeout.c
        amazon-freertos/aws_demo.c
        $<$<C_COMPILER_ID:ARMClang>:freertos-demo/section_limits.c>

        # CLCD files
        clcd_lib/clcd_mps3_lib.c
        clcd_lib/clcd_mps3_drv.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/timer/armv8m/systimer_armv8-m_drv.c

        # DMA350 unprivileged-specific files
        dma350_lib/dma350_lib_unprivileged.c

        # DMA350 files
        device_definition.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350/dma350_checker_layer.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350/dma350_ch_drv.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350/dma350_drv.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350/dma350_lib.c
        ${CONFIG_SPE_PATH}/platform/device/source/dma350_address_remap.c

        # freeRTOS kernel files
        ${FREERTOS_SRC_PATH}/portable/Common/mpu_wrappers.c
        ${FREERTOS_SRC_PATH}/portable/GCC/ARM_CM85_NTZ/non_secure/port.c
        ${FREERTOS_SRC_PATH}/portable/GCC/ARM_CM85_NTZ/non_secure/portasm.c
        ${FREERTOS_SRC_PATH}/list.c
        ${FREERTOS_SRC_PATH}/queue.c
        ${FREERTOS_SRC_PATH}/tasks.c
        ${FREERTOS_SRC_PATH}/stream_buffer.c
        ${FREERTOS_SRC_PATH}/timers.c
        ${FREERTOS_SRC_PATH}/event_groups.c
        ${FREERTOS_SRC_PATH}/portable/MemMang/heap_4.c
        ${FREERTOS_SRC_PATH}/portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c

        # GNU Arm compiler version greater equal than *11.3.Rel1*
        # has a linker issue that required system calls are missing,
        # such as _read and _write. Add stub functions of required
        # system calls to solve this issue.
        $<$<BOOL:${CONFIG_GNU_SYSCALL_STUB_ENABLED}>:syscalls_stub.c>
)

target_include_directories(tfm_ns
    PRIVATE
        .
        clcd_lib/
        dma350_lib/
        freertos-config/
        amazon-freertos/
        ${CONFIG_SPE_PATH}/interface/include/
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/timer/armv8m/
        # freeRTOS kernel
        ${FREERTOS_SRC_PATH}/include/
        ${FREERTOS_SRC_PATH}/portable/GCC/ARM_CM85_NTZ/non_secure/

        # DMA350
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350
)

target_compile_definitions(tfm_ns
    PRIVATE
        # Needed for DMA-350 library
        CMSIS_device_header=<cmsis.h>
)

target_link_libraries(tfm_ns
    PRIVATE
        platform_ns
        tfm_api_ns
        $<$<BOOL:${CONFIG_TFM_USE_TRUSTZONE}>:tfm_api_ns_tz>
)

set_target_properties(tfm_ns PROPERTIES
    SUFFIX ".axf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(${CMAKE_C_COMPILER_ID} STREQUAL "ARMClang")
set_property(TARGET platform_ns PROPERTY INTERFACE_LINK_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/freertos-demo/corstone310_freertos.sct
)
elseif(${CMAKE_C_COMPILER_ID} STREQUAL "GNU")
set_property(TARGET platform_ns PROPERTY INTERFACE_LINK_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/corstone310_freertos.ld
)
endif()
target_add_scatter_file(tfm_ns)

target_link_options(tfm_ns
    PRIVATE
        $<$<C_COMPILER_ID:GNU>:-Wl,-Map=${CMAKE_BINARY_DIR}/bin/tfm_ns.map>
        $<$<C_COMPILER_ID:ARMClang>:--map>
        $<$<C_COMPILER_ID:IAR>:--map\;${CMAKE_BINARY_DIR}/bin/tfm_ns.map>
)

add_convert_to_bin_target(tfm_ns)

###################### TF-M NS interface api (NS lib) ##########################

target_sources(tfm_api_ns PRIVATE
    ${CONFIG_SPE_PATH}/interface/src/os_wrapper/tfm_ns_interface_rtos.c
)
