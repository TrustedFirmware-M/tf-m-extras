#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

############################# Configuration ############################################

############################# External Dependencies ############################################

set(FREERTOS_SRC_PATH     "DOWNLOAD"  CACHE PATH  "Path to FreeRTOS kernel (or DOWNLOAD to fetch automatically")

add_subdirectory(ext/freertos-kernel freertos-kernel)

############################# Common variables ############################################

# In actual NS integration, NS side build should include the source files
# exported by TF-M build.
# Directly include interface folder to simplify the NS build in this demo, since
# install always occurs at the end of build.
set(INTERFACE_SRC_DIR    ${CMAKE_SOURCE_DIR}/interface/src)
set(INTERFACE_INC_DIR    ${CMAKE_SOURCE_DIR}/interface/include)
set(TFM_SRC_DIR          ${CMAKE_SOURCE_DIR})

#################### TF-M NS interface (header only) ###########################

add_library(tfm_ns_interface INTERFACE)

# Include interface headers exported by TF-M
target_include_directories(tfm_ns_interface
    INTERFACE
        ${INTERFACE_INC_DIR}
        ${CMAKE_BINARY_DIR}/generated/interface/include
)

# Include selection of Secure Partitions from TF-M build.
# It can be replaced by NS side configurations later.
target_link_libraries(tfm_ns_interface
    INTERFACE
        tfm_partition_defs
)

############################# TFM NS app #######################################

add_executable(tfm_ns)

target_add_scatter_file(tfm_ns
    $<$<C_COMPILER_ID:ARMClang>:${CMAKE_CURRENT_SOURCE_DIR}/freertos-demo/corstone310_freertos.sct>
    $<$<C_COMPILER_ID:GNU>:${CMAKE_CURRENT_SOURCE_DIR}/corstone310_freertos.ld>
)

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
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/common/native_drivers/systimer_armv8-m_drv.c

        # DMA350 unprivileged-specific files
        dma350_lib/dma350_lib_unprivileged.c

        # DMA350 files
        device_definition.c
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers/dma350_ch_drv.c
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers/dma350_drv.c
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/libraries/dma350_lib.c
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/libraries/dma350_checker_layer.c
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/device/source/dma350_address_remap.c

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
)

target_include_directories(tfm_ns
    PRIVATE
        .
        clcd_lib/
        dma350_lib/
        freertos-config/
        amazon-freertos/
        ${INTERFACE_INC_DIR}/
        # freeRTOS kernel
        ${FREERTOS_SRC_PATH}/include/
        ${FREERTOS_SRC_PATH}/portable/GCC/ARM_CM85_NTZ/non_secure/

        # DMA350
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/libraries
)

target_compile_definitions(tfm_ns
    PRIVATE
        MBEDTLS_CONFIG_FILE="aws_mbedtls_config.h"
        # Needed for DMA-350 library
        CMSIS_device_header=<corstone310.h>
)

target_link_libraries(tfm_ns
    PRIVATE
        platform_ns
        tfm_api_ns
        tfm_s_veneers
)

set_target_properties(tfm_ns PROPERTIES
    SUFFIX ".axf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_link_options(tfm_ns
    PRIVATE
        $<$<C_COMPILER_ID:GNU>:-Wl,-Map=${CMAKE_BINARY_DIR}/bin/tfm_ns.map>
        $<$<C_COMPILER_ID:ARMClang>:--map>
        $<$<C_COMPILER_ID:IAR>:--map\;${CMAKE_BINARY_DIR}/bin/tfm_ns.map>
)

add_convert_to_bin_target(tfm_ns)

###################### TF-M NS interface api (NS lib) ##########################

add_library(tfm_api_ns STATIC)

target_sources(tfm_api_ns PRIVATE
    $<$<BOOL:${TFM_PARTITION_PLATFORM}>:${INTERFACE_SRC_DIR}/tfm_platform_api.c>

)

target_sources(tfm_api_ns PRIVATE
    ${INTERFACE_SRC_DIR}/tfm_psa_ns_api.c
    ${TFM_TEST_REPO_PATH}/app/tfm_ns_interface.c
)

target_include_directories(tfm_api_ns PUBLIC
    ${TFM_TEST_REPO_PATH}/ns_interface
)

target_link_libraries(tfm_api_ns
    PUBLIC
        tfm_ns_interface
    PRIVATE
        platform_ns
)

############################# CMSIS ############################################

# Platform cmake config adds sources to CMSIS_5_tfm_ns, so we need to define it, but it is unused.
add_library(CMSIS_5_tfm_ns INTERFACE)
