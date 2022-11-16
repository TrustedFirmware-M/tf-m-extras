#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

############################# Configuration ############################################


############################# Common variables ############################################
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

target_include_directories(tfm_ns
    PRIVATE
        # DMA350
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/libraries
)

target_sources(tfm_ns
    PRIVATE
        main_ns.c
        # DMA350 files
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers/dma350_ch_drv.c
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers/dma350_drv.c
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/libraries/dma350_lib.c
        ${TFM_SRC_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/device/source/dma350_address_remap.c
)

target_compile_definitions(tfm_ns
    PRIVATE
        # Needed for DMA-350 library
        CMSIS_device_header=<corstone310.h>
)

target_link_libraries(tfm_ns
    PRIVATE
        platform_ns
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

############################# CMSIS ############################################

# Platform cmake config adds sources to CMSIS_5_tfm_ns, so we need to define it, but it is unused.
add_library(CMSIS_5_tfm_ns INTERFACE)
