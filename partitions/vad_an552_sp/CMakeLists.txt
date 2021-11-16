#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

# Voice activity algorithm is fetched from external repository
set(ARM_ENDPOINTAI_SRC_PATH     "DOWNLOAD"  CACHE PATH      "Path to Arm's EndpointAI repository (or DOWNLOAD to fetch automatically")
add_subdirectory(ext/arm-endpoint-ai)

# CMSIS 5 repository
set(CMSIS_5_SRC_PATH    "DOWNLOAD"  CACHE PATH      "Path to CMSIS_5 repository (or DOWNLOAD to fetch automatically")
add_subdirectory(ext/CMSIS)

add_library(tfm_app_rot_partition_vad_an552 STATIC)

target_sources(tfm_app_rot_partition_vad_an552
    PRIVATE
        Libraries/audio_codec_mps3.c
        Libraries/systimer_armv8-m_timeout.c
        native_drivers/i2c_sbcon_drv.c
        native_drivers/audio_i2s_mps3_drv.c
        ${CMAKE_SOURCE_DIR}/platform/ext/target/arm/mps3/an552/native_drivers/systimer_armv8-m_drv.c
        vad_an552_device_definition.c
        vad_an552_sp_main.c

        ${ARM_ENDPOINTAI_SRC_PATH}/Kernels/tinyVAD/tinyVAD.c

        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/StatisticsFunctions/arm_max_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/ComplexMathFunctions/arm_cmplx_mag_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/FastMathFunctions/arm_sqrt_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/TransformFunctions/arm_rfft_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/TransformFunctions/arm_rfft_init_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/TransformFunctions/arm_cfft_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/BasicMathFunctions/arm_shift_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/CommonTables/arm_common_tables.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/CommonTables/arm_const_structs.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/TransformFunctions/arm_cfft_radix4_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/TransformFunctions/arm_bitreversal2.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/TransformFunctions/arm_bitreversal.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/TransformFunctions/arm_cfft_init_q15.c
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Source/CommonTables/arm_mve_tables.c
)

target_include_directories(tfm_app_rot_partition_vad_an552
    PRIVATE
        .
        Libraries
        native_drivers
        ns_interface
        ${CMAKE_BINARY_DIR}/generated
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/Include
        ${CMSIS_5_SRC_PATH}/CMSIS/DSP/PrivateInclude
)

target_compile_definitions(tfm_app_rot_partition_vad_an552
    INTERFACE
        CONFIG_TFM_BUILDING_SPE=1
        ARM_ALL_FFT_TABLES
)

target_compile_options(tfm_app_rot_partition_vad_an552
    PRIVATE
        -flax-vector-conversions
)

target_include_directories(tfm_partitions
    INTERFACE
        .
        ${CMAKE_BINARY_DIR}/generated
)

# IRQ handler should be part of SPM, the actual handling of the IRQ is done
# in the partition
target_sources(tfm_spm
    PRIVATE
        i2s_spm_irq.c
)

# The generated sources
target_sources(tfm_app_rot_partition_vad_an552
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/auto_generated/intermedia_vad_an552_sp.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/auto_generated/load_info_vad_an552_sp.c
)

target_link_libraries(tfm_app_rot_partition_vad_an552
    PRIVATE
        psa_interface
        platform_s
        tfm_sprt
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_vad_an552
)
