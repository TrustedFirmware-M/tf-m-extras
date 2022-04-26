#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.15)

cmake_policy(SET CMP0079 NEW)

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/mx75_armor_lib.a)
    Message(FATAL_ERROR "mx75_armor_lib.a should be download and put under current directory")
else()
    add_library(mx75_armor_lib STATIC IMPORTED)
    set_target_properties(mx75_armor_lib PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/mx75_armor_lib.a)
    set_target_properties(mx75_armor_lib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_include_directories(hw_secure_flash
        PUBLIC
            ../../crypto_interface
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_sources(hw_secure_flash
        PRIVATE
            mx75_armor_vendor.c
            mxic_spi_nor_command.c
           ../../crypto_interface/crypto_interface.c
    )
    target_link_libraries(hw_secure_flash
       PRIVATE
           mx75_armor_lib
    )
endif()
