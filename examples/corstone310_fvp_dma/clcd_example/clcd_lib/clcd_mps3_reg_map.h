/*
 * Copyright (c) 2022 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file clcd_mps3_reg_map.h
 * \brief Register map for Color LCD.
 */

#ifndef __CLCD_MPS3_REG_MAP_H__
#define __CLCD_MPS3_REG_MAP_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Color LCD register map structure */
struct clcd_mps3_reg_map_t {
    volatile uint32_t char_com;     /* Offset: 0x000 (R/W) Write to the LCD
                                     *          command register, read from
                                     *          the LCD busy register */
    volatile uint32_t char_dat;     /* Offset: 0x004 (R/W) Write/Read LCD
                                     *          data register */
    volatile uint32_t char_rd;      /* Offset: 0x000 (R/ )
                                     *          [31:8] : Reserved
                                     *          [7:0]  : Data from last
                                     *                  request read */
    volatile uint32_t char_raw;     /* Offset: 0x00C (R/W) Write to reset
                                     *          access complete flag, read
                                     *          to determine if data in
                                     *          CHAR_RD is valid
                                     *          [31:1] : Reserved
                                     *          [0]    : indicates Access
                                                        Complete */
    volatile uint32_t char_mask;    /* Offset: 0x010 ( /W) Enable Access
                                                Complete to generate an
                                                interrupt */
    volatile uint32_t char_stat;    /* Offset: 0x014 (R/ ) Status
                                     *          [31:1] : Reserved
                                     *          [0]    : state of Access
                                                        Complete ANDed with
                                                        the CHAR_MASK */
    volatile uint32_t reserved[13];
    volatile uint32_t char_misc;    /* Offset: 0x04C (R/W) Miscellaneous Ctrl
                                     *          [31:7] : Reserved
                                     *          [6]    : CLCD_BL
                                     *          [5]    : CLCD_RD
                                     *          [4]    : CLCD_RS
                                     *          [3]    : CLCD_RESET
                                     *          [2]    : RESERVED
                                     *          [1]    : CLCD_WR
                                     *          [0]    : CLCD_CS */
};

#ifdef __cplusplus
}
#endif

#endif /* __CLCD_MPS3_REG_MAP_H__ */
