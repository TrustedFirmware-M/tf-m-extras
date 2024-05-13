/*
 * FreeRTOS Kernel V10.4.1
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://www.FreeRTOS.org
 * http://aws.amazon.com/freertos
 *
 * 1 tab == 4 spaces!
 */

#include "stdint.h"
#include "region.h"

REGION_DECLARE(Image$$, ER_IROM_NS_FREERTOS_SYSTEM_CALLS, $$Base);
REGION_DECLARE(Image$$, ER_IROM_NS_FREERTOS_SYSTEM_CALLS_ALIGN, $$Limit);
REGION_DECLARE(Image$$, ER_IROM_NS_PRIVILEGED, $$Base);
REGION_DECLARE(Image$$, ER_IROM_NS_PRIVILEGED_ALIGN, $$Limit);
REGION_DECLARE(Image$$, ER_IROM_NS_UNPRIVILEGED, $$Base);
REGION_DECLARE(Image$$, ER_IROM_NS_UNPRIVILEGED_ALIGN, $$Limit);

REGION_DECLARE(Image$$, ER_IRAM_NS_PRIVILEGED, $$Base);
REGION_DECLARE(Image$$, ER_IRAM_NS_PRIVILEGED_ALIGN, $$Limit);
REGION_DECLARE(Image$$, ER_IRAM_NS_UNPRIVILEGED, $$Base);
REGION_DECLARE(Image$$, ER_IRAM_NS_UNPRIVILEGED_ALIGN, $$Limit);

/* Privileged flash. */
const uint32_t * __privileged_functions_start__		= ( uint32_t * ) &( Image$$ER_IROM_NS_PRIVILEGED$$Base );
const uint32_t * __privileged_functions_end__		= ( uint32_t * ) ( ( uint32_t ) &( Image$$ER_IROM_NS_PRIVILEGED_ALIGN$$Limit ) - 0x1 ); /* Last address in privileged Flash region. */

/* Flash containing system calls. */
const uint32_t * __syscalls_flash_start__			= ( uint32_t * ) &( Image$$ER_IROM_NS_FREERTOS_SYSTEM_CALLS$$Base );
const uint32_t * __syscalls_flash_end__				= ( uint32_t * ) ( ( uint32_t ) &( Image$$ER_IROM_NS_FREERTOS_SYSTEM_CALLS_ALIGN$$Limit ) - 0x1 ); /* Last address in Flash region containing system calls. */

/* Unprivileged flash. Note that the section containing system calls is
 * unprivileged so that unprivileged tasks can make system calls. */
const uint32_t * __unprivileged_flash_start__		= ( uint32_t * ) &( Image$$ER_IROM_NS_UNPRIVILEGED$$Base );
const uint32_t * __unprivileged_flash_end__			= ( uint32_t * ) ( ( uint32_t ) &( Image$$ER_IROM_NS_UNPRIVILEGED_ALIGN$$Limit ) - 0x1 ); /* Last address in un-privileged Flash region. */

/* RAM with priviledged access only. This contains kernel data. */
const uint32_t * __privileged_sram_start__			= ( uint32_t * ) &( Image$$ER_IRAM_NS_PRIVILEGED$$Base );
const uint32_t * __privileged_sram_end__			= ( uint32_t * ) ( ( uint32_t ) &( Image$$ER_IRAM_NS_PRIVILEGED_ALIGN$$Limit ) - 0x1 ); /* Last address in privileged RAM. */

/* Unprivileged RAM. */
const uint32_t * __unprivileged_sram_start__		= ( uint32_t * ) &( Image$$ER_IRAM_NS_UNPRIVILEGED$$Base );
const uint32_t * __unprivileged_sram_end__			= ( uint32_t * ) ( ( uint32_t ) &( Image$$ER_IRAM_NS_UNPRIVILEGED_ALIGN$$Limit ) - 0x1 ); /* Last address in un-privileged RAM. */
