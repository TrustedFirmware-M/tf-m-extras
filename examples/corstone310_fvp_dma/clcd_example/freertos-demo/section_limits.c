#include "stdint.h"

extern uint32_t Image$$ER_IROM_NS_FREERTOS_SYSTEM_CALLS$$Base;
extern uint32_t Image$$ER_IROM_NS_FREERTOS_SYSTEM_CALLS_ALIGN$$Limit;
extern uint32_t Image$$ER_IROM_NS_PRIVILEGED$$Base;
extern uint32_t Image$$ER_IROM_NS_PRIVILEGED_ALIGN$$Limit;
extern uint32_t Image$$ER_IROM_NS_UNPRIVILEGED$$Base;
extern uint32_t Image$$ER_IROM_NS_UNPRIVILEGED_ALIGN$$Limit;

extern uint32_t Image$$ER_IRAM_NS_PRIVILEGED$$Base;
extern uint32_t Image$$ER_IRAM_NS_PRIVILEGED_ALIGN$$Limit;
extern uint32_t Image$$ER_IRAM_NS_UNPRIVILEGED$$Base;
extern uint32_t Image$$ER_IRAM_NS_UNPRIVILEGED_ALIGN$$Limit;

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
