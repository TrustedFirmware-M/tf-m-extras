/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "measured_boot_utils.h"
#include "measured_boot_api.h"
#include "tfm_sp_log.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void print_byte_array(const uint8_t *array, size_t len)
{
    size_t i;

    if (array == NULL || len == 0) {
        LOG_DBGFMT("\r\n");
    } else {
        for (i = 0; i < len; ++i) {
            if (array[i] < 0x10) {
               LOG_DBGFMT(" 0%x", array[i]);
            } else {
                LOG_DBGFMT(" %x", array[i]);
            }
            if ((i & 0xFu) == 0xFu) {
                LOG_DBGFMT("\r\n");
                if (i < (len - 1)) {
                    LOG_DBGFMT("               :");
                }
            }
        }
    }
}

static inline void add_null_terminator(uint8_t *dest,
                                       const uint8_t *src,
                                       size_t src_len)
{
    memcpy(dest, src, src_len);
    *(dest + src_len) = '\0';
}

void log_extend_measurement(uint8_t index,
                            const uint8_t *signer_id,
                            size_t signer_id_size,
                            const uint8_t *version,
                            uint8_t version_size,
                            uint32_t measurement_algo,
                            const uint8_t *sw_type,
                            uint8_t sw_type_size,
                            const uint8_t *measurement_value,
                            size_t measurement_value_size,
                            uint8_t lock_measurement)
{
    uint8_t string_buf[((SW_TYPE_MAX_SIZE > VERSION_MAX_SIZE) ?
                         SW_TYPE_MAX_SIZE : VERSION_MAX_SIZE) + 1];

    LOG_DBGFMT("Measured Boot : store and extend measurement:\r\n");
    LOG_DBGFMT(" - slot        : %u\r\n", index);
    LOG_DBGFMT(" - signer_id   :");
    print_byte_array(signer_id, signer_id_size);
    add_null_terminator(string_buf, version, version_size);
    LOG_DBGFMT(" - version     : %s\r\n", string_buf);
    LOG_DBGFMT(" - algorithm   : %x\r\n", measurement_algo);
    add_null_terminator(string_buf, sw_type, sw_type_size);
    LOG_DBGFMT(" - sw_type     : %s\r\n", string_buf);
    LOG_DBGFMT(" - measurement :");
    print_byte_array(measurement_value, measurement_value_size);
    LOG_DBGFMT(" - locking     : %s\r\n", lock_measurement ? "true" : "false");
}
