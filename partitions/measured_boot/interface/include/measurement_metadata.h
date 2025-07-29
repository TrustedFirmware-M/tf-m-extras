/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */
#ifndef __MEASUREMENT_METADATA_H__
#define __MEASUREMENT_METADATA_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Minimum measurement value size that can be requested to store */
#define MEASUREMENT_VALUE_MIN_SIZE          32U
/* Maximum measurement value size that can be requested to store */
#define MEASUREMENT_VALUE_MAX_SIZE          64U
/* Minimum signer id size that can be requested to store */
#define SIGNER_ID_MIN_SIZE   MEASUREMENT_VALUE_MIN_SIZE
/* Maximum signer id size that can be requested to store */
#define SIGNER_ID_MAX_SIZE   MEASUREMENT_VALUE_MAX_SIZE
/* The theoretical maximum image version is: "255.255.65535\0" */
#define VERSION_MAX_SIZE                    14U
/* Example sw_type: "TFM_BLX, AP_BL1, etc." */
#define SW_TYPE_MAX_SIZE                    32U

#define NUM_OF_MEASUREMENT_SLOTS            32U

#define MEASUREMENT_VALUE_INIT_PATTERN        0

struct measurement_metadata_t {
    uint8_t  signer_id[SIGNER_ID_MAX_SIZE];
    size_t   signer_id_size;
    uint8_t  version[VERSION_MAX_SIZE];
    size_t   version_size;
    uint32_t measurement_algo;
    uint8_t  sw_type[SW_TYPE_MAX_SIZE];
    size_t   sw_type_size;
};

struct measurement_value_t {
    uint8_t hash_buf[MEASUREMENT_VALUE_MAX_SIZE];
    uint8_t hash_buf_size;
};

struct measurement_t {
    struct measurement_value_t value;                   /* measurement value */
    struct measurement_metadata_t metadata;             /* metadata */
};


#ifdef __cplusplus
}
#endif

#endif /* __MEASUREMENT_METADATA_H__ */
