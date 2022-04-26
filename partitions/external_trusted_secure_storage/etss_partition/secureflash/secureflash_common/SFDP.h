/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _SFDP_H_
#define _SFDP_H_

#include <stddef.h>
#include <stdint.h>

/* SFDP(serial flash discoverable parameters) */

#define SFDP_HEADER_SIZE   8           ///< Size of an SFDP header in bytes,2 DWORDS
#define SFDP_BASIC_PARAMS_TBL_SIZE  80 ///< Basic Parameter Table size in bytes, 20 DWORDS
#define SFDP_SECTOR_MAP_MAX_REGIONS 10 ///< Maximum number of regions with different erase granularity
#define SFDP_MAX_NUM_OF_ERASE_TYPES 4  ///< Maximum number of different erase types (erase granularity)

// Erase Types Per Region BitMask
#define SFDP_ERASE_BITMASK_TYPE4  0x08 ///< Erase type 4 (erase granularity) identifier
#define SFDP_ERASE_BITMASK_TYPE3  0x04 ///< Erase type 3 (erase granularity) identifier
#define SFDP_ERASE_BITMASK_TYPE2  0x02 ///< Erase type 2 (erase granularity) identifier
#define SFDP_ERASE_BITMASK_TYPE1  0x01 ///< Erase type 1 (erase granularity) identifier
#define SFDP_ERASE_BITMASK_NONE   0x00 ///< Erase type None
#define SFDP_ERASE_BITMASK_ALL    0x0F ///< Erase type All


/* Size of a command specified by SFDP */
enum sfdp_cmd_addr_size_t {
    SFDP_CMD_ADDR_NONE = 0x00,           // No address in command
    SFDP_CMD_ADDR_3_BYTE = 0x01,         // 3-byte address
    SFDP_CMD_ADDR_4_BYTE = 0x02,         // 4-byte address
    SFDP_CMD_ADDR_SIZE_VARIABLE = 0x03   // Address size from current setting
};

// Parameters for SFDP Read command
#define SFDP_READ_CMD_ADDR_TYPE      SFDP_CMD_ADDR_3_BYTE // Read SFDP has
                                                          // 3-byte address
#define SFDP_READ_CMD_INST           0x5A // Read SFDP instruction
#define SFDP_READ_CMD_DUMMY_CYCLES   8    // READ SFDP dummy cycles

// Special value from SFDP for using dummy cycles from current setting
#define SFDP_CMD_DUMMY_CYCLES_VARIABLE  0xF
/** JEDEC Basic Flash Parameter Table info */
struct sfdp_bptbl_info {
    uint32_t addr;                ///< Address
    size_t size;                  ///< Size
    size_t device_size_bytes;
    int legacy_erase_instruction; ///< Legacy 4K erase instruction
};

/** JEDEC Sector Map Table info */
struct sfdp_smptbl_info {
    uint32_t addr;      ///< Address
    size_t size;        ///< Size
    int32_t region_cnt; ///< Number of erase regions
    /**
     * Erase region size in bytes
     */
    int32_t region_size[SFDP_SECTOR_MAP_MAX_REGIONS];
    /**
     * Each Region can support a bit combination of any of the 4 Erase Types
     */
    uint8_t region_erase_types_bitfld[SFDP_SECTOR_MAP_MAX_REGIONS];
    /**
     * Minimal common erase size for all regions (0 if none exists)
     */
    unsigned int regions_min_common_erase_size;
    /**
     * Region high address offset boundary
     */
    size_t region_high_boundary[SFDP_SECTOR_MAP_MAX_REGIONS];
    /**
     * Up To 4 Erase Types are supported by SFDP (each with its own command
     * Instruction and Size)
     */
    int32_t erase_type_inst_arr[SFDP_MAX_NUM_OF_ERASE_TYPES];
    /**
     * Erase sizes for all different erase types
     */
    unsigned int erase_type_size_arr[SFDP_MAX_NUM_OF_ERASE_TYPES];
};

/** JEDEC 4-byte Address Instruction Parameter Table info */
struct sfdp_fbatbl_info {
    uint32_t addr; ///< Address
    size_t size;   ///< Size
    /**
     * Up To 4 Erase Types are supported by SFDP (each with its own command
     * Instruction and Size)
     */
    int32_t erase_type_4_byte_inst_arr[SFDP_MAX_NUM_OF_ERASE_TYPES];
};

/** Secure Flash Parameter Table info */
struct sfdp_sftbl_info {
    uint32_t addr; ///< Address
    size_t size;   ///< Size
    uint32_t security_feature;
    uint64_t cipher_suite;
    uint16_t session_key_size;
    uint16_t private_key_size;
    uint32_t public_key_size;
    uint16_t preshare_key_size;
    uint32_t salt_key_size;
    uint16_t root_key_size;
    uint32_t rpmc_root_key_size;
    uint16_t rpmc_hmac_key_size;
    uint32_t secure_zone_number;
    uint32_t secure_zone_size;
    uint32_t secure_read_size;
    uint32_t secure_program_size;
    uint32_t secure_erase_type_size_arr[SFDP_MAX_NUM_OF_ERASE_TYPES];
    uint32_t regions_min_secure_erase_size;
};

/** SFDP JEDEC Parameter Table info */
struct sfdp_hdr_info {
    struct sfdp_bptbl_info bptbl;
    struct sfdp_smptbl_info smptbl;
    struct sfdp_fbatbl_info fbatbl;
    struct sfdp_sftbl_info sftbl;
};

#endif /* _SFDP_H_ */
