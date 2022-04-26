/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <string.h>
#include "secureflash_common.h"
#include "secureflash_error.h"
#include "SFDP.h"
#include "tfm_memory_utils.h"

#define SFTBL_SECURE_FLASH_FEATURE_ADDR 0x00000000
#define SFTBL_SECURE_FLASH_FEATURE_SIZE 4

#define SFTBL_CIPHER_SUITE_ADDR         0x00000004

#define SFTBL_SESSION_KEY_SIZE_ADDR     0x00000024
#define SFTBL_PRIVATE_KEY_SIZE_ADDR     0x00000026
#define SFTBL_PUBLIC_KEY_SIZE_ADDR      0x00000028
#define SFTBL_PRESHARE_KEY_SIZE_ADDR    0x0000002A
#define SFTBL_SALT_KEY_SIZE_ADDR        0x0000002C
#define SFTBL_ROOT_KEY_SIZE_ADDR        0x0000002E
#define SFTBL_RPMC_ROOT_KEY_SIZE_ADDR   0x00000030
#define SFTBL_RPMC_HMAC_KEY_SIZE_ADDR   0x00000032

#define SFTBL_ZONE_NUM_ADDR             0x00000034
#define SFTBL_ZONE_SIZE_ADDR            0x00000035
#define SFTBL_SECURE_READ_SIZE_ADDR     0x00000036
#define SFTBL_SECURE_PROGRAM_SIZE_ADDR  0x00000037
#define SFTBL_SECURE_ERASE_SIZE_ADDR    0x00000038

sf_ctx_t sf_context_slots[SECURE_FLASH_CONTEXT_NUM] = {{0}};

/* Extracts Parameter ID MSB from the second DWORD of a parameter header */
inline uint8_t sfdp_get_param_id_msb(uint32_t dword2)
{
    return (dword2 & 0xFF000000) >> 24;
}

/* Extracts Parameter Table Pointer from the second DWORD of a parameter header */
inline uint32_t sfdp_get_param_tbl_ptr(uint32_t dword2)
{
    return dword2 & 0x00FFFFFF;
}

/* Erase Types Params */
const int32_t SFDP_BASIC_PARAM_TABLE_ERASE_TYPE_1_BYTE = 29; /* Erase Type 1 Instruction */
const int32_t SFDP_BASIC_PARAM_TABLE_ERASE_TYPE_2_BYTE = 31; /* Erase Type 2 Instruction */
const int32_t SFDP_BASIC_PARAM_TABLE_ERASE_TYPE_3_BYTE = 33; /* Erase Type 3 Instruction */
const int32_t SFDP_BASIC_PARAM_TABLE_ERASE_TYPE_4_BYTE = 35; /* Erase Type 4 Instruction */
const int32_t SFDP_BASIC_PARAM_TABLE_ERASE_TYPE_1_SIZE_BYTE = 28; /* Erase Type 1 Size */
const int32_t SFDP_BASIC_PARAM_TABLE_ERASE_TYPE_2_SIZE_BYTE = 30; /* Erase Type 2 Size */
const int32_t SFDP_BASIC_PARAM_TABLE_ERASE_TYPE_3_SIZE_BYTE = 32; /* Erase Type 3 Size */
const int32_t SFDP_BASIC_PARAM_TABLE_ERASE_TYPE_4_SIZE_BYTE = 34; /* Erase Type 4 Size */
const int32_t SFDP_BASIC_PARAM_TABLE_4K_ERASE_TYPE_BYTE = 1; /* 4 Kilobyte Erase Instruction */

const int32_t SFDP_ERASE_BITMASK_TYPE_4K_ERASE_UNSUPPORTED = 0xFF;

/** SFDP Header */
struct sfdp_hdr {
    uint8_t SIG_B0;  /* SFDP Signature, Byte 0 */
    uint8_t SIG_B1;  /* SFDP Signature, Byte 1 */
    uint8_t SIG_B2;  /* SFDP Signature, Byte 2 */
    uint8_t SIG_B3;  /* SFDP Signature, Byte 3 */
    uint8_t R_MINOR; /* SFDP Minor Revision */
    uint8_t R_MAJOR; /* SFDP Major Revision */
    uint8_t NPH;     /* Number of parameter headers (0-based,
                        0 indicates 1 parameter header) */
    uint8_t ACP;     /* SFDP Access Protocol */
};

/** SFDP Parameter header */
struct sfdp_prm_hdr {
    uint8_t PID_LSB; /* Parameter ID LSB */
    uint8_t P_MINOR; /* Parameter Minor Revision */
    uint8_t P_MAJOR; /* Parameter Major Revision */
    uint8_t P_LEN;   /* Parameter length in DWORDS */
    uint32_t DWORD2; /* Parameter ID MSB + Parameter Table Pointer */
};


static sf_ctx_t *query_sf_common_context(const char *name)
{
    uint8_t n;

    for (n = 0; n < SECURE_FLASH_CONTEXT_NUM; n++) {
        if (0 == strcmp(&sf_context_slots[n].name, name)) {
            return &sf_context_slots[n];
        }
    }
    return NULL;
}

static session_info_t *query_session_info(sf_ctx_t *sf_ctx, uint32_t session_id)
{
    uint32_t n;

    for (n = 0; n < SESSION_INFO_MAX_NUM; n++ ) {
        if (sf_ctx->session_info[n].session_id == session_id) {
            return &sf_ctx->session_info[n];
        }
    }
    return NULL;
}

static int32_t sftbl_detect_cipher_suite(sf_ctx_t *sf_ctx, uint8_t *param_table)
{
    uint8_t n, alg;

    for (n = 0; n < 4; n++) {
        tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.cipher_suite),
                   &param_table[SFTBL_CIPHER_SUITE_ADDR + n * 8], 8);
        if (0 == sf_ctx->sfdp_info.sftbl.cipher_suite) {
            break;
        }
        /* for Key Exchange */
        alg = sf_ctx->sfdp_info.sftbl.cipher_suite & 0xFF;
        if (SECUREFLASH_ERROR_OK !=
                       sf_ctx->vendor_op.check_algorithm_support(sf_ctx, alg)) {
            break;
        }
        /* for Key Derive */
        alg = (sf_ctx->sfdp_info.sftbl.cipher_suite & 0xFF00) >> 8;
        if (SECUREFLASH_ERROR_OK !=
                       sf_ctx->vendor_op.check_algorithm_support(sf_ctx, alg)) {
            break;
        }
        /* for Encryption */
        alg = (sf_ctx->sfdp_info.sftbl.cipher_suite & 0xFF0000) >> 16;
        if (SECUREFLASH_ERROR_OK !=
                       sf_ctx->vendor_op.check_algorithm_support(sf_ctx, alg)) {
            break;
        }
        /* for Authentication */
        alg = (sf_ctx->sfdp_info.sftbl.cipher_suite & 0xFF000000) >> 24;
        if (SECUREFLASH_ERROR_OK !=
                       sf_ctx->vendor_op.check_algorithm_support(sf_ctx, alg)) {
            break;
        }
    }
    if (4 < n) {
        return SECUREFLASH_ERROR_SFDP_SFTBL;
    }
    return SECUREFLASH_ERROR_OK;
}
static int32_t sftbl_detect_key_size(sf_ctx_t *sf_ctx, uint8_t *param_table)
{
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.session_key_size),
               &param_table[SFTBL_SESSION_KEY_SIZE_ADDR], 2);
    sf_ctx->sfdp_info.sftbl.session_key_size /= 8;
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.private_key_size),
               &param_table[SFTBL_PRIVATE_KEY_SIZE_ADDR], 2);
    sf_ctx->sfdp_info.sftbl.private_key_size /= 8;
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.public_key_size),
               &param_table[SFTBL_PUBLIC_KEY_SIZE_ADDR], 2);
    sf_ctx->sfdp_info.sftbl.public_key_size /= 8;
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.preshare_key_size),
               &param_table[SFTBL_PRESHARE_KEY_SIZE_ADDR], 2);
    sf_ctx->sfdp_info.sftbl.preshare_key_size /= 8;
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.salt_key_size),
               &param_table[SFTBL_SALT_KEY_SIZE_ADDR], 2);
    sf_ctx->sfdp_info.sftbl.salt_key_size /= 8;
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.root_key_size),
               &param_table[SFTBL_ROOT_KEY_SIZE_ADDR], 2);
    sf_ctx->sfdp_info.sftbl.root_key_size /= 8;
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.rpmc_root_key_size),
               &param_table[SFTBL_RPMC_ROOT_KEY_SIZE_ADDR], 2);
    sf_ctx->sfdp_info.sftbl.rpmc_root_key_size /= 8;
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.rpmc_hmac_key_size),
               &param_table[SFTBL_RPMC_HMAC_KEY_SIZE_ADDR], 2);
    sf_ctx->sfdp_info.sftbl.rpmc_hmac_key_size /= 8;
    return SECUREFLASH_ERROR_OK;
}
static int32_t sftbl_detect_architecture(sf_ctx_t *sf_ctx, uint8_t *param_table)
{
    uint8_t n;
    sf_ctx->sfdp_info.sftbl.secure_zone_number =
                                              param_table[SFTBL_ZONE_NUM_ADDR];
    sf_ctx->sfdp_info.sftbl.secure_zone_size =
                                        1 << param_table[SFTBL_ZONE_SIZE_ADDR];
    sf_ctx->sfdp_info.sftbl.secure_read_size =
                                 1 << param_table[SFTBL_SECURE_READ_SIZE_ADDR];
    sf_ctx->sfdp_info.sftbl.secure_program_size =
                              1 << param_table[SFTBL_SECURE_PROGRAM_SIZE_ADDR];
    sf_ctx->sfdp_info.sftbl.regions_min_secure_erase_size = 0;
    for (n = 0; n < 4; n++) {
        sf_ctx->sfdp_info.sftbl.secure_erase_type_size_arr[n] =
                            1 << param_table[SFTBL_SECURE_ERASE_SIZE_ADDR + n];
        if (1 == sf_ctx->sfdp_info.sftbl.secure_erase_type_size_arr[n]) {
            break;
        }
        if ((sf_ctx->sfdp_info.sftbl.secure_erase_type_size_arr[n] <
                      sf_ctx->sfdp_info.sftbl.regions_min_secure_erase_size) ||
            (0 == sf_ctx->sfdp_info.sftbl.regions_min_secure_erase_size)) {
            /* Set default minimal secure erase for signal region */
            sf_ctx->sfdp_info.sftbl.regions_min_secure_erase_size =
                         sf_ctx->sfdp_info.sftbl.secure_erase_type_size_arr[n];
        }
    }
    return SECUREFLASH_ERROR_OK;
}
/** Parse SFDP Header
 * @param sfdp_hdr_ptr Pointer to memory holding an SFDP header
 * @return Number of Parameter Headers on success, -1 on failure
 */
int32_t sfdp_parse_sfdp_header(struct sfdp_hdr *sfdp_hdr_ptr)
{
    if (!(tfm_memcmp(sfdp_hdr_ptr, "SFDP", 4) == 0 &&
        sfdp_hdr_ptr->R_MAJOR == 1)) {
        return -1;
    }
    int32_t hdr_cnt = sfdp_hdr_ptr->NPH + 1;
    return hdr_cnt;
}

/** Parse Parameter Header
 * @param phdr_ptr Pointer to memory holding a single SFDP Parameter header
 * @param hdr_info Reference to a Parameter Table structure where info about
 *                 the table is written
 * @return 0 on success, -1 on failure
 */
static int32_t sfdp_parse_single_param_header(struct sfdp_prm_hdr *phdr_ptr,
                                              struct sfdp_hdr_info *hdr_info)
{
    if (phdr_ptr->P_MAJOR != 1) {
        return -1;
    }
    int32_t param_id_msb = sfdp_get_param_id_msb(phdr_ptr->DWORD2);
    /* MSB JEDEC ID */
    if (param_id_msb == 0xFF) {
        /* LSB JEDEC ID */
        switch (phdr_ptr->PID_LSB) {
            case 0x0:
                hdr_info->bptbl.addr = sfdp_get_param_tbl_ptr(phdr_ptr->DWORD2);
                hdr_info->bptbl.size = UTILS_MIN((phdr_ptr->P_LEN * 4),
                                                 SFDP_BASIC_PARAMS_TBL_SIZE);
                break;
            case 0x81:
                hdr_info->smptbl.addr = sfdp_get_param_tbl_ptr(phdr_ptr->DWORD2);
                hdr_info->smptbl.size = phdr_ptr->P_LEN * 4;
                break;
            case 0x84:
                hdr_info->fbatbl.addr = sfdp_get_param_tbl_ptr(phdr_ptr->DWORD2);
                hdr_info->fbatbl.size = phdr_ptr->P_LEN * 4;
                break;
            case 0x14:
                hdr_info->sftbl.addr = sfdp_get_param_tbl_ptr(phdr_ptr->DWORD2);
                hdr_info->sftbl.size = phdr_ptr->P_LEN * 4;
                break;
            /* Unsupported */
            default:
                break;
        }
    } else if (param_id_msb >= 0x80) {
        /* TODO */
    } else { /* MSB Vendor ID */
        /* TODO */
    }
   return 0;
}

static int32_t sfdp_parse_headers(sfdp_reader_func sfdp_reader,
                                  sf_ctx_t *sf_ctx,
                                  struct sfdp_hdr_info *sfdp_info)
{
    uint64_t addr = 0x0;
    int32_t number_of_param_headers = 0;
    size_t data_length;

    {
        data_length = SFDP_HEADER_SIZE;
        uint8_t sfdp_header[SFDP_HEADER_SIZE];
        int32_t status = sfdp_reader(
                                     sf_ctx,
                                     addr,
                                     SFDP_READ_CMD_ADDR_TYPE,
                                     SFDP_READ_CMD_INST,
                                     SFDP_READ_CMD_DUMMY_CYCLES,
                                     sfdp_header,
                                     data_length
                                     );
        if (status < 0) {
            return -1;
        }
        number_of_param_headers =
                        sfdp_parse_sfdp_header((struct sfdp_hdr *)sfdp_header);
        if (number_of_param_headers < 0) {
            return number_of_param_headers;
        }
    }
    addr += SFDP_HEADER_SIZE;
    {
        data_length = SFDP_HEADER_SIZE;
        uint8_t param_header[SFDP_HEADER_SIZE];
        int32_t status;
        int32_t hdr_status;

        /* Loop over Param Headers and parse them (currently supports
         * Basic Param Table and Sector Region Map Table) */
        for (int32_t idx = 0; idx < number_of_param_headers; idx++) {
            status = sfdp_reader(
                                 sf_ctx,
                                 addr,
                                 SFDP_READ_CMD_ADDR_TYPE,
                                 SFDP_READ_CMD_INST,
                                 SFDP_READ_CMD_DUMMY_CYCLES,
                                 param_header,
                                 data_length
                                 );
            if (status < 0) {
                return -1;
            }
            hdr_status = sfdp_parse_single_param_header(
                                           (struct sfdp_prm_hdr *)param_header,
                                           sfdp_info);
            if (hdr_status < 0) {
                return hdr_status;
            }
            addr += SFDP_HEADER_SIZE;
        }
    }
    return 0;
}
static int32_t sfdp_parse_secure_flash_param_table(sf_ctx_t *sf_ctx,
                                                   sfdp_reader_func sfdp_reader)
{
    uint8_t param_table[SFDP_BASIC_PARAMS_TBL_SIZE];
    if (0 > sfdp_reader(sf_ctx, sf_ctx->sfdp_info.sftbl.addr,
                        SFDP_READ_CMD_ADDR_TYPE,
                        SFDP_READ_CMD_INST,
                        SFDP_READ_CMD_DUMMY_CYCLES,
                        param_table,
                        sf_ctx->sfdp_info.sftbl.size)) {
        return -1;
    }
    tfm_memcpy(&(sf_ctx->sfdp_info.sftbl.security_feature),
               &param_table[SFTBL_SECURE_FLASH_FEATURE_ADDR],
               SFTBL_SECURE_FLASH_FEATURE_SIZE);
    sftbl_detect_cipher_suite(sf_ctx, param_table);
    sftbl_detect_key_size(sf_ctx, param_table);
    sftbl_detect_architecture(sf_ctx, param_table);
    return 0;
}

static int32_t read_sfdp_command(sf_ctx_t *sf_ctx, uint64_t addr,
                                 size_t addr_size, uint8_t inst,
                                 uint8_t dummy_cycles, void *rx_buffer,
                                 uint64_t rx_length)
{
    uint8_t addr_length;

    switch (addr_size) {
        case SFDP_CMD_ADDR_3_BYTE:
            addr_length = 3;
            break;
        case SFDP_CMD_ADDR_4_BYTE:
            addr_length = 4;
            break;
        case SFDP_CMD_ADDR_NONE: // no address in command
            addr_length = 0;
            break;
        default:
            SF_COMMON_ERR_PR("Invalid SFDP command address size: 0x%02X",
                             addr_size);
            return -1;
    }
    if (0 > sf_ctx->vendor_op.send_read_sfdp_command(inst,
                                                     (uint8_t *)(rx_buffer),
                                                     rx_length, addr,
                                                     addr_length,
                                                     dummy_cycles)) {
        SF_COMMON_ERR_PR("_read_sfdp_command failed");
        return -1;
    }
    return 0;
}

static int32_t get_flash_profile(sf_ctx_t *sf_ctx)
{
    tfm_memcpy(&(sf_ctx->flash_profile.security_feature),
               &(sf_ctx->sfdp_info.sftbl.security_feature),
               sizeof(security_feature_t));
    tfm_memcpy(&(sf_ctx->flash_profile.cipher_suite),
               &(sf_ctx->sfdp_info.sftbl.cipher_suite),
               sizeof(cipher_suite_t));

    sf_ctx->flash_profile.key_size.session_key_size =
                                      sf_ctx->sfdp_info.sftbl.session_key_size;
    sf_ctx->flash_profile.key_size.private_key_size =
                                      sf_ctx->sfdp_info.sftbl.private_key_size;
    sf_ctx->flash_profile.key_size.public_key_size =
                                       sf_ctx->sfdp_info.sftbl.public_key_size;
    sf_ctx->flash_profile.key_size.preshare_key_size =
                                     sf_ctx->sfdp_info.sftbl.preshare_key_size;
    sf_ctx->flash_profile.key_size.salt_key_size =
                                         sf_ctx->sfdp_info.sftbl.salt_key_size;
    sf_ctx->flash_profile.key_size.root_key_size =
                                         sf_ctx->sfdp_info.sftbl.root_key_size;
    sf_ctx->flash_profile.key_size.rpmc_root_key_size =
                                    sf_ctx->sfdp_info.sftbl.rpmc_root_key_size;
    sf_ctx->flash_profile.key_size.rpmc_hmac_key_size =
                                    sf_ctx->sfdp_info.sftbl.rpmc_hmac_key_size;
    sf_ctx->flash_profile.architecture.secure_zone_number =
                                    sf_ctx->sfdp_info.sftbl.secure_zone_number;
    sf_ctx->flash_profile.architecture.secure_zone_size =
                                      sf_ctx->sfdp_info.sftbl.secure_zone_size;
    sf_ctx->flash_profile.architecture.secure_read_size =
                                      sf_ctx->sfdp_info.sftbl.secure_read_size;
    sf_ctx->flash_profile.architecture.secure_program_size =
                                   sf_ctx->sfdp_info.sftbl.secure_program_size;

    for (uint8_t n = 0; n < 4; n++ ){
        if (1 != sf_ctx->sfdp_info.sftbl.secure_erase_type_size_arr[n]) {
            sf_ctx->flash_profile.architecture.secure_erase_size[n] =
                         sf_ctx->sfdp_info.sftbl.secure_erase_type_size_arr[n];
        }
    }
    sf_ctx->flash_profile.architecture.regions_min_secure_erase_size =
                         sf_ctx->sfdp_info.sftbl.regions_min_secure_erase_size;
    sf_ctx->flash_profile.architecture.secure_zone_total_size =
                                   sf_ctx->sfdp_info.sftbl.secure_zone_number *
                                   sf_ctx->sfdp_info.sftbl.secure_zone_size;

    SF_COMMON_DBG0_PR("%s\r\n", __func__);
    SF_COMMON_DBG0_PR("Secure Flash security_feature: %d\r\n",
                      sf_ctx->flash_profile.security_feature);
    SF_COMMON_DBG0_PR("Secure Flash security_feature.security_storage: %02x\r\n",
                      sf_ctx->flash_profile.security_feature.security_storage);
    SF_COMMON_DBG0_PR("key exchange   alg: %d\r\n",
                      sf_ctx->flash_profile.cipher_suite.key_exchange_alg);
    SF_COMMON_DBG0_PR("key derive     alg: %d\r\n",
                      sf_ctx->flash_profile.cipher_suite.key_derive_alg);
    SF_COMMON_DBG0_PR("encryption     alg: %d\r\n",
                      sf_ctx->flash_profile.cipher_suite.encryption_alg);
    SF_COMMON_DBG0_PR("authentication alg: %d\r\n",
                      sf_ctx->flash_profile.cipher_suite.signature_alg);
    SF_COMMON_DBG0_PR("key exchange   alg: %d\r\n",
                      sf_ctx->flash_profile.cipher_suite.key_exchange_alg);
    SF_COMMON_DBG0_PR("session_key_size: %d bytes\r\n",
                      sf_ctx->flash_profile.key_size.session_key_size);
    SF_COMMON_DBG0_PR("private_key_size: %d bytes\r\n",
                      sf_ctx->flash_profile.key_size.private_key_size);
    SF_COMMON_DBG0_PR("public_key_size: %d bytes\r\n",
                      sf_ctx->flash_profile.key_size.public_key_size);
    SF_COMMON_DBG0_PR("preshare_key_size: %d bytes\r\n",
                      sf_ctx->flash_profile.key_size.preshare_key_size);
    SF_COMMON_DBG0_PR("salt_key_size: %d bytes\r\n",
                      sf_ctx->flash_profile.key_size.salt_key_size);
    SF_COMMON_DBG0_PR("root_key_size: %d bytes\r\n",
                      sf_ctx->flash_profile.key_size.root_key_size);
    SF_COMMON_DBG0_PR("rpmc_root_key_size: %d bytes\r\n",
                      sf_ctx->flash_profile.key_size.rpmc_root_key_size);
    SF_COMMON_DBG0_PR("rpmc_hmac_key_size: %d bytes\r\n",
                      sf_ctx->flash_profile.key_size.rpmc_hmac_key_size);
    SF_COMMON_DBG0_PR("secure_zone_number: %d\r\n",
                      sf_ctx->flash_profile.architecture.secure_zone_number);
    SF_COMMON_DBG0_PR("secure_zone_size: %d bytes\r\n",
                      sf_ctx->flash_profile.architecture.secure_zone_size);
    SF_COMMON_DBG0_PR("secure_read_size: %d bytes\r\n",
                      sf_ctx->flash_profile.architecture.secure_read_size);
    SF_COMMON_DBG0_PR("secure_program_size: %d bytes\r\n",
                      sf_ctx->flash_profile.architecture.secure_program_size);
    SF_COMMON_DBG0_PR("secure_erase0_size: %d bytes\r\n",
                      sf_ctx->flash_profile.architecture.secure_erase_size[0]);
    SF_COMMON_DBG0_PR("secure_erase1_size: %d bytes\r\n",
                      sf_ctx->flash_profile.architecture.secure_erase_size[1]);
    SF_COMMON_DBG0_PR("secure_erase2_size: %d bytes\r\n",
                      sf_ctx->flash_profile.architecture.secure_erase_size[2]);
    SF_COMMON_DBG0_PR("secure_erase3_size: %d bytes\r\n",
                      sf_ctx->flash_profile.architecture.secure_erase_size[3]);
    SF_COMMON_DBG0_PR("regions_min_secure_erase_size: %d bytes\r\n",
             sf_ctx->flash_profile.architecture.regions_min_secure_erase_size);
    SF_COMMON_DBG0_PR("secure zone total size: %d bytes\r\n",
                    sf_ctx->flash_profile.architecture.secure_zone_total_size);
    return SECUREFLASH_ERROR_OK;
}


/*
* create a new secure flash common context, and initialize it
*/
int32_t sf_common_create_and_init_context(vendor_op_register_t *vendor_impl_cfg,
                                          sf_ctx_t **sf_ctx)
{
    uint32_t n;

    if (NULL != query_sf_common_context(vendor_impl_cfg->sf_name)) {
        SF_COMMON_ERR_PR("%s existed\r\n", vendor_impl_cfg->sf_name);
        return SECUREFLASH_ERROR_PARTITION_EXIST;
     }
     for (n = 0; n < SECURE_FLASH_CONTEXT_NUM; n++) {
         if (NULL == sf_context_slots[n].name) {
             tfm_memset(&sf_context_slots[n], 0, sizeof(sf_ctx_t));
             sf_context_slots[n].name = vendor_impl_cfg->sf_name;
             vendor_impl_cfg->vendor_op_register(&sf_context_slots[n]);
             *sf_ctx = &sf_context_slots[n];
             return SECUREFLASH_ERROR_OK;
         }
    }
    return SECUREFLASH_ERROR_PARTITION_EXHAUST;
}

int32_t sf_common_delete_context(const char *name)
{
    uint32_t n;

    for (n = 0; n < SECURE_FLASH_CONTEXT_NUM; n++) {
        if (0 == strcmp(sf_context_slots[n].name, name)) {
            sf_context_slots[n].name = NULL;
            tfm_memset(&sf_context_slots[n], 0, sizeof(sf_ctx_t));
            return SECUREFLASH_ERROR_OK;
        }
    }
    return SECUREFLASH_ERROR_PARTITION_NOT_EXIST;
}

int32_t sf_common_init(sf_ctx_t *sf_ctx)
{
    int32_t status = SECUREFLASH_ERROR_OK;

    status = sf_ctx->vendor_op.init(sf_ctx);
    if (SECUREFLASH_ERROR_UNPROVISIONED == status) {
        SF_COMMON_ERR_PR("vendor_op unprovisioned\r\n");
        return status;
    }
    if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("  vendor_op failed\r\n");
        goto init_exit_point;
    }
    /************* Parse SFDP headers and tables **************/
    sf_ctx->sfdp_info.sftbl.addr = 0x0;
    sf_ctx->sfdp_info.sftbl.size = 0;
    if (0 > sfdp_parse_headers(read_sfdp_command, sf_ctx,
                               &(sf_ctx->sfdp_info))) {
        SF_COMMON_ERR_PR("init - Parse SFDP - Headers Failed\r\n");
        status = SECUREFLASH_ERROR_INITIAL;
        goto init_exit_point;
    }
    if (0 > sfdp_parse_secure_flash_param_table(sf_ctx, read_sfdp_command)) {
        SF_COMMON_ERR_PR("init - Parse SFDP - Secure Flash Parameter Table Failed\r\n");
        status = SECUREFLASH_ERROR_INITIAL;
        goto init_exit_point;
    }
    /* get flash profile from sfdp's tables */
    status = get_flash_profile(sf_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("Get flash profile failed\r\n");
        goto init_exit_point;
    }
    return SECUREFLASH_ERROR_OK;
init_exit_point:
    sf_ctx->vendor_op.deinit(sf_ctx);
    return SECUREFLASH_ERROR_INITIAL;
}

int32_t sf_common_deinit(sf_ctx_t *sf_ctx)
{
    sf_ctx->vendor_op.deinit(sf_ctx);
    sf_common_delete_context(sf_ctx->name);
    return SECUREFLASH_ERROR_OK;
}

int32_t sf_common_write_provision(sf_ctx_t *sf_ctx, void *provision_data)
{
    return sf_ctx->vendor_op.write_provision(sf_ctx, provision_data);
}

int32_t sf_common_read_provision(sf_ctx_t *sf_ctx, void *provision_data)
{
    return sf_ctx->vendor_op.read_provision(sf_ctx, provision_data);
}

int32_t sf_common_lock_provision(sf_ctx_t *sf_ctx, void *provision_data)
{
    return sf_ctx->vendor_op.lock_provision(sf_ctx, provision_data);
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_SESSION_EXHAUST
// SECUREFLASH_ERROR_CREATE_SESSION
int32_t sf_common_create_session(sf_ctx_t *sf_ctx, uint32_t key_id,
                                 uint32_t *session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    session_info_t *session_info;
    uint32_t session_key_id;

    if (NULL == sf_ctx->vendor_op.create_session) {
        return SECUREFLASH_ERROR_CREATE_SESSION;
    }
    /* query a free session_info */
    session_info = query_session_info(sf_ctx, 0);
    if (NULL == session_info) {
        SF_COMMON_ERR_PR("Session Exhausted\r\n");
        return SECUREFLASH_ERROR_SESSION_EXHAUST;
    }
    /* create a session based on key_id, and get
       session_id and session_key_id */
    status = sf_ctx->vendor_op.create_session(sf_ctx, key_id, &session_key_id,
                                              session_id);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    session_info->key_id = key_id;
    session_info->session_key_id = session_key_id;
    session_info->session_id = *session_id;
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_SESSION_ID_NOT_EXIST
// SECUREFLASH_ERROR_CLOSE_SESSION
int32_t sf_common_close_session(sf_ctx_t *sf_ctx, uint32_t session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    session_info_t *session_info;

    if (NULL == sf_ctx->vendor_op.close_session) {
        return SECUREFLASH_ERROR_CLOSE_SESSION;
    }
    /* find a session_info by specified session_id  */
    session_info = query_session_info(sf_ctx, session_id);
    if (NULL == session_info) {
        SF_COMMON_ERR_PR("Session id does not exist\r\n");
        return SECUREFLASH_ERROR_SESSION_ID_NOT_EXIST;
    }
    status = sf_ctx->vendor_op.close_session(sf_ctx, session_id);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    tfm_memset(session_info, 0, sizeof(session_info_t));
    return status;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_ALLOCATION
// SECUREFLASH_ERROR_SECURE_READ
int32_t sf_common_secure_read(sf_ctx_t *sf_ctx, uint8_t *buffer, size_t addr,
                              size_t size, uint32_t session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint32_t secure_read_size;
    size_t offset, remain;
    uint8_t *buffer_temp = (uint8_t *)buffer;
    uint8_t read_buf[ETSS_SF_READ_BUF_SIZE] = {0};

    if (NULL == sf_ctx->vendor_op.secure_read) {
        SF_COMMON_ERR_PR("vendor_op.secure_read is NULL\r\n");
        return SECUREFLASH_ERROR_SECURE_READ;
    }
    secure_read_size = sf_common_get_secure_read_size(sf_ctx);
    if ((0 == secure_read_size) || (secure_read_size > ETSS_SF_READ_BUF_SIZE)) {
        SF_COMMON_ERR_PR("secure_read_size error\r\n");
        return SECUREFLASH_ERROR_SECURE_READ;
    }
    if ((addr + size) > sf_common_get_chip_size(sf_ctx)) {
        SF_COMMON_ERR_PR("(address + size) > chip size\r\n");
        return SECUREFLASH_ERROR_SECURE_READ;
    }
    offset = addr % secure_read_size;
    if (offset) {
        status = sf_ctx->vendor_op.secure_read(sf_ctx, read_buf, addr - offset,
                                               secure_read_size, session_id);
        if (SECUREFLASH_ERROR_OK != status) {
            SF_COMMON_ERR_PR("vendor_op.secure_read failed\r\n");
            status = SECUREFLASH_ERROR_SECURE_READ;
            goto secure_read_exit_point;
        }
        remain = secure_read_size - offset;
        if (remain > size) {
            tfm_memcpy(buffer_temp, read_buf + offset, size);
            status = SECUREFLASH_ERROR_OK;
            goto secure_read_exit_point;
        } else {
            tfm_memcpy(buffer_temp, read_buf + offset, remain);
        }
        buffer_temp += remain;
        addr += remain;
        size -= remain;
    }
    remain = (addr + size) % secure_read_size;
    if (remain) {
        size -= remain;
    }
    while (size) {
        status = sf_ctx->vendor_op.secure_read(sf_ctx, buffer_temp, addr,
                                               secure_read_size, session_id);
        if (SECUREFLASH_ERROR_OK != status) {
            SF_COMMON_ERR_PR("vendor_op.secure_read failed\r\n");
            status = SECUREFLASH_ERROR_SECURE_READ;
            goto secure_read_exit_point;
        }
        buffer_temp += secure_read_size;
        addr += secure_read_size;
        size -= secure_read_size;
    }
    if (remain) {
        status = sf_ctx->vendor_op.secure_read(sf_ctx, read_buf, addr,
                                               secure_read_size, session_id);
        if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("vendor_op.secure_read failed\r\n");
        status = SECUREFLASH_ERROR_SECURE_READ;
        goto secure_read_exit_point;
        }
        tfm_memcpy(buffer_temp, read_buf, remain);
    }
secure_read_exit_point:
    return status;
}

int32_t sf_common_secure_program(sf_ctx_t *sf_ctx, const uint8_t *buffer,
                                 size_t addr, size_t size, uint32_t session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint32_t secure_pgm_size;
    size_t offset, remain;
    uint8_t *buffer_temp = (uint8_t*)buffer;
    uint8_t pgm_buf[ETSS_SF_WRITE_BUF_SIZE] = {0};

    if (NULL == sf_ctx->vendor_op.secure_program) {
        SF_COMMON_ERR_PR("vendor_op.secure_program is NULL\r\n");
        return SECUREFLASH_ERROR_SECURE_PROGRAM;
    }
    secure_pgm_size = sf_common_get_secure_program_size(sf_ctx);
    if ((0 == secure_pgm_size) || (secure_pgm_size > ETSS_SF_WRITE_BUF_SIZE)) {
        return SECUREFLASH_ERROR_SECURE_PROGRAM;
    }
    if ((addr + size) > sf_common_get_chip_size(sf_ctx)) {
        return SECUREFLASH_ERROR_SECURE_PROGRAM;
    }
    offset = addr % secure_pgm_size;
    if (offset) {
        tfm_memset(pgm_buf, 0xFF, secure_pgm_size);
        remain = secure_pgm_size - offset;
        remain = remain > size ? size : remain;
        tfm_memcpy(pgm_buf + offset, buffer_temp, remain);
        status = sf_ctx->vendor_op.secure_program(sf_ctx, pgm_buf, addr - offset,
                                                  secure_pgm_size, session_id);
        if (SECUREFLASH_ERROR_OK != status) {
            status = SECUREFLASH_ERROR_SECURE_PROGRAM;
            goto secure_program_exit_point;
        }
        if (remain == size) {
            status = SECUREFLASH_ERROR_OK;
            goto secure_program_exit_point;
        }
        buffer_temp += remain;
        addr += remain;
        size -= remain;
    }
    remain = (addr + size) % secure_pgm_size;
    if (remain) {
        size -= remain;
    }
    while(size) {
        status = sf_ctx->vendor_op.secure_program(sf_ctx, buffer_temp, addr,
                                                  secure_pgm_size, session_id);
        if (SECUREFLASH_ERROR_OK != status) {
             status = SECUREFLASH_ERROR_SECURE_PROGRAM;
             goto secure_program_exit_point;
        }
        buffer_temp += secure_pgm_size;
        addr += secure_pgm_size;
        size -= secure_pgm_size;
    }
    if (remain) {
        tfm_memset(pgm_buf, 0xFF, secure_pgm_size);
        tfm_memcpy(pgm_buf, buffer_temp, remain);
        status = sf_ctx->vendor_op.secure_program(sf_ctx, pgm_buf, addr,
                                                  secure_pgm_size, session_id);
        if (SECUREFLASH_ERROR_OK != status) {
            status = SECUREFLASH_ERROR_SECURE_PROGRAM;
            goto secure_program_exit_point;
        }
    }
secure_program_exit_point:
    return status;
}


// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_OK_SECURE_ERASE
// SECUREFLASH_ERROR_NOT_SUPPORT_OP_SECURE_ERASE
int32_t sf_common_secure_erase(sf_ctx_t *sf_ctx, size_t addr, size_t size,
                               uint32_t session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint32_t secure_erase_size;

    if (NULL == sf_ctx->vendor_op.secure_erase) {
        SF_COMMON_ERR_PR("vendor_op.secure_erase is NULL\r\n");
        return SECUREFLASH_ERROR_SECURE_ERASE;
    }
    secure_erase_size = sf_common_get_secure_erase_size(sf_ctx);
    if (0 == secure_erase_size) {
        return SECUREFLASH_ERROR_SECURE_ERASE;
    }
    if ((addr + size) > sf_common_get_chip_size(sf_ctx)) {
        SF_COMMON_ERR_PR("secure erase exceeds flash device size\r\n");
        return SECUREFLASH_ERROR_SECURE_ERASE;
    }
    if ((0 != (addr % secure_erase_size)) ||
        (0 != ((addr + size) % secure_erase_size))) {
        SF_COMMON_ERR_PR("invalid secure erase - unaligned address and size\r\n");
        return SECUREFLASH_ERROR_SECURE_ERASE;
    }
    while (size) {
        status = sf_ctx->vendor_op.secure_erase(sf_ctx, addr, secure_erase_size,
                                                session_id);
        if (SECUREFLASH_ERROR_OK != status) {
            return SECUREFLASH_ERROR_SECURE_ERASE;
        }
        addr += secure_erase_size;
        size -= secure_erase_size;
    }
    return status;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_RPMC_WRITE_ROOT_KEY
//int32_t sf_common_rpmc_write_root_key(sf_ctx_t *sf_ctx, uint8_t mc_addr,
//                                      uint8_t *root_key)
//{
//    if (NULL == sf_ctx->vendor_op.rpmc_write_root_key) {
//        return SECUREFLASH_ERROR_RPMC_WRITE_ROOT_KEY;
//    }
//    /* TODO */
//    return SECUREFLASH_ERROR_OK;
//}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_RPMC_UPDATE_HMAC_KEY
int32_t sf_common_rpmc_update_hmac_key(sf_ctx_t *sf_ctx, uint8_t mc_addr,
                                       uint32_t root_key_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;

    if (NULL == sf_ctx->vendor_op.rpmc_update_hmac_key) {
        return SECUREFLASH_ERROR_RPMC_UPDATE_HMAC_KEY;
    }
    status = sf_ctx->vendor_op.rpmc_update_hmac_key(sf_ctx, mc_addr,
                                                    root_key_id);
    return status;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_GET_PUF
int32_t sf_common_get_puf(sf_ctx_t *sf_ctx, uint8_t *puf, uint8_t size,
                          uint8_t *actual_size, uint8_t *input_param,
                          uint8_t input_param_size)
{
    int32_t status = SECUREFLASH_ERROR_OK;

    if (NULL == sf_ctx->vendor_op.get_puf) {
        return SECUREFLASH_ERROR_GET_PUF;
    }
    status = sf_ctx->vendor_op.get_puf(sf_ctx, puf, size, actual_size,
                                       input_param, input_param_size);
    return status;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_GET_UID
int32_t sf_common_get_uid(sf_ctx_t *sf_ctx, uint8_t *uid, uint8_t size,
                          uint8_t *actual_size)
{
    if (NULL == sf_ctx->vendor_op.get_uid) {
        return SECUREFLASH_ERROR_GET_UID;
    }
    if (SECUREFLASH_ERROR_OK != sf_ctx->vendor_op.get_uid(sf_ctx, uid, size,
                                                          actual_size)) {
        return SECUREFLASH_ERROR_GET_MC;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_GET_TRNG
int32_t sf_common_get_trng(sf_ctx_t *sf_ctx, uint8_t *random, uint8_t size,
                           uint8_t *actual_size)
{
    if (NULL == sf_ctx->vendor_op.get_trng) {
        return SECUREFLASH_ERROR_GET_TRNG;
    }
    if (SECUREFLASH_ERROR_OK != sf_ctx->vendor_op.get_trng(sf_ctx, random, size,
                                                           actual_size)) {
        return SECUREFLASH_ERROR_GET_MC;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_GET_MC
int32_t sf_common_get_mc(sf_ctx_t *sf_ctx, uint8_t mc_addr, uint8_t *mc,
                         uint8_t size, uint8_t *actual_size)
{
    if (NULL == sf_ctx->vendor_op.get_mc) {
        return SECUREFLASH_ERROR_GET_MC;
    }
    if (SECUREFLASH_ERROR_OK != sf_ctx->vendor_op.get_mc(sf_ctx, mc_addr, mc,
                                                         size, actual_size)) {
        return SECUREFLASH_ERROR_GET_MC;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_INCREASE_MC
int32_t sf_common_increase_mc(sf_ctx_t *sf_ctx, uint8_t mc_addr, uint8_t *mc)
{
    if (NULL == sf_ctx->vendor_op.increase_mc) {
        return SECUREFLASH_ERROR_INCREASE_MC;
    }
    if (SECUREFLASH_ERROR_OK != sf_ctx->vendor_op.increase_mc(sf_ctx, mc_addr,
                                                              mc)) {
        return SECUREFLASH_ERROR_INCREASE_MC;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_OK_PROGRAM
int32_t sf_common_read(sf_ctx_t *sf_ctx, uint8_t *buffer, size_t addr,
                       size_t size)
{
    if (SECUREFLASH_ERROR_OK != sf_ctx->vendor_op.read(sf_ctx, buffer, addr,
                                                       size)) {
        return SECUREFLASH_ERROR_READ;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_OK_PROGRAM
int32_t sf_common_program(sf_ctx_t *sf_ctx, uint8_t *buffer, size_t addr,
                          size_t size)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint32_t program_size;
    uint32_t offset = 0;
    uint32_t chunk = 0;

    program_size = sf_common_get_secure_program_size(sf_ctx);
    if (!program_size) {
        return SECUREFLASH_ERROR_PROGRAM;
    }
    while (size) {
        // Write on _page_size_bytes boundaries (Default 256 bytes a page)
        offset = addr % program_size;
        chunk = (offset + size < program_size) ? size : (program_size - offset);
        status = sf_ctx->vendor_op.program(sf_ctx, buffer, addr, chunk);
        if (SECUREFLASH_ERROR_OK != status) {
            return SECUREFLASH_ERROR_PROGRAM;
        }
        buffer = buffer + chunk;
        addr += chunk;
        size -= chunk;
    }
    return status;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_ERASE
int32_t sf_common_erase(sf_ctx_t *sf_ctx, size_t addr, size_t size)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint64_t erase_size = 0;

    erase_size = sf_common_get_secure_erase_size(sf_ctx);
    if (!erase_size) {
        return SECUREFLASH_ERROR_ERASE;
    }
    if ((addr + size) > sf_common_get_chip_size(sf_ctx)) {
        return SECUREFLASH_ERROR_ERASE;
    }
    if ((0 != (addr % erase_size)) || (0 != ((addr + size) % erase_size))) {
        return SECUREFLASH_ERROR_ERASE;
    }
    while (size) {
        status = sf_ctx->vendor_op.erase(sf_ctx, addr, size);
        if (SECUREFLASH_ERROR_OK != status) {
            return SECUREFLASH_ERROR_ERASE;
        }
        addr += erase_size;
        size -= erase_size;
    }
    return status;
}

int32_t sf_common_get_app_info(sf_ctx_t *sf_ctx, void *app_info)
{
    return sf_ctx->vendor_op.get_app_info(sf_ctx, app_info);
}

uint64_t sf_common_get_secure_read_size(sf_ctx_t *sf_ctx)
{
    return sf_ctx->flash_profile.architecture.secure_read_size;
}
uint64_t sf_common_get_secure_program_size(sf_ctx_t *sf_ctx)
{
    return sf_ctx->flash_profile.architecture.secure_program_size;
}
uint64_t sf_common_get_secure_erase_size(sf_ctx_t *sf_ctx)
{
    return sf_ctx->flash_profile.architecture.regions_min_secure_erase_size;
}
uint64_t sf_common_get_chip_size(sf_ctx_t *sf_ctx)
{
    return sf_ctx->flash_profile.architecture.secure_zone_total_size;
}
uint64_t sf_common_get_secure_zone_size(sf_ctx_t *sf_ctx)
{
    return sf_ctx->flash_profile.architecture.secure_zone_size;
}
uint64_t sf_common_get_secure_zone_number(sf_ctx_t *sf_ctx)
{
    return sf_ctx->flash_profile.architecture.secure_zone_number;
}
