/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "include/mx75_armor_lib.h"
#include "include/mx75_armor_sfdp.h"
#include "include/mx75_armor_vendor.h"
#include "include/mx75_armor_vendor_info.h"
#include "include/mx75_armor_vendor_local_funcs.h"
#include "include/mxic_spi_nor_command.h"
#include "include/secureflash_layout.h"
#include "../../template/plat_secure_flash.h"
#include "tfm_memory_utils.h"

#define PACKET_MAX_LEN        0x100
#define MODIFIER_LEN_3B       3
#define MODIFIER_LEN_4B       4
#define LATENCY_LEN           0
#define MAX_RETRIES           10000
#define PROVISION_INFO_SIZE   0x400
#define PGM_SIZE_DEFAULT      0x20
#define READ_SIZE_DEFAULT     0x20
#define ERASE_SIZE_DEFAULT    0x20
/* SPI Nor flash host driver */
extern ARM_DRIVER_SPI   SPI_NOR_HOST_DRIVER;

mx75_armor_vendor_context_t mx75_armor_vendor_context = {0};
/*====================================================*
 *====== Vendor specific local normal functions ======*
 *====================================================*/
static void _params_init(mx75_armor_security_ops_params_t *op_params)
{
    if(op_params != NULL) {
        tfm_memset(op_params, 0x00, sizeof(mx75_armor_security_ops_params_t));
    }
}

static void _params_free(mx75_armor_security_ops_params_t *op_params)
{
    if (op_params == NULL) {
        return;
    }
    tfm_memset(op_params, 0x00, sizeof(mx75_armor_security_ops_params_t));
}

/*====================================================*
 *====== Vendor specific local secure commands ======*
 *====================================================*/
static int32_t _aes_ccm256(sf_ctx_t *sf_ctx, uint32_t key_id,
                           uint8_t *iv, uint8_t iv_len,
                           uint8_t *add, uint8_t add_len,
                           uint8_t *tag, uint8_t tag_len,
                           uint8_t *plain_data, uint8_t *cipher_data,
                           uint8_t data_len, EncryptionProperty property)
{
    mx75_armor_vendor_context_t *armor_vendor_ctx
                          = (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    crypto_indicator_t indicator = {};

    indicator.algorithm = ALG_AES_CCM_256;
    indicator.property = property;
    indicator.aead.key_id = key_id;
    indicator.aead.iv = iv;
    indicator.aead.iv_len = iv_len;
    indicator.aead.add = add;
    indicator.aead.add_len = add_len;
    indicator.aead.tag = tag;
    indicator.aead.tag_len = tag_len;
    indicator.aead.plain_text = plain_data;
    indicator.aead.plain_text_len = data_len;
    indicator.aead.cipher_text = cipher_data;
    indicator.aead.cipher_text_len = data_len;
    switch (property) {
    case PROP_ENCRYPT_TAG_DATA:
    case PROP_ENCRYPT_TAG:
    case PROP_ENCRYPT_DATA:
        if (CRYPTO_SERVICE_ERROR_OK
                 != armor_vendor_ctx->crypto_service.aes_ccm_enc(&indicator)) {
            return SECUREFLASH_ERROR_CRYPTO_SERVICE;
        }
        break;
    case PROP_AUTHEN_TAG_DECRYPT_DATA:
    case PROP_AUTHEN_TAG:
    case PROP_DECRYPT_DATA:
        if (CRYPTO_SERVICE_ERROR_OK
                 != armor_vendor_ctx->crypto_service.aes_ccm_dec(&indicator)) {
            return SECUREFLASH_ERROR_CRYPTO_SERVICE;
        }
        break;
    default:
        return SECUREFLASH_ERROR_CRYPTO_SERVICE;
    }
    return SECUREFLASH_ERROR_OK;
}

static int32_t _hkdf_sha256(sf_ctx_t *sf_ctx, uint8_t *salt, uint8_t salt_len,
                            uint8_t *ikm, uint8_t ikm_len,
                            uint8_t *info, uint8_t info_len,
                            uint8_t *okm, uint8_t okm_len,
                            EncryptionProperty property)
{
    /* TODO */
    return SECUREFLASH_ERROR_CRYPTO_SERVICE;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_DEVICE_BUSY
/* Check if secure Flash ready to program */
static int32_t _check_ready_wo_outrdy(mx75_armor_vendor_context_t *armor_vendor_ctx)
{
    int32_t retries = 0;
    uint8_t status_reg;
    /* Polling for secure Flash ready for program */
    do {
        retries++;
        if (0 != mxic_send_spi_nor_rdsr(armor_vendor_ctx->mxic_nor_ctx,
                                        &status_reg, 1)) {
            return SECUREFLASH_ERROR_DEVICE;
        }
    } while ((__write_busy(status_reg)) && (retries < MAX_RETRIES));

    if (retries >= MAX_RETRIES) {
        return SECUREFLASH_ERROR_DEVICE_BUSY;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_DEVICE_BUSY
/* Check if secure Flash ready to read */
static int32_t _check_ready_w_outrdy(mx75_armor_vendor_context_t *armor_vendor_ctx)
{
    int32_t retries = 0;
    uint8_t status_reg;
    /* Polling for secure Flash ready for read */
    do {
        retries++;
        if (0 != mxic_send_spi_nor_rdsr(armor_vendor_ctx->mxic_nor_ctx,
                                        &status_reg, 1)) {
            return SECUREFLASH_ERROR_DEVICE_BUSY;
        }
    } while ((__read_not_ready(status_reg)) && retries < MAX_RETRIES);

    if (retries >= MAX_RETRIES) {
        return SECUREFLASH_ERROR_DEVICE_BUSY;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_DEVICE_BUSY
// SECUREFLASH_ERROR_READ_PACKET
static int32_t _receive_read_packet(mx75_armor_vendor_context_t *armor_vendor_ctx,
                                    uint8_t *read_packet, uint32_t packet_len)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    SF_COMMON_DBG_PR("%s -------------------------- <S RP>\r\n", __func__);
    /* Check ready for read */
    status = _check_ready_w_outrdy(armor_vendor_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("_check_ready_w_outrdy failed\r\n");
        status = SECUREFLASH_ERROR_READ_PACKET;
        goto read_packet_exit_point;
    }
    /* Send read packet command */
    if (0 != mxic_send_read_packet(
                                armor_vendor_ctx->mxic_nor_ctx,
                                armor_vendor_ctx->protocol.read_packet.command,
                                read_packet,
                                armor_vendor_ctx->protocol.read_packet.modifier,
                                packet_len)) {
        SF_COMMON_ERR_PR("Send read packet command failed\r\n");
        status = SECUREFLASH_ERROR_READ_PACKET;
        goto read_packet_exit_point;
    }
read_packet_exit_point:
    SF_COMMON_DBG_PR("%s -------------------------- <E RP>\r\n", __func__);
    return status;
}

static int32_t _send_reset_packet(mx75_armor_vendor_context_t *armor_vendor_ctx)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    /* check ready */
    status = _check_ready_wo_outrdy(armor_vendor_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("_check_ready_wo_outrdy failed\r\n");
        return SECUREFLASH_ERROR_WRITE_PACKET;
    }
    /* Send wren command */
    if (0 != mxic_send_spi_nor_wren(armor_vendor_ctx->mxic_nor_ctx)) {
        SF_COMMON_ERR_PR("Send reset_packet - wren failed\r\n");
        return SECUREFLASH_ERROR_WRITE_PACKET;
    }
    /* Send packet buffer address reset command */
    if (0 != mxic_send_write_packet(
                               armor_vendor_ctx->mxic_nor_ctx,
                               armor_vendor_ctx->protocol.reset_packet.command,
                               NULL,
                               armor_vendor_ctx->protocol.reset_packet.modifier,
                               0)) {
        SF_COMMON_ERR_PR("Send reset_packet failed\r\n");
        return SECUREFLASH_ERROR_WRITE_PACKET;
    }
    SF_COMMON_ERR_PR("mxic_send_write_packet OK\r\n");
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_DEVICE_BUSY
// SECUREFLASH_ERROR_WRITE_PACKET
static int32_t _send_write_packet(mx75_armor_vendor_context_t *armor_vendor_ctx,
                                  uint8_t *write_packet, uint32_t packet_len)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    SF_COMMON_DBG_PR("%s   -------------------------- <S WP>\r\n", __func__);
    status = _send_reset_packet(armor_vendor_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("_send_reset_packet failed\r\n");
        return status;
    }
    /* Check ready */
    status = _check_ready_wo_outrdy(armor_vendor_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("_check_ready_wo_outrdy failed\r\n");
        return status;
    }
    /* Send wren command */
    if (0 != mxic_send_spi_nor_wren(armor_vendor_ctx->mxic_nor_ctx)) {
        SF_COMMON_ERR_PR("Send write_packet - wren failed\r\n");
        status = SECUREFLASH_ERROR_WRITE_PACKET;
        goto write_packet_exit_point;
    }
    /* Send write packet command */
    if (0 != mxic_send_write_packet(
                               armor_vendor_ctx->mxic_nor_ctx,
                               armor_vendor_ctx->protocol.write_packet.command,
                               write_packet,
                               armor_vendor_ctx->protocol.write_packet.modifier,
                               packet_len)) {
        SF_COMMON_ERR_PR("Send write packet failed\r\n");
        status = SECUREFLASH_ERROR_WRITE_PACKET;
        goto write_packet_exit_point;
    }
write_packet_exit_point:
    SF_COMMON_DBG_PR("%s   -------------------------- <E WP>\r\n", __func__);
    return status;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_WRITE_PACKET
// SECUREFLASH_ERROR_READ_PACKET
static int32_t _armor_get_config(sf_ctx_t *sf_ctx, uint8_t *buffer,
                                 uint32_t addr, uint8_t size)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    uint8_t data[BUFFER_SIZE] = {0};
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx
                          = (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.addr = addr;
    op_params.out_size = size;
    op_params.ops = GET_CFG;
    status = __prepare_write_packet(&op_params,
                                    NULL, 0,
                                    NULL, 0,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_cfgrd_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_cfgrd_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_cfgrd_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 data, size,
                                 NULL, 0,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_cfgrd_exit_point;
    }
    tfm_memcpy(buffer, data, size);
armor_cfgrd_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_spi_write(sf_ctx_t *sf_ctx, uint8_t *buffer,
                                uint32_t addr, uint8_t size)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_vendor_context_t *armor_vendor_ctx
                          = (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    uint32_t offset, chunk;
    while (size) {
        status = _check_ready_wo_outrdy(armor_vendor_ctx);
        if (SECUREFLASH_ERROR_OK != status) {
            return status;
        }
        /* Write on page boundaries (Default 256 bytes a page) */
        offset = addr % PGM_SIZE_DEFAULT;
        chunk =
       (offset + size < PGM_SIZE_DEFAULT) ? size : (PGM_SIZE_DEFAULT - offset);
        if (0 != mxic_send_spi_nor_wren(armor_vendor_ctx->mxic_nor_ctx)) {
            return SECUREFLASH_ERROR_DEVICE;
        }
        if (0 != mxic_send_spi_nor_program(armor_vendor_ctx->mxic_nor_ctx,
                                           buffer, addr, chunk)) {
            return SECUREFLASH_ERROR_DEVICE;
        }
        buffer += chunk;
        addr += chunk;
        size -= chunk;
    }
    return status;
}

/*
* Nonce confirmation
*/
static int32_t _armor_confirm_nonce(mx75_armor_vendor_context_t *armor_vendor_ctx)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_security_ops_params_t op_params;
    _params_init(&op_params);
    op_params.ops = CONFIRM_NONCE;
    status = __prepare_write_packet(&op_params,
                                    NULL, 0,
                                    NULL, 0,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_nonce_cfrm_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_nonce_cfrm_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_nonce_cfrm_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 NULL, 0,
                                 NULL, 0,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_nonce_cfrm_exit_point;
    }
armor_nonce_cfrm_exit_point:
    _params_free(&op_params);
    return status;
}

/* Generate a random nonce from ArmorFlash */
static int32_t _armor_generate_nonce(sf_ctx_t *sf_ctx)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    uint8_t random[ARMOR_TRNG_SIZE];
    uint8_t nonce_len, actual_size;
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;

    _params_init(&op_params);
    op_params.ops = GENERATE_NONCE;
    nonce_len = __get_nonce_size(&op_params);
    if ((nonce_len > 0) && (nonce_len <= MAX_CCM_IV_LENGTH)) {
        /* generate true random number from ArmorFlash */
        status = _get_trng(sf_ctx, random, nonce_len, &actual_size);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _armor_generate_nonce_exit_point;
        }
        status = __prepare_write_packet(&op_params,
                                        random, nonce_len,
                                        NULL, 0,
                                        wr_packet, &wr_packet_len,
                                        &rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _armor_generate_nonce_exit_point;
        }
        status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _armor_generate_nonce_exit_point;
        }
        status = _receive_read_packet(armor_vendor_ctx, rd_packet,
                                      rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _armor_generate_nonce_exit_point;
        }
        status = __parse_read_packet(&op_params,
                                     NULL, 0,
                                     NULL, 0,
                                     rd_packet, rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _armor_generate_nonce_exit_point;
        }
        status = _armor_confirm_nonce(armor_vendor_ctx);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _armor_generate_nonce_exit_point;
        }
    }
_armor_generate_nonce_exit_point:
    _params_free(&op_params);
    return status;
}

/* Generate a random nonce from host */
static int32_t _armor_set_nonce(sf_ctx_t *sf_ctx,
                                mx75_armor_security_ops_params_t *params)
{
    uint8_t actual_size;
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    uint8_t random[ARMOR_TRNG_SIZE];
    uint8_t nonce_len;
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.ops = SET_NONCE;

    nonce_len = __get_nonce_size(&op_params);
    if ((nonce_len > 0) && (nonce_len <= MAX_CCM_IV_LENGTH)) {
        /* generate true random number from host*/
        status = _get_trng(sf_ctx, random, nonce_len, &actual_size);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _set_nonce_exit_point;
        }
        status = __prepare_write_packet(&op_params,
                                        random, nonce_len,
                                        NULL, 0,
                                        wr_packet, &wr_packet_len,
                                        &rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _set_nonce_exit_point;
        }
        status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _set_nonce_exit_point;
        }
        status = _receive_read_packet(armor_vendor_ctx, rd_packet,
                                      rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _set_nonce_exit_point;
        }
        status = __parse_read_packet(&op_params,
                                     NULL , 0,
                                     NULL, 0,
                                     rd_packet, rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _set_nonce_exit_point;
        }
        status = _armor_confirm_nonce(armor_vendor_ctx);
        if (SECUREFLASH_ERROR_OK != status) {
            goto _set_nonce_exit_point;
        }
    }
_set_nonce_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_import_key(sf_ctx_t *sf_ctx, uint8_t *key,
                                 uint8_t target_key_id)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    uint8_t plain_key_buf[ARMOR_KEY_SIZE] = {};
    uint8_t cipher_key_buf[ARMOR_KEY_SIZE] = {};
    uint8_t mac_buf[ARMOR_MAC_SIZE] = {};
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.in_data = plain_key_buf;
    tfm_memcpy(op_params.in_data, key, ARMOR_KEY_SIZE);
    op_params.in_size = ARMOR_KEY_SIZE;
    op_params.addr = target_key_id;
    op_params.ops = IMPORT_KEY;
    uint8_t nonce_valid = __check_nonce_valid(armor_vendor_ctx);
    if (!nonce_valid) {
        status = _armor_generate_nonce(sf_ctx);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_key_import_exit_point;
        }
    } 
    /* get linked monotonic counter id and crypto key id */
    status = __get_linked_mc_key(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_import_exit_point;
    }
    /* get IV and ADD for AES-CCM */
    status = __get_iv_add(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_import_exit_point;
    }
    /* AES CCM encryption and mac calculation */
    status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                         op_params.iv, op_params.iv_len,
                         op_params.add, op_params.add_len,
                         mac_buf, ARMOR_MAC_SIZE,
                         key, cipher_key_buf, ARMOR_KEY_SIZE,
                         PROP_ENCRYPT_TAG_DATA);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_import_exit_point;
    }
    status = __prepare_write_packet(&op_params,
                                    cipher_key_buf, ARMOR_KEY_SIZE,
                                    mac_buf, ARMOR_MAC_SIZE,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_import_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_import_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_import_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 NULL, 0,
                                 NULL, 0,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_import_exit_point;
    }
armor_key_import_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_generate_key(sf_ctx_t *sf_ctx, uint8_t *key,
                                   uint8_t target_key_id)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    uint8_t cipher_key_buf[ARMOR_KEY_SIZE] = { };
    uint8_t key_buf[ARMOR_KEY_SIZE] = { };
    uint8_t mac_buf[ARMOR_MAC_SIZE] = { };
    uint8_t imac_need;
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.addr = target_key_id;
    op_params.ops = GENERATE_KEY;
    uint8_t nonce_valid = __check_nonce_valid(armor_vendor_ctx);
    if (!nonce_valid) {
        status = _armor_generate_nonce(sf_ctx);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_key_gen_exit_point;
        }
    }
    /* get linked monotonic counter id and crypto key id */
    status = __get_linked_mc_key(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_gen_exit_point;
    }
    /* check if input MAC needed */
    imac_need = __check_optional_authen(&op_params);
    if (imac_need) {
        /* get IV and ADD for AES-CCM */
        status = __get_iv_add(&op_params);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_key_gen_exit_point;
        }
        /* Calculate authentication mac with AES CCM */
        status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                             op_params.iv, op_params.iv_len,
                             op_params.add, op_params.add_len,
                             mac_buf, ARMOR_MAC_SIZE,
                             NULL, NULL, 0, PROP_ENCRYPT_TAG);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_key_gen_exit_point;
        }
        status = __prepare_write_packet(&op_params,
                                        NULL, 0,
                                        mac_buf, ARMOR_MAC_SIZE,
                                        wr_packet, &wr_packet_len,
                                        &rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_key_gen_exit_point;
        }
    } else {
        status = __prepare_write_packet(&op_params,
                                        NULL, 0,
                                        NULL, 0,
                                        wr_packet, &wr_packet_len,
                                        &rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
             goto armor_key_gen_exit_point;
        }
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_gen_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_gen_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 cipher_key_buf, ARMOR_KEY_SIZE,
                                 mac_buf, ARMOR_MAC_SIZE,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_gen_exit_point;
    }
    /* get IV and ADD for AES-CCM */
    status = __get_iv_add(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_gen_exit_point;
    }
    /* Authenticate mac and decrypt cipher_key with AES CCM */
    status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                         op_params.iv, op_params.iv_len,
                         op_params.add, op_params.add_len,
                         mac_buf, ARMOR_MAC_SIZE, 
                         cipher_key_buf, key_buf, ARMOR_KEY_SIZE,
                         PROP_AUTHEN_TAG_DECRYPT_DATA);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_gen_exit_point;
    }
    tfm_memcpy(key, key_buf, ARMOR_KEY_SIZE);
armor_key_gen_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_derive_key(sf_ctx_t *sf_ctx, uint8_t target_key_id)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx
                          = (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.ops = DERIVE_KEY;
    status = __prepare_write_packet(&op_params,
                                    NULL, 0,
                                    NULL, 0,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_derive_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_derive_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_derive_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 NULL, 0,
                                 NULL, 0,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_key_derive_exit_point;
    }
armor_key_derive_exit_point:
    _params_free(&op_params);
    return status;
}

static inline int32_t _armor_inject_key(sf_ctx_t *sf_ctx, uint8_t *key,
                                        uint8_t target_key_id)
{
    uint32_t key_addr = __get_target_addr(KEY_ITEM);
    return _armor_spi_write(sf_ctx, key,
                            key_addr + target_key_id * ARMOR_KEY_SIZE,
                            ARMOR_KEY_SIZE);
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_ENCRYPTION
// SECUREFLASH_ERROR_MAC_VERIFICATION
static int32_t _armor_read_mc(sf_ctx_t *sf_ctx, uint8_t mc_id, uint8_t *mc,
                              uint8_t mc_size)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t mc_buf[ARMOR_MC_SIZE];
    uint8_t authen_need;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.addr = mc_id;
    op_params.ops = MC_READ;
    /* check if output MAC authentication needed */
    authen_need = __check_optional_authen(&op_params);
    if (authen_need) {
        uint8_t nonce_valid = __check_nonce_valid(armor_vendor_ctx);
        if (!nonce_valid) {
            status = _armor_generate_nonce(sf_ctx);
            if (SECUREFLASH_ERROR_OK != status) {
                goto armor_mc_rd_exit_point;
            }
        }
    }
    status = __prepare_write_packet(&op_params,
                                    NULL, 0, 
                                    NULL, 0,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_mc_rd_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("send_write_packet failed, %d\r\n", status);
        goto armor_mc_rd_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        SF_COMMON_ERR_PR("receive_read_packet failed, %d\r\n", status);
        goto armor_mc_rd_exit_point;
    }
    if (authen_need) {
        uint8_t mac_buf[ARMOR_MAC_SIZE] = {};
        status = __parse_read_packet(&op_params,
                                     mc_buf, ARMOR_MC_SIZE,
                                     mac_buf, ARMOR_MAC_SIZE,
                                     rd_packet, rd_packet_len);
        op_params.out_data = mc_buf;
        op_params.out_size = ARMOR_MC_SIZE;
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_rd_exit_point;
        }
        /* get linked monotonic counter id and crypto key id */
        status = __get_linked_mc_key(&op_params);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_rd_exit_point;
        }
        /* get IV and ADD for AES-CCM */
        status = __get_iv_add(&op_params);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_rd_exit_point;
        }
        /* Authenticate MAC with AES CCM */
        status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                             op_params.iv, op_params.iv_len,
                             op_params.add, op_params.add_len,
                             mac_buf, ARMOR_MAC_SIZE, NULL,
                             NULL, 0, PROP_AUTHEN_TAG);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_rd_exit_point;
        }
    } else {
        status = __parse_read_packet(&op_params,
                                     mc_buf, ARMOR_MC_SIZE,
                                     NULL, 0,
                                     rd_packet, rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_rd_exit_point;
        }
    }
    tfm_memcpy(mc, mc_buf, mc_size);
armor_mc_rd_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_increase_mc(sf_ctx_t *sf_ctx, uint8_t mc_id, uint8_t *mc)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t mc_buf[ARMOR_MC_SIZE];
    uint8_t imac_need;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.in_data = mc;
    op_params.in_size = ARMOR_MC_SIZE;
    op_params.addr = mc_id;
    op_params.ops = MC_INCREASEMENT;
    /* check if input MAC needed */
    imac_need = __check_optional_authen(&op_params);
    if (imac_need) {
        uint8_t mac_buf[ARMOR_MAC_SIZE] = {};
        uint8_t nonce_valid = __check_nonce_valid(armor_vendor_ctx);
        if (!nonce_valid) {
            status = _armor_generate_nonce(sf_ctx);
            if (SECUREFLASH_ERROR_OK != status) {
                goto armor_mc_inc_exit_point;
            }
        }
        /* get linked monotonic counter id and crypto key id */
        status = __get_linked_mc_key(&op_params);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_inc_exit_point;
        }
        /* get IV and ADD for AES-CCM */
        status = __get_iv_add(&op_params);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_inc_exit_point;
        }
        /* Calculate authentication mac with AES CCM */
        status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                             op_params.iv, op_params.iv_len, 
                             op_params.add, op_params.add_len,
                             mac_buf, ARMOR_MAC_SIZE, 
                             NULL, NULL, 0, PROP_ENCRYPT_TAG);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_inc_exit_point;
        }
        status = __prepare_write_packet(&op_params,
                                        NULL, 0, 
                                        mac_buf, ARMOR_MAC_SIZE,
                                        wr_packet, &wr_packet_len,
                                        &rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_mc_inc_exit_point;
        }
    } else {
        status = __prepare_write_packet(&op_params,
                                        NULL, 0,
                                        NULL, 0,
                                        wr_packet, &wr_packet_len,
                                        &rd_packet_len);
         if (SECUREFLASH_ERROR_OK != status) {
             goto armor_mc_inc_exit_point;
         }
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_mc_inc_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_mc_inc_exit_point;;
    }
    status = __parse_read_packet(&op_params,
                                 mc_buf, ARMOR_MC_SIZE,
                                 NULL, 0,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_mc_inc_exit_point;
    }
armor_mc_inc_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_pufrd(sf_ctx_t *sf_ctx, uint8_t *puf)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    uint8_t cipher_buf[ARMOR_PUF_SIZE] = {};
    uint8_t plain_buf[ARMOR_PUF_SIZE] = {};
    uint8_t mac[ARMOR_MAC_SIZE] = {};
    int32_t status = SECUREFLASH_ERROR_OK;

    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.ops = READ_PUF;
    uint8_t nonce_valid = __check_nonce_valid(armor_vendor_ctx);
    if (!nonce_valid) {
        status = _armor_generate_nonce(sf_ctx);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_puf_rd_exit_point;
        }
    }
    status = __prepare_write_packet(&op_params,
                                    NULL, 0,
                                    NULL, 0,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_puf_rd_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_puf_rd_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_puf_rd_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 cipher_buf, ARMOR_PUF_SIZE,
                                 mac, ARMOR_MAC_SIZE,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_puf_rd_exit_point;
    }    
    /* get linked monotonic counter id and crypto key id */
    status = __get_linked_mc_key(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_puf_rd_exit_point;
    }
    /* get IV and ADD for AES-CCM */
    status = __get_iv_add(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_puf_rd_exit_point;
    }
    /* Authenticate mac and decrypt cipher_key with AES CCM */
    status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                         op_params.iv, op_params.iv_len,
                         op_params.add, op_params.add_len,
                         mac, ARMOR_MAC_SIZE,
                         cipher_buf, plain_buf,
                         ARMOR_PUF_SIZE, PROP_AUTHEN_TAG_DECRYPT_DATA);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_puf_rd_exit_point;
    }
    tfm_memcpy(puf, plain_buf, ARMOR_PUF_SIZE);
armor_puf_rd_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_secure_read(sf_ctx_t *sf_ctx, uint8_t *buffer,
                                  uint32_t addr, uint32_t size,
                                  uint32_t key_id)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    uint8_t cipher_buf[BUFFER_SIZE] = {0};
    uint8_t plain_buf[BUFFER_SIZE] = {0};
    uint8_t mac[ARMOR_MAC_SIZE] = {};
    int32_t status = SECUREFLASH_ERROR_OK;

    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    uint32_t read_size = sf_ctx->flash_profile.architecture.secure_read_size;
    if (read_size > BUFFER_SIZE) {
        status = SECUREFLASH_ERROR_ALLOCATION;
        goto armor_sread_exit_point;
    }
    op_params.addr = addr;
    op_params.out_size = size;
    op_params.crypto_key_id = key_id;
    op_params.ops = SECURITY_READ;
    uint8_t nonce_valid = __check_nonce_valid(armor_vendor_ctx);
    if (!nonce_valid) {
        status = _armor_generate_nonce(sf_ctx);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_sread_exit_point;
        }
    }
    status = __prepare_write_packet(&op_params,
                                    NULL, 0,
                                    NULL, 0,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sread_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sread_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sread_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 cipher_buf, read_size,
                                 mac, ARMOR_MAC_SIZE,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sread_exit_point;
    }
    /* get linked monotonic counter id and crypto key id */
    status = __get_linked_mc_key(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sread_exit_point;
    }
    /* get IV and ADD for AES-CCM */
    status = __get_iv_add(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sread_exit_point;
    }
    /* Authenticate mac and decrypt cipher_key with AES CCM */
    status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                         op_params.iv, op_params.iv_len,
                         op_params.add, op_params.add_len,
                         mac, ARMOR_MAC_SIZE,
                         plain_buf, cipher_buf, read_size,
                         PROP_AUTHEN_TAG_DECRYPT_DATA);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sread_exit_point;
    }
    size = (size > read_size) ? read_size : size;
    tfm_memcpy(buffer, plain_buf, size);
armor_sread_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_secure_write_impl(sf_ctx_t *sf_ctx, uint8_t *buffer,
                                        uint32_t addr, uint32_t size,
                                        uint32_t key_id,
                                        mx75_armor_security_ops_t wr_op)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t actual_size;
    uint8_t mc[ARMOR_MC_SIZE];
    uint8_t cipher_buf[BUFFER_SIZE] = {0};
    uint8_t mac_buf[ARMOR_MAC_SIZE] = {};

    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    uint32_t program_size =
                        sf_ctx->flash_profile.architecture.secure_program_size;
    if (program_size > BUFFER_SIZE) {
        status = SECUREFLASH_ERROR_ALLOCATION;
        goto armor_sec_wr_exit_point;
    }
    op_params.addr = addr;
    op_params.in_size = size;
    op_params.crypto_key_id = key_id;
    op_params.ops = wr_op;
    uint8_t nonce_valid = __check_nonce_valid(armor_vendor_ctx);
    if (!nonce_valid) {
        status = _armor_generate_nonce(sf_ctx);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_sec_wr_exit_point;
        }
    }
    /* get linked monotonic counter id and crypto key id */
    status = __get_linked_mc_key(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sec_wr_exit_point;
    }
    /* get IV and ADD for AES-CCM */
    status = __get_iv_add(&op_params);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sec_wr_exit_point;
    }
    /* AES CCM encryption */
    status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                         op_params.iv, op_params.iv_len,
                         op_params.add, op_params.add_len,
                         mac_buf, ARMOR_MAC_SIZE,
                         buffer, cipher_buf, program_size,
                         PROP_ENCRYPT_TAG_DATA);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sec_wr_exit_point;
    }
    status = __prepare_write_packet(&op_params,
                                    cipher_buf, program_size,
                                    mac_buf, ARMOR_MAC_SIZE,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sec_wr_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sec_wr_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_sec_wr_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 NULL, 0,
                                 NULL, 0,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK == status) {
        /* Refresh linked monotonic counter value after successful security program */
        status = _get_mc(sf_ctx, op_params.linked_mc_id, mc,
                         ARMOR_MC_SIZE, &actual_size);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_sec_wr_exit_point;
        }
    }
armor_sec_wr_exit_point:
    _params_free(&op_params);
    return status;
}

static int32_t _armor_secure_write(sf_ctx_t *sf_ctx, uint8_t *buffer,
                                   uint32_t addr, uint32_t size,
                                   uint32_t key_id)
{
    return _armor_secure_write_impl(sf_ctx, buffer, addr, size, key_id,
                                    SECURITY_WRITE);
}

static int32_t _armor_secure_erase(sf_ctx_t *sf_ctx, uint32_t addr,
                                   uint32_t size, uint32_t key_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t ers_data[BUFFER_SIZE] = {};
    uint32_t erase_size =
                        sf_ctx->flash_profile.architecture.secure_program_size;

    if (erase_size > BUFFER_SIZE) {
        status = SECUREFLASH_ERROR_ALLOCATION;
        goto armor_sec_ers_exit_point;
    }
    tfm_memset(ers_data, 0xFF, erase_size);
    status = _armor_secure_write_impl(sf_ctx, ers_data, addr, size, key_id,
                                      SECURITY_ERASE);
armor_sec_ers_exit_point:
    return status;
}

static int32_t _armor_lkd(sf_ctx_t *sf_ctx, lock_data_t *lock_data)
{
    uint8_t wr_packet[PACKET_MAX_LEN], rd_packet[PACKET_MAX_LEN];
    uint32_t wr_packet_len, rd_packet_len;
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t mac_buf[ARMOR_MAC_SIZE] = {};
    uint8_t imac_need = 0;
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    _params_init(&op_params);
    op_params.ops = LOCK_DOWN;
    if (__check_lkd_data(lock_data, &op_params)) {
        goto armor_lkd_exit_point;
    }
    imac_need = __check_optional_authen(&op_params);
    if (imac_need) {
        /* generate true random number */
        uint8_t nonce_valid = __check_nonce_valid(armor_vendor_ctx);
        if (!nonce_valid) {
            status = _armor_generate_nonce(sf_ctx);
            if (SECUREFLASH_ERROR_OK != status) {
                goto armor_lkd_exit_point;
            }
        }
        /* get linked monotonic counter id and crypto key id */
        status = __get_linked_mc_key(&op_params);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_lkd_exit_point;
        }
        /* get IV and ADD for AES-CCM */
        status = __get_iv_add(&op_params);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_lkd_exit_point;
        }
        /* Calculate authentication mac with AES CCM */
        status = _aes_ccm256(sf_ctx, op_params.crypto_key_id,
                             op_params.iv, op_params.iv_len,
                             op_params.add, op_params.add_len,
                             mac_buf, ARMOR_MAC_SIZE,
                             NULL, NULL, 0, PROP_ENCRYPT_TAG);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_lkd_exit_point;
        }
        status = __prepare_write_packet(&op_params,
                                        NULL, 0,
                                        mac_buf, ARMOR_MAC_SIZE,
                                        wr_packet, &wr_packet_len,
                                        &rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_lkd_exit_point;
        }
    } else {
        status = __prepare_write_packet(&op_params,
                                        NULL, 0,
                                        NULL, 0,
                                        wr_packet, &wr_packet_len,
                                        &rd_packet_len);
        if (SECUREFLASH_ERROR_OK != status) {
            goto armor_lkd_exit_point;
        }
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_lkd_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_lkd_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 NULL, 0,
                                 NULL, 0,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto armor_lkd_exit_point;
    }
armor_lkd_exit_point:
    _params_free(&op_params);
    return status;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_DEVICE
static int32_t _enter_sf(mx75_armor_vendor_context_t *armor_vendor_ctx)
{
    uint8_t scur_reg;

    if (0 != mxic_send_spi_nor_ensf(armor_vendor_ctx->mxic_nor_ctx)) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != mxic_send_spi_nor_rdscur(armor_vendor_ctx->mxic_nor_ctx,
                                      &scur_reg, 1)) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 == __check_security_field(scur_reg)) {
        SF_COMMON_ERR_PR("Enter security field failed, scur: %02X\r\n",
                         scur_reg);
        return SECUREFLASH_ERROR_ENTER_SECURITY_FIELD;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_DEVICE
static int32_t _exit_sf(mx75_armor_vendor_context_t *armor_vendor_ctx)
{
    uint8_t scur_reg;

    if(0 != mxic_send_spi_nor_exsf(armor_vendor_ctx->mxic_nor_ctx)) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != mxic_send_spi_nor_rdscur(armor_vendor_ctx->mxic_nor_ctx,
                                      &scur_reg, 1)) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != __check_security_field(scur_reg)) {
        SF_COMMON_ERR_PR("Exit security field failed, scur: %02X\r\n",
                         scur_reg);
        return SECUREFLASH_ERROR_EXIT_SECURITY_FIELD;
    }
    return SECUREFLASH_ERROR_OK;
}

static int32_t _switch_security_field(
                                 mx75_armor_vendor_context_t *armor_vendor_ctx,
                                 uint8_t enter_security_field)
{
    if (enter_security_field) {
        return _enter_sf(armor_vendor_ctx);
    }
    return _exit_sf(armor_vendor_ctx);
}

/**
 * security key commands
 */
static int32_t _write_key(sf_ctx_t *sf_ctx, uint8_t *key,
                          uint8_t target_key_id, uint8_t type)
{
    int32_t status = SECUREFLASH_ERROR_OK;

    switch (type) {
    case KEY_INFO_IMPORT:
        status = _armor_import_key(sf_ctx, key, target_key_id);
        break;
    case KEY_INFO_GENERATE:
        status = _armor_generate_key(sf_ctx, key, target_key_id);
        break;
    case KEY_INFO_DERIVE:
        status = _armor_derive_key(sf_ctx, target_key_id);
        break;
    case KEY_INFO_INJECT:
        status = _armor_inject_key(sf_ctx, key, target_key_id);
        break;
    default:
        status = SECUREFLASH_ERROR_WRITE_PROVISION;
        break;
    }
    return status;
}

// SECUREFLASH_ERROR_OK
static int32_t _get_config_data(sf_ctx_t *sf_ctx)
{
    int32_t status = SECUREFLASH_ERROR_OK, n;
    uint8_t data_buf[BUFFER_SIZE];

    uint32_t cfg_addr = __get_target_addr(CFG_ITEM);
    uint32_t cfg_size = __get_target_size(CFG_ITEM);
    uint32_t read_size = READ_SIZE_DEFAULT;
    for (n = 0; n < cfg_size; n += read_size) {
        status = _armor_get_config(sf_ctx, data_buf + n,
                                   cfg_addr + n, read_size);
        if (SECUREFLASH_ERROR_OK != status) {
            return status;
        }
    }
    status = __parse_security_configuration(data_buf, cfg_size);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    return SECUREFLASH_ERROR_OK;
}

// SECUREFLASH_ERROR_OK
static int32_t _mc_init(sf_ctx_t *sf_ctx)
{
    int32_t status = SECUREFLASH_ERROR_OK, n;
    uint8_t mc_num;
    uint8_t mc[ARMOR_MC_SIZE];
    mc_num = __get_mc_num();
    for (n = 0; n < mc_num; n++) {
        status = _armor_read_mc(sf_ctx, n, mc, ARMOR_MC_SIZE);
        if (SECUREFLASH_ERROR_OK != status) {
            return status;
        }
    }
    return SECUREFLASH_ERROR_OK;
}

/*
* Get true random number with ArmorFlash TRNG(True random number generator)
*/
static int32_t _get_trng(sf_ctx_t *sf_ctx, uint8_t *random, uint8_t size,
                         uint8_t *actual_size)
{
    uint8_t wr_packet[PACKET_MAX_LEN] = {0}, rd_packet[PACKET_MAX_LEN] = {0};
    uint32_t wr_packet_len, rd_packet_len;
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t buf[ARMOR_TRNG_SIZE] = {0};
    mx75_armor_security_ops_params_t op_params;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;

    _params_init(&op_params);
    op_params.ops = GENERATE_TRUE_RANDOM;
    status = __prepare_write_packet(&op_params,
                                    NULL, 0,
                                    NULL, 0,
                                    wr_packet, &wr_packet_len, &rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto get_trng_exit_point;
    }
    status = _send_write_packet(armor_vendor_ctx, wr_packet, wr_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto get_trng_exit_point;
    }
    status = _receive_read_packet(armor_vendor_ctx, rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto get_trng_exit_point;
    }
    status = __parse_read_packet(&op_params,
                                 buf, ARMOR_TRNG_SIZE,
                                 NULL, 0,
                                 rd_packet, rd_packet_len);
    if (SECUREFLASH_ERROR_OK != status) {
        goto get_trng_exit_point;
    }
    *actual_size = (size > ARMOR_TRNG_SIZE) ? ARMOR_TRNG_SIZE : size;
    tfm_memcpy(random, buf, *actual_size);
get_trng_exit_point:
    _params_free(&op_params);
    return status;
}

/*
* Get ArmorFlash unique id
*/
static int32_t _get_uid(sf_ctx_t *sf_ctx, uint8_t *uid, uint8_t size,
                        uint8_t *actual_size)
{
    return __get_uid(uid, size, actual_size);
}

static int32_t _get_puf(sf_ctx_t *sf_ctx, uint8_t *puf, uint8_t size,
                        uint8_t *actual_size, uint8_t *input_param,
                        uint8_t input_param_size)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t buf[ARMOR_PUF_SIZE] = {};
    uint8_t random[ARMOR_TRNG_SIZE] = {};
    uint8_t trng_size = ARMOR_TRNG_SIZE;

    status = _armor_pufrd(sf_ctx, buf);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    status = _get_trng(sf_ctx, random, ARMOR_TRNG_SIZE, &trng_size);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    *actual_size = size > ARMOR_PUF_SIZE ? ARMOR_PUF_SIZE : size;
    _hkdf_sha256(sf_ctx, buf, ARMOR_PUF_SIZE, input_param, input_param_size,
                 random, ARMOR_TRNG_SIZE, puf, *actual_size, PROP_HKDF);
    return status;
}

static inline int32_t _get_mc(sf_ctx_t *sf_ctx, uint8_t mc_id, uint8_t *mc,
                              uint8_t size, uint8_t *actual_size)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    *actual_size = size > ARMOR_MC_SIZE ? ARMOR_MC_SIZE : size;
    status = _armor_read_mc(sf_ctx, mc_id, mc, *actual_size);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    return SECUREFLASH_ERROR_OK;
}

static inline int32_t _increase_mc(sf_ctx_t *sf_ctx, uint8_t mc_id, uint8_t *mc)
{
    return _armor_increase_mc(sf_ctx, mc_id, mc);
}

static int32_t _get_security_info(sf_ctx_t *sf_ctx)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    status = _get_config_data(sf_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    status = _mc_init(sf_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    status = _armor_generate_nonce(sf_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    return status;
}

static int32_t _check_major_header(uint8_t *provision_data_blob,
                                   provision_major_header_t **major_header)
{
    *major_header = (provision_major_header_t *)provision_data_blob;

    SF_COMMON_DBG_PR("major_header-magic:      %c%c%c%c\r\n",
                     (*major_header)->magic[0],(*major_header)->magic[1],
                     (*major_header)->magic[2],(*major_header)->magic[3]);
    SF_COMMON_DBG_PR("major_header-version:        %02X\r\n",
                     (*major_header)->version);
    SF_COMMON_DBG_PR("major_header-total size:     %04X\r\n",
                     (*major_header)->total_size);
    SF_COMMON_DBG_PR("major_header-sub_header num: %02X\r\n",
                     (*major_header)->sub_header_num);
    if (0 != tfm_memcmp((*major_header)->magic, "SFPI", 4)) {
        SF_COMMON_ERR_PR("Check magic \"SFPI\" failed\r\n");
        return -1;
    }
    return 0;
}

/*
* Lock down configuration.
*/
static int32_t _config_lock(sf_ctx_t *sf_ctx, lock_info_t *lock_info,
                            lock_info_t *actual_lock_info)
{
    int32_t n;
    if (SUB_ID_LOCK_INFO != lock_info->id) {
        return -1;
    }
    if (__check_lock_info(lock_info, actual_lock_info)) {
        return -1;
    }
    for (n = 0; n < lock_info->num; n++) {
        if (SECUREFLASH_ERROR_OK != _armor_lkd(sf_ctx,
                                               &lock_info->lock_data[n])) {
            return -1;
        }
    }
    return 0;
}

static int32_t _config_mc(sf_ctx_t *sf_ctx, mc_info_t *mc_info)
{
    int32_t n;

    if (SUB_ID_MC_INFO != mc_info->id) {
        return -1;
    }
    uint32_t mc_addr = __get_target_addr(MC_ITEM);
    for (n = 0; n < mc_info->num; n++) {
        if (SECUREFLASH_ERROR_OK !=
                            _armor_spi_write(sf_ctx, mc_info->mc_data[n].value,
                                             mc_addr + n * ARMOR_MC_SIZE,
                                             ARMOR_MC_SIZE)) {
            return -1;
        }
    }
    return 0;
}

static int32_t _config_secure_flash(sf_ctx_t *sf_ctx, config_info_t *config_info,
                                    uint16_t config_info_size)
{
    int32_t n;
    uint16_t config_data_size = config_info_size - sizeof(int32_t);
    if (SUB_ID_CONFIG_INFO != config_info->id) {
        return -1;
    }
    uint32_t cfg_addr = __get_target_addr(CFG_ITEM);
    uint32_t program_size = PGM_SIZE_DEFAULT;
    for (n = 0; n < config_data_size; n += program_size) {
        if (SECUREFLASH_ERROR_OK !=
           _armor_spi_write(sf_ctx, ((uint8_t *)&config_info->config_data) + n,
                            cfg_addr + n, program_size)) {
            return -1;
        }
    }
    return 0;
}

/* derive ArmorFlash pre-provision keys */
static int32_t _derive_preprovision_key(sf_ctx_t *sf_ctx, key_data_t *key_data,
                                        uint8_t *key)
{
    key_attr_t key_attr = KEY_ATTR_INIT;
    int32_t status = SECUREFLASH_ERROR_OK;
    crypto_indicator_t indicator = {};
    uint8_t puf[ARMOR_PUF_SIZE] = {}, random[ARMOR_TRNG_SIZE] = {}, zero[4] = {};
    uint8_t uid_size, actual_size;
    uint8_t uid[BUFFER_SIZE] = {};
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    if (ARMOR_KEY_SIZE != (key_data->key_len / 8)) {
        return -1;
    }
    /* Import input key message of hkdf */
    key_attr.usage = KEY_USAGE_DERIVE;
    key_attr.alg = ALG_HKDF;
    key_attr.bits = sizeof(key_data->derive_message) * 8;
    key_attr.lifetime = KEY_LIFETIME_VOLATILE;
    key_attr.type = KEY_TYPE_DERIVE;
    if (CRYPTO_SERVICE_ERROR_OK !=
                          armor_vendor_ctx->crypto_service.store_key(&key_attr,
                                        (uint8_t *)(&key_data->derive_message),
                                        sizeof(key_data->derive_message),
                                        &key_attr.key_id)) {
        return SECUREFLASH_ERROR_CRYPTO_SERVICE;
    }
    indicator.algorithm = ALG_HKDF_SHA_256;
    indicator.property = PROP_HKDF;
    indicator.hkdf.ik_id = key_attr.key_id;
    indicator.hkdf.okm = key;
    indicator.hkdf.okm_len = ARMOR_KEY_SIZE;
    switch (key_data->derive_params_suite) {
    case HKDF_0_MSG_UID:
        uid_size = __get_uid_size();
        if (uid_size > BUFFER_SIZE) {
            return SECUREFLASH_ERROR_ALLOCATION;
        }
        status = _get_uid(sf_ctx, uid, uid_size, &actual_size);
        if (SECUREFLASH_ERROR_OK != status) {
            return SECUREFLASH_ERROR_INITIAL;
        }
        indicator.hkdf.salt = zero;
        indicator.hkdf.salt_len = 4;
        indicator.hkdf.info = uid;
        indicator.hkdf.info_len = actual_size;
        break;
    case HKDF_0_MSG_PUF:
        status = _get_trng(sf_ctx, random, ARMOR_TRNG_SIZE, &actual_size);
        if (SECUREFLASH_ERROR_OK != status) {
            return SECUREFLASH_ERROR_INITIAL;
        }
        status = _get_puf(sf_ctx, puf, ARMOR_PUF_SIZE, &actual_size,
                          random, actual_size);
        if (SECUREFLASH_ERROR_OK != status) {
            return SECUREFLASH_ERROR_INITIAL;
        }
        indicator.hkdf.salt = zero;
        indicator.hkdf.salt_len = 4;
        indicator.hkdf.info = puf;
        indicator.hkdf.info_len = actual_size;
        break;
    case HKDF_0_MSG_TRNG:
        status = _get_trng(sf_ctx, random, ARMOR_TRNG_SIZE, &actual_size);
        if (SECUREFLASH_ERROR_OK != status) {
            return SECUREFLASH_ERROR_INITIAL;
        }
        indicator.hkdf.salt = zero;
        indicator.hkdf.salt_len = 4;
        indicator.hkdf.info = random;
        indicator.hkdf.info_len = actual_size;
        break;
    default:
        return -1;
    }
    /* derive pre-provisioned keys */
    key_attr.usage = KEY_USAGE_EXPORT;
    key_attr.alg = ALG_CCM;
    key_attr.bits = ARMOR_KEY_SIZE * 8;
    key_attr.lifetime = KEY_LIFETIME_VOLATILE;
    key_attr.type = KEY_TYPE_AES;
    if (CRYPTO_SERVICE_ERROR_OK !=
             armor_vendor_ctx->crypto_service.gen_key(&key_attr, &indicator)) {
        return SECUREFLASH_ERROR_CRYPTO_SERVICE;
    }
    /* export key value */
    if (CRYPTO_SERVICE_ERROR_OK !=
                 armor_vendor_ctx->crypto_service.get_key(key_attr.key_id, key,
                                                          ARMOR_KEY_SIZE)) {
        return SECUREFLASH_ERROR_CRYPTO_SERVICE;
    }
    status = armor_vendor_ctx->crypto_service.delete_key(key_attr.key_id);
    if (CRYPTO_SERVICE_ERROR_OK != status) {
        return SECUREFLASH_ERROR_CRYPTO_SERVICE;
    }
    /* import key */
    key_attr.usage = KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT;
    key_attr.alg = ALG_CCM;
    key_attr.bits = ARMOR_KEY_SIZE * 8;
    key_attr.lifetime = KEY_LIFETIME_PERSISTENT;
    key_attr.type = KEY_TYPE_AES;
    key_attr.key_id = key_data->key_id;
    if (CRYPTO_SERVICE_ERROR_OK !=
                    armor_vendor_ctx->crypto_service.store_key(&key_attr, key,
                                                               ARMOR_KEY_SIZE,
                                                               &key_attr.key_id)
                                                                ) {
        return SECUREFLASH_ERROR_CRYPTO_SERVICE;
    }
    return CRYPTO_SERVICE_ERROR_OK;
}

static int32_t _provision_key(sf_ctx_t *sf_ctx, uint8_t flag_inject_key)
{
    int32_t n;
    mx75_armor_vendor_context_t *armor_vendor_ctx
                          = (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    uint8_t key[ARMOR_KEY_SIZE];
    key_data_t *key_data = NULL;

    if (SUB_ID_KEY_INFO != armor_vendor_ctx->provision_info.key_info.id ) {
        SF_COMMON_ERR_PR("Table ID is not matched\r\n");
        return -1;
    }
    for (n = 0; n < armor_vendor_ctx->provision_info.key_info.num; n++) {
        key_data = &armor_vendor_ctx->provision_info.key_info.key_data[n];
        SF_COMMON_DBG_PR("key info<%d> - key_id:  %08X\r\n",
                         n, key_data->key_id);
        SF_COMMON_DBG_PR("key info<%d> - d msg:   %08X\r\n",
                         n, key_data->derive_message);
        SF_COMMON_DBG_PR("key info<%d> - d p s:   %02X\r\n",
                         n, key_data->derive_params_suite);
        SF_COMMON_DBG_PR("key info<%d> - key len: %04X -bytes\r\n",
                         n, key_data->key_len / 8);
        SF_COMMON_DBG_PR("key info<%d> - inject:  %02X\r\n",
                         n, key_data->inject_type);
        if (0 != _derive_preprovision_key(sf_ctx, key_data, key)) {
            SF_COMMON_ERR_PR("key derivation failed\r\n");
            return -1;
        }
        SF_COMMON_DBG_PR("key_id<%d>:  %08X\r\n", n, key_data->key_id);
        for (int32_t q = 0; q < key_data->key_len / 8; q++) {
            SF_COMMON_DBG_PR("%02X", key[q]);
        }
        SF_COMMON_DBG_PR("\r\n");
        if (flag_inject_key) {
            if (SECUREFLASH_ERROR_OK !=
                           _write_key(sf_ctx, key, n, key_data->inject_type)) {
                SF_COMMON_ERR_PR("Inject key to flash failed\r\n");
                return -1;
            }
        }
    }
    return 0;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_INITIAL
// SECUREFLASH_ERROR_UNPROVISIONED
static int32_t _get_provision_info(mx75_armor_vendor_context_t *armor_vendor_ctx)
{
    int32_t status = SECUREFLASH_ERROR_OK, n;
    provision_major_header_t *major_header = NULL;
    provision_sub_header_t *sub_header = NULL;
    uint8_t provision_data_buf[PROVISION_INFO_SIZE] = {};

    status = plat_get_secure_flash_provision_info(provision_data_buf,
                                                  PROVISION_INFO_SIZE);
    if (SECUREFLASH_ERROR_OK != status) {
        return SECUREFLASH_ERROR_INITIAL;
    }
    /* check magic of major header of achieved provision data */
    if (0 == _check_major_header(provision_data_buf, &major_header)) {
        armor_vendor_ctx->provision_info.is_provisioned = 1;
        SF_COMMON_DBG0_PR("Flash is provisioned\r\n");
        for (n = 0; n < major_header->sub_header_num; n++) {
            sub_header = (provision_sub_header_t *)(provision_data_buf +
                            SFPI_MAJOR_HEADER_SIZE + n * SFPI_SUB_HEADER_SIZE);
            SF_COMMON_DBG_PR("sub_header-id:         %02X\r\n",
                             sub_header->id);
            SF_COMMON_DBG_PR("sub_header-version:    %02X\r\n",
                             sub_header->version);
            SF_COMMON_DBG_PR("sub_header-store:      %02X\r\n",
                             sub_header->store);
            SF_COMMON_DBG_PR("sub_header-table size: %04X\r\n",
                             sub_header->table_size);
            SF_COMMON_DBG_PR("sub_header-offset:     %04X\r\n",
                             sub_header->offset);
            if (provision_data_buf[sub_header->offset] != sub_header->id) {
                SF_COMMON_ERR_PR("sub header id is not matched, exp: %02X, act: %02X\r\n",
                                 sub_header->id,
                                 provision_data_buf[sub_header->offset]);
                return SECUREFLASH_ERROR_INITIAL;
            }
            switch (sub_header->id) {
            case SUB_ID_KEY_INFO:
                tfm_memcpy(&armor_vendor_ctx->provision_info.key_info,
                           &provision_data_buf[sub_header->offset],
                           sub_header->table_size);
                status = __parse_key_provision_info(
                                    &armor_vendor_ctx->provision_info.key_info,
                                    sizeof(key_info_t));
                if (SECUREFLASH_ERROR_OK != status) {
                    return status;
                }
                break;
            case SUB_ID_APP_INFO:
                tfm_memcpy(&armor_vendor_ctx->provision_info.app_info,
                           &provision_data_buf[sub_header->offset],
                           sub_header->table_size);
                break;
            case SUB_ID_LOCK_INFO:
                tfm_memcpy(&armor_vendor_ctx->provision_info.lock_info,
                           &provision_data_buf[sub_header->offset],
                           sub_header->table_size);
            default:
                break;
            }
        }
    } else {
        armor_vendor_ctx->provision_info.is_provisioned = 0;
        SF_COMMON_ERR_PR("This flash is not provisioned\r\n");
        return SECUREFLASH_ERROR_UNPROVISIONED;
    }
    return status;
}

/* Provisioning data blob structure template
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Major header
|                         Magic                            |
-----------------------------------------------------------
|Sub header stored num |Sub header num |Total size |Version|
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //APP info Sub header
|APP info id |APP info version |APP info store flag | Rsvd |
-----------------------------------------------------------
|APP info table size          |APP info table offset       |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Key info Sub header
|Key info id |Key info version |Key info store flag | Rsvd |
-----------------------------------------------------------
|Key info table size          |Key info table offset       |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Lock info Sub header
|Lock info id|Lock info version|Lock info store flag| Rsvd |
-----------------------------------------------------------
|Lock info table size         |Lock info table offset      |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //CNT info Sub header
|CNT info id |CNT info version |CNT info store flag | Rsvd |
-----------------------------------------------------------
|CNT info table size          |CNT info table offset       |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Cfg info Sub header
|Cfg info id |Cfg info version |Cfg info store flag | Rsvd |
-----------------------------------------------------------
|Cfg info table size          |Cfg info table offset       |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //APP info table
|APP info id |APP info num |            Rsvd               |
-----------------------------------------------------------
|          Detailed APP info description                   |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Key info table
|Key info id |Key info num |            Rsvd               |
-----------------------------------------------------------
|          Detailed Key info description                   |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Lock info table
|Lock info id |Lock info num |            Rsvd             |
-----------------------------------------------------------
|          Detailed Lock info description                  |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //CNT info table
|CNT info id |CNT info num |            Rsvd               |
-----------------------------------------------------------
|          Detailed CNT info description                   |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Cfg info table
|Cfg info id |Cfg info num |            Rsvd               |
-----------------------------------------------------------
|          Detailed Cfg info description                   |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_WRITE_PROVISION
static int32_t _write_provision(sf_ctx_t *sf_ctx, void *provision_data)
{
    int32_t status = SECUREFLASH_ERROR_OK, n;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    provision_major_header_t *major_header = NULL;
    provision_sub_header_t *sub_header = NULL;
    uint8_t provision_data_buf[PROVISION_INFO_SIZE] = {};
    uint8_t vfy_provision_data_buf[PROVISION_INFO_SIZE] = {};
    uint8_t *provision_data_blob = (uint8_t *)provision_data;
    uint8_t *header_offset, *table_offset;

    SF_COMMON_DBG0_PR("%s\r\n", __func__);
    if (1 == armor_vendor_ctx->provision_info.is_provisioned) {
        if (armor_vendor_ctx->provision_info.lock_info.prvs_wr_en != PROV_ENABLE) {
            SF_COMMON_ERR_PR("Write provision is locked\r\n");
            return SECUREFLASH_ERROR_WRITE_PROVISION;
        }
    }
    tfm_memcpy(provision_data_buf, provision_data_blob, SFPI_MAJOR_HEADER_SIZE);
    /* check magic of major header */
    if (0 != _check_major_header(provision_data_buf, &major_header)) {
        SF_COMMON_ERR_PR("check sfpi major header failed\r\n");
        return SECUREFLASH_ERROR_WRITE_PROVISION;
    }
    header_offset = provision_data_buf + SFPI_MAJOR_HEADER_SIZE;
    table_offset = provision_data_buf + SFPI_MAJOR_HEADER_SIZE +
                   major_header->sub_table_store_num * SFPI_SUB_HEADER_SIZE;
    for (n = 0; n < major_header->sub_header_num; n++) {
        sub_header = (provision_sub_header_t *)(provision_data_blob +
                      SFPI_MAJOR_HEADER_SIZE + SFPI_SUB_HEADER_SIZE * n);
        SF_COMMON_DBG_PR("sub_header-id:         %02X\r\n",
                         sub_header->id);
        SF_COMMON_DBG_PR("sub_header-version:    %02X\r\n",
                         sub_header->version);
        SF_COMMON_DBG_PR("sub_header-store:      %02X\r\n",
                         sub_header->store);
        SF_COMMON_DBG_PR("sub_header-table size: %04X\r\n",
                         sub_header->table_size);
        SF_COMMON_DBG_PR("sub_header-offset:     %04X\r\n", sub_header->offset);
        if (provision_data_blob[sub_header->offset] != sub_header->id) {
            SF_COMMON_ERR_PR("SFPI, sub header compare failed, exp: %02X, act: %02X\r\n",
                      sub_header->id, provision_data_blob[sub_header->offset]);
            return SECUREFLASH_ERROR_WRITE_PROVISION;
        }
        switch (sub_header->id) {
        case SUB_ID_APP_INFO:
            SF_COMMON_DBG_PR("%s, app_info\r\n", __func__);
            break;
        case SUB_ID_LOCK_INFO:
            SF_COMMON_DBG_PR("%s, lock_info\r\n", __func__);
            break;
        case SUB_ID_KEY_INFO:
            SF_COMMON_DBG_PR("%s, key_info\r\n", __func__);
            tfm_memcpy(&armor_vendor_ctx->provision_info.key_info,
                       &provision_data_blob[sub_header->offset],
                       sub_header->table_size);
            if (0 != __check_provision_info(
                                     &armor_vendor_ctx->provision_info.key_info,
                                     sizeof(key_info_t), KEY_ITEM)) {
                SF_COMMON_ERR_PR("check sfpi major header failed\r\n");
                return SECUREFLASH_ERROR_WRITE_PROVISION;
            }
            if (0 != _provision_key(sf_ctx, 1)) {
                SF_COMMON_ERR_PR("Key info failed\r\n");
                return SECUREFLASH_ERROR_WRITE_PROVISION;
            }
            break;
        case SUB_ID_MC_INFO:
            SF_COMMON_DBG_PR("%s, mc_info\r\n", __func__);
            if (0 != __check_provision_info(
                          (mc_info_t *)&provision_data_blob[sub_header->offset],
                          sub_header->table_size, MC_ITEM)) {
                SF_COMMON_ERR_PR("check sfpi major header failed\r\n");
                return SECUREFLASH_ERROR_WRITE_PROVISION;
            }
            if (0 != _config_mc(sf_ctx,
                      (mc_info_t *)&provision_data_blob[sub_header->offset])) {
                SF_COMMON_ERR_PR("MC info failed\r\n");
                return SECUREFLASH_ERROR_WRITE_PROVISION;
            }
            break;
        case SUB_ID_CONFIG_INFO:
            SF_COMMON_DBG_PR("%s, config_info\r\n", __func__);
            if (0 != __check_provision_info(
                     (config_info_t *)&provision_data_blob[sub_header->offset],
                     sub_header->table_size, CFG_ITEM)) {
                SF_COMMON_ERR_PR("check sfpi major header failed\r\n");
                return SECUREFLASH_ERROR_WRITE_PROVISION;
            }
            if (0 != _config_secure_flash(sf_ctx,
                     (config_info_t *)&provision_data_blob[sub_header->offset],
                     sub_header->table_size)) {
                SF_COMMON_ERR_PR("Config info failed\r\n");
                return SECUREFLASH_ERROR_WRITE_PROVISION;
            }
            break;
        }
        if (sub_header->store) {
            SF_COMMON_DBG_PR("store provision data to internal flash\r\n");
            tfm_memcpy(table_offset, &provision_data_blob[sub_header->offset],
                       sub_header->table_size);
            sub_header->offset = (uint16_t)(table_offset - provision_data_buf);
            tfm_memcpy(header_offset, sub_header, SFPI_SUB_HEADER_SIZE);
            header_offset += SFPI_SUB_HEADER_SIZE;
            table_offset += sub_header->table_size;
        }
    }
    major_header->sub_header_num = major_header->sub_table_store_num;
    status = plat_store_secure_flash_provision_info(provision_data_buf,
                                            table_offset - provision_data_buf);
    if (SECUREFLASH_ERROR_OK !=  status) {
        return SECUREFLASH_ERROR_WRITE_PROVISION;
    }
    status = plat_get_secure_flash_provision_info(vfy_provision_data_buf,
                                            table_offset - provision_data_buf);
    if (SECUREFLASH_ERROR_OK !=  status) {
        return SECUREFLASH_ERROR_WRITE_PROVISION;
    }
    /* Read back provision data stored by above code line, and check whether
       provision data has been stored successfully */
    if (0 != tfm_memcmp(vfy_provision_data_buf, provision_data_buf,
                        PROVISION_INFO_SIZE)) {
        SF_COMMON_ERR_PR("Provision data comparison failed\r\n");
        return SECUREFLASH_ERROR_WRITE_PROVISION;
    }
    SF_COMMON_DBG0_PR("Write provosion successful\r\n");
    return status;
}

/* Provisioning data blob stored in memory structure template
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Major header
|                         Magic                            |
-----------------------------------------------------------
|Sub header stored num |Sub header num |Total size |Version|
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //APP info Sub header
|APP info id |APP info version |APP info store flag | Rsvd |
-----------------------------------------------------------
|APP info table size          |APP info table offset       |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Key info Sub header
|Key info id |Key info version |Key info store flag | Rsvd |
-----------------------------------------------------------
|Key info table size          |Key info table offset       |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Lock info Sub header
|Lock info id|Lock info version|Lock info store flag| Rsvd |
-----------------------------------------------------------
|Lock info table size         |Lock info table offset      |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //APP info table
|APP info id |APP info num |            Rsvd               |
-----------------------------------------------------------
|          Detailed APP info description                   |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Key info table
|Key info id |Key info num |            Rsvd               |
-----------------------------------------------------------
|          Detailed Key info description                   |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   //Lock info table
|Lock info id |Lock info num |            Rsvd             |
-----------------------------------------------------------
|          Detailed Lock info description                  |
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_UNPROVISIONED
// SECUREFLASH_ERROR_READ_PROVISION
static int32_t _read_provision(sf_ctx_t *sf_ctx, void *provision_data)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;

    SF_COMMON_DBG0_PR("%s\r\n", __func__);
    if (0 == armor_vendor_ctx->provision_info.is_provisioned) {
        return SECUREFLASH_ERROR_UNPROVISIONED;
    }
    if (armor_vendor_ctx->provision_info.lock_info.prvs_rd_en != PROV_ENABLE) {
        return SECUREFLASH_ERROR_READ_PROVISION;
    }
    status = plat_get_secure_flash_provision_info((uint8_t *)provision_data,
                                                  PROVISION_INFO_SIZE);
    if (SECUREFLASH_ERROR_OK != status) {
        return SECUREFLASH_ERROR_READ_PROVISION;
    }
    return status;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_UNPROVISIONED
// SECUREFLASH_ERROR_LOCK_PROVISION
static int32_t _lock_provision(sf_ctx_t *sf_ctx, void *provision_data)
{
    int32_t status = SECUREFLASH_ERROR_OK, n;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    provision_major_header_t *major_header = NULL;
    provision_sub_header_t *sub_header = NULL;
    uint8_t provision_data_buf[PROVISION_INFO_SIZE] = {};
    lock_info_t *lock_info;

    SF_COMMON_DBG0_PR("%s\r\n", __func__);
    if (0 == armor_vendor_ctx->provision_info.is_provisioned) {
        return SECUREFLASH_ERROR_UNPROVISIONED;
    }
    if (armor_vendor_ctx->provision_info.lock_info.lock_flags &
        LOCK_INFO_LOCK_PROVISION) {
        return SECUREFLASH_ERROR_LOCK_PROVISION;
    }
    lock_info = (lock_info_t *)provision_data;
    status = _config_lock(sf_ctx, lock_info,
                          &armor_vendor_ctx->provision_info.lock_info);
    if (SECUREFLASH_ERROR_OK != status) {
        return SECUREFLASH_ERROR_LOCK_PROVISION;
    }
    if (0 != plat_get_secure_flash_provision_info(provision_data_buf,
                                                  PROVISION_INFO_SIZE)) {
        return SECUREFLASH_ERROR_WRITE_PROVISION;
    }
    major_header = (provision_major_header_t *)provision_data_buf;
    /* Refresh stored lock information */
    for (n = 0; n < major_header->sub_header_num; n++) {
        sub_header = (provision_sub_header_t *)(provision_data_buf +
                            SFPI_MAJOR_HEADER_SIZE + n * SFPI_SUB_HEADER_SIZE);
        if (SUB_ID_LOCK_INFO == sub_header->id) {
            tfm_memcpy(&provision_data_buf[sub_header->offset],
                       &armor_vendor_ctx->provision_info.lock_info,
                       sizeof(lock_info_t));
        }
    }
    if (0 != plat_store_secure_flash_provision_info(provision_data_buf,
                                                    PROVISION_INFO_SIZE)) {
        return SECUREFLASH_ERROR_WRITE_PROVISION;
    }
    return 0;
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_INIT
// SECUREFLASH_ERROR_UNPROVISIONED
// SECUREFLASH_ERROR_ALLOCATION
static int32_t _init(sf_ctx_t *sf_ctx)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;

    /* Allocate mx75_armor_vendor_context_t */
    if (0 == armor_vendor_ctx) {
        tfm_memset(&mx75_armor_vendor_context, 0x00,
                   sizeof(mx75_armor_vendor_context_t));
        armor_vendor_ctx = &mx75_armor_vendor_context;
        sf_ctx->priv_vendor = armor_vendor_ctx;
    }
    /* init armorflash by mxic standard spi nor command */
    if (0 == armor_vendor_ctx->mxic_nor_ctx) {
        uint8_t id[3] = {};
        if (0 != mxic_spi_nor_init(&armor_vendor_ctx->mxic_nor_ctx,
                                   &SPI_NOR_HOST_DRIVER)) {
            SF_COMMON_ERR_PR("mxic_spi_nor_init failed\r\n");
            goto init_exit_point;
        }
        if (0 != mxic_send_spi_nor_rdid(armor_vendor_ctx->mxic_nor_ctx, id, 3)) {
            SF_COMMON_ERR_PR("Read flash ID failed\r\n");
            goto init_exit_point;
        }
        SF_COMMON_DBG0_PR("Flash ID: %02X%02X%2X\r\n", id[0], id[1], id[2]);
    }
    armor_vendor_ctx->crypto_service.hkdf = crypto_if_hkdf;
    armor_vendor_ctx->crypto_service.aes_ccm_enc = crypto_if_aead_encrypt;
    armor_vendor_ctx->crypto_service.aes_ccm_dec = crypto_if_aead_decrypt;
    armor_vendor_ctx->crypto_service.aes_ecb_enc = crypto_if_cipher_encrypt;
    armor_vendor_ctx->crypto_service.gen_key = crypto_if_derive_key;
    armor_vendor_ctx->crypto_service.store_key = crypto_if_import_key;
    armor_vendor_ctx->crypto_service.get_key = crypto_if_export_key;
    armor_vendor_ctx->crypto_service.open_key = crypto_if_open_key;
    armor_vendor_ctx->crypto_service.close_key = crypto_if_close_key;
    armor_vendor_ctx->crypto_service.delete_key = crypto_if_destroy_key;
    armor_vendor_ctx->crypto_service.check_algorithm_support =
                                             crypto_if_check_algorithm_support;
    status = _switch_security_field(armor_vendor_ctx, 1);
    if (SECUREFLASH_ERROR_OK != status) {
        goto init_exit_point;
    }
    status = _get_provision_info(armor_vendor_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        if (SECUREFLASH_ERROR_UNPROVISIONED == status) {
            return status;
        }
        SF_COMMON_ERR_PR("Get provision data failed %d\r\n", status);
        goto init_exit_point;
    }
    __pre_get_security_info(armor_vendor_ctx);
    status = _get_security_info(sf_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        goto init_exit_point;
    }
    __post_get_security_info(armor_vendor_ctx);
    return SECUREFLASH_ERROR_OK;

init_exit_point:
    _deinit(sf_ctx);
    return SECUREFLASH_ERROR_INITIAL;
}

static int32_t _deinit(sf_ctx_t *sf_ctx)
{
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;

    if (0 != armor_vendor_ctx) {
        if (0 != armor_vendor_ctx->mxic_nor_ctx) {
            mxic_spi_nor_deinit(&armor_vendor_ctx->mxic_nor_ctx);
        }
        armor_vendor_ctx = 0;
        sf_ctx->priv_vendor = 0;
    }
    return SECUREFLASH_ERROR_OK;
}

static session_info_t *_query_session_info(sf_ctx_t *sf_ctx,
                                           uint32_t session_id)
{
    int32_t n;

    for (n = 0; n < SESSION_INFO_MAX_NUM; n++ ) {
        if (sf_ctx->session_info[n].session_id == session_id) {
            break;
        }
    }
    if (SESSION_INFO_MAX_NUM == n) {
        return NULL;
    }
    return &sf_ctx->session_info[n];
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_ZONE_ISOLATION
// SECUREFLASH_ERROR_SESSION_ID_NOT_EXIST
static int32_t _secure_read(sf_ctx_t *sf_ctx, uint8_t *buffer, size_t addr,
                            size_t size, uint32_t session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    session_info_t *session_info;

    session_info = _query_session_info(sf_ctx, session_id);
    if (NULL == session_info) {
        SF_COMMON_ERR_PR("Query session info failed\r\n");
        return SECUREFLASH_ERROR_SESSION_ID_NOT_EXIST;
    }
    status = __check_address_validation(addr, session_info->key_id);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    return _armor_secure_read(sf_ctx, buffer, addr, size,
                              session_info->session_key_id);
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_ZONE_ISOLATION
// SECUREFLASH_ERROR_SESSION_ID_NOT_EXIST
static int32_t _secure_program(sf_ctx_t *sf_ctx, const uint8_t *buffer,
                               size_t addr, size_t size, uint32_t session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    session_info_t *session_info;

    session_info = _query_session_info(sf_ctx, session_id);
    if (NULL == session_info) {
        SF_COMMON_ERR_PR("Query session info failed\r\n");
        return SECUREFLASH_ERROR_SESSION_ID_NOT_EXIST;
    }
    status = __check_address_validation(addr, session_info->key_id);
    if (SECUREFLASH_ERROR_OK) {
        return status;
    }
    return _armor_secure_write(sf_ctx, (uint8_t *)buffer, addr, size,
                               session_info->session_key_id);
}

// SECUREFLASH_ERROR_OK
// SECUREFLASH_ERROR_ZONE_ISOLATION
// SECUREFLASH_ERROR_SESSION_ID_NOT_EXIST
static int32_t _secure_erase(sf_ctx_t *sf_ctx, size_t addr, size_t size,
                             uint32_t session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    session_info_t *session_info;

    session_info = _query_session_info(sf_ctx, session_id);
    if (NULL == session_info) {
        SF_COMMON_ERR_PR("Query session info failed\r\n");
        return SECUREFLASH_ERROR_SESSION_ID_NOT_EXIST;
    }
    status = __check_address_validation(addr, session_info->key_id);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    return _armor_secure_erase(sf_ctx, addr, SIZE_4K_BYTES,
                               session_info->session_key_id);
}

static int32_t _create_session(sf_ctx_t *sf_ctx, uint32_t key_id,
                               uint32_t *session_key_id, uint32_t *session_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t actual_size;

    status = _get_trng(sf_ctx, (uint8_t *)session_id, 4, &actual_size);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    *session_id ^= key_id;
    *session_key_id = key_id;
    return SECUREFLASH_ERROR_OK;
}

static int32_t _close_session(sf_ctx_t *sf_ctx, uint32_t session_id)
{
    return SECUREFLASH_ERROR_OK;
}

static int32_t _read(sf_ctx_t *sf_ctx, uint8_t *buffer,
                     size_t addr, size_t size)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;

    status = _check_ready_wo_outrdy(armor_vendor_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    if (0 != mxic_send_spi_nor_read(armor_vendor_ctx->mxic_nor_ctx, buffer,
                                    addr, size)) {
        return SECUREFLASH_ERROR_READ;
    }
    return status;
}

static int32_t _program(sf_ctx_t *sf_ctx, const uint8_t *buffer,
                        size_t addr, size_t size)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;

    status = _check_ready_wo_outrdy(armor_vendor_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    if (0 !=  mxic_send_spi_nor_wren(armor_vendor_ctx->mxic_nor_ctx)) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != mxic_send_spi_nor_program(armor_vendor_ctx->mxic_nor_ctx,
                                       (uint8_t *)buffer, addr, size)) {
        return SECUREFLASH_ERROR_PROGRAM;
    }
    return status;
}

static int32_t _erase(sf_ctx_t *sf_ctx, size_t addr, size_t size)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    status = _check_ready_wo_outrdy(armor_vendor_ctx);
    if (SECUREFLASH_ERROR_OK != status) {
        return status;
    }
    if (0 != mxic_send_spi_nor_wren(armor_vendor_ctx->mxic_nor_ctx)) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != mxic_send_spi_nor_erase(armor_vendor_ctx->mxic_nor_ctx,
                                     addr, size)) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    return status;
}

static int32_t _get_app_info(sf_ctx_t *sf_ctx, void *app_info)
{
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    tfm_memcpy(app_info, &armor_vendor_ctx->provision_info.app_info,
               sizeof(mx_app_info_t));
    return SECUREFLASH_ERROR_OK;
}

static int32_t _check_algorithm_support(sf_ctx_t *sf_ctx, int32_t alg)
{
    mx75_armor_vendor_context_t *armor_vendor_ctx =
                            (mx75_armor_vendor_context_t *)sf_ctx->priv_vendor;
    if (0 == armor_vendor_ctx->crypto_service.check_algorithm_support(alg)) {
        return SECUREFLASH_ERROR_OK;
    }
    return SECUREFLASH_ERROR_ERR;
}

void mx75_armor_set_vendor_operation(void *priv)
{
    sf_ctx_t *sf_ctx = (sf_ctx_t *)priv;
    sf_ctx->vendor_op.name = "VENDOR-SPECIFIC_MXIC-MX75-ARMOR-FLASH";

    sf_ctx->vendor_op.write_provision = _write_provision;
    sf_ctx->vendor_op.read_provision = _read_provision;
    sf_ctx->vendor_op.lock_provision = _lock_provision;
    sf_ctx->vendor_op.init = _init;
    sf_ctx->vendor_op.deinit = _deinit;
    sf_ctx->vendor_op.secure_read = _secure_read;
    sf_ctx->vendor_op.secure_program = _secure_program;
    sf_ctx->vendor_op.secure_erase = _secure_erase;
    sf_ctx->vendor_op.create_session = _create_session;
    sf_ctx->vendor_op.close_session = _close_session;
    sf_ctx->vendor_op.get_uid = _get_uid;
    sf_ctx->vendor_op.get_trng = _get_trng;
    sf_ctx->vendor_op.get_puf = _get_puf;
    sf_ctx->vendor_op.read = _read;
    sf_ctx->vendor_op.program = _program;
    sf_ctx->vendor_op.erase = _erase;
    sf_ctx->vendor_op.get_mc = _get_mc;
    sf_ctx->vendor_op.increase_mc = _increase_mc;
    sf_ctx->vendor_op.send_read_sfdp_command = _send_read_sfdp_command;
    sf_ctx->vendor_op.get_app_info = _get_app_info;
    sf_ctx->vendor_op.check_algorithm_support = _check_algorithm_support;
}
