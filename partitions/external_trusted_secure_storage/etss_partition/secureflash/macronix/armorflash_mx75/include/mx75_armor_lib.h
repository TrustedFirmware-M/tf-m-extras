/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef _MX75_ARMOR_LIB_H
#define _MX75_ARMOR_LIB_H

#include <stdint.h>
#include "../../../secureflash_common/secureflash_defs.h"
#include "mx75_armor_vendor_info.h"


/**
 * \file mx75_armor_lib.h
 *
 * \brief This file lists APIs of mx75_armor_lib.a
 *
 */

/* Check and parse provision info */
/**
 * \brief Check a certain security item's provisioning information.
 *
 * \param[in] info          Pointer to the provisioning information
 * \param[in] info_size     The size of provisioning information in bytes
 * \param[in] item          One of the security items
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __check_provision_info(void *info, uint16_t info_size,
                               SecurityItem item);
/**
 * \brief Parse security key provisioning information.
 *
 * \param[in] key_info      Pointer to the key provisioning information
 * \param[in] key_info_size The size of key provisioning information in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __parse_key_provision_info(key_info_t *key_info,
                                   uint16_t key_info_size);
/**
 * \brief Parse secure Flash security field configuration information.
 *
 * \param[in] data_buf      Pointer to the configuration information
 * \param[in] data_size     The size of the configuration information in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __parse_security_configuration(uint8_t *data_buf, uint16_t data_size);
/**
 * \brief Get security item's access address.
 *
 * \param[in] item          One of the security items
 *
 * \return Address
 */
uint32_t __get_target_addr(SecurityItem item);
/**
 * \brief Get security item's size.
 *
 * \param[in] item          One of the security items
 *
 * \return Size
 */
uint32_t __get_target_size(SecurityItem item);
/**
 * \brief Prepare for getting secure Flash security information.
 * \param[in] armor_vendor_ctx    Pointer to MX75 ArmorFlash context
 */
void __pre_get_security_info(mx75_armor_vendor_context_t *armor_vendor_ctx);
/**
 * \brief Operations after getting secure Flash security information.
 * \param[in] armor_vendor_ctx    Pointer to MX75 ArmorFlash context
 */
void __post_get_security_info(mx75_armor_vendor_context_t *armor_vendor_ctx);
/**
 * \brief Get size of the unique id.
 *
 * \return The size in byte
 */
uint8_t __get_uid_size(void);

/**
 * \brief Get ArmorFlash unique identifier.
 *
 * \param[out] uid          Pointer to buffer holding the unique identifier
 * \param[in]  size         The size of buffer in bytes
 * \param[out] actual_size  The actual size of unique identifier in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __get_uid(uint8_t *uid, uint8_t size, uint8_t *actual_size);

/**
 * \brief Parse and check lock down data.
 *
 */
int32_t __check_lkd_data(lock_data_t *lock_data,
                         mx75_armor_security_ops_params_t *params);

/**
 * \brief Parse and check lock down information.
 *
 */
int32_t __check_lock_info(lock_info_t *lock_info,
                          lock_info_t *actual_lock_info);

/**
 * \brief Return whether secure Flash is ready for program.
 *
 */
int32_t __write_busy(uint8_t status_reg);
/**
 * \brief Return whether secure Flash is ready for read.
 *
 */
int32_t __read_not_ready(uint8_t status_reg);
/**
 * \brief Return whether secure Flash enter/exit security filed.
 *
 */
int32_t __check_security_field(uint8_t status_reg);

/* Check some security operations' optional  mac authentication */
/**
 * \brief Check the optional authentication configuration of security operations.
 *
 * \param[in] params    Structure containing security operation's parameters
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __check_optional_authen(mx75_armor_security_ops_params_t *params);
/* Check whether operation is valid */
/* Check some security operations' optional mac authentication */
/**
 * \brief Check whether a key id has access to current address.
 *
 * \param[in] addr          Secure Flash address
 * \param[in] key_id        Identification of key
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __check_address_validation(size_t addr, uint32_t key_id);
/**
 * \brief Get secure Flash's nonce size.
 * \param[in,out] params   Structure containing security operation's parameters
 *
 * \return The size of nonce in bytes
 */
uint8_t __get_nonce_size(mx75_armor_security_ops_params_t *params);
/**
 * \brief Check whether need to regenerate a nonce.
 * \param[in] armor_vendor_ctx   Pointer to MX75 ArmorFlash context
 *
 * \return The status of nonce validation
 */
uint8_t __check_nonce_valid(mx75_armor_vendor_context_t *armor_vendor_ctx);
/**
 * \brief Get number of secure Flash's monotonic counters.
 * \return The number of monotonic counters
 */
uint8_t __get_mc_num(void);
/* Get linked monotonic counter and crypto key id */
/**
 * \brief Get the linked monotonic counter and crypto key id
 *        of current security operation.
 *
 * \param[in,out] params   Structure containing security operation's parameters
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __get_linked_mc_key(mx75_armor_security_ops_params_t *params);
/* Get iv and additional authentication data */
/**
 * \brief Get iv and additional authentication data of current security operation.
 *
 * \param[in,out] params   Structure containing security operation's parameters
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __get_iv_add(mx75_armor_security_ops_params_t *params);
/* Prepare write packet to be sent */
/**
 * \brief Prepare write packet to be sent to secure Flash.
 *
 * \param[in]  params         Structure containing security operation's
 *                            parameters
 * \param[in]  buf            Buffer containing ciphertext data
 * \param[in]  buf_size       The size of ciphertext data i bytes
 * \param[in]  mac            Buffer containing authentication code
 * \param[in]  mac_size       The size of authentication code
 * \param[out] wr_packet      Pointer to write packet
 * \param[out] wr_packet_len  The size of write packet in bytes
 * \param[out] rd_packet_len  The size of read packet in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __prepare_write_packet(mx75_armor_security_ops_params_t *params,
                               uint8_t *buf, uint32_t buf_size,
                               uint8_t *mac, uint8_t mac_size,
                               uint8_t *wr_packet, uint32_t *wr_packet_len,
                               uint32_t *rd_packet_len);
/* Parse received read packet */
/**
 * \brief Parse read packet received from secure Flash.
 *
 * \param[in]  params        Structure containing security operation's
 *                           parameters
 * \param[out] buf           Buffer containing ciphertext data parsed from
 *                           read packet
 * \param[in]  buf_size      The size of ciphertext data in bytes
 * \param[in]  mac           Buffer containing authentication code
 * \param[in]  mac_size      The size of authentication code in bytes
 * \param[in]  rd_packet     Pointer to read packet
 * \param[in]  rd_packet_len The size of read packet in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t __parse_read_packet(mx75_armor_security_ops_params_t *params,
                            uint8_t *buf, uint32_t buf_size,
                            uint8_t *mac_buf, uint8_t mac_size,
                            uint8_t *rd_packet, uint32_t rd_packet_len);

#endif /* _MX75_ARMOR_LIB_H */
