/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef _MX75_ARMOR_VENDOR_LOCAL_FUNCS_H
#define _MX75_ARMOR_VENDOR_LOCAL_FUNCS_H

/*====================================================*
 *====== encryption functions ========================*
 *====================================================*/
/**
 * \brief AES-CCM256 encryption/decryption wrapper.
 *
 * \param[in]  sf_ctx        Pointer to secure Flash context
 * \param[in]  key_id        Identifier of the key to use for the operation
 * \param[in]  iv            Initialization vector or nonce to use
 * \param[in]  iv_len        Size of the \p iv buffer in bytes
 * \param[in]  add           Additional data that will be authenticated but
 *                           not encrypted
 * \param[in]  add_len       Size of \p add in bytes
 * \param[out] tag           The buffer holding the authentication field
 * \param[out] tag_len       The length of authentication field in bytes
 * \param[in]  plain_data    The buffer holding plain text
 * \param[out] cipher_data   The buffer holding cipher text
 * \param[in]  data_len      The length of input data in bytes
 * \param[in]  property      AES-CCM256 operation property(PROP_ENCRYPT_TAG_DATA
 *                           or PROP_AUTHEN_TAG_DECRYPT_DATA,etc.)
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_CRYPTO_SERVICE if failed
 */
static int32_t _aes_ccm256(sf_ctx_t *sf_ctx, uint32_t key_id,
                           uint8_t *iv, uint8_t iv_len,
                           uint8_t *add, uint8_t add_len,
                           uint8_t *tag, uint8_t tag_len,
                           uint8_t *plain_data, uint8_t *cipher_data,
                           uint8_t data_len,
                           EncryptionProperty property);

/**
 * \brief HMAC-based Extract-and-Expand Key Derivation Function(Here is
 *        HKDF based on sha256) wrapper.
 *
 * \param[in]  sf_ctx        Pointer to secure Flash context
 * \param[in]  salt          Optional salt value
 * \param[in]  salt_len      Salt length in bytes
 * \param[in]  ikm           The input key material
 * \param[in]  ikm_len       Input key material length in bytes
 * \param[in]  info          Optional context and application specific
 *                           information string
 * \param[in]  info_len      The length of info in bytes
 * \param[out] okm           The out key material
 * \param[out] okm_len       Output key material length in bytes
 * \param[in]  property      HKDF operation property(HKDF-EXTRACT,HKDF-EXPAND or
 *                           HKDF-EXTRACT-and-EXPAND)
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_CRYPTO_SERVICE if failed
 */
static int32_t _hkdf_sha256(sf_ctx_t *sf_ctx, uint8_t *salt, uint8_t salt_len,
                            uint8_t *ikm, uint8_t ikm_len,
                            uint8_t *info, uint8_t info_len,
                            uint8_t *okm, uint8_t okm_len,
                            EncryptionProperty property);

/*====================================================*
 *====== Vendor specific secure commands =============*
 *====================================================*/
/**
 * \brief This function is used for writing configure/key/counter memory of
 *        ArmorFlash before the region lock down.
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] buffer         Buffer holding the data to write
 * \param[in] addr           The region address to write
 * \param[in] size           Size of buffer in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _armor_spi_write(sf_ctx_t *sf_ctx, uint8_t *buffer,
                                uint32_t addr, uint8_t size);


/**
 * \brief Read ArmorFlash monotonic counter value
 *
 * \param[in]  sf_ctx        Pointer to secure Flash context
 * \param[in]  mc_id         Monotonic counter id
 * \param[out] mc            Pointer to current monotonic counter value
 * \param[in]  mc_size       Size of the buffer to store monotonic counter
 *                           value in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _armor_read_mc(sf_ctx_t *sf_ctx, uint8_t mc_id,
                              uint8_t *mc, uint8_t mc_size);

/**
 * \brief Increase ArmorFlash monotonic counter value by one
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] mc_id          Monotonic counter id
 * \param[in] mc             The buffer holding current monotonic counter value
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _armor_increase_mc(sf_ctx_t *sf_ctx, uint8_t mc_id, uint8_t *mc);


/**
 * \brief Read ArmorFlash PUF code
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] puf            The buffer holding PUF code
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _armor_pufrd(sf_ctx_t *sf_ctx, uint8_t *puf);


/**
 * \brief Authenticate the cipher text data read from ArmorFlash, and
 *        decrypt to derive the plain text data
 *
 * \param[in]  sf_ctx        Pointer to secure Flash context
 * \param[out] buffer        Pointer to the derived plain text data
 * \param[in]  addr          The address of data memory to read
 * \param[in]  size          The size of read data in bytes
 * \param[in]  key_id        The crypto operation related key id
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _armor_secure_read(sf_ctx_t *sf_ctx, uint8_t *buffer,
                                  uint32_t addr, uint32_t size,
                                  uint32_t key_id);

/**
 * \brief Encrypt plain text data and compute mac, then send cipher text data
 *        and mac to ArmorFlash
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] buffer         Pointer to the input plain text data
 * \param[in] addr           The address of data memory to write
 * \param[in] size           The size of plain text data in bytes
 * \param[in] key_id         The crypto operation related key id
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _armor_secure_write(sf_ctx_t *sf_ctx, uint8_t *buffer,
                                   uint32_t addr, uint32_t size,
                                   uint32_t key_id);

/**
 * \brief Erase a sector/block of ArmorFlash security field
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] addr           The address of security field to erase
 * \param[in] size           The size to erase
 * \param[in] key_id         The crypto operation related key id
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _armor_secure_erase(sf_ctx_t *sf_ctx, uint32_t addr,
                                   uint32_t size, uint32_t key_id);

/**
 * \brief Lock down ArmorFlash's configuration/key memory or data zone,etc.
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] lock_data      Indicates the specific lock down information
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _armor_lkd(sf_ctx_t *sf_ctx, lock_data_t *lock_data);

/*====================================================*
 *====== Vendor specific local secure commands ======*
 *====================================================*/

static int32_t _check_ready_wo_outrdy(mx75_armor_vendor_context_t *armor_vendor_ctx);
static int32_t _check_ready_w_outrdy(mx75_armor_vendor_context_t *armor_vendor_ctx);
/**
 * \brief Receive response packet from ArmorFlash.
 *
 * \param[in]  armor_vendor_ctx  Pointer to MX75 ArmorFlash context
 * \param[out] read_packet       Pointer to the buffer to store received packet
 * \param[in]  packet_len        The size of received packet in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _receive_read_packet(mx75_armor_vendor_context_t *armor_vendor_ctx,
                                    uint8_t *read_packet, uint32_t packet_len);

/**
 * \brief Send request packet to ArmorFlash.
 *
 * \param[in] sf_ctx         Pointer to MX75 ArmorFlash context
 * \param[in] write_packet   Pointer to the buffer to send to ArmorFlash
 * \param[in] packet_len     The size of the packet to send in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _send_write_packet(mx75_armor_vendor_context_t *armor_vendor_ctx,
                                  uint8_t *write_packet, uint32_t packet_len);

/**
 * \brief Enter security field.
 *
 */
static int32_t _enter_sf(mx75_armor_vendor_context_t *armor_vendor_ctx);

/**
 * \brief Exist security field.
 *
 */
static int32_t _exit_sf(mx75_armor_vendor_context_t *armor_vendor_ctx);

/**
 * \brief Enter or exist security field.
 *
 */
static int32_t _switch_security_field(
                                 mx75_armor_vendor_context_t *armor_vendor_ctx,
                                 uint8_t enter_security_field);

/**
 * \brief Write to key memory of ArmorFlash before locking down this region.
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] key            Pointer to the key data to write
 * \param[in] target_key_id  The id of the key to write
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static inline int32_t _armor_inject_key(sf_ctx_t *sf_ctx, uint8_t *key,
                                        uint8_t target_key_id);

/**
 * \brief Update key memory of ArmorFlash.
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] key            Pointer to the key data to write
 * \param[in] target_key_id  The id of the key to write
 * \param[in] type           The specific mode of storing data to
 *                           key memory region
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _write_key(sf_ctx_t *sf_ctx, uint8_t *key,
                          uint8_t target_key_id, uint8_t type);

/**
 * \brief Get ArmorFlash configuration information.
 *
 */
static int32_t _get_config_data(sf_ctx_t *sf_ctx);

/**
 * \brief Get ArmorFlash security field information.
 *
 */
static int32_t _get_security_info(sf_ctx_t *sf_ctx);

/**
 * \brief Check the major header of ArmorFlash provisioning information.
 *
 * \param[in] provision_data_blob   Pointer to the provisioning information
 * \param[in] major_header          Pointer to the major header's pointer
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _check_major_header(uint8_t *provision_data_blob,
                                   provision_major_header_t **major_header);

/**
 * \brief Lock down configuration memory,key memory,extra zone memory,etc.
 *
 * \param[in] sf_ctx             Pointer to secure Flash context
 * \param[in] lock_info          Pointer to lock down provisioning information
 * \param[out] actual_lock_info  Pointer to ArmorFlash actual lock down
 *                               information
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _config_lock(sf_ctx_t *sf_ctx, lock_info_t *lock_info,
                            lock_info_t *actual_lock_info);

/**
 * \brief Configure ArmorFlash monotonic counters based on provisioning information
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] mc_info        Pointer to the monotonic counter
 *                           provisioning information
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _config_mc(sf_ctx_t *sf_ctx, mc_info_t *mc_info);

/**
 * \brief Configure ArmorFlash based on provisioning information
 *
 * \param[in] sf_ctx            Pointer to secure Flash context
 * \param[in] config_info       Pointer to configuration information
 * \param[in] config_info_size  The size of configuration information in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_XX if failed
 */
static int32_t _config_secure_flash(sf_ctx_t *sf_ctx,
                                    config_info_t *config_info,
                                    uint16_t config_info_size);

/**
 * \brief Confirmation after nonce generation
 *
 * \param[in] armor_vendor_ctx     Pointer to MX75 ArmorFlash specific context
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_CRYPTO_SERVICE if failed
 */
static int32_t _armor_confirm_nonce(mx75_armor_vendor_context_t *armor_vendor_ctx);
/**
 * \brief ArmorFlash generates a random nonce internally
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_CRYPTO_SERVICE if failed
 */
static int32_t _armor_generate_nonce(sf_ctx_t *sf_ctx);

/**
 * \brief User enters a random nonce
 *
 * \param[in]     sf_ctx     Pointer to secure Flash context
 * \param[in,out] params     ArmorFlash security operation parameters
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_CRYPTO_SERVICE if failed
 */
static int32_t _armor_set_nonce(sf_ctx_t *sf_ctx,
                                mx75_armor_security_ops_params_t *params);

/**
 * \brief Derive root key based on provisioning information
 *
 * \param[in]  sf_ctx        Pointer to secure Flash context
 * \param[in]  key_data_t    Key provisioning information
 * \param[out] key           Pointer to the derived key value
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_CRYPTO_SERVICE if failed
 */
static int32_t _derive_preprovision_key(sf_ctx_t *sf_ctx, key_data_t *key_data,
                                        uint8_t *key);

/**
 * \brief Derive root keys, then write these keys to ArmorFlash key memory
 *        region based on key injection flag
 *
 * \param[in] sf_ctx          Pointer to secure Flash context
 * \param[in] flag_inject_key Write these keys to ArmorFlash key memory region
 *                            if flag_inject_key is not zero
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_CRYPTO_SERVICE if failed
 */
static int32_t _provision_key(sf_ctx_t *sf_ctx, uint8_t flag_inject_key);

/**
 * \brief Get ArmorFlash provisioning information.
 *
 */
static int32_t _get_provision_info(mx75_armor_vendor_context_t *armor_vendor_ctx);

/**
 * \brief Query a session's information based on session_id
 *
 * \param[in] sf_ctx         Pointer to secure Flash context
 * \param[in] session_id     Session id
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         SECUREFLASH_ERROR_CRYPTO_SERVICE if failed
 */
static session_info_t *_query_session_info(sf_ctx_t *sf_ctx,
                                           uint32_t session_id);

/**
 * \brief MX75 ArmorFlash specific implementation of parsing and
 *        storing provisioning data.
 *
 */
static int32_t _write_provision(sf_ctx_t *sf_ctx, void *provision_data);

/**
 * \brief MX75 ArmorFlash specific implementation of reading provisioning data.
 *
 */
static int32_t _read_provision(sf_ctx_t *sf_ctx, void *provision_data);

/**
 * \brief MX75 ArmorFlash specific implementation of parsing lock down
 *        provisioning data.
 *
 */
static int32_t _lock_provision(sf_ctx_t *sf_ctx, void *provision_data);

/**
 * \brief MX75 ArmorFlash initialization.
 *
 */
static int32_t _init(sf_ctx_t *sf_ctx);

/**
 * \brief MX75 ArmorFlash deinitialization.
 *
 */
static int32_t _deinit(sf_ctx_t *sf_ctx);

/**
 * \brief Security read data from MX75 ArmorFlash.
 *
 */
static int32_t _secure_read(sf_ctx_t *sf_ctx, uint8_t *buffer,
                            size_t addr, size_t size,
                            uint32_t session_id);

/**
 * \brief Security program data to MX75 ArmorFlash.
 *
 */
static int32_t _secure_program(sf_ctx_t *sf_ctx, const uint8_t *buffer,
                               size_t addr, size_t size,
                               uint32_t session_id);

/**
 * \brief Security erase a sector/block of MX75 ArmorFlash.
 *
 */
static int32_t _secure_erase(sf_ctx_t *sf_ctx,
                             size_t addr, size_t size,
                             uint32_t session_id);

/**
 * \brief Create a session for MX75 ArmorFlash.
 *
 */
static int32_t _create_session(sf_ctx_t *sf_ctx, uint32_t key_id,
                               uint32_t *session_key_id, uint32_t *session_id);

/**
 * \brief Close a session of MX75 ArmorFlash.
 *
 */
static int32_t _close_session(sf_ctx_t *sf_ctx, uint32_t session_id);

/**
 * \brief Get true random number from MX75 ArmorFlash.
 *
 */
static int32_t _get_trng(sf_ctx_t *sf_ctx, uint8_t *random,
                         uint8_t size, uint8_t *actual_size);

/**
 * \brief Get the unique id of MX75 ArmorFlash.
 *
 */
static int32_t _get_uid(sf_ctx_t *sf_ctx, uint8_t *uid,
                        uint8_t size, uint8_t *actual_size);

/**
 * \brief Get the PUF code of MX75 ArmorFlash.
 *
 */
static int32_t _get_puf(sf_ctx_t *sf_ctx, uint8_t *puf,
                        uint8_t size, uint8_t *actual_size,
                        uint8_t *input_param, uint8_t input_param_size);

/**
 * \brief Normal read data from MX75 ArmorFlash.
 *
 */
static int32_t _read(sf_ctx_t *sf_ctx, uint8_t *buffer,
                     size_t addr, size_t size);

/**
 * \brief Normal program data to MX75 ArmorFlash.
 *
 */
static int32_t _program(sf_ctx_t *sf_ctx, const uint8_t *buffer,
                        size_t addr, size_t size);

/**
 * \brief Normal erase a sector/block of MX75 ArmorFlash.
 *
 */
static int32_t _erase(sf_ctx_t *sf_ctx, size_t addr, size_t size);

/**
 * \brief Read MX75 ArmorFlash monotonic counters' current value.
 *
 */
static inline int32_t _get_mc(sf_ctx_t *sf_ctx, uint8_t mc_id, uint8_t *mc,
                              uint8_t size, uint8_t *actual_size);

/**
 * \brief Increase MX75 ArmorFlash monotonic counters' value by one.
 *
 */
static inline int32_t _increase_mc(sf_ctx_t *sf_ctx, uint8_t mc_id,
                                   uint8_t *mc);

/**
 * \brief Get MX75 ArmorFlash's application provisioning information.
 *
 */
static int32_t _get_app_info(sf_ctx_t *sf_ctx, void *app_info);

/**
 * \brief Check whether a cipher algorithm is supported by MX75 ArmorFlash.
 *
 */
static int32_t _check_algorithm_support(sf_ctx_t *sf_ctx, int32_t alg);

#endif /* _MX75_ARMOR_VENDOR_LOCAL_FUNCS_H */
