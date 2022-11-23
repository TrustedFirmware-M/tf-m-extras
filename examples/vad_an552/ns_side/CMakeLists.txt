#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022 Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

############################# Configuration ############################################
set(VAD_AN552_NO_CONNECTIVITY  OFF  CACHE BOOL  "If turned on the network is not used")

############################# External Dependencies ############################################

set(AMAZON_FREERTOS_SRC_PATH  "DOWNLOAD"  CACHE PATH  "Path to Amazon FreeRTOS (or DOWNLOAD to fetch automatically")
set(FREERTOS_KERNEL_SRC_PATH  "DOWNLOAD"  CACHE PATH  "Path to FreeRTOS kernel (or DOWNLOAD to fetch automatically")
set(PKCS11_PSA_SRC_PATH       "DOWNLOAD"  CACHE PATH  "Path to freertos-pkcs11-psa (or DOWNLOAD to fetch automatically")
set(OTA_FOR_AWS_SRC_PATH      "DOWNLOAD"  CACHE PATH  "Path to OTA for AWS (or DOWNLOAD to fetch automatically")
set(OTA_PAL_PSA_SRC_PATH      "DOWNLOAD"  CACHE PATH  "Path to freertos-ota-pal-psa (or DOWNLOAD to fetch automatically")

add_subdirectory(ext/amazon-freertos)
add_subdirectory(ext/freertos-kernel)
add_subdirectory(ext/freertos-pkcs11-psa)
add_subdirectory(ext/ota-for-aws)
add_subdirectory(ext/freertos-ota-pal-psa)

############################# Common variables ############################################

# In actual NS integration, NS side build should include the source files
# exported by TF-M build.
# Directly include interface folder to simplify the NS build in this demo, since
# install always occurs at the end of build.
set(INTERFACE_SRC_DIR    ${CMAKE_SOURCE_DIR}/interface/src)
set(INTERFACE_INC_DIR    ${CMAKE_SOURCE_DIR}/interface/include)

#################### TF-M NS interface (header only) ###########################

add_library(tfm_ns_interface INTERFACE)

# Include interface headers exported by TF-M
target_include_directories(tfm_ns_interface
    INTERFACE
        ${INTERFACE_INC_DIR}
        ${CMAKE_BINARY_DIR}/generated/interface/include
)

# Include selection of Secure Partitions from TF-M build.
# It can be replaced by NS side configurations later.
target_link_libraries(tfm_ns_interface
    INTERFACE
        tfm_partition_defs
)

############################# TFM NS app #######################################

add_executable(tfm_ns)

target_sources(tfm_ns
    PRIVATE
        main_ns.c
        smsc9220_eth_drv.c
        NetworkInterface.c
        platform_eth_dev.c
        ota_provision.c
        print_log.c
        amazon-freertos/publish_aws.c

        # aws demo
        ${AMAZON_FREERTOS_SRC_PATH}/demos/demo_runner/aws_demo.c
        ${AMAZON_FREERTOS_SRC_PATH}/demos/demo_runner/aws_demo_network_addr.c
        ${AMAZON_FREERTOS_SRC_PATH}/demos/demo_runner/iot_demo_freertos.c
        ${AMAZON_FREERTOS_SRC_PATH}/demos/demo_runner/iot_demo_runner.c
        ${AMAZON_FREERTOS_SRC_PATH}/demos/network_manager/aws_iot_network_manager.c
        ${AMAZON_FREERTOS_SRC_PATH}/demos/common/mqtt_subscription_manager/mqtt_subscription_manager.c
        ${AMAZON_FREERTOS_SRC_PATH}/demos/dev_mode_key_provisioning/src/aws_dev_mode_key_provisioning.c
        ${AMAZON_FREERTOS_SRC_PATH}/demos/ota/ota_demo_core_mqtt/ota_demo_core_mqtt.c
        ${AMAZON_FREERTOS_SRC_PATH}/demos/common/pkcs11_helpers/pkcs11_helpers.c
        # freeRTOS kernel files
        ${FREERTOS_KERNEL_SRC_PATH}/portable/GCC/ARM_CM55_NTZ/non_secure/port.c
        ${FREERTOS_KERNEL_SRC_PATH}/portable/GCC/ARM_CM55_NTZ/non_secure/portasm.c
        ${FREERTOS_KERNEL_SRC_PATH}/list.c
        ${FREERTOS_KERNEL_SRC_PATH}/queue.c
        ${FREERTOS_KERNEL_SRC_PATH}/tasks.c
        ${FREERTOS_KERNEL_SRC_PATH}/stream_buffer.c
        ${FREERTOS_KERNEL_SRC_PATH}/timers.c
        ${FREERTOS_KERNEL_SRC_PATH}/event_groups.c
        ${FREERTOS_KERNEL_SRC_PATH}/portable/MemMang/heap_4.c
        ${FREERTOS_KERNEL_SRC_PATH}/portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c
        # freertos plus tcp
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/portable/BufferManagement/BufferAllocation_2.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_ARP.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_DHCP.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_DNS.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_IP.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_Sockets.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_Stream_Buffer.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_TCP_IP.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_TCP_WIN.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/FreeRTOS_UDP_IP.c
        # amazon-freertos platform layer
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/freertos/iot_clock_freertos.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/freertos/iot_metrics.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/freertos/iot_network_freertos.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/freertos/iot_threads_freertos.c
        # secure sockets
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/secure_sockets/freertos_plus_tcp/iot_secure_sockets.c
        # c sdk common
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/c_sdk/standard/common/iot_init.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/c_sdk/standard/common/taskpool/iot_taskpool.c
        # core MQTT
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/coreMQTT/source/core_mqtt.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/coreMQTT/source/core_mqtt_state.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/coreMQTT/source/core_mqtt_serializer.c
        # MQTT agent
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/mqtt_agent/freertos_command_pool.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/mqtt_agent/freertos_agent_message.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/coreMQTT-Agent/source/core_mqtt_agent.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/coreMQTT-Agent/source/core_mqtt_agent_command_functions.c
        # backoff algorithm
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/backoff_algorithm/source/backoff_algorithm.c
        # secure sockets
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/transport/secure_sockets/transport_secure_sockets.c
        # tls
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/tls/src/iot_tls.c
        # freertos plus standard crypto
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/crypto/src/iot_crypto.c
        # pkcs11
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/pkcs11/corePKCS11/source/core_pkcs11.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/pkcs11/corePKCS11/source/core_pki_utils.c
        ${PKCS11_PSA_SRC_PATH}/iot_pkcs11_psa.c
        ${PKCS11_PSA_SRC_PATH}/iot_pkcs11_psa_input_format.c
        ${PKCS11_PSA_SRC_PATH}/iot_pkcs11_psa_object_management.c
        # OTA for aws
        ${OTA_FOR_AWS_SRC_PATH}/source/portable/os/ota_os_freertos.c
        ${OTA_FOR_AWS_SRC_PATH}/source/ota_base64.c
        ${OTA_FOR_AWS_SRC_PATH}/source/ota_cbor.c
        ${OTA_FOR_AWS_SRC_PATH}/source/ota_interface.c
        ${OTA_FOR_AWS_SRC_PATH}/source/ota_mqtt.c
        ${OTA_FOR_AWS_SRC_PATH}/source/ota.c
        # OTA PAL
        ${OTA_PAL_PSA_SRC_PATH}/ota_pal.c
        ${OTA_PAL_PSA_SRC_PATH}/version/application_version.c
        # Core JSON
        ${OTA_FOR_AWS_SRC_PATH}/source/dependency/coreJSON/source/core_json.c
        # CBOR
        ${OTA_FOR_AWS_SRC_PATH}/source/dependency/3rdparty/tinycbor/src/cborencoder.c
        ${OTA_FOR_AWS_SRC_PATH}/source/dependency/3rdparty/tinycbor/src/cborparser.c
        ${OTA_FOR_AWS_SRC_PATH}/source/dependency/3rdparty/tinycbor/src/cborencoder_close_container_checked.c
        # mbedTLS
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls_utils/mbedtls_error.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls_utils/mbedtls_utils.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/aes.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/aesni.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/arc4.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/aria.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/asn1parse.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/asn1write.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/base64.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/bignum.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/blowfish.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/camellia.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ccm.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/certs.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/chacha20.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/chachapoly.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/cipher.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/cipher_wrap.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/cmac.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ctr_drbg.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/debug.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/des.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/dhm.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ecdh.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ecdsa.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ecjpake.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ecp.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ecp_curves.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/entropy.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/entropy_poll.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/error.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/gcm.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/havege.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/hkdf.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/hmac_drbg.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/md.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/md_wrap.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/md2.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/md4.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/md5.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/memory_buffer_alloc.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/net_sockets.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/nist_kw.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/oid.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/padlock.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/pem.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/pk.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/pk_wrap.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/pkcs11.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/pkcs12.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/pkcs5.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/pkparse.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/pkwrite.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/platform.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/platform_util.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/poly1305.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ripemd160.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/rsa.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/rsa_internal.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/sha1.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/sha256.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/sha512.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ssl_cache.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ssl_ciphersuites.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ssl_cli.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ssl_cookie.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ssl_srv.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ssl_ticket.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/ssl_tls.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/threading.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/timing.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/version.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/version_features.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/x509.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/x509_create.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/x509_crl.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/x509_crt.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/x509_csr.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/x509write_crt.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/x509write_csr.c
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/library/xtea.c
)

target_include_directories(tfm_ns
    PRIVATE
        .
        ${TFM_TEST_PATH}/../ns_interface
        ${INTERFACE_INC_DIR}/
        ../../../partitions/vad_an552_sp/ns_interface
        amazon-freertos

        # aws demo
        ${AMAZON_FREERTOS_SRC_PATH}/demos/include
        ${AMAZON_FREERTOS_SRC_PATH}/demos/network_manager/
        ${AMAZON_FREERTOS_SRC_PATH}/demos/dev_mode_key_provisioning/include/
        ${AMAZON_FREERTOS_SRC_PATH}/demos/common/mqtt_subscription_manager
        ${AMAZON_FREERTOS_SRC_PATH}/demos/common/pkcs11_helpers
        # freeRTOS kernel
        ${FREERTOS_KERNEL_SRC_PATH}/include/
        ${FREERTOS_KERNEL_SRC_PATH}/portable/GCC/ARM_CM55_NTZ/non_secure/
        # freertos plus tcp
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/include/
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_tcp/portable/Compiler/GCC
        # amazon-freertos platform layer
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/freertos/include
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/freertos/include/platform
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/include/
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/include/platform
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/platform/include/types
        # secure sockets
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/secure_sockets/include/
        # c sdk common
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/c_sdk/standard/common/include/
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/c_sdk/standard/common/include/types
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/c_sdk/standard/common/include/private
        # c sdk mqtt
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/c_sdk/standard/mqtt/include/
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/c_sdk/standard/mqtt/include/types/
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/c_sdk/standard/mqtt/src/private/
        # core MQTT
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/coreMQTT/source/include/
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/coreMQTT/source/interface/
        # MQTT agent
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/mqtt_agent/include/
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/coreMQTT-Agent/source/include
        # backoff algorithm
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/backoff_algorithm/source/include
        # secure sockets
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/transport/secure_sockets
        # tls
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/tls/include
        # freertos plus standard crypto
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/crypto/include
        # mbedtls
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls/include
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls_config
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/mbedtls_utils
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/posix/include/
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/posix/include/FreeRTOS_POSIX
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/freertos_plus/standard/freertos_plus_posix/include
        # pkcs11
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/3rdparty/pkcs11
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/pkcs11/corePKCS11/source/include
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/pkcs11/corePKCS11/source/dependency/3rdparty/mbedtls_utils
        ${AMAZON_FREERTOS_SRC_PATH}/libraries/abstractions/pkcs11/corePKCS11/source/dependency/3rdparty/pkcs11
        ${PKCS11_PSA_SRC_PATH}
        # OTA for AWS
        ${OTA_FOR_AWS_SRC_PATH}/source/include
        ${OTA_FOR_AWS_SRC_PATH}/source/portable/os
        # OTA PAL PSA
        ${OTA_PAL_PSA_SRC_PATH}
        # CBOR
        ${OTA_FOR_AWS_SRC_PATH}/source/dependency/3rdparty/tinycbor/src
        # CoreJSON
        ${OTA_FOR_AWS_SRC_PATH}/source/dependency/coreJSON/source/include/
)

target_compile_definitions(tfm_ns
    PRIVATE
        MBEDTLS_CONFIG_FILE="aws_mbedtls_config.h"
        $<$<BOOL:${VAD_AN552_NO_CONNECTIVITY}>:VAD_AN552_NO_CONNECTIVITY>
        # FreeRTOS OTA PSA PAL configuration
        OTA_PAL_CODE_SIGNING_ALGO=OTA_PAL_CODE_SIGNING_RSA
        OTA_PAL_SIGNATURE_FORMAT=OTA_PAL_SIGNATURE_RAW
)

target_link_libraries(tfm_ns
    PRIVATE
        platform_ns
        tfm_api_ns
        tfm_s_veneers
)

set_target_properties(tfm_ns PROPERTIES
    SUFFIX ".axf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_link_options(tfm_ns
    PRIVATE
        $<$<C_COMPILER_ID:GNU>:-Wl,-Map=${CMAKE_BINARY_DIR}/bin/tfm_ns.map>
        $<$<C_COMPILER_ID:ARMClang>:--map>
        $<$<C_COMPILER_ID:IAR>:--map\;${CMAKE_BINARY_DIR}/bin/tfm_ns.map>
)

add_convert_to_bin_target(tfm_ns)

###################### TF-M NS interface api (NS lib) ##########################

add_library(tfm_api_ns STATIC)

target_sources(tfm_api_ns PRIVATE
    $<$<BOOL:${TFM_PARTITION_PLATFORM}>:${INTERFACE_SRC_DIR}/tfm_platform_api.c>
    $<$<BOOL:${TFM_PARTITION_PROTECTED_STORAGE}>:${INTERFACE_SRC_DIR}/tfm_ps_api.c>
    $<$<BOOL:${TFM_PARTITION_INTERNAL_TRUSTED_STORAGE}>:${INTERFACE_SRC_DIR}/tfm_its_api.c>
    $<$<BOOL:${TFM_PARTITION_CRYPTO}>:${INTERFACE_SRC_DIR}/tfm_crypto_api.c>
    $<$<BOOL:${TFM_PARTITION_INITIAL_ATTESTATION}>:${INTERFACE_SRC_DIR}/tfm_attest_api.c>
    $<$<BOOL:${TFM_PARTITION_FIRMWARE_UPDATE}>:${INTERFACE_SRC_DIR}/tfm_fwu_api.c>

    # vad_an552 secure partition is needed for this demo
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../partitions/vad_an552_sp/ns_interface/vad_an552_ipc_api.c
)

target_sources(tfm_api_ns PRIVATE
    ${INTERFACE_SRC_DIR}/tfm_psa_ns_api.c
    ${TFM_TEST_REPO_PATH}/app/tfm_ns_interface.c
)

target_include_directories(tfm_api_ns PRIVATE
    ${TFM_TEST_REPO_PATH}/ns_interface
)

target_link_libraries(tfm_api_ns
    PUBLIC
        tfm_ns_interface
    PRIVATE
        platform_ns
)

############################# CMSIS ############################################

# Platform cmake config adds sources to CMSIS_5_tfm_ns, so we need to define it, but it is unused.
add_library(CMSIS_5_tfm_ns INTERFACE)
