/*
 * Copyright (c) 2022 Arm Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dma350_checker_layer.h"

enum dma350_lib_error_t request_dma350_priv_config(enum dma350_config_type_t config_type, uint8_t channel, void* args) FREERTOS_SYSTEM_CALL;

enum dma350_lib_error_t request_dma350_priv_config(enum dma350_config_type_t config_type, uint8_t channel, void* args)
{
    BaseType_t xRunningPrivileged;
    enum dma350_lib_error_t ret_val;

    xPortRaisePrivilege(xRunningPrivileged);
    ret_val = config_dma350_for_unprivileged_actor(config_type, channel, args);
    vPortResetPrivilege(xRunningPrivileged);

    return ret_val;
}
