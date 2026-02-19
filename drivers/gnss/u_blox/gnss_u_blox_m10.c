/*
 * Copyright (c) 2026 Hong Nguyen <hong.nguyen.k54@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT u_blox_m10

#include <zephyr/kernel.h>
#include <zephyr/drivers/gnss.h>
#include <zephyr/drivers/gnss/gnss_publish.h>

#include <zephyr/modem/ubx.h>
#include <zephyr/modem/backend/uart.h>

#include <zephyr/logging/log.h>

#include "gnss_u_blox_iface.h"

LOG_MODULE_REGISTER(ubx_m10, CONFIG_GNSS_LOG_LEVEL);

UBX_FRAME_DEFINE(disable_nmea, UBX_FRAME_CFG_VAL_SET_U8_INITIALIZER(UBX_KEY_UART1_PROTO_OUT_NMEA, 0));
UBX_FRAME_DEFINE(enable_uart_nav, UBX_FRAME_CFG_VAL_SET_U8_INITIALIZER(UBX_KEY_MSG_OUT_UBX_NAV_PVT_UART1, 1));
UBX_FRAME_DEFINE(nav_fix_mode_auto, UBX_FRAME_CFG_VAL_SET_U8_INITIALIZER(UBX_KEY_NAV_CFG_FIX_MODE, UBX_FIX_MODE_AUTO));
UBX_FRAME_DEFINE(enable_prot_in_ubx, UBX_FRAME_CFG_VAL_SET_U8_INITIALIZER(UBX_KEY_UART1_PROTO_IN_UBX, 1));
UBX_FRAME_DEFINE(enable_prot_out_ubx, UBX_FRAME_CFG_VAL_SET_U8_INITIALIZER(UBX_KEY_UART1_PROTO_OUT_UBX, 1));
#if CONFIG_GNSS_SATELLITES
UBX_FRAME_DEFINE(enable_sat, UBX_FRAME_CFG_VAL_SET_U8_INITIALIZER(UBX_KEY_MSG_OUT_UBX_NAV_SAT_UART1, 1));
#endif

static int ubx_m10_init(const struct device *dev) {
    return 0;
}

static int ubx_m10_set_fix_rate(const struct device *dev, uint32_t fix_interval_ms) {
    return 0;
}

static int ubx_m10_get_fix_rate(const struct device *dev, uint32_t *fix_interval_ms) {
    return 0;
}

static int ubx_m10_set_navigation_mode(const struct device *dev, enum gnss_navigation_mode mode) {
    return 0;
}

static int ubx_m10_get_navigation_mode(const struct device *dev, enum gnss_navigation_mode *mode) {
    return 0;
}

static int ubx_m10_set_enabled_systems(const struct device *dev, gnss_systems_t systems) {
    return 0;
}

static int ubx_m10_get_enabled_systems(const struct device *dev, gnss_systems_t *systems) {
    return 0;
}

static int ubx_m10_get_supported_systems(const struct device *dev, gnss_systems_t *systems) {
    return 0;
}

static int ubx_m10_get_latest_timepulse(const struct device *dev, k_ticks_t *timestamp) {
    return 0;
}

static int ubx_m10_pm_action(const struct device *dev, enum pm_device_action action) {
    /* TODO: look at the luatos air for example */
    return 0;
}

static DEVICE_API(gnss, ublox_m10_driver_api) = {
    .set_fix_rate = ubx_m10_set_fix_rate,
    .get_fix_rate = ubx_m10_get_fix_rate,
    .set_navigation_mode = ubx_m10_set_navigation_mode,
    .get_navigation_mode = ubx_m10_get_navigation_mode,
    .set_enabled_systems = ubx_m10_set_enabled_systems,
    .get_enabled_systems = ubx_m10_get_enabled_systems,
    .get_supported_systems = ubx_m10_get_supported_systems,
    .get_latest_timepulse = ubx_m10_get_latest_timepulse,
};

#define UBX_M10(inst) \
    \
    BUILD_ASSERT((DT_INST_PROP(inst, fix_rate) >= 50) && \
                 (DT_INST_PROP(inst, fix_rate) <= 65535), \
                 "Invalid fix-rate. Please set it higher than 50-ms"			   \
		         " and must fit in 16-bits."); \
                \
    static const struct u_blox_iface_config u_blox_m10_cfg_##inst = { \
        .bus = DEVICE_DT_GET(DT_INST_BUS(inst)), \
        .reset_gpio = GPIO_DT_SPEC_GET_OR(inst, reset_gpios, {}), \
        .fix_rate_ms = DT_INST_PROP(inst, fix_rate), \
        .baudrate = { \
            .initial = DT_INST_PROP(inst, initial_baudrate), \
            .desired = DT_PROP(DT_INST_BUS(inst), current_speed), \
        }, \
    }; \
    \
    static struct u_blox_iface_data u_blox_m10_data_##inst; \
    \
    PM_DEVICE_DT_INST_DEFINE(inst, ubx_m10_pm_action); \
    \
    DEVICE_DT_INST_DEFINE(inst, \
                          ubx_m10_init, \
                          PM_DEVICE_DT_INST_GET(inst), \
                          &u_blox_m10_data_##inst, \
                          &u_blox_m10_cfg_##inst, \
                          POST_KERNEL, \
                          CONFIG_GNSS_INIT_PRIORITY, \
                          &ublox_m10_driver_api);

DT_INST_FOREACH_STATUS_OKAY(UBX_M10)
