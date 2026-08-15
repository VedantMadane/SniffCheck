#pragma once

#include "sdkconfig.h"

#if defined(CONFIG_IDF_TARGET_ESP32C3)

#define SC_PLATFORM_X4      1
#define SC_HAS_PSRAM        0
#define SC_HAS_5GHZ         0
#define SC_HAS_EINK         1
#define SC_HAS_BUTTONS      7

#define SC_ENABLE_SELF_TEST 0

#define SC_SHARE_SNAPSHOT_BUFFERS 1

#define SC_WIFI_SCAN_MAX_APS   32
#define SC_BLE_MAX_DEVICES     40
#define SC_SNIFF_MAX_APS       16

#define SC_BLE_ADV_RING_CAP    48

#define SC_BLE_ADV_DATA_MAX    31
#define SC_PROBE_FRAME_RING_CAP 48
#define SC_SSID_DETAIL_CAP     32
#define SC_SSID_BEACON_CAP     16
#define SC_IE_DETAIL_CAP       24
#define SC_SEQ_DETAIL_CAP      24
#define SC_ANQP_DETAIL_CAP     24

#define SC_TWIN_MAX_FINDINGS   12

#define SC_PDC_MAX_EDGES       96

#else

#define SC_PLATFORM_X4      0
#define SC_HAS_PSRAM        1
#define SC_HAS_5GHZ         1
#define SC_HAS_EINK         0
#define SC_HAS_BUTTONS      1

#define SC_ENABLE_SELF_TEST 1
#define SC_SHARE_SNAPSHOT_BUFFERS 0

#define SC_WIFI_SCAN_MAX_APS   128
#define SC_BLE_MAX_DEVICES     192
#define SC_SNIFF_MAX_APS       128

#define SC_BLE_ADV_RING_CAP    128

#define SC_BLE_ADV_DATA_MAX    255

#define SC_PROBE_FRAME_RING_CAP 128
#define SC_SSID_DETAIL_CAP     64
#define SC_SSID_BEACON_CAP     32
#define SC_IE_DETAIL_CAP       64
#define SC_SEQ_DETAIL_CAP      64
#define SC_ANQP_DETAIL_CAP     64

#define SC_TWIN_MAX_FINDINGS   48

#define SC_PDC_MAX_EDGES       512

#endif
