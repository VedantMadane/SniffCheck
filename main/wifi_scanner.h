#pragma once

#include "esp_wifi.h"
#include "esp_err.h"
#include "sc_profile.h"
#include <stdint.h>
#include <stdbool.h>

#define WIFI_SCAN_MAX_APS  SC_WIFI_SCAN_MAX_APS

typedef struct {
    char             ssid[33];
    uint8_t          bssid[6];
    int8_t           rssi;
    uint8_t          channel;
    bool             band_5g;
    wifi_auth_mode_t auth;
} ap_record_t;

typedef struct {
    ap_record_t entries[WIFI_SCAN_MAX_APS];
    uint16_t    count;
} scan_results_t;

typedef struct {
    bool     show_hidden;
    bool     passive;
    uint16_t dwell_ms;
    bool     band_2g_only;
} wifi_scan_opts_t;

esp_err_t wifi_scanner_init(void);

esp_err_t wifi_scanner_deinit(void);

esp_err_t wifi_scan_run(scan_results_t *out);

typedef enum {
    WIFI_SCAN_ASYNC_IDLE = 0,
    WIFI_SCAN_ASYNC_RUNNING,
    WIFI_SCAN_ASYNC_DONE,
} wifi_scan_async_state_t;

esp_err_t wifi_scan_async_start(const wifi_scan_opts_t *opts);

esp_err_t wifi_scan_async_start_wardrive(bool include_5g);

wifi_scan_async_state_t wifi_scan_async_state(void);

esp_err_t wifi_scan_async_collect(scan_results_t *out);

void wifi_scan_async_cancel(void);

esp_err_t wifi_scan_run_opts(scan_results_t *out, const wifi_scan_opts_t *opts);

esp_err_t wifi_scan_run_broad(scan_results_t *out, uint8_t active_sweeps, uint32_t max_ms);

esp_err_t wifi_scan_run_wardrive(scan_results_t *out, bool include_5g);

esp_err_t wifi_scan_run_channels(scan_results_t *out, const uint8_t *chans,
                                 uint8_t n, uint16_t dwell_ms);

esp_err_t wifi_scan_channels_append(scan_results_t *out, const uint8_t *chans,
                                    uint8_t n, uint16_t dwell_ms);
