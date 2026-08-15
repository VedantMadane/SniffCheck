#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    PC_RADIO_WIFI_AP = 0,
    PC_RADIO_WIFI_STA,
    PC_RADIO_BLE,
} pc_radio_t;

typedef enum {
    PC_RSSI_VERY_WEAK = 0,
    PC_RSSI_WEAK,
    PC_RSSI_MEDIUM,
    PC_RSSI_STRONG,
    PC_RSSI_VERY_STRONG,
} pc_rssi_bucket_t;

typedef struct {
    char     a_label[24];
    char     b_label[24];
    uint8_t  confidence;
    uint16_t together;
    uint16_t a_windows;
    uint16_t b_windows;
    uint16_t apart;
    uint16_t arrivals;
    uint16_t departures;
    uint8_t  p_b_given_a;
    uint8_t  p_a_given_b;
    bool     rssi_trend_similar;
    bool     same_environment;
} pc_pair_t;

typedef struct {
    uint16_t windows;
    uint16_t nodes;
    uint16_t edges;
    uint16_t edges_dropped;
    uint16_t surfaced;
    uint16_t infrastructure;
} pc_stats_t;

void pc_init(void);
void pc_reset(void);

void pc_window_begin(void);
void pc_observe_wifi_ap(const uint8_t bssid[6], int8_t rssi);
void pc_observe_wifi_sta(const uint8_t mac[6], bool randomized, int8_t rssi);
void pc_observe_ble(const uint8_t addr[6], uint8_t addr_subtype, int8_t rssi);
void pc_window_end(void);

void pc_get_stats(pc_stats_t *out);

int pc_top_pairs(pc_pair_t *out, int max);
