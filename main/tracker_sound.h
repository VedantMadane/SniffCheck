#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "ble_scanner.h"

#define TSND_MAX_TARGETS 12

typedef struct {
    uint8_t mac[6];
    uint8_t addr_type;
    char    name[32];
    char    kind[20];
    int8_t  rssi;
} tsnd_target_t;

void tracker_sound_init(void);

void tracker_sound_start_task(void);

void tracker_sound_ingest(const ble_results_t *ble);

int  tracker_sound_targets(tsnd_target_t *out, int max);

void tracker_sound_set_armed(bool armed);
bool tracker_sound_armed(void);

bool tracker_sound_bark(const uint8_t mac[6]);

int  tracker_sound_howl_start(void);
void tracker_sound_howl_stop(void);

void tracker_sound_status_json(char *out, size_t cap);

bool tracker_sound_busy(void);
