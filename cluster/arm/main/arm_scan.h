#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "cluster_proto.h"

void arm_scan_init(uint8_t arm_index);

void arm_scan_set_plan(const cl_plan_t *p);

void arm_scan_run(bool adv, uint16_t *wifi_seen, uint16_t *ble_seen);

void arm_walk_start(void);
void arm_walk_sweep(uint16_t *wifi_unique, uint16_t *ble_unique, uint32_t *dur_sec);
void arm_walk_finish(bool *capped, uint16_t *wifi_seen, uint16_t *ble_seen);

const uint8_t *arm_scanset_ptr(void);
uint32_t       arm_scanset_len(void);

void arm_locate_start(const uint8_t mac[6], uint8_t kind, uint8_t channel);
void arm_locate_stop(void);
bool arm_locate_active(void);
void arm_locate_sweep(void);
void arm_locate_get(cl_locate_state_t *st);
