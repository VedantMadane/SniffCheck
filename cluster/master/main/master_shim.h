#pragma once
#include <stdint.h>

void master_shim_set_session(const char *id, const char *fw);
void master_shim_set_last_scan(uint16_t s);

void master_on_rescan_request(void);
void master_on_walk_request(bool start);

void master_on_epup_label(const char *label);

void master_cluster_status_json(char *buf, size_t buflen);

void master_cluster_log_json(char *buf, size_t buflen);

void master_cluster_sentinel_json(char *buf, size_t buflen);
void master_on_sentinel_cfg(const char *body, int len);

void master_cluster_places_json(char *buf, size_t buflen);
void master_cluster_infra_json(char *buf, size_t buflen);
void master_cluster_place_detail_json(int idx, char *buf, size_t buflen);
void master_on_landmark_edit(const char *body, int len);
void master_on_learn(const char *body, int len);
void master_on_place_label(const char *body, int len);
void master_cluster_hits_json(char *buf, size_t buflen);
void master_on_settime(uint32_t epoch);

void master_on_tracker_sound(const char *body, int len);
void master_on_tracker_burst(const char *body, int len);
void master_on_tracker_burst_stop(void);
void master_cluster_tracker_json(char *buf, size_t buflen);

void master_on_brain_reset(void);

void master_on_locate_start(const char *body, int len);
void master_on_locate_stop(void);
void master_locate_json(char *buf, size_t buflen);

uint32_t    master_cluster_merge_count(void);
const char *master_cluster_session_id(void);
int         master_cluster_device_count(void);
int         master_cluster_device_json(int idx, uint32_t since, char *buf, size_t buflen);
