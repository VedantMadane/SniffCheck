#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ENV_MAX            6
#define ENV_LM_MAX         24
#define ENV_LM_NAME        20
#define ENV_LABEL_MAX      16

#define ENV_LM_PINNED      0x01u
#define ENV_LM_CONFIRMED   0x02u

void env_learn_init(uint32_t boot_count);

void env_learn_scan_begin(void);
void env_learn_scan_ap(const uint8_t bssid[6], const char *ssid);
void env_learn_scan_end(void);

typedef struct {
    int8_t   cur;
    uint8_t  count;
    uint8_t  similarity;
    bool     known;
    bool     is_new;
    uint32_t scans;
    uint8_t  quality;
    char     label[ENV_LABEL_MAX];
} env_status_t;

void env_learn_status(env_status_t *out);

typedef struct {
    uint8_t  idx;
    uint8_t  landmarks;
    uint8_t  quality;
    bool     known;
    bool     current;
    uint32_t scans;
    char     label[ENV_LABEL_MAX];
} env_entry_t;

int env_learn_list(env_entry_t *out, int max);

typedef struct {
    uint64_t unit;
    uint16_t hits;
    uint8_t  scans_seen;
    uint8_t  flags;
    char     name[ENV_LM_NAME];
} env_landmark_t;

int env_learn_detail(int idx, env_landmark_t *out, int max);

void env_learn_label(int idx, const char *label);
void env_learn_forget(int idx);
void env_learn_landmark_pin(int idx, uint64_t unit, bool pin);
void env_learn_landmark_delete(int idx, uint64_t unit);

bool env_learn_is_fixture(uint64_t unit);

void env_learn_reset(void);

void env_learn_start(int want_scans, bool reposition, bool fresh,
                     const char *label);
void env_learn_cancel(void);

typedef struct {
    bool     active;
    uint8_t  want, done;
    bool     reposition;
    int8_t   target;
} env_run_t;

void env_learn_run_status(env_run_t *out);

#ifdef __cplusplus
}
#endif
