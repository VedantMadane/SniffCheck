#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "epup_summary.h"

#ifdef __cplusplus
extern "C" {
#endif

bool epup_brain_init(uint32_t boot_count);

void epup_brain_observe(const char *jsonl, size_t len);

void epup_brain_get(epup_summary_t *out);

typedef struct {
    int8_t   cur;
    uint8_t  count;
    uint8_t  similarity;
    bool     known;
    bool     is_new;
    uint32_t scans;
    char     label[16];
} epup_place_t;

void epup_brain_place(epup_place_t *out);

#include "cluster_proto.h"
void epup_brain_places(cl_places_t *out);

void epup_brain_place_label(int i, const char *label);

#define EPUP_LM_MAX        24
#define EPUP_LM_PINNED     0x01u
#define EPUP_LM_CONFIRMED  0x02u

typedef struct {
    uint64_t unit;
    uint16_t hits;
    uint8_t  scans_seen;
    uint8_t  flags;
    char     name[20];
} epup_landmark_t;

int  epup_brain_place_detail(int idx, epup_landmark_t *out, int max);

void epup_brain_landmark_pin(int place, uint64_t unit, bool pin);

void epup_brain_landmark_delete(int place, uint64_t unit);

void epup_brain_place_delete(int idx);

int  epup_brain_place_quality(int idx);

void epup_brain_learn_start(int want_scans, bool reposition, bool fresh);
void epup_brain_learn_cancel(void);

typedef struct {
    bool    active;
    uint8_t want, done;
    bool    reposition;
    int8_t  target;
} epup_learn_t;
void epup_brain_learn_status(epup_learn_t *out);

void epup_brain_reset(void);

size_t epup_brain_ckpt_size(void);

size_t epup_brain_ckpt_save(uint8_t *out, size_t cap);

bool epup_brain_ckpt_load(const uint8_t *in, size_t len);

#ifdef __cplusplus
}
#endif
