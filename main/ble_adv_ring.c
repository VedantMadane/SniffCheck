#include "ble_adv_ring.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "sc_profile.h"
#include <string.h>

#define BLE_ADV_RING_CAP SC_BLE_ADV_RING_CAP

static const char *TAG = "sc_advring";

static EXT_RAM_BSS_ATTR ble_adv_frame_t s_ring[BLE_ADV_RING_CAP];
static uint16_t s_head;
static uint16_t s_count;
static uint16_t s_scan_idx;
static bool     s_retain;
static uint32_t s_overwrites;

void ble_adv_ring_init(void)
{
    memset(s_ring, 0, sizeof(s_ring));
    s_head       = 0;
    s_count      = 0;
    s_scan_idx   = 0;
    s_retain     = false;
    s_overwrites = 0;
}

void ble_adv_ring_set_retention_mode(bool retain)
{
    s_retain = retain;
}

void ble_adv_ring_begin_scan(void)
{
    s_scan_idx++;
}

void ble_adv_ring_add(const ble_adv_frame_t *f)
{
    if (!s_retain || !f) return;

    ble_adv_frame_t *slot = &s_ring[s_head];
    *slot = *f;
    if (slot->data_len > BLE_ADV_DATA_MAX) slot->data_len = BLE_ADV_DATA_MAX;
    slot->scan_idx = s_scan_idx;
    slot->used     = true;

    s_head = (uint16_t)((s_head + 1) % BLE_ADV_RING_CAP);
    if (s_count < BLE_ADV_RING_CAP) s_count++;
    else if (s_overwrites != UINT32_MAX) s_overwrites++;
}

static const ble_adv_frame_t *phys_at(uint16_t logical)
{
    if (logical >= s_count) return NULL;
    uint16_t start = (uint16_t)((s_head + BLE_ADV_RING_CAP - s_count) % BLE_ADV_RING_CAP);
    uint16_t phys  = (uint16_t)((start + logical) % BLE_ADV_RING_CAP);
    return &s_ring[phys];
}

uint16_t ble_adv_ring_count(void)
{
    return s_count;
}

const ble_adv_frame_t *ble_adv_ring_at(uint16_t idx)
{
    return phys_at(idx);
}

uint16_t ble_adv_ring_count_for_addr(const uint8_t addr[6])
{
    if (!addr) return 0;
    uint16_t n = 0;
    for (uint16_t i = 0; i < s_count; i++) {
        const ble_adv_frame_t *e = phys_at(i);
        if (e && memcmp(e->addr, addr, 6) == 0) n++;
    }
    return n;
}

const ble_adv_frame_t *ble_adv_ring_nth_for_addr(const uint8_t addr[6], uint16_t n)
{
    if (!addr) return NULL;
    uint16_t seen = 0;
    for (uint16_t i = 0; i < s_count; i++) {
        const ble_adv_frame_t *e = phys_at(i);
        if (e && memcmp(e->addr, addr, 6) == 0) {
            if (seen == n) return e;
            seen++;
        }
    }
    return NULL;
}

void ble_adv_ring_log_summary(void)
{
    uint16_t ext = 0, srsp = 0, clipped = 0, coded = 0, periodic = 0, maxlen = 0;
    for (uint16_t i = 0; i < s_count; i++) {
        const ble_adv_frame_t *e = phys_at(i);
        if (!e) continue;
        if (!(e->flags & BLE_ADV_F_LEGACY)) ext++;
        if (e->flags & BLE_ADV_F_SCAN_RSP)  srsp++;
        if (e->flags & BLE_ADV_F_CLIPPED)   clipped++;
        if (e->prim_phy == 3 || e->sec_phy == 3) coded++;
        if (e->periodic_itvl)               periodic++;
        if (e->data_full_len > maxlen)      maxlen = e->data_full_len;
    }
    ESP_LOGI(TAG,
             "adv ring: %u/%u frames over=%lu | ext=%u legacy=%u scanrsp=%u "
             "coded=%u periodic=%u clipped=%u maxlen=%u (cap %u B/frame, schema %u)",
             (unsigned)s_count, (unsigned)BLE_ADV_RING_CAP,
             (unsigned long)s_overwrites,
             (unsigned)ext, (unsigned)(s_count - ext), (unsigned)srsp,
             (unsigned)coded, (unsigned)periodic, (unsigned)clipped,
             (unsigned)maxlen, (unsigned)BLE_ADV_DATA_MAX, (unsigned)BLE_ADV_SCHEMA);
}

uint16_t ble_adv_ring_capacity(void)
{
    return BLE_ADV_RING_CAP;
}

uint32_t ble_adv_ring_overwrites(void)
{
    return s_overwrites;
}
