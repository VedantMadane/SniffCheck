#include "tracker_sound.h"

#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "action_sched.h"
#include "driver_dult.h"
#include "capture_writer.h"

static const char *TAG = "sc_tsnd";

#define TSND_TASK_STACK   4096
#define TSND_TASK_PRIO    4
#define TSND_GAP_MS       1500

static tsnd_target_t s_targets[TSND_MAX_TARGETS];
static int           s_n;
static SemaphoreHandle_t s_lock;

static volatile bool s_armed;
static volatile bool s_howl;
static volatile int  s_howl_i, s_howl_total, s_howl_done;
static volatile bool s_stop;

static TaskHandle_t s_task;

static bool lock(void)
{
    return s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) == pdTRUE;
}
static void unlock(void) { if (s_lock) xSemaphoreGive(s_lock); }

static void name_copy(char *dst, size_t dstsz, const char *src)
{
    size_t i = 0;
    if (!dstsz) return;
    for (; src && src[i] && i + 1 < dstsz; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (c < 0x20 || c > 0x7e || c == '"' || c == '\\') ? ' ' : (char)c;
    }
    while (i && dst[i - 1] == ' ') i--;
    dst[i] = '\0';
}

static bool kind_is_ringable(const char *kind)
{
    if (!kind) return false;
    return strcmp(kind, "find_my_other") == 0 || strcmp(kind, "generic") == 0;
}

void tracker_sound_init(void)
{
    if (!s_lock) s_lock = xSemaphoreCreateMutex();
    action_sched_init();
    action_sched_register(&driver_dult);
    s_armed = false;
    ESP_LOGI(TAG, "tracker safety sound ready (disarmed)");
}

void tracker_sound_ingest(const ble_results_t *ble)
{
    if (!ble || !lock()) return;

    s_n = 0;
    for (uint16_t i = 0; i < ble->count && s_n < TSND_MAX_TARGETS; i++) {
        const ble_device_t *d = &ble->devices[i];
        if (d->suppressed) continue;
        const char *kind = capture_tracker_kind(d);
        if (!kind_is_ringable(kind)) continue;

        tsnd_target_t *t = &s_targets[s_n++];
        memset(t, 0, sizeof(*t));
        memcpy(t->mac, d->addr, 6);

        t->addr_type = (d->addr_subtype == BLE_ADDR_SUB_PUBLIC) ? 0 : 1;
        t->rssi = d->rssi;
        name_copy(t->name, sizeof(t->name), d->name);
        snprintf(t->kind, sizeof(t->kind), "%s", kind);
    }
    unlock();

    if (s_n) ESP_LOGI(TAG, "%d ringable tracker(s) in range", s_n);
}

int tracker_sound_targets(tsnd_target_t *out, int max)
{
    if (!out || max <= 0 || !lock()) return 0;
    int n = s_n < max ? s_n : max;
    memcpy(out, s_targets, (size_t)n * sizeof(*out));
    unlock();
    return n;
}

void tracker_sound_set_armed(bool armed)
{
    s_armed = armed;
    if (!armed) {
        s_stop = true;
        action_sched_cancel();
    }
    ESP_LOGW(TAG, "tracker safety sound %s", armed ? "ARMED (will transmit)" : "disarmed");
}

bool tracker_sound_armed(void) { return s_armed; }

bool tracker_sound_busy(void)
{
    return s_howl || action_sched_busy();
}

static bool submit_target(const tsnd_target_t *t)
{
    act_target_t at;
    memset(&at, 0, sizeof(at));
    memcpy(at.mac, t->mac, 6);
    at.addr_type  = t->addr_type;
    at.proto_hint = ACT_PROTO_AUTO;
    name_copy(at.name, sizeof(at.name), t->name);

    bool ok = action_sched_submit(&at, ACT_CMD_SOUND_START);
    if (ok && s_task) xTaskNotifyGive(s_task);
    return ok;
}

bool tracker_sound_bark(const uint8_t mac[6])
{
    if (!s_armed) {
        ESP_LOGW(TAG, "bark refused — safety sound is not armed");
        return false;
    }
    if (!mac || !lock()) return false;

    const tsnd_target_t *found = NULL;
    for (int i = 0; i < s_n; i++)
        if (memcmp(s_targets[i].mac, mac, 6) == 0) { found = &s_targets[i]; break; }
    tsnd_target_t copy;
    if (found) copy = *found;
    unlock();

    if (!found) {
        ESP_LOGW(TAG, "bark refused — %02X:%02X:%02X:%02X:%02X:%02X is not a ringable "
                 "tracker in the latest scan", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return false;
    }
    ESP_LOGW(TAG, "BARK -> %02X:%02X:%02X:%02X:%02X:%02X (%s) — transmitting",
             copy.mac[0], copy.mac[1], copy.mac[2], copy.mac[3], copy.mac[4], copy.mac[5],
             copy.kind);
    return submit_target(&copy);
}

int tracker_sound_howl_start(void)
{
    if (!s_armed) {
        ESP_LOGW(TAG, "howl refused — safety sound is not armed");
        return 0;
    }
    if (s_howl) return 0;
    if (!lock()) return 0;
    int n = s_n;
    unlock();
    if (n <= 0) {
        ESP_LOGW(TAG, "howl: nothing ringable in range");
        return 0;
    }

    s_stop = false;
    s_howl_i = 0;
    s_howl_done = 0;
    s_howl_total = n;
    s_howl = true;
    if (s_task) xTaskNotifyGive(s_task);
    ESP_LOGW(TAG, "HOWL started — %d tracker(s), one at a time", n);
    return n;
}

void tracker_sound_howl_stop(void)
{
    if (!s_howl) return;
    s_stop = true;
    action_sched_cancel();
    ESP_LOGW(TAG, "howl stop requested");
}

static void tsnd_task(void *arg)
{
    (void)arg;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(250));

        action_sched_service(s_armed);

        if (!s_howl) continue;

        if (s_stop || !s_armed) {
            ESP_LOGW(TAG, "howl ended early (%d/%d done)", s_howl_done, s_howl_total);
            s_howl = false;
            continue;
        }
        if (action_sched_busy()) continue;

        if (s_howl_i >= s_howl_total) {
            ESP_LOGW(TAG, "howl complete — %d tracker(s) commanded", s_howl_done);
            s_howl = false;
            continue;
        }

        tsnd_target_t t;
        bool have = false;
        if (lock()) {
            if (s_howl_i < s_n) { t = s_targets[s_howl_i]; have = true; }
            unlock();
        }
        s_howl_i++;
        if (!have) continue;

        if (submit_target(&t)) s_howl_done++;
        vTaskDelay(pdMS_TO_TICKS(TSND_GAP_MS));
    }
}

void tracker_sound_start_task(void)
{
    if (s_task) return;
    xTaskCreate(tsnd_task, "sc_tsnd", TSND_TASK_STACK, NULL, TSND_TASK_PRIO, &s_task);
}

void tracker_sound_status_json(char *out, size_t cap)
{
    if (!out || cap == 0) return;

    tsnd_target_t t[TSND_MAX_TARGETS];
    int n = tracker_sound_targets(t, TSND_MAX_TARGETS);

    int p = snprintf(out, cap,
        "{\"armed\":%s,\"busy\":%s,\"howl\":{\"active\":%s,\"done\":%d,\"total\":%d},"
        "\"targets\":[",
        s_armed ? "true" : "false",
        tracker_sound_busy() ? "true" : "false",
        s_howl ? "true" : "false", s_howl_done, s_howl_total);
    if (p < 0 || (size_t)p + 3 > cap) { snprintf(out, cap, "{\"targets\":[]}"); return; }
    size_t used = (size_t)p;

    for (int i = 0; i < n; i++) {
        char row[160];
        int rn = snprintf(row, sizeof(row),
            "%s{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"addr_type\":%u,"
            "\"kind\":\"%s\",\"name\":\"%s\",\"rssi\":%d}",
            i ? "," : "", t[i].mac[0], t[i].mac[1], t[i].mac[2],
            t[i].mac[3], t[i].mac[4], t[i].mac[5], t[i].addr_type,
            t[i].kind, t[i].name, t[i].rssi);
        if (rn <= 0 || used + (size_t)rn + 16 > cap) break;
        memcpy(out + used, row, (size_t)rn);
        used += (size_t)rn;
    }

    used += (size_t)snprintf(out + used, cap - used, "],\"audit\":");
    if (used + 8 < cap) {
        int an = action_sched_status_json(out + used, (int)(cap - used));
        if (an > 0) used += (size_t)an;
    }
    snprintf(out + used, cap - used, "}");
}
