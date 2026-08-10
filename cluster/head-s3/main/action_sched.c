#include "action_sched.h"

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "sc-act";

#define ACT_MAX_DRIVERS   4
#define ACT_AUDIT_N       16
#define ACT_DEADLINE_MS   8000
#define ACT_COOLDOWN_US   30000000LL

enum { ST_IDLE = 0, ST_QUEUED = 1, ST_INFLIGHT = 2 };

typedef struct {
    int64_t  us;
    uint8_t  mac[6];
    uint8_t  proto;
    uint8_t  cmd;
    uint8_t  result;
    uint16_t dur_ms;
} act_audit_t;

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile int s_state = ST_IDLE;
static volatile bool s_cancel;
static act_target_t s_pend;
static act_cmd_t    s_pend_cmd;
static uint32_t     s_epoch;

static const act_driver_t *s_drv[ACT_MAX_DRIVERS];
static int s_ndrv;

static void (*s_pause)(void);
static void (*s_resume)(void);

static act_audit_t s_audit[ACT_AUDIT_N];
static int s_audit_head, s_audit_count;
static act_result_t s_last_result;

static uint8_t s_cd_mac[6];
static int64_t s_cd_until;

void action_sched_init(void)
{
    s_state = ST_IDLE;
    s_ndrv = 0;
    s_audit_head = s_audit_count = 0;
    s_last_result = ACT_RESULT_NONE;
    s_cd_until = 0;
}

void action_sched_register(const act_driver_t *drv)
{
    if (drv && s_ndrv < ACT_MAX_DRIVERS) s_drv[s_ndrv++] = drv;
    ESP_LOGI(TAG, "driver registered: %s (%d total)", drv ? drv->id : "?", s_ndrv);
}

void action_sched_set_radio_hooks(void (*pause)(void), void (*resume)(void))
{
    s_pause = pause;
    s_resume = resume;
}

static bool mac_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }

bool action_sched_submit(const act_target_t *t, act_cmd_t cmd)
{
    if (!t) return false;
    int64_t now = esp_timer_get_time();

    portENTER_CRITICAL(&s_mux);
    bool ok = (s_state == ST_IDLE);
    if (ok && cmd == ACT_CMD_SOUND_START &&
        s_cd_until > now && mac_eq(s_cd_mac, t->mac)) {
        ok = false;
    }
    if (ok) {
        s_pend = *t;
        s_pend.captured_seq = ++s_epoch;
        s_pend_cmd = cmd;
        s_cancel = false;
        s_state = ST_QUEUED;
    }
    portEXIT_CRITICAL(&s_mux);

    if (ok) ESP_LOGI(TAG, "queued %s for %02x:%02x:%02x:%02x:%02x:%02x (proto=%u)",
                     cmd == ACT_CMD_SOUND_STOP ? "SOUND_STOP" : "SOUND_START",
                     t->mac[0], t->mac[1], t->mac[2], t->mac[3], t->mac[4], t->mac[5],
                     t->proto_hint);
    else    ESP_LOGW(TAG, "submit rejected (busy/cooldown)");
    return ok;
}

void action_sched_cancel(void)
{
    portENTER_CRITICAL(&s_mux);
    s_cancel = true;
    if (s_state == ST_QUEUED) s_state = ST_IDLE;
    portEXIT_CRITICAL(&s_mux);
    ESP_LOGI(TAG, "cancel requested");
}

bool action_sched_busy(void)
{
    return s_state != ST_IDLE;
}

static void audit_add(const act_target_t *t, act_cmd_t cmd, act_result_t r, uint16_t dur_ms)
{
    portENTER_CRITICAL(&s_mux);
    act_audit_t *a = &s_audit[s_audit_head];
    a->us     = esp_timer_get_time();
    a->proto  = t->proto_hint;
    a->cmd    = (uint8_t)cmd;
    a->result = (uint8_t)r;
    a->dur_ms = dur_ms;
    memcpy(a->mac, t->mac, 6);
    s_audit_head = (s_audit_head + 1) % ACT_AUDIT_N;
    if (s_audit_count < ACT_AUDIT_N) s_audit_count++;
    s_last_result = r;
    portEXIT_CRITICAL(&s_mux);
}

void action_sched_service(bool armed)
{
    if (s_state != ST_QUEUED) return;

    act_target_t t;
    act_cmd_t cmd;
    portENTER_CRITICAL(&s_mux);
    t = s_pend;
    cmd = s_pend_cmd;
    s_state = ST_INFLIGHT;
    portEXIT_CRITICAL(&s_mux);

    if (!armed || s_cancel) {
        audit_add(&t, cmd, s_cancel ? ACT_RESULT_CANCELLED : ACT_RESULT_REJECTED, 0);
        s_state = ST_IDLE;
        return;
    }
    if (s_ndrv == 0) {
        audit_add(&t, cmd, ACT_RESULT_UNSUPPORTED, 0);
        s_state = ST_IDLE;
        return;
    }

    if (s_pause) s_pause();
    int64_t t0 = esp_timer_get_time();
    act_result_t r = s_drv[0]->run(&t, cmd, ACT_DEADLINE_MS);
    uint16_t dur = (uint16_t)((esp_timer_get_time() - t0) / 1000);
    if (s_resume) s_resume();

    if (r == ACT_RESULT_SUCCEEDED && cmd == ACT_CMD_SOUND_START) {
        portENTER_CRITICAL(&s_mux);
        memcpy(s_cd_mac, t.mac, 6);
        s_cd_until = esp_timer_get_time() + ACT_COOLDOWN_US;
        portEXIT_CRITICAL(&s_mux);
    }

    audit_add(&t, cmd, r, dur);
    ESP_LOGI(TAG, "%s -> result=%d (%u ms)", s_drv[0]->id, r, dur);
    s_state = ST_IDLE;
}

static const char *result_str(uint8_t r)
{
    switch (r) {
    case ACT_RESULT_SUCCEEDED:       return "succeeded";
    case ACT_RESULT_REJECTED:        return "rejected";
    case ACT_RESULT_UNSUPPORTED:     return "unsupported";
    case ACT_RESULT_TIMED_OUT:       return "timed_out";
    case ACT_RESULT_TRANSPORT_ERROR: return "transport_error";
    case ACT_RESULT_CANCELLED:       return "cancelled";
    default:                         return "none";
    }
}

int action_sched_status_json(char *buf, int cap)
{
    int off = snprintf(buf, cap, "{\"busy\":%s,\"last\":\"%s\",\"audit\":[",
                       action_sched_busy() ? "true" : "false", result_str(s_last_result));
    portENTER_CRITICAL(&s_mux);
    int n = s_audit_count, head = s_audit_head;
    portEXIT_CRITICAL(&s_mux);
    for (int k = 0; k < n && off > 0 && off < cap; k++) {
        int idx = (head + ACT_AUDIT_N - 1 - k) % ACT_AUDIT_N;
        act_audit_t *a = &s_audit[idx];
        off += snprintf(buf + off, cap - off,
            "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"proto\":%u,\"cmd\":%u,"
            "\"result\":\"%s\",\"dur_ms\":%u,\"transmitted\":%s,\"auth\":\"tracker_safety\"}",
            k ? "," : "", a->mac[0], a->mac[1], a->mac[2], a->mac[3], a->mac[4], a->mac[5],
            a->proto, a->cmd, result_str(a->result), a->dur_ms,
            a->result == ACT_RESULT_UNSUPPORTED || a->result == ACT_RESULT_REJECTED ? "false" : "true");
    }
    if (off > 0 && off < cap) off += snprintf(buf + off, cap - off, "]}");
    return (off > 0 && off < cap) ? off : cap - 1;
}
