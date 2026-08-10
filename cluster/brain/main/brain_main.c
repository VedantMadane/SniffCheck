#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_rom_sys.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "driver/i2c_master.h"

#include "cluster_pins.h"
#include "cluster_proto.h"
#include "cluster_ui.h"
#include "node_display.h"
#include "led.h"
#include "epup_brain.h"
#include "infra_cluster.h"

#include "capture_ring.h"
#include "download_mode.h"
#include "download_http.h"
#include "master_shim.h"
#include "cluster_web.h"
#include "sentinel.h"
#include "virtual_pup.h"
#include "virtual_pup_walk.h"
#include "pup_trophy.h"

#define FW_CKPT "brain-1.2"

#define BRAIN_I2C_HZ  1000000

static const char *TAG = "cluster-brain";

#define N_ARMS 2
static const struct { uint8_t addr; uint8_t index; const char *band; } ARMS[N_ARMS] = {
    { CL_ARM1_ADDR, 1, "2.4+5 A/BLE" },
    { CL_ARM2_ADDR, 2, "2.4+5 B/BLE" },
};

#define BRAIN_PLAN_DWELL_LITE   80
#define BRAIN_PLAN_DWELL_ADV    160
#define BRAIN_PLAN_BLE_EVERY_N  4

typedef struct {
    cl_status_t last;
    uint32_t    ok, polls;
    int64_t     last_ok_us;
    uint32_t    last_ingest_seq;
    bool        planned;
} arm_link_t;

static arm_link_t s_link[N_ARMS];
static i2c_master_bus_handle_t s_bus;
static i2c_master_dev_handle_t s_dev[N_ARMS];

static i2c_master_dev_handle_t s_s3_dev;
static uint32_t s_s3_pushes, s_s3_fail;
static uint32_t s_bus_resets;

#define BRAIN_ARM_CAP   (64 * 1024)
#define BRAIN_MERGE_CAP (96 * 1024)

typedef struct {
    uint8_t  *buf;
    uint32_t  len, recs;
    bool      have;
} arm_slot_t;
static arm_slot_t s_arm[2];

static uint8_t  *s_merge_buf;
static uint32_t  s_merge_len, s_merge_uniq, s_merge_dup, s_merge_count;

#define DEV_MAX       1024
#define DEV_LINE_MAX  3072
typedef struct {
    uint64_t key;
    uint32_t first_scan, last_scan, times_seen;
    uint32_t last_ts;
    uint16_t len;
    char     line[DEV_LINE_MAX];
} dev_ent_t;
static dev_ent_t        *s_devtab;
static int               s_dev_n;
static uint32_t          s_dev_evict;
static SemaphoreHandle_t  s_dev_mux;
static char              s_sess_id[16];

#define CL_CHUNK_SETTLE_US  300

static void led_blank_cb(void) { led_off(); }

static uint64_t fnv1a(const char *s, int n)
{
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 1099511628211ULL; }
    return h;
}

static int find_str(const char *s, int n, const char *pat, char *out, int outsz)
{
    int pl = (int)strlen(pat);
    for (int i = 0; i + pl <= n; i++) {
        if (memcmp(s + i, pat, pl) == 0) {
            int k = i + pl, o = 0;
            while (k < n && s[k] != '"' && o < outsz - 1) out[o++] = s[k++];
            out[o] = '\0';
            return o;
        }
    }
    return 0;
}

static int line_key(const char *line, int n, char *kb, int kbsz)
{
    char type[24], id[40];
    if (!find_str(line, n, "\"type\":\"", type, sizeof type)) return 0;
    if (!find_str(line, n, "\"bssid\":\"", id, sizeof id) &&
        !find_str(line, n, "\"addr\":\"",  id, sizeof id)) return 0;
    int o = snprintf(kb, kbsz, "%s|%s", type, id);
    return o < kbsz ? o : kbsz - 1;
}

static void do_merge(void)
{
    uint32_t out = 0, kept = 0;
    for (int ai = 0; ai < 2; ai++) {
        const char *b = (const char *)s_arm[ai].buf;
        uint32_t n = s_arm[ai].len, i = 0;
        while (i < n) {
            uint32_t j = i;
            while (j < n && b[j] != '\n') j++;
            uint32_t linelen = j - i;
            if (linelen > 0 && s_merge_buf && out + linelen + 1 <= BRAIN_MERGE_CAP) {
                memcpy(s_merge_buf + out, b + i, linelen);
                out += linelen;
                s_merge_buf[out++] = '\n';
                kept++;
            }
            i = j + 1;
        }
    }
    s_merge_len  = out;
    s_merge_uniq = kept;
    s_merge_dup  = 0;
    s_merge_count++;
}

static void ring_feed_scanset(const uint8_t *buf, uint32_t len, uint32_t wall_ts)
{
    static char rl[DEV_LINE_MAX + 24];
    uint32_t i = 0;
    while (i < len) {
        uint32_t j = i;
        while (j < len && buf[j] != '\n') j++;
        int ll = (int)(j - i);
        if (ll > 0) {

            if (wall_ts && buf[j - 1] == '}' && ll + 20 < (int)sizeof(rl)) {
                memcpy(rl, buf + i, ll - 1);
                int o = ll - 1;
                o += snprintf(rl + o, sizeof(rl) - o, ",\"ts\":%lu}", (unsigned long)wall_ts);
                capture_ring_write(rl, o);
            } else {
                capture_ring_write((const char *)(buf + i), ll);
            }
        }
        i = j + 1;
    }
}

static dev_ent_t *dev_find(uint64_t key)
{
    for (int i = 0; i < s_dev_n; i++) if (s_devtab[i].key == key) return &s_devtab[i];
    return NULL;
}

static void dev_upsert(const char *line, int n, uint32_t scan, uint32_t wall_ts)
{

    if (n <= 0 || n >= DEV_LINE_MAX || line[n - 1] != '}') return;
    char kb[72];
    int kl = line_key(line, n, kb, sizeof kb);
    if (kl <= 0) return;
    uint64_t h = fnv1a(kb, kl);
    dev_ent_t *e = dev_find(h);
    if (!e) {
        if (s_dev_n < DEV_MAX) {
            e = &s_devtab[s_dev_n++];
        } else {
            int lru = 0;
            for (int i = 1; i < s_dev_n; i++)
                if (s_devtab[i].last_scan < s_devtab[lru].last_scan) lru = i;
            e = &s_devtab[lru];
            s_dev_evict++;
        }
        e->key = h; e->first_scan = scan; e->times_seen = 0;
    }
    e->last_scan = scan;
    e->last_ts   = wall_ts;
    e->times_seen++;
    int cp = n < DEV_LINE_MAX - 1 ? n : DEV_LINE_MAX - 1;
    memcpy(e->line, line, cp);
    e->len = (uint16_t)cp;
}

static void dev_table_ingest(const uint8_t *buf, uint32_t len, uint32_t scan, uint32_t wall_ts)
{
    if (!s_devtab || !s_dev_mux) return;
    xSemaphoreTake(s_dev_mux, portMAX_DELAY);
    uint32_t i = 0;
    while (i < len) {
        uint32_t j = i;
        while (j < len && buf[j] != '\n') j++;
        if (j > i) dev_upsert((const char *)(buf + i), (int)(j - i), scan, wall_ts);
        i = j + 1;
    }
    xSemaphoreGive(s_dev_mux);
}

#define ALOG_N   48
#define ALOG_LEN 72
typedef struct { int64_t us; char text[ALOG_LEN]; } alog_entry_t;
static alog_entry_t      s_alog[ALOG_N];
static volatile uint32_t s_alog_head, s_alog_count;
static portMUX_TYPE      s_alog_mux = portMUX_INITIALIZER_UNLOCKED;

static void alog(const char *fmt, ...)
{
    char tmp[ALOG_LEN];
    va_list ap; va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    for (char *p = tmp; *p; p++) if (*p == '"' || *p == '\\') *p = '\'';
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_alog_mux);
    uint32_t i = s_alog_head;
    s_alog[i].us = now;
    strlcpy(s_alog[i].text, tmp, ALOG_LEN);
    s_alog_head = (i + 1) % ALOG_N;
    if (s_alog_count < ALOG_N) s_alog_count++;
    portEXIT_CRITICAL(&s_alog_mux);
    ESP_LOGI(TAG, "alog: %s", tmp);
}

void master_cluster_log_json(char *buf, size_t buflen)
{
    portENTER_CRITICAL(&s_alog_mux);
    uint32_t n = s_alog_count, head = s_alog_head;
    portEXIT_CRITICAL(&s_alog_mux);
    int off = snprintf(buf, buflen, "{\"log\":[");
    for (uint32_t k = 0; k < n && off > 0 && off < (int)buflen; k++) {
        uint32_t idx = (head + ALOG_N - 1 - k) % ALOG_N;
        off += snprintf(buf + off, buflen - off, "%s{\"t\":%lld,\"s\":\"%s\"}",
                        k ? "," : "", (long long)(s_alog[idx].us / 1000000),
                        s_alog[idx].text);
    }
    if (off > 0 && off < (int)buflen) snprintf(buf + off, buflen - off, "]}");
}

static struct { bool online; uint32_t recs, flagged, windows; int64_t last_ok_us; } s_s3;

static char *s_sent_json;   static int s_sent_json_len;
static char *s_hits_json;   static int s_hits_json_len;
static char *s_tracker_json; static int s_tracker_json_len;

typedef struct { uint8_t mac[6]; uint8_t addr_type; uint8_t proto; } tsnd_target_t;
static volatile bool    s_tsnd_req;
static tsnd_target_t    s_tsnd_one;
static volatile uint8_t s_tsnd_action;

#define BURST_MAX 8
static tsnd_target_t    s_burst[BURST_MAX];
static volatile int     s_burst_n, s_burst_i;
static volatile bool    s_burst_active, s_burst_stop;
static int64_t          s_burst_next_us;
static SemaphoreHandle_t s_s3_mux;

#define HARVEST_MAX BURST_MAX
static tsnd_target_t    s_harvest[HARVEST_MAX];
static volatile int     s_harvest_n;

static char             s_cfg_pending[512];
static volatile int     s_cfg_pending_len;
static volatile bool    s_cfg_req;
static volatile uint32_t s_clock_pending;
static volatile bool    s_clock_req;

static volatile bool     s_loc_start_req, s_loc_stop_req;
static cl_locate_req_t   s_loc_pending;
static volatile bool     s_loc_active;
static cl_locate_state_t s_loc_best;

static void poll_s3(void)
{
    cl_getreq_t g; cl_getreq_build_cmd(&g, CL_CMD_STATUS_SEL, 0);
    if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&g, sizeof(g), 100) != ESP_OK) return;
    esp_rom_delay_us(CL_CHUNK_SETTLE_US);
    cl_status_t st;
    if (i2c_master_receive(s_s3_dev, (uint8_t *)&st, sizeof(st), 100) == ESP_OK
        && cl_status_valid(&st) && st.arm_index == CL_S3_ADDR) {
        s_s3.online   = true;
        s_s3.recs     = st.scanset_len;
        s_s3.flagged  = st.wifi_seen;
        s_s3.windows  = st.scan_seq;
        s_s3.last_ok_us = esp_timer_get_time();
    }
}

static int fetch_s3_blob(uint8_t cmd, char *dst, int cap)
{
    static cl_chunk_t ch;
    uint32_t off = 0, total = 0;
    for (;;) {
        cl_getreq_t g; cl_getreq_build_cmd(&g, cmd, off);
        if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&g, sizeof(g), 100) != ESP_OK) return -1;
        esp_rom_delay_us(CL_CHUNK_SETTLE_US);
        if (i2c_master_receive(s_s3_dev, (uint8_t *)&ch, sizeof(ch), 200) != ESP_OK) return -1;
        if (!cl_chunk_valid(&ch) || ch.offset != off) return -1;
        total = ch.total_len;
        if (ch.len && (int)(off + ch.len) < cap) memcpy(dst + off, ch.payload, ch.len);
        off += ch.len;
        if (ch.len == 0 || off >= total) break;
    }
    if ((int)off >= cap) off = cap - 1;
    dst[off] = '\0';
    return (int)off;
}

static void refresh_s3_blobs(void)
{
    static char tmp[6144];
    if (!s_sent_json || !s_hits_json) return;
    int n = fetch_s3_blob(CL_CMD_GET_SENT, tmp, sizeof tmp);
    if (n > 0 && xSemaphoreTake(s_s3_mux, portMAX_DELAY) == pdTRUE) {
        memcpy(s_sent_json, tmp, n + 1); s_sent_json_len = n; xSemaphoreGive(s_s3_mux);
    }
    n = fetch_s3_blob(CL_CMD_GET_HITS, tmp, sizeof tmp);
    if (n > 0 && xSemaphoreTake(s_s3_mux, portMAX_DELAY) == pdTRUE) {
        memcpy(s_hits_json, tmp, n + 1); s_hits_json_len = n; xSemaphoreGive(s_s3_mux);
    }
    n = fetch_s3_blob(CL_CMD_GET_TRACKER, tmp, sizeof tmp);
    if (n > 0 && s_tracker_json && xSemaphoreTake(s_s3_mux, portMAX_DELAY) == pdTRUE) {
        memcpy(s_tracker_json, tmp, n + 1); s_tracker_json_len = n; xSemaphoreGive(s_s3_mux);
    }
}

static void push_sentcfg_to_s3(const char *body, int n)
{
    static cl_chunk_t ch;
    uint32_t off = 0, total = (uint32_t)n;
    for (;;) {
        memset(&ch, 0, sizeof ch);
        ch.type = CL_PUT_SENTCFG; ch.scan_seq = 0; ch.total_len = total; ch.offset = off;
        uint16_t len = 0;
        if (off < total) {
            uint32_t rem = total - off;
            len = rem > CL_CHUNK_PAYLOAD ? CL_CHUNK_PAYLOAD : (uint16_t)rem;
            memcpy(ch.payload, body + off, len);
        }
        ch.len = len; cl_chunk_seal(&ch);
        if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&ch, sizeof(ch), 100) != ESP_OK) break;
        esp_rom_delay_us(CL_CHUNK_SETTLE_US);
        off += len;
        if (len == 0) break;
    }
}

static void push_clock_to_s3(uint32_t epoch)
{
    cl_getreq_t g; cl_getreq_build_cmd(&g, CL_CMD_SET_CLOCK, epoch);
    i2c_master_transmit(s_s3_dev, (const uint8_t *)&g, sizeof(g), 100);
}

static SemaphoreHandle_t s_ui_mux;
static cl_uiframe_t      s_ui_pending;
static volatile bool     s_ui_pending_req;
static QueueHandle_t     s_ui_evq;
static uint32_t          s_ui_ev_seq;
static bool              s_ui_ev_synced;

static bool              s_ui_have_frame;
static uint32_t          s_ui_pushes, s_ui_fail;

static void ui_frame_queue(const cl_uiframe_t *f)
{
    if (!s_ui_mux) return;
    if (xSemaphoreTake(s_ui_mux, pdMS_TO_TICKS(50)) != pdTRUE) return;
    memcpy(&s_ui_pending, f, sizeof s_ui_pending);
    s_ui_have_frame  = true;
    s_ui_pending_req = true;
    xSemaphoreGive(s_ui_mux);
}

static void ui_frame_refresh(void)
{
    if (s_ui_have_frame) s_ui_pending_req = true;
}

static void push_uiframe_to_s3(void)
{
    static cl_chunk_t ch;
    if (!s_ui_pending_req) return;
    if (xSemaphoreTake(s_ui_mux, pdMS_TO_TICKS(20)) != pdTRUE) return;
    memset(&ch, 0, sizeof ch);
    ch.type      = CL_PUT_UIFRAME;
    ch.total_len = sizeof(cl_uiframe_t);
    ch.len       = (uint16_t)sizeof(cl_uiframe_t);
    memcpy(ch.payload, &s_ui_pending, sizeof(cl_uiframe_t));
    s_ui_pending_req = false;
    xSemaphoreGive(s_ui_mux);

    cl_chunk_seal(&ch);
    if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&ch, sizeof(ch), 100) == ESP_OK)
        s_ui_pushes++;
    else
        s_ui_fail++;
    esp_rom_delay_us(CL_CHUNK_SETTLE_US);
}

static void poll_s3_uievent(void)
{
    cl_getreq_t g; cl_getreq_build_cmd(&g, CL_CMD_GET_UIEVENT, 0);
    if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&g, sizeof(g), 100) != ESP_OK) return;
    esp_rom_delay_us(CL_CHUNK_SETTLE_US);
    cl_uievent_t e;
    if (i2c_master_receive(s_s3_dev, (uint8_t *)&e, sizeof(e), 100) != ESP_OK) return;
    if (!cl_uievent_valid(&e)) return;

    if (!s_ui_ev_synced) { s_ui_ev_seq = e.seq; s_ui_ev_synced = true; return; }
    if (e.seq == s_ui_ev_seq || e.ev == CL_UI_EV_NONE) return;
    s_ui_ev_seq = e.seq;
    uint8_t ev = e.ev;
    xQueueSend(s_ui_evq, &ev, 0);
}

static void push_tracker_to_s3(const tsnd_target_t *t, uint8_t action)
{
    cl_tracker_sound_t req; memset(&req, 0, sizeof req);
    req.addr_type  = t->addr_type;
    req.action     = action;
    req.proto_hint = t->proto;
    memcpy(req.mac, t->mac, 6);
    cl_tracker_sound_seal(&req);
    i2c_master_transmit(s_s3_dev, (const uint8_t *)&req, sizeof(req), 100);
    esp_rom_delay_us(CL_CHUNK_SETTLE_US);
}

typedef enum { REQ_NONE = 0, REQ_SCAN, REQ_WALK, REQ_STOPWALK } req_t;
static volatile req_t s_req;
static bool s_walking;
static bool s_boot_scanned;
static bool s_rescan_once;
static volatile bool s_reset_req;
static volatile uint32_t s_epoch_base;

static volatile bool s_ap_want;
static bool          s_ap_autolaunch = true;

static int json_field(const char *b, int n, const char *pat, char *out, int outsz)
{
    int pl = (int)strlen(pat);
    for (int i = 0; i + pl <= n; i++) if (memcmp(b + i, pat, pl) == 0) {
        int k = i + pl, o = 0;
        while (k < n && b[k] != '"' && o < outsz - 1) out[o++] = b[k++];
        out[o] = '\0'; return o;
    }
    return 0;
}
static long json_int(const char *b, int n, const char *key, long dflt)
{
    char pat[24]; snprintf(pat, sizeof pat, "\"%s\":", key);
    int pl = (int)strlen(pat);
    for (int i = 0; i + pl <= n; i++) if (memcmp(b + i, pat, pl) == 0)
        return strtol(b + i + pl, NULL, 10);
    return dflt;
}

static bool parse_mac6(const char *s, uint8_t mac[6])
{
    int b = 0; unsigned v = 0, nib = 0;
    for (const char *p = s; *p && b < 6; p++) {
        int d = (*p >= '0' && *p <= '9') ? *p - '0'
              : (*p >= 'a' && *p <= 'f') ? *p - 'a' + 10
              : (*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 : -1;
        if (d < 0) continue;
        v = (v << 4) | (unsigned)d;
        if (++nib == 2) { mac[b++] = (uint8_t)v; v = 0; nib = 0; }
    }
    return b == 6;
}

void master_on_tracker_sound(const char *body, int n)
{
    char mac[24] = {0};
    json_field(body, n, "\"mac\":\"", mac, sizeof mac);
    tsnd_target_t t; memset(&t, 0, sizeof t);
    if (!parse_mac6(mac, t.mac)) return;
    t.addr_type   = (uint8_t)json_int(body, n, "addr_type", 1);
    t.proto       = (uint8_t)json_int(body, n, "proto", CL_TSND_PROTO_AUTO);
    s_tsnd_one    = t;
    s_tsnd_action = (uint8_t)json_int(body, n, "action", CL_TSND_START);
    s_tsnd_req    = true;
    alog("tracker sound requested");
}

void master_on_locate_start(const char *body, int n)
{
    char mac[24] = {0};
    if (json_field(body, n, "\"mac\":\"", mac, sizeof mac) <= 0) return;
    cl_locate_req_t r; memset(&r, 0, sizeof r);
    if (!parse_mac6(mac, r.mac)) return;
    r.kind    = (uint8_t)json_int(body, n, "kind", CL_LOCATE_BLE);
    r.channel = (uint8_t)json_int(body, n, "channel", 0);
    cl_locate_req_seal(&r);
    s_loc_pending   = r;
    s_loc_start_req = true;
    alog("locate start %s (%s)", mac, r.kind == CL_LOCATE_WIFI ? "wifi" : "ble");
}

void master_on_locate_stop(void)
{
    s_loc_stop_req = true;
    alog("locate stop");
}

void master_locate_json(char *buf, size_t cap)
{
    cl_locate_state_t s = s_loc_best;
    char mac[20];
    snprintf(mac, sizeof mac, "%02x:%02x:%02x:%02x:%02x:%02x",
             s.mac[0], s.mac[1], s.mac[2], s.mac[3], s.mac[4], s.mac[5]);
    snprintf(buf, cap,
        "{\"active\":%s,\"found\":%s,\"rssi\":%d,\"age_ds\":%u,\"samples\":%lu,"
        "\"channel\":%u,\"kind\":%u,\"mac\":\"%s\"}",
        s_loc_active ? "true" : "false", s.found ? "true" : "false", (int)s.rssi,
        (unsigned)s.age_ds, (unsigned long)s.samples, s.channel, s.kind, mac);
}

void master_on_tracker_burst(const char *body, int n)
{
    int count = 0;
    const char *p = body, *end = body + n;
    while (count < BURST_MAX) {
        const char *m = strstr(p, "\"mac\":\"");
        if (!m || m >= end) break;
        int wn = (int)(end - m);
        const char *brace = strchr(m, '}');
        if (brace && brace - m < wn) wn = (int)(brace - m);
        char mac[24] = {0};
        json_field(m, wn, "\"mac\":\"", mac, sizeof mac);
        tsnd_target_t t; memset(&t, 0, sizeof t);
        if (parse_mac6(mac, t.mac)) {
            t.addr_type = (uint8_t)json_int(m, wn, "addr_type", 1);
            t.proto     = (uint8_t)json_int(m, wn, "proto", CL_TSND_PROTO_AUTO);
            s_burst[count++] = t;
        }
        p = m + 7;
    }
    if (count == 0) return;
    s_burst_n = count; s_burst_i = 0;
    s_burst_stop = false; s_burst_next_us = 0; s_burst_active = true;
    alog("safety burst started");
}

void master_on_tracker_burst_stop(void)
{
    s_burst_stop = true;
    alog("safety burst stop");
}

void master_cluster_tracker_json(char *buf, size_t buflen)
{
    int off = snprintf(buf, buflen,
        "{\"burst\":{\"active\":%s,\"total\":%d,\"done\":%d},\"nearby\":[",
        s_burst_active ? "true" : "false", s_burst_n, s_burst_i);

    for (int i = 0; i < s_harvest_n && off > 0 && off < (int)buflen; i++)
        off += snprintf(buf + off, buflen - off,
            "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"at\":%u}",
            i ? "," : "",
            s_harvest[i].mac[0], s_harvest[i].mac[1], s_harvest[i].mac[2],
            s_harvest[i].mac[3], s_harvest[i].mac[4], s_harvest[i].mac[5],
            s_harvest[i].addr_type);
    if (off > 0 && off < (int)buflen) off += snprintf(buf + off, buflen - off, "],\"s3\":");
    bool served = false;
    if (xSemaphoreTake(s_s3_mux, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (s_tracker_json && s_tracker_json_len > 0 &&
            off + s_tracker_json_len + 2 < (int)buflen) {
            memcpy(buf + off, s_tracker_json, s_tracker_json_len);
            off += s_tracker_json_len; served = true;
        }
        xSemaphoreGive(s_s3_mux);
    }
    if (!served && off < (int)buflen)
        off += snprintf(buf + off, buflen - off, "{\"busy\":false,\"last\":\"none\",\"audit\":[]}");
    if (off < (int)buflen) snprintf(buf + off, buflen - off, "}");
}

void master_on_rescan_request(void)     { s_req = REQ_SCAN;  alog("scan started (WebAP)"); }
void master_on_walk_request(bool start) { s_req = start ? REQ_WALK : REQ_STOPWALK;
                                          alog("walk %s (WebAP)", start ? "started" : "stopped"); }

void master_on_epup_label(const char *label) { epup_brain_place_label(-1, label); alog("ePup place named"); }
void master_on_place_label(const char *body, int n)
{
    long idx = json_int(body, n, "idx", -1);
    char label[48] = {0};
    json_field(body, n, "\"label\":\"", label, sizeof label);
    if (idx < 0 || idx >= CL_PLACE_MAX) return;
    epup_brain_place_label((int)idx, label);
    alog("environment renamed");
}

void master_on_brain_reset(void) { s_reset_req = true; alog("brain HARD RESET requested"); }

void master_on_settime(uint32_t epoch)
{
    if (epoch < 1700000000UL) return;
    uint32_t up = (uint32_t)(esp_timer_get_time() / 1000000);
    s_epoch_base = epoch - up;
    s_clock_pending = epoch; s_clock_req = true;
}

void master_on_sentinel_cfg(const char *body, int n)
{
    if (n <= 0 || n >= (int)sizeof(s_cfg_pending)) return;
    memcpy(s_cfg_pending, body, n);
    s_cfg_pending[n] = '\0';
    s_cfg_pending_len = n;
    s_cfg_req = true;
    alog("sentinel config updated");
}

void master_cluster_sentinel_json(char *buf, size_t buflen)
{
    bool served = false;
    if (xSemaphoreTake(s_s3_mux, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (s_sent_json_len > 0 && s_sent_json_len < (int)buflen) {
            memcpy(buf, s_sent_json, s_sent_json_len + 1);
            served = true;
        }
        xSemaphoreGive(s_s3_mux);
    }
    if (!served)
        snprintf(buf, buflen, "{\"armed\":false,\"mask\":0,\"total\":0,\"recent\":0,\"seq\":0,"
                              "\"cats\":[],\"byoi\":[],\"last\":{\"label\":\"\",\"mac\":\"\"}}");
}

void master_cluster_hits_json(char *buf, size_t buflen)
{
    bool served = false;
    if (xSemaphoreTake(s_s3_mux, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (s_hits_json_len > 0 && s_hits_json_len < (int)buflen) {
            memcpy(buf, s_hits_json, s_hits_json_len + 1);
            served = true;
        }
        xSemaphoreGive(s_s3_mux);
    }
    if (!served)
        snprintf(buf, buflen, "{\"base\":%lu,\"hits\":[]}", (unsigned long)s_epoch_base);
}

void master_cluster_places_json(char *buf, size_t buflen)
{
    cl_places_t pl; epup_brain_places(&pl);
    if (!cl_places_valid(&pl)) { snprintf(buf, buflen, "{\"cur\":-1,\"places\":[]}"); return; }
    int off = snprintf(buf, buflen, "{\"cur\":%d,\"places\":[", pl.cur);
    for (int i = 0; i < pl.count && off > 0 && off < (int)buflen; i++) {
        const cl_place_entry_t *e = &pl.entries[i];
        char lbl[16]; strlcpy(lbl, e->label, sizeof lbl);
        off += snprintf(buf + off, buflen - off,
            "%s{\"idx\":%u,\"label\":\"%s\",\"scans\":%lu,\"landmarks\":%u,\"known\":%s,\"current\":%s}",
            i ? "," : "", e->idx, lbl, (unsigned long)e->scans, e->landmarks,
            (e->flags & CL_PLACE_F_KNOWN)   ? "true" : "false",
            (e->flags & CL_PLACE_F_CURRENT) ? "true" : "false");
    }
    if (off > 0 && off < (int)buflen) snprintf(buf + off, buflen - off, "]}");
}

#define INFRA_VIEW_MAX 48
void master_cluster_infra_json(char *buf, size_t buflen)
{
    static struct { uint64_t unit, sys; uint32_t radios, sightings; char ssid[24], bssid[18]; } u[INFRA_VIEW_MAX];
    int nu = 0, raw = 0;

    if (s_devtab && s_dev_mux && xSemaphoreTake(s_dev_mux, pdMS_TO_TICKS(80)) == pdTRUE) {
        for (int i = 0; i < s_dev_n; i++) {
            const dev_ent_t *d = &s_devtab[i];
            char type[24];
            if (!find_str(d->line, d->len, "\"type\":\"", type, sizeof type)) continue;
            if (strcmp(type, "wifi_ap") != 0) continue;
            char bssid[24], ssid[40], iehash[24];
            if (!find_str(d->line, d->len, "\"bssid\":\"", bssid, sizeof bssid)) continue;
            uint8_t mac[6];
            if (!infra_parse_mac(bssid, (int)strlen(bssid), mac)) continue;
            int sl = find_str(d->line, d->len, "\"ssid\":\"", ssid, sizeof ssid);
            uint32_t ieh = 0;
            if (find_str(d->line, d->len, "\"ie_pattern_hash\":", iehash, sizeof iehash))
                ieh = (uint32_t)strtoul(iehash, NULL, 10);
            uint64_t uk = infra_unit_key(mac, ieh);
            uint64_t sk = infra_system_key(mac, ssid, sl, ieh);
            raw++;
            int idx = -1;
            for (int k = 0; k < nu; k++) if (u[k].unit == uk) { idx = k; break; }
            if (idx < 0) {
                if (nu >= INFRA_VIEW_MAX) continue;
                idx = nu++;
                u[idx].unit = uk; u[idx].sys = sk; u[idx].radios = 0; u[idx].sightings = 0;
                u[idx].ssid[0] = '\0';
                strlcpy(u[idx].bssid, bssid, sizeof u[idx].bssid);
            }
            u[idx].radios++;
            u[idx].sightings += d->times_seen;
            if (u[idx].ssid[0] == '\0' && sl > 0) strlcpy(u[idx].ssid, ssid, sizeof u[idx].ssid);
        }
        xSemaphoreGive(s_dev_mux);
    }

    int off = snprintf(buf, buflen, "{\"units\":%d,\"radios\":%d,\"list\":[", nu, raw);
    for (int i = 0; i < nu && off > 0 && off < (int)buflen; i++) {
        char sesc[24]; strlcpy(sesc, u[i].ssid, sizeof sesc);
        for (char *p = sesc; *p; p++) if (*p == '"' || *p == '\\') *p = '\'';
        off += snprintf(buf + off, buflen - off,
            "%s{\"unit\":\"%08lx%08lx\",\"sys\":\"%08lx%08lx\",\"ssid\":\"%s\",\"bssid\":\"%s\","
            "\"radios\":%lu,\"sightings\":%lu}",
            i ? "," : "",
            (unsigned long)(u[i].unit >> 32), (unsigned long)(u[i].unit & 0xFFFFFFFF),
            (unsigned long)(u[i].sys >> 32), (unsigned long)(u[i].sys & 0xFFFFFFFF),
            sesc, u[i].bssid, (unsigned long)u[i].radios, (unsigned long)u[i].sightings);
    }
    if (off > 0 && off < (int)buflen) snprintf(buf + off, buflen - off, "]}");
}

void master_cluster_place_detail_json(int idx, char *buf, size_t buflen)
{
    epup_landmark_t lm[EPUP_LM_MAX];
    int n = epup_brain_place_detail(idx, lm, EPUP_LM_MAX);
    int off = snprintf(buf, buflen, "{\"idx\":%d,\"quality\":%d,\"landmarks\":[",
                       idx, epup_brain_place_quality(idx));
    for (int i = 0; i < n && off > 0 && off < (int)buflen; i++) {
        char nm[24]; strlcpy(nm, lm[i].name, sizeof nm);
        for (char *p = nm; *p; p++) if (*p == '"' || *p == '\\') *p = '\'';
        off += snprintf(buf + off, buflen - off,
            "%s{\"unit\":\"%08lx%08lx\",\"name\":\"%s\",\"hits\":%u,\"scans\":%u,"
            "\"pinned\":%s,\"confirmed\":%s}",
            i ? "," : "",
            (unsigned long)(lm[i].unit >> 32), (unsigned long)(lm[i].unit & 0xFFFFFFFF),
            nm, lm[i].hits, lm[i].scans_seen,
            (lm[i].flags & EPUP_LM_PINNED)    ? "true" : "false",
            (lm[i].flags & EPUP_LM_CONFIRMED) ? "true" : "false");
    }
    if (off > 0 && off < (int)buflen) snprintf(buf + off, buflen - off, "]}");
}

void master_on_landmark_edit(const char *body, int n)
{
    long idx = json_int(body, n, "idx", -1);
    char op[16] = {0}, unit[24] = {0};
    json_field(body, n, "\"op\":\"", op, sizeof op);
    json_field(body, n, "\"unit\":\"", unit, sizeof unit);
    uint64_t u = (uint64_t)strtoull(unit, NULL, 16);
    if (idx < 0) return;
    if      (!strcmp(op, "pin"))    epup_brain_landmark_pin((int)idx, u, true);
    else if (!strcmp(op, "unpin"))  epup_brain_landmark_pin((int)idx, u, false);
    else if (!strcmp(op, "delete")) epup_brain_landmark_delete((int)idx, u);
    else if (!strcmp(op, "forget")) epup_brain_place_delete((int)idx);
    alog("environment edited");
}

void master_on_learn(const char *body, int n)
{
    if (json_int(body, n, "cancel", 0)) { epup_brain_learn_cancel(); alog("learn cancelled"); return; }
    int scans = (int)json_int(body, n, "scans", 3);
    bool reposition = json_int(body, n, "reposition", 1) != 0;
    bool fresh      = json_int(body, n, "fresh", 1) != 0;
    epup_brain_learn_start(scans, reposition, fresh);
    alog("learning environment (%d scans)", scans);
}

void master_cluster_status_json(char *buf, size_t buflen)
{
    int64_t now = esp_timer_get_time();
    capture_ring_stats_t rs; capture_ring_get_stats(&rs);
    int off = snprintf(buf, buflen, "{\"arms\":[");
    for (int i = 0; i < N_ARMS && off > 0 && off < (int)buflen; i++) {
        bool fresh = s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL;
        long age_ms = s_link[i].ok ? (long)((now - s_link[i].last_ok_us) / 1000) : -1;
        off += snprintf(buf + off, buflen - off,
            "%s{\"i\":%u,\"band\":\"%s\",\"online\":%s,\"state\":%u,\"wifi\":%u,\"ble\":%u,\"seq\":%lu,"
            "\"age_ms\":%ld,\"ok\":%lu,\"polls\":%lu,\"planned\":%s}",
            i ? "," : "", ARMS[i].index, ARMS[i].band, fresh ? "true" : "false",
            s_link[i].last.state, s_link[i].last.wifi_seen, s_link[i].last.ble_seen,
            (unsigned long)s_link[i].last_ingest_seq,
            age_ms, (unsigned long)s_link[i].ok, (unsigned long)s_link[i].polls,
            s_link[i].planned ? "true" : "false");
    }
    if (off < 0 || off >= (int)buflen) off = (int)buflen - 1;

    off += snprintf(buf + off, buflen - off,
                    "],\"brain\":{\"addr\":%u,\"online\":true,\"age_ms\":0,\"ok\":%lu,\"polls\":%lu},"
                    "\"walking\":%s,\"recs\":%u,\"ckpt\":\"%s\"",
                    CL_BRAIN_ADDR, (unsigned long)s_merge_count, (unsigned long)s_merge_count,
                    s_walking ? "true" : "false", (unsigned)rs.records_current, FW_CKPT);
    epup_summary_t ep; epup_brain_get(&ep);
    epup_learn_t lrn; epup_brain_learn_status(&lrn);
    if (off > 0 && off < (int)buflen) {
        off += snprintf(buf + off, buflen - off,
            ",\"epup\":{\"title\":\"%s\",\"level\":%lu,\"confidence\":%u,\"scans\":%lu,"
            "\"unique\":%lu,\"wifi\":%u,\"ble\":%u,\"new\":%u,\"ema\":%u,\"boots\":%lu,"
            "\"place\":{\"cur\":%d,\"count\":%u,\"sim\":%u,\"known\":%s,\"is_new\":%s,"
            "\"scans\":%lu,\"label\":\"%s\"},"
            "\"learn\":{\"active\":%s,\"want\":%u,\"done\":%u,\"reposition\":%s}}",
            epup_title_label((epup_title_t)ep.title), (unsigned long)ep.level,
            ep.confidence, (unsigned long)ep.total_scans,
            (unsigned long)ep.unique_est, ep.last_wifi, ep.last_ble,
            ep.last_new, ep.ema_total,
            (unsigned long)(ep.boot_now >= ep.born_boot ? ep.boot_now - ep.born_boot + 1 : 1),
            ep.place_cur, ep.place_count, ep.place_sim,
            (ep.place_flags & EPUP_PLACE_KNOWN) ? "true" : "false",
            (ep.place_flags & EPUP_PLACE_NEW) ? "true" : "false",
            (unsigned long)ep.place_scans, ep.place_label,
            lrn.active ? "true" : "false", lrn.want, lrn.done,
            lrn.reposition ? "true" : "false");
    }
    if (off < 0 || off >= (int)buflen) off = (int)buflen - 1;

    bool s3on = s_s3.online && (now - s_s3.last_ok_us) < 3000000LL;
    off += snprintf(buf + off, buflen - off,
             ",\"sd\":{\"ok\":%s,\"full\":false,\"gb\":0.0,\"free_gb\":0.0,\"recs\":%u,\"kb\":0}",
             s3on ? "true" : "false", (unsigned)s_s3.recs);
    if (off < 0 || off >= (int)buflen) off = (int)buflen - 1;

    snprintf(buf + off, buflen - off,
             ",\"health\":{\"up\":%lld,\"heap\":%u,\"merges\":%lu,\"s3push\":%lu,\"s3fail\":%lu,"
             "\"busrst\":%lu,\"s3\":{\"online\":%s,\"up\":%lld,\"recs\":%lu,\"flagged\":%lu,\"windows\":%lu}}}",
             (long long)(now / 1000000), (unsigned)esp_get_free_heap_size(),
             (unsigned long)s_merge_count, (unsigned long)s_s3_pushes, (unsigned long)s_s3_fail,
             (unsigned long)s_bus_resets, s3on ? "true" : "false",
             (long long)(s3on ? (now - s_s3.last_ok_us) / 1000000 : -1),
             (unsigned long)s_s3.recs, (unsigned long)s_s3.flagged, (unsigned long)s_s3.windows);
}

uint32_t master_cluster_merge_count(void) { return s_merge_count; }
const char *master_cluster_session_id(void) { return s_sess_id; }
int master_cluster_device_count(void) { return s_dev_n; }

int master_cluster_device_json(int idx, uint32_t since, char *buf, size_t buflen)
{
    if (!s_devtab || !s_dev_mux || idx < 0 || idx >= s_dev_n) return 0;
    int out = 0;
    xSemaphoreTake(s_dev_mux, portMAX_DELAY);
    dev_ent_t *e = &s_devtab[idx];
    if (e->len > 2 && e->last_scan > since) {
        int body = e->len;
        while (body > 0 && (e->line[body - 1] == ' ' ||
                            e->line[body - 1] == '\n' || e->line[body - 1] == '\r')) body--;
        if (body > 0 && e->line[body - 1] == '}') body--;
        if (body > 0 && body < (int)buflen) {
            memcpy(buf, e->line, body);
            out = body;
            out += snprintf(buf + out, buflen - out,
                ",\"scan_index\":%lu,\"first_scan\":%lu,\"last_scan\":%lu,\"seen\":%lu",
                (unsigned long)e->last_scan, (unsigned long)e->first_scan,
                (unsigned long)e->last_scan, (unsigned long)e->times_seen);
            if (e->last_ts)
                out += snprintf(buf + out, buflen - out, ",\"ts\":%lu", (unsigned long)e->last_ts);
            if (out < (int)buflen - 1) buf[out++] = '}';
            buf[out < (int)buflen ? out : (int)buflen - 1] = '\0';
            if (out >= (int)buflen) out = 0;
        }
    }
    xSemaphoreGive(s_dev_mux);
    return out;
}

static void i2c_master_setup(void)
{
    i2c_master_bus_config_t bus_cfg = {
        .i2c_port          = CL_I2C_PORT,
        .sda_io_num        = CL_I2C_SDA_GPIO,
        .scl_io_num        = CL_I2C_SCL_GPIO,
        .clk_source        = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_cfg, &s_bus));
    for (int i = 0; i < N_ARMS; i++) {
        i2c_device_config_t dc = {
            .dev_addr_length = I2C_ADDR_BIT_LEN_7,
            .device_address  = ARMS[i].addr,
            .scl_speed_hz    = BRAIN_I2C_HZ,
        };
        ESP_ERROR_CHECK(i2c_master_bus_add_device(s_bus, &dc, &s_dev[i]));
    }
    i2c_device_config_t s3c = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address  = CL_S3_ADDR,
        .scl_speed_hz    = BRAIN_I2C_HZ,
    };
    ESP_ERROR_CHECK(i2c_master_bus_add_device(s_bus, &s3c, &s_s3_dev));
    ESP_LOGI(TAG, "I2C master up: SDA=%d SCL=%d @%luHz arms 0x%02x/0x%02x S3 0x%02x",
             CL_I2C_SDA_GPIO, CL_I2C_SCL_GPIO, (unsigned long)BRAIN_I2C_HZ,
             CL_ARM1_ADDR, CL_ARM2_ADDR, CL_S3_ADDR);
}

static void push_merge_to_s3(void)
{
    static cl_chunk_t ch;
    uint32_t off = 0, total = s_merge_len;
    bool ok = true;

    for (;;) {
        memset(&ch, 0, sizeof(ch));
        ch.type      = CL_PUT_S3MERGE;
        ch.scan_seq  = s_merge_count;
        ch.total_len = total;
        ch.offset    = off;
        uint16_t len = 0;
        if (s_merge_buf && off < total) {
            uint32_t rem = total - off;
            len = rem > CL_CHUNK_PAYLOAD ? CL_CHUNK_PAYLOAD : (uint16_t)rem;
            memcpy(ch.payload, s_merge_buf + off, len);
        }
        ch.len = len;
        cl_chunk_seal(&ch);
        if (i2c_master_transmit(s_s3_dev, (const uint8_t *)&ch, sizeof(ch), 100) != ESP_OK) {
            ok = false; break;
        }
        esp_rom_delay_us(CL_CHUNK_SETTLE_US);
        off += len;
        if (len == 0) break;
    }
    if (ok) s_s3_pushes++; else s_s3_fail++;
}

static void arm_broadcast(cl_cmd_t cmd, uint8_t arg)
{
    cl_cmd_frame_t f; cl_cmd_build(&f, cmd, arg);
    for (int i = 0; i < N_ARMS; i++)
        i2c_master_transmit(s_dev[i], (const uint8_t *)&f, sizeof(f), 100);
}

static bool send_plan(int i)
{
    cl_plan_t p = {
        .n_arms       = N_ARMS,
        .arm_slot     = (uint8_t)i,
        .dwell_ms     = BRAIN_PLAN_DWELL_LITE,
        .dwell_adv_ms = BRAIN_PLAN_DWELL_ADV,
        .ble_every_n  = BRAIN_PLAN_BLE_EVERY_N,
        .flags        = CL_PLAN_FLAG_DFS,
    };
    cl_plan_seal(&p);
    bool ok = i2c_master_transmit(s_dev[i], (const uint8_t *)&p, sizeof(p), 100) == ESP_OK;
    ESP_LOGI(TAG, "SET_PLAN -> arm%d: slot %d/%d dwell %d/%d ble_n=%d %s",
             ARMS[i].index, i, N_ARMS, BRAIN_PLAN_DWELL_LITE, BRAIN_PLAN_DWELL_ADV,
             BRAIN_PLAN_BLE_EVERY_N, ok ? "ok" : "FAIL");
    return ok;
}

static bool ingest_arm(int i, uint32_t seq)
{
    static cl_chunk_t ch;
    arm_slot_t *a = &s_arm[i];
    uint32_t off = 0, total = 0;
    int64_t t0 = esp_timer_get_time();

    do {
        cl_getreq_t g; cl_getreq_build(&g, off);
        if (i2c_master_transmit(s_dev[i], (const uint8_t *)&g, sizeof(g), 100) != ESP_OK)
            return false;
        esp_rom_delay_us(CL_CHUNK_SETTLE_US);
        if (i2c_master_receive(s_dev[i], (uint8_t *)&ch, sizeof(ch), 200) != ESP_OK)
            return false;
        if (!cl_chunk_valid(&ch) || ch.scan_seq != seq || ch.offset != off)
            return false;
        total = ch.total_len;
        if (ch.len && a->buf && (uint32_t)off + ch.len <= BRAIN_ARM_CAP)
            memcpy(a->buf + off, ch.payload, ch.len);
        off += ch.len;
        if (ch.len == 0) break;
    } while (off < total);

    uint32_t recs = 0;
    for (uint32_t k = 0; k < off; k++) if (a->buf[k] == '\n') recs++;
    a->len  = off;
    a->recs = recs;
    a->have = true;

    uint32_t wall_ts = s_epoch_base
        ? (uint32_t)(s_epoch_base + esp_timer_get_time() / 1000000) : 0;
    ring_feed_scanset(a->buf, off, wall_ts);
    ESP_LOGI(TAG, "ingest arm%d seq=%lu: %lu bytes, %lu recs, %lldms",
             ARMS[i].index, (unsigned long)seq, (unsigned long)off,
             (unsigned long)recs, (long long)(esp_timer_get_time() - t0) / 1000);
    return true;
}

static bool blk_contains(const char *b, int n, const char *pat)
{
    int pl = (int)strlen(pat);
    for (int i = 0; i + pl <= n; i++) if (memcmp(b + i, pat, pl) == 0) return true;
    return false;
}

static void harvest_tracker_line(const char *line, int n)
{
    if (!blk_contains(line, n, "\"type\":\"tracker\"")) return;
    if (blk_contains(line, n, "\"tracker_kind\":\"tile\"")) return;

    if (blk_contains(line, n, "\"tracker_kind\":\"find_my_maintained\"")) return;
    char mac[24] = {0};
    if (json_field(line, n, "\"addr\":\"", mac, sizeof mac) <= 0) return;
    tsnd_target_t t; memset(&t, 0, sizeof t);
    if (!parse_mac6(mac, t.mac)) return;
    t.addr_type = (uint8_t)json_int(line, n, "addr_type", 1);
    t.proto     = CL_TSND_PROTO_AUTO;
    for (int i = 0; i < s_harvest_n; i++)
        if (memcmp(s_harvest[i].mac, t.mac, 6) == 0) { s_harvest[i] = t; return; }
    if (s_harvest_n < HARVEST_MAX) s_harvest[s_harvest_n++] = t;
    else {
        memmove(&s_harvest[0], &s_harvest[1], (HARVEST_MAX - 1) * sizeof(tsnd_target_t));
        s_harvest[HARVEST_MAX - 1] = t;
    }
}

static void harvest_from_merge(const uint8_t *buf, uint32_t len)
{
    uint32_t i = 0;
    while (i < len) {
        uint32_t j = i;
        while (j < len && buf[j] != '\n') j++;
        if (j > i) harvest_tracker_line((const char *)(buf + i), (int)(j - i));
        i = j + 1;
    }
}

static void merge_window(void)
{
    do_merge();

    uint32_t wall_ts = s_epoch_base
        ? (uint32_t)(s_epoch_base + esp_timer_get_time() / 1000000) : 0;
    dev_table_ingest(s_merge_buf, s_merge_len, s_merge_count, wall_ts);
    harvest_from_merge(s_merge_buf, s_merge_len);
    ESP_LOGI(TAG, "MERGE #%lu: %lu uniq, %lu dup, %lu bytes (arm1=%lu arm2=%lu recs) devtab=%d/%d evict=%lu",
             (unsigned long)s_merge_count, (unsigned long)s_merge_uniq,
             (unsigned long)s_merge_dup, (unsigned long)s_merge_len,
             (unsigned long)s_arm[0].recs, (unsigned long)s_arm[1].recs,
             s_dev_n, DEV_MAX, (unsigned long)s_dev_evict);
    epup_brain_observe((const char *)s_merge_buf, s_merge_len);

    push_merge_to_s3();

    s_arm[0].have = s_arm[1].have = false;
}

static void poll_arm(int i)
{
    arm_link_t *L = &s_link[i];
    cl_status_t st;
    int64_t now = esp_timer_get_time();

    if (L->planned && L->ok && (now - L->last_ok_us) > 3000000LL) L->planned = false;
    L->polls++;
    if (i2c_master_receive(s_dev[i], (uint8_t *)&st, sizeof(st), 100) == ESP_OK
        && cl_status_valid(&st)) {
        L->last = st; L->ok++; L->last_ok_us = esp_timer_get_time();
        if (!L->planned && send_plan(i)) L->planned = true;
        if (st.scanset_ready && st.scanset_len > 0 && st.scan_seq != L->last_ingest_seq) {
            if (ingest_arm(i, st.scan_seq)) L->last_ingest_seq = st.scan_seq;
        }
    }
}

static inline bool bus_line_stuck(void)
{
    return gpio_get_level(CL_I2C_SDA_GPIO) == 0 || gpio_get_level(CL_I2C_SCL_GPIO) == 0;
}

static void bus_health_check(void)
{
    if (!bus_line_stuck()) return;
    esp_rom_delay_us(50);
    if (!bus_line_stuck()) return;
    int sda = gpio_get_level(CL_I2C_SDA_GPIO), scl = gpio_get_level(CL_I2C_SCL_GPIO);
    esp_err_t e = i2c_master_bus_reset(s_bus);
    s_bus_resets++;
    ESP_LOGW(TAG, "I2C bus wedged (SDA=%d SCL=%d) -> bus_reset #%lu: %s",
             sda, scl, (unsigned long)s_bus_resets, esp_err_to_name(e));
}

static void bus_task(void *arg)
{
    (void)arg;
    bool arm_was_online[N_ARMS] = { false };
    bool scan_inflight = false;

    for (;;) {
        bus_health_check();

        for (int i = 0; i < N_ARMS; i++) poll_arm(i);
        poll_s3();

        if (s_cfg_req) {
            s_cfg_req = false;
            push_sentcfg_to_s3(s_cfg_pending, s_cfg_pending_len);
            refresh_s3_blobs();
        }
        if (s_clock_req) { s_clock_req = false; push_clock_to_s3(s_clock_pending); }

        if (s_tsnd_req) {
            s_tsnd_req = false;
            push_tracker_to_s3(&s_tsnd_one, s_tsnd_action);
            refresh_s3_blobs();
        }

        if (s_loc_start_req) {
            s_loc_start_req = false;
            for (int i = 0; i < N_ARMS; i++)
                i2c_master_transmit(s_dev[i], (const uint8_t *)&s_loc_pending,
                                    sizeof(s_loc_pending), 100);
            memset((void *)&s_loc_best, 0, sizeof(s_loc_best));
            s_loc_active = true;
        }
        if (s_loc_stop_req) {
            s_loc_stop_req = false;
            cl_cmd_frame_t f; cl_cmd_build(&f, CL_CMD_STOP_LOCATE, 0);
            for (int i = 0; i < N_ARMS; i++)
                i2c_master_transmit(s_dev[i], (const uint8_t *)&f, sizeof(f), 100);
            s_loc_active = false;
        }
        if (s_loc_active) {
            cl_locate_state_t best; memset(&best, 0, sizeof best); bool have = false;
            for (int i = 0; i < N_ARMS; i++) {
                cl_cmd_frame_t g; cl_cmd_build(&g, CL_CMD_GET_LOCATE, 0);
                if (i2c_master_transmit(s_dev[i], (const uint8_t *)&g, sizeof(g), 100) != ESP_OK)
                    continue;
                cl_locate_state_t ls;
                if (i2c_master_receive(s_dev[i], (uint8_t *)&ls, sizeof(ls), 100) != ESP_OK)
                    continue;
                if (!cl_locate_state_valid(&ls)) continue;
                if (!have) { best = ls; have = true; }
                else if (ls.found && (!best.found || ls.age_ds < best.age_ds ||
                         (ls.age_ds == best.age_ds && ls.rssi > best.rssi)))
                    best = ls;
            }
            if (have) s_loc_best = best;
        }
        if (s_burst_active) {
            int64_t bnow = esp_timer_get_time();
            if (s_burst_stop || s_burst_i >= s_burst_n) {
                if (s_burst_stop) push_tracker_to_s3(&s_burst[0], CL_TSND_CANCEL);
                s_burst_active = false;
            } else if (bnow >= s_burst_next_us) {
                push_tracker_to_s3(&s_burst[s_burst_i], CL_TSND_START);
                s_burst_i++;
                s_burst_next_us = bnow + 6000000LL;
                refresh_s3_blobs();
            }
        }
        {
            static int64_t last_blob_us;
            int64_t bnow = esp_timer_get_time();
            if (bnow - last_blob_us >= 1000000LL) { last_blob_us = bnow; refresh_s3_blobs(); }
        }

        push_uiframe_to_s3();
        {
            static int64_t last_uiev_us, last_uirep_us;
            int64_t bnow = esp_timer_get_time();
            if (bnow - last_uiev_us >= 300000LL) { last_uiev_us = bnow; poll_s3_uievent(); }
            if (bnow - last_uirep_us >= 3000000LL) { last_uirep_us = bnow; ui_frame_refresh(); }
        }

        if (s_reset_req) {
            s_reset_req = false;
            ESP_LOGW(TAG, "HARD RESET (WebAP): wiping model + place memory, restarting");
            epup_brain_reset();
            vTaskDelay(pdMS_TO_TICKS(150));
            esp_restart();
        }

        req_t req = s_req; s_req = REQ_NONE;
        if      (req == REQ_WALK)     s_walking = true;
        else if (req == REQ_STOPWALK) s_walking = false;
        else if (req == REQ_SCAN)     s_rescan_once = true;

        int64_t now = esp_timer_get_time();

        int online = 0;
        for (int i = 0; i < N_ARMS; i++) {
            bool on = s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL;
            if (on) online++;
            if (on != arm_was_online[i]) {
                ESP_LOGI(TAG, "arm %u %s", ARMS[i].index, on ? "online" : "went offline");
                arm_was_online[i] = on;
            }
        }

        if (s_arm[0].have && s_arm[1].have) {
            merge_window();
            scan_inflight = false;
            if (!s_walking) s_rescan_once = false;
        }

        bool want_scan = !s_boot_scanned || s_walking || s_rescan_once;
        if (want_scan && online == N_ARMS && !scan_inflight && !s_loc_active &&
            !(s_arm[0].have || s_arm[1].have)) {
            const char *why = !s_boot_scanned ? "boot" : s_walking ? "walk" : "rescan";
            ESP_LOGI(TAG, "LINK %d/%d -> broadcast SCAN (adv) [%s]", online, N_ARMS, why);
            arm_broadcast(CL_CMD_SCAN, CL_SCAN_ADV);
            scan_inflight = true;
            s_boot_scanned = true;
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

static int arms_online(void)
{
    int online = 0;
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < N_ARMS; i++)
        if (s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL) online++;
    return online;
}

static void status_line(char *out, size_t cap)
{
    snprintf(out, cap, "LINK%d/%d m#%lu SD%lu", arms_online(), N_ARMS,
             (unsigned long)s_merge_count, (unsigned long)s_s3.recs);
}

static void s3_ui_line(int idx, char *out, size_t cap)
{
    char key[8];
    snprintf(key, sizeof key, "\"ui%d\":\"", idx);
    out[0] = '\0';
    if (xSemaphoreTake(s_s3_mux, pdMS_TO_TICKS(50)) != pdTRUE) return;
    if (s_sent_json && s_sent_json_len > 0) {
        const char *p = strstr(s_sent_json, key);
        if (p) {
            p += strlen(key);
            size_t n = 0;
            while (p[n] && p[n] != '"' && n < cap - 1) n++;
            memcpy(out, p, n);
            out[n] = '\0';
        }
    }
    xSemaphoreGive(s_s3_mux);
}

static void log_task(void *arg)
{
    (void)arg;
    int64_t last_log = 0;
    for (;;) {
        int64_t now = esp_timer_get_time();
        if (now - last_log >= 2000000LL) {
            last_log = now;
            int online = 0;
            for (int i = 0; i < N_ARMS; i++)
                if (s_link[i].ok && (now - s_link[i].last_ok_us) < 1500000LL) online++;
            epup_summary_t ep; epup_brain_get(&ep);
            ESP_LOGI(TAG, "BRAIN-MASTER [%s] up=%llds LINK %d/%d (a1=%s a2=%s) merge#%lu(%luuq %ludp) S3push=%lu/%lu UI=%lu/%lu busrst=%lu ePup:%s L%lu %lu%% scans=%lu uniq~%lu",
                     FW_CKPT, (long long)(now / 1000000), online, N_ARMS,
                     s_link[0].ok && (now-s_link[0].last_ok_us)<1500000LL ? "OK":"--",
                     s_link[1].ok && (now-s_link[1].last_ok_us)<1500000LL ? "OK":"--",
                     (unsigned long)s_merge_count, (unsigned long)s_merge_uniq,
                     (unsigned long)s_merge_dup,
                     (unsigned long)s_s3_pushes, (unsigned long)s_s3_fail,
                     (unsigned long)s_ui_pushes, (unsigned long)s_ui_fail,
                     (unsigned long)s_bus_resets,
                     epup_title_label((epup_title_t)ep.title), (unsigned long)ep.level,
                     (unsigned long)ep.confidence, (unsigned long)ep.total_scans,
                     (unsigned long)ep.unique_est);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

static void web_task(void *arg)
{
    (void)arg;

    httpd_handle_t registered = NULL;
    for (;;) {
        bool active = download_mode_is_active();
        if (s_ap_want && !active)       download_mode_request_enable();
        else if (!s_ap_want && active)  download_mode_request_disable(CAP_END_USER_DISABLE);

        httpd_handle_t sv = download_http_server();
        if (sv && sv != registered) {
            if (cluster_web_start(sv) == ESP_OK) {
                registered = sv;
                alog("WebAP up at 192.168.4.1");
                ESP_LOGI(TAG, "WebAP up — dashboard at http://192.168.4.1/");
            }
        } else if (!sv) {
            registered = NULL;
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

#define BRAIN_PIN_BOOT      28
#define BRAIN_LONG_HOLD_MS  2500
#define BRAIN_DBL_GAP_MS    450

typedef enum { BEV_NONE = 0, BEV_SINGLE, BEV_DOUBLE, BEV_LONG } bev_t;
typedef enum {
    MSCR_MAIN = 0, MSCR_AP, MSCR_AP_LIVE, MSCR_WALK, MSCR_SENTINEL, MSCR_HOWL, MSCR_RESCAN,
    MSCR_S3
} mscr_t;

static mscr_t   s_mscr = MSCR_MAIN;
static int      s_msel;
static bool     s_sent_armed = true;
static uint32_t s_rescan_base_merge;
static int      s_rescan_ticks;

static void ap_autolaunch_load(void)
{
    nvs_handle_t h;
    if (nvs_open("brain", NVS_READONLY, &h) == ESP_OK) {
        uint8_t v = 1;
        if (nvs_get_u8(h, "ap_auto", &v) == ESP_OK) s_ap_autolaunch = (v != 0);
        nvs_close(h);
    }
}
static void ap_autolaunch_save(void)
{
    nvs_handle_t h;
    if (nvs_open("brain", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, "ap_auto", s_ap_autolaunch ? 1 : 0);
        nvs_commit(h);
        nvs_close(h);
    }
}

static void sentinel_sync_shadow(void)
{
    if (xSemaphoreTake(s_s3_mux, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (s_sent_json && s_sent_json_len > 0) {
            if (blk_contains(s_sent_json, s_sent_json_len, "\"armed\":true"))       s_sent_armed = true;
            else if (blk_contains(s_sent_json, s_sent_json_len, "\"armed\":false")) s_sent_armed = false;
        }
        xSemaphoreGive(s_s3_mux);
    }
}
static void sentinel_set_armed(bool on)
{
    const char *b = on ? "{\"armed\":1}" : "{\"armed\":0}";
    master_on_sentinel_cfg(b, (int)strlen(b));
    alog("sentinel %s (device)", on ? "armed" : "disarmed");
}

static void howl_start(void)
{
    if (s_harvest_n <= 0) { alog("Howl: no trackers nearby"); return; }
    int n = s_harvest_n < BURST_MAX ? s_harvest_n : BURST_MAX;
    for (int i = 0; i < n; i++) s_burst[i] = s_harvest[i];
    s_burst_n = n; s_burst_i = 0; s_burst_stop = false; s_burst_next_us = 0;
    s_burst_active = true;
    alog("Howl started (device): %d tracker(s)", n);
}
static void howl_stop(void) { s_burst_stop = true; alog("Howl stop (device)"); }

static int menu_count(mscr_t s)
{
    switch (s) {
    case MSCR_MAIN:                                        return 5;
    case MSCR_AP:                                          return 3;
    case MSCR_WALK: case MSCR_SENTINEL: case MSCR_HOWL:    return 2;
    default:                                              return 0;
    }
}

static void menu_compose(cl_uiframe_t *f)
{
    char l0[CL_UI_ITEM], l1[CL_UI_ITEM], extra[CL_UI_EXTRA];

    switch (s_mscr) {
    case MSCR_MAIN:
        cl_ui_frame_reset(f, CL_UI_SCR_MENU, "SNIFFCHECK BRAIN", "1:next  2:select");
        cl_ui_frame_item(f, "AP");
        cl_ui_frame_item(f, "Walk");
        cl_ui_frame_item(f, "Sentinel");
        cl_ui_frame_item(f, "Rescan");
        cl_ui_frame_item(f, "S3");
        f->sel = (int8_t)s_msel;
        return;

    case MSCR_AP:
        cl_ui_frame_reset(f, CL_UI_SCR_MENU, "AP", "2:sel  hold:back");
        snprintf(l0, sizeof l0, "%s", s_ap_want ? "Stop AP" : "Start AP");
        snprintf(l1, sizeof l1, "Auto-Launch:%s", s_ap_autolaunch ? "ON" : "OFF");
        cl_ui_frame_item(f, l0);
        cl_ui_frame_item(f, l1);
        cl_ui_frame_item(f, "QR");
        f->sel = (int8_t)s_msel;
        return;

    case MSCR_AP_LIVE: {

        bool joined = download_mode_get_client_count() > 0;
        const char *ssid = download_mode_get_ssid();
        const char *pass = download_mode_get_passphrase();
        cl_ui_frame_reset(f, CL_UI_SCR_QR, "BRAIN AP", "hold: back");
        if (joined) {
            snprintf(f->qr, CL_UI_QR, "http://192.168.4.1/");
            cl_ui_frame_item(f, "scan to open");
            cl_ui_frame_item(f, "192.168.4.1");
        } else {
            snprintf(f->qr, CL_UI_QR, "WIFI:T:WPA2;S:%s;P:%s;;", ssid, pass);
            cl_ui_frame_item(f, ssid);
            cl_ui_frame_item(f, pass);
        }
        cl_ui_frame_item(f, FW_CKPT);
        status_line(extra, sizeof extra);
        cl_ui_frame_extra(f, extra, 0);
        return;
    }

    case MSCR_WALK:
        cl_ui_frame_reset(f, CL_UI_SCR_MENU, "WALK", "2:sel  hold:back");
        cl_ui_frame_item(f, "Start Walk");
        cl_ui_frame_item(f, "Stop Walk");
        f->sel = (int8_t)s_msel;
        snprintf(extra, sizeof extra, "%s arms %d/%d m#%lu",
                 s_walking ? "WALKING" : "stopped", arms_online(), N_ARMS,
                 (unsigned long)s_merge_count);
        cl_ui_frame_extra(f, extra, s_walking ? 1 : 0);
        return;

    case MSCR_SENTINEL:
        cl_ui_frame_reset(f, CL_UI_SCR_MENU, "SENTINEL", "2:sel  hold:back");
        snprintf(l0, sizeof l0, "Sentinel: %s", s_sent_armed ? "ON" : "OFF");
        cl_ui_frame_item(f, l0);
        cl_ui_frame_item(f, "Howl");
        f->sel = (int8_t)s_msel;
        return;

    case MSCR_HOWL:
        cl_ui_frame_reset(f, CL_UI_SCR_MENU, "HOWL", "2:sel  hold:back");
        cl_ui_frame_item(f, "Start Howl");
        cl_ui_frame_item(f, "Stop Howl");
        f->sel = (int8_t)s_msel;
        snprintf(extra, sizeof extra, "%d nearby  ring %d/%d",
                 s_harvest_n, s_burst_i, s_burst_n);
        cl_ui_frame_extra(f, extra, s_burst_active ? 1 : 0);
        return;

    case MSCR_RESCAN:
        cl_ui_frame_reset(f, CL_UI_SCR_MENU, "RESCAN", "returns when done");
        cl_ui_frame_item(f, "scanning...");
        return;

    case MSCR_S3: {

        bool online = s_s3.online &&
                      (esp_timer_get_time() - s_s3.last_ok_us) < 3000000LL;
        cl_ui_frame_reset(f, CL_UI_SCR_MENU, "S3 NODE", "hold: back");
        if (!online) {
            cl_ui_frame_item(f, "offline");
            cl_ui_frame_item(f, "check Qwiic cable");
            return;
        }
        for (int i = 0; i < 4; i++) {
            char line[CL_UI_ITEM];
            s3_ui_line(i, line, sizeof line);
            if (line[0]) cl_ui_frame_item(f, line);
        }
        if (f->n_items == 0) cl_ui_frame_item(f, "no data yet");
        snprintf(extra, sizeof extra, "windows %lu", (unsigned long)s_s3.windows);
        cl_ui_frame_extra(f, extra, 1);
        return;
    }
    }
}

static void menu_render(void)
{
    static cl_uiframe_t f, last;
    static bool have_last;

    menu_compose(&f);
    if (!cl_ui_draw_diff(&f, &last, have_last)) return;
    memcpy(&last, &f, sizeof last);
    have_last = true;

    ui_frame_queue(&f);
}

static void menu_back(void)
{
    switch (s_mscr) {
    case MSCR_HOWL:                                   s_mscr = MSCR_SENTINEL; s_msel = 0; break;
    case MSCR_AP_LIVE:  s_mscr = MSCR_AP;   s_msel = 2; break;
    case MSCR_S3:                                     s_mscr = MSCR_MAIN;     s_msel = 4; break;
    case MSCR_AP: case MSCR_WALK: case MSCR_SENTINEL: s_mscr = MSCR_MAIN;     s_msel = 0; break;
    default: break;
    }
}

static void menu_select(void)
{
    switch (s_mscr) {
    case MSCR_MAIN:
        switch (s_msel) {
        case 0: s_mscr = MSCR_AP;       s_msel = 0; break;
        case 1: s_mscr = MSCR_WALK;     s_msel = 0; break;
        case 2: s_mscr = MSCR_SENTINEL; s_msel = 0; sentinel_sync_shadow(); break;
        case 3: s_rescan_base_merge = s_merge_count; s_rescan_ticks = 0;
                s_req = REQ_SCAN; alog("rescan (device)"); s_mscr = MSCR_RESCAN; break;
        case 4: s_mscr = MSCR_S3;       s_msel = 0; break;
        }
        break;
    case MSCR_AP:
        if (s_msel == 0) {
            s_ap_want = !s_ap_want;
            alog("AP %s (device)", s_ap_want ? "start" : "stop");
        } else if (s_msel == 1) {
            s_ap_autolaunch = !s_ap_autolaunch;
            ap_autolaunch_save();
        } else {
            s_ap_want = true;
            s_mscr = MSCR_AP_LIVE;
        }
        break;
    case MSCR_WALK:
        if (s_msel == 0) { s_req = REQ_WALK;     alog("walk started (device)"); }
        else             { s_req = REQ_STOPWALK; alog("walk stopped (device)"); }
        break;
    case MSCR_SENTINEL:
        if (s_msel == 0) { s_sent_armed = !s_sent_armed; sentinel_set_armed(s_sent_armed); }
        else             { s_mscr = MSCR_HOWL; s_msel = 0; }
        break;
    case MSCR_HOWL:
        if (s_msel == 0) howl_start();
        else             howl_stop();
        break;
    default: break;
    }
}

static bev_t brain_wait_button(uint32_t timeout_ms)
{
    uint32_t waited = 0;
    while (gpio_get_level(BRAIN_PIN_BOOT) != 0) {
        vTaskDelay(pdMS_TO_TICKS(20));
        waited += 20;
        if (waited >= timeout_ms) return BEV_NONE;
    }
    vTaskDelay(pdMS_TO_TICKS(30));
    if (gpio_get_level(BRAIN_PIN_BOOT) != 0) return BEV_NONE;

    uint32_t held = 0;
    while (gpio_get_level(BRAIN_PIN_BOOT) == 0 && held < BRAIN_LONG_HOLD_MS) {
        vTaskDelay(pdMS_TO_TICKS(20));
        held += 20;
    }
    if (gpio_get_level(BRAIN_PIN_BOOT) == 0 && held >= BRAIN_LONG_HOLD_MS) {
        while (gpio_get_level(BRAIN_PIN_BOOT) == 0) vTaskDelay(pdMS_TO_TICKS(20));
        return BEV_LONG;
    }
    uint32_t gap = 0;
    while (gap < BRAIN_DBL_GAP_MS) {
        vTaskDelay(pdMS_TO_TICKS(20));
        gap += 20;
        if (gpio_get_level(BRAIN_PIN_BOOT) == 0) {
            vTaskDelay(pdMS_TO_TICKS(30));
            if (gpio_get_level(BRAIN_PIN_BOOT) != 0) continue;
            while (gpio_get_level(BRAIN_PIN_BOOT) == 0) vTaskDelay(pdMS_TO_TICKS(20));
            return BEV_DOUBLE;
        }
    }
    return BEV_SINGLE;
}

static void menu_task(void *arg)
{
    (void)arg;
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << BRAIN_PIN_BOOT),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
    menu_render();

    for (;;) {
        bev_t ev = brain_wait_button(400);

        if (ev == BEV_NONE && s_ui_evq) {
            uint8_t rev;
            if (xQueueReceive(s_ui_evq, &rev, 0) == pdTRUE) {
                ev = (rev == CL_UI_EV_SINGLE) ? BEV_SINGLE
                   : (rev == CL_UI_EV_DOUBLE) ? BEV_DOUBLE
                   : (rev == CL_UI_EV_LONG)   ? BEV_LONG : BEV_NONE;
                if (ev != BEV_NONE) alog("S3 button: %s",
                    ev == BEV_SINGLE ? "next" : ev == BEV_DOUBLE ? "select" : "back");
            }
        }

        if (ev == BEV_NONE) {
            if (s_mscr == MSCR_RESCAN) {
                if (s_merge_count != s_rescan_base_merge || ++s_rescan_ticks > 60) {
                    s_mscr = MSCR_MAIN; s_msel = 0;
                    menu_render();
                    continue;
                }
            }

            menu_render();
            continue;
        }

        if (ev == BEV_SINGLE) { int n = menu_count(s_mscr); if (n > 0) s_msel = (s_msel + 1) % n; }
        else if (ev == BEV_DOUBLE) menu_select();
        else if (ev == BEV_LONG)   menu_back();
        menu_render();
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "==================================================");
    ESP_LOGI(TAG, " SniffCheck Cluster BRAIN (T-Dongle-C5)  [%s]", FW_CKPT);
    ESP_LOGI(TAG, " I2C MASTER + WebAP host");
    ESP_LOGI(TAG, "==================================================");

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase()); ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    spi_bus_config_t bus = {
        .mosi_io_num   = CL_LCD_MOSI, .miso_io_num = CL_LCD_MISO, .sclk_io_num = CL_LCD_SCK,
        .quadwp_io_num = -1, .quadhd_io_num = -1,
        .max_transfer_sz = DISPLAY_W * DISPLAY_H * (int)sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(CL_LCD_SPI_HOST, &bus, SPI_DMA_CH_AUTO));
    ESP_ERROR_CHECK(led_init(CL_LCD_SPI_HOST));
    ESP_ERROR_CHECK(display_init(CL_LCD_SPI_HOST));
    display_set_post_blit_cb(led_blank_cb);
    led_off();

    for (int f = 0; f < 10; f++) { display_logo_frame(f); vTaskDelay(pdMS_TO_TICKS(160)); }
    display_splash_credit();
    vTaskDelay(pdMS_TO_TICKS(1200));

    uint32_t caps = MALLOC_CAP_SPIRAM;
    s_arm[0].buf = heap_caps_malloc(BRAIN_ARM_CAP, caps);
    s_arm[1].buf = heap_caps_malloc(BRAIN_ARM_CAP, caps);
    s_merge_buf  = heap_caps_malloc(BRAIN_MERGE_CAP, caps);
    if (!s_arm[0].buf || !s_arm[1].buf || !s_merge_buf) {
        caps = MALLOC_CAP_8BIT;
        if (!s_arm[0].buf) s_arm[0].buf = heap_caps_malloc(BRAIN_ARM_CAP, caps);
        if (!s_arm[1].buf) s_arm[1].buf = heap_caps_malloc(BRAIN_ARM_CAP, caps);
        if (!s_merge_buf)  s_merge_buf  = heap_caps_malloc(BRAIN_MERGE_CAP, caps);
    }
    ESP_LOGI(TAG, "buffers: 2x%uKB arm + %uKB merge (%s)",
             BRAIN_ARM_CAP / 1024, BRAIN_MERGE_CAP / 1024,
             caps == MALLOC_CAP_SPIRAM ? "PSRAM" : "internal RAM");

    s_dev_mux = xSemaphoreCreateMutex();
    s_devtab = heap_caps_malloc((size_t)DEV_MAX * sizeof(dev_ent_t), MALLOC_CAP_SPIRAM);
    snprintf(s_sess_id, sizeof s_sess_id, "b-%08lx", (unsigned long)esp_random());
    ESP_LOGI(TAG, "devtable: %s (%d slots, %uKB, free PSRAM %uKB) sess=%s",
             s_devtab ? "PSRAM ok" : "DISABLED (no PSRAM) -> ring fallback", DEV_MAX,
             (unsigned)((DEV_MAX * sizeof(dev_ent_t)) / 1024),
             (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024), s_sess_id);

    s_s3_mux  = xSemaphoreCreateMutex();
    s_ui_mux  = xSemaphoreCreateMutex();
    s_ui_evq  = xQueueCreate(4, sizeof(uint8_t));
    uint32_t jcaps = (caps == MALLOC_CAP_SPIRAM) ? MALLOC_CAP_SPIRAM : MALLOC_CAP_8BIT;
    s_sent_json = heap_caps_malloc(6144, jcaps);
    s_hits_json = heap_caps_malloc(6144, jcaps);
    if (s_sent_json) s_sent_json[0] = '\0';
    if (s_hits_json) s_hits_json[0] = '\0';
    s_tracker_json = heap_caps_malloc(2048, jcaps);
    if (s_tracker_json) s_tracker_json[0] = '\0';

    epup_brain_init(0);

    ESP_ERROR_CHECK(capture_ring_init(2 * 1024 * 1024, 128 * 1024));
    master_shim_set_session("cluster-brain-0001", FW_CKPT);
    virtual_pup_init(1);
    virtual_pup_walk_init();
    pup_trophy_init();
    const char *seed = "{\"type\":\"info\",\"src\":\"cluster-brain\",\"msg\":\"brain WebAP online\"}";
    capture_ring_write(seed, strlen(seed));

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wc));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_country_t country = { .cc = "US", .schan = 1, .nchan = 11,
                               .policy = WIFI_COUNTRY_POLICY_MANUAL };
    esp_wifi_set_country(&country);
    download_mode_init();

    i2c_master_setup();

    ap_autolaunch_load();
    s_ap_want = s_ap_autolaunch;
    ESP_LOGI(TAG, "AP auto-launch %s", s_ap_autolaunch ? "ON" : "OFF");

    xTaskCreate(bus_task,  "brain_bus",  6144, NULL, 6, NULL);
    xTaskCreate(log_task,  "brain_log",  3072, NULL, 4, NULL);
    xTaskCreate(web_task,  "brain_web",  4096, NULL, 5, NULL);
    xTaskCreate(menu_task, "brain_menu", 4096, NULL, 5, NULL);
    ESP_LOGI(TAG, "app_main done — I2C MASTER + WebAP host (arms 0x%02x/0x%02x, S3 0x%02x)",
             CL_ARM1_ADDR, CL_ARM2_ADDR, CL_S3_ADDR);
}
