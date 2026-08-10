#include "epup_brain.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "cluster_proto.h"
#include "infra_cluster.h"

static const char *TAG = "epup-brain";

#define EPUP_NVS_NS     "epup"
#define EPUP_NVS_SUM    "sum"
#define EPUP_NVS_BOOT   "boot"
#define EPUP_FLUSH_EVERY 16

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  schema_ver;
    uint16_t _pad;
    uint32_t born_boot;
    uint32_t total_scans;
    uint64_t total_obs;
    uint32_t unique_est;
    int32_t  ema_total_x1000, ema_wifi_x1000, ema_ble_x1000;
    uint16_t last_wifi, last_ble, last_new, last_total;
    uint16_t crc;
} epup_persist_t;

#define CM_DEPTH   4
#define CM_WIDTH   4096u
#define CM_MASK    (CM_WIDTH - 1)
#define BLOOM_BITS 65536u
#define BLOOM_MASK (BLOOM_BITS - 1)
#define BLOOM_K    4

#define PLACE_MAX          6
#define LM_MAX             24
#define LM_NAME            20
#define WIN_MAX            48
#define PLACE_MIN_UNITS    2
#define PLACE_MATCH_PCT    35
#define PLACE_MIN_DISTINCT 2
#define PLACE_KNOWN_MIN    3
#define LM_CONFIRM_SCANS   2
#define LM_PRUNE_AFTER     6
#define LM_PRUNE_PCT       15
#define PLACE_SCHEMA_VER   2

#define LM_F_PINNED        0x01u
#define LM_F_CONFIRMED     0x02u

#define EMA_SHIFT  6

typedef struct {

    uint32_t born_boot;
    uint32_t total_scans;
    uint64_t total_obs;
    uint32_t unique_est;
    int32_t  ema_total_x1000;
    int32_t  ema_wifi_x1000;
    int32_t  ema_ble_x1000;
    uint16_t last_wifi, last_ble, last_new, last_total;

    uint16_t *cm;
    uint8_t  *bloom;
    bool      ready;
} brain_t;

static brain_t B;
static int      s_dirty;
static uint32_t s_boot_now;

typedef struct __attribute__((packed)) {
    uint64_t unit;
    uint16_t hits;
    uint8_t  scans_seen;
    uint8_t  flags;
    char     name[LM_NAME];
} landmark_t;

typedef struct __attribute__((packed)) {
    landmark_t lm[LM_MAX];
    uint8_t    lm_count;
    uint8_t    quality;
    char       label[16];
    uint32_t   scans;
    uint32_t   born_boot;
    uint32_t   last_seq;
} place_t;

typedef struct { uint64_t unit; uint16_t cnt; char name[LM_NAME]; } win_unit_t;

static struct {
    place_t  places[PLACE_MAX];
    uint8_t  count;
    int8_t   cur;
    uint8_t  sim;
    bool     known;
    bool     is_new;
    uint32_t seq;
} P = { .cur = -1 };

static struct {
    bool    active;
    int8_t  target;
    uint8_t want, done;
    bool    reposition;
    bool    fresh;
} L = { .target = -1 };

static void place_persist_save(nvs_handle_t h);

static bool persist_load(void)
{
    nvs_handle_t h;
    if (nvs_open(EPUP_NVS_NS, NVS_READONLY, &h) != ESP_OK) return false;
    epup_persist_t p;
    size_t sz = sizeof(p);
    esp_err_t e = nvs_get_blob(h, EPUP_NVS_SUM, &p, &sz);
    nvs_close(h);
    if (e != ESP_OK || sz != sizeof(p)) return false;
    if (p.magic != EPUP_SUMMARY_MAGIC || p.schema_ver != EPUP_SCHEMA_VER) return false;
    if (cl_crc16((const uint8_t *)&p, sizeof(p) - sizeof(p.crc)) != p.crc) {
        ESP_LOGW(TAG, "persist: bad CRC — ignoring, fresh brain");
        return false;
    }
    B.born_boot      = p.born_boot;
    B.total_scans    = p.total_scans;
    B.total_obs      = p.total_obs;
    B.unique_est     = p.unique_est;
    B.ema_total_x1000 = p.ema_total_x1000;
    B.ema_wifi_x1000  = p.ema_wifi_x1000;
    B.ema_ble_x1000   = p.ema_ble_x1000;
    B.last_wifi = p.last_wifi; B.last_ble = p.last_ble;
    B.last_new  = p.last_new;  B.last_total = p.last_total;
    return true;
}

static void persist_save(void)
{
    nvs_handle_t h;
    if (nvs_open(EPUP_NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    epup_persist_t p;
    memset(&p, 0, sizeof(p));
    p.magic = EPUP_SUMMARY_MAGIC; p.schema_ver = EPUP_SCHEMA_VER;
    p.born_boot   = B.born_boot;
    p.total_scans = B.total_scans;
    p.total_obs   = B.total_obs;
    p.unique_est  = B.unique_est;
    p.ema_total_x1000 = B.ema_total_x1000;
    p.ema_wifi_x1000  = B.ema_wifi_x1000;
    p.ema_ble_x1000   = B.ema_ble_x1000;
    p.last_wifi = B.last_wifi; p.last_ble = B.last_ble;
    p.last_new  = B.last_new;  p.last_total = B.last_total;
    p.crc = cl_crc16((const uint8_t *)&p, sizeof(p) - sizeof(p.crc));
    nvs_set_blob(h, EPUP_NVS_SUM, &p, sizeof(p));
    place_persist_save(h);
    nvs_commit(h);
    nvs_close(h);
    s_dirty = 0;
}

static uint32_t boot_bump(void)
{
    nvs_handle_t h;
    uint32_t bc = 0;
    if (nvs_open(EPUP_NVS_NS, NVS_READWRITE, &h) != ESP_OK) return 0;
    nvs_get_u32(h, EPUP_NVS_BOOT, &bc);
    bc++;
    if (nvs_set_u32(h, EPUP_NVS_BOOT, bc) == ESP_OK) nvs_commit(h);
    nvs_close(h);
    return bc;
}

static uint64_t fnv1a(const char *s, int n)
{
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 1099511628211ULL; }
    return h;
}

static uint32_t isqrt32(uint32_t x)
{
    uint32_t r = 0, b = 1u << 30;
    while (b > x) b >>= 2;
    while (b) {
        if (x >= r + b) { x -= r + b; r = (r >> 1) + b; }
        else r >>= 1;
        b >>= 2;
    }
    return r;
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

static int line_key(const char *line, int n, char *kb, int kbsz, bool *is_wifi)
{
    char type[24], id[40];
    if (!find_str(line, n, "\"type\":\"", type, sizeof type)) return 0;
    if (!find_str(line, n, "\"bssid\":\"", id, sizeof id) &&
        !find_str(line, n, "\"addr\":\"",  id, sizeof id)) return 0;
    *is_wifi = (strcmp(type, "wifi_ap") == 0);
    int o = snprintf(kb, kbsz, "%s|%s", type, id);
    return o < kbsz ? o : kbsz - 1;
}

static void cm_add(uint64_t h)
{
    for (int d = 0; d < CM_DEPTH; d++) {

        uint64_t hd = h ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(d + 1));
        hd ^= hd >> 29; hd *= 0xBF58476D1CE4E5B9ULL; hd ^= hd >> 32;
        uint32_t idx = (uint32_t)(hd & CM_MASK);
        uint16_t *cell = &B.cm[d * CM_WIDTH + idx];
        if (*cell != 0xFFFF) (*cell)++;
    }
}

static bool bloom_touch(uint64_t h)
{
    bool novel = false;
    for (int k = 0; k < BLOOM_K; k++) {
        uint64_t hk = h ^ (0x100000001B3ULL * (uint64_t)(k + 1));
        hk ^= hk >> 33; hk *= 0xFF51AFD7ED558CCDULL; hk ^= hk >> 33;
        uint32_t bit = (uint32_t)(hk & BLOOM_MASK);
        uint8_t  m = (uint8_t)(1u << (bit & 7));
        uint8_t *byte = &B.bloom[bit >> 3];
        if (!(*byte & m)) { novel = true; *byte |= m; }
    }
    return novel;
}

static landmark_t *lm_find(place_t *p, uint64_t unit)
{
    for (int i = 0; i < p->lm_count; i++) if (p->lm[i].unit == unit) return &p->lm[i];
    return NULL;
}

static int lm_confirmed(const place_t *p)
{
    int c = 0; for (int i = 0; i < p->lm_count; i++) if (p->lm[i].flags & LM_F_CONFIRMED) c++;
    return c;
}

static int unit_df(uint64_t unit)
{
    int df = 0; for (int i = 0; i < P.count; i++) if (lm_find(&P.places[i], unit)) df++;
    return df;
}

static int unit_weight(uint64_t unit) { return 100 / (unit_df(unit) + 1); }

static landmark_t *lm_weakest(place_t *p)
{
    landmark_t *w = NULL;
    for (int i = 0; i < p->lm_count; i++) {
        landmark_t *l = &p->lm[i];
        if (l->flags & LM_F_PINNED) continue;
        if (!w || l->scans_seen < w->scans_seen ||
            (l->scans_seen == w->scans_seen && l->hits < w->hits)) w = l;
    }
    return w;
}

static void place_prune(place_t *p)
{
    int o = 0;
    for (int i = 0; i < p->lm_count; i++) {
        landmark_t *l = &p->lm[i];
        bool keep = (l->flags & (LM_F_PINNED | LM_F_CONFIRMED)) ||
                    ((uint32_t)l->scans_seen * 100 >= p->scans * LM_PRUNE_PCT);
        if (keep) { if (o != i) p->lm[o] = *l;
                    o++; }
    }
    p->lm_count = (uint8_t)o;
}

static void place_prune_enroll(place_t *p, int want)
{
    int need = (want + 1) / 2; if (need < 1) need = 1;
    int o = 0;
    for (int i = 0; i < p->lm_count; i++) {
        landmark_t *l = &p->lm[i];
        if ((l->flags & LM_F_PINNED) || l->scans_seen >= need) {
            if (o != i) p->lm[o] = *l;
            o++;
        }
    }
    p->lm_count = (uint8_t)o;
}

#define EPUP_NVS_PLACES "places"
typedef struct __attribute__((packed)) {
    uint8_t  magic, schema_ver, count; int8_t cur;
    uint32_t seq;
    place_t  places[PLACE_MAX];
    uint16_t crc;
} place_persist_t;

static void place_persist_save(nvs_handle_t h)
{
    place_persist_t *pp = calloc(1, sizeof(*pp));
    if (!pp) return;
    pp->magic = EPUP_SUMMARY_MAGIC; pp->schema_ver = PLACE_SCHEMA_VER;
    pp->count = P.count; pp->cur = P.cur; pp->seq = P.seq;
    memcpy(pp->places, P.places, sizeof(pp->places));
    pp->crc = cl_crc16((const uint8_t *)pp, sizeof(*pp) - sizeof(pp->crc));
    nvs_set_blob(h, EPUP_NVS_PLACES, pp, sizeof(*pp));
    free(pp);
}

static void place_persist_load(void)
{
    nvs_handle_t h;
    if (nvs_open(EPUP_NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    place_persist_t *pp = calloc(1, sizeof(*pp));
    if (!pp) { nvs_close(h); return; }
    size_t sz = sizeof(*pp);
    esp_err_t e = nvs_get_blob(h, EPUP_NVS_PLACES, pp, &sz);
    nvs_close(h);
    if (e == ESP_OK && sz == sizeof(*pp) &&
        pp->magic == EPUP_SUMMARY_MAGIC && pp->schema_ver == PLACE_SCHEMA_VER &&
        cl_crc16((const uint8_t *)pp, sizeof(*pp) - sizeof(pp->crc)) == pp->crc &&
        pp->count <= PLACE_MAX) {
        P.count = pp->count; P.cur = -1; P.seq = pp->seq;
        memcpy(P.places, pp->places, sizeof(P.places));
    }
    free(pp);
}

static void place_absorb(place_t *pl, const win_unit_t *win, int win_n)
{
    for (int w = 0; w < win_n; w++) {
        landmark_t *lm = lm_find(pl, win[w].unit);
        if (!lm) {
            lm = (pl->lm_count < LM_MAX) ? &pl->lm[pl->lm_count++] : lm_weakest(pl);
            if (!lm) continue;
            if (lm->unit != win[w].unit) { memset(lm, 0, sizeof(*lm)); lm->unit = win[w].unit; }
        }
        if (lm->hits < 0xFFFF) lm->hits = (uint16_t)(lm->hits + win[w].cnt);
        if (lm->scans_seen < 0xFF) lm->scans_seen++;
        if (lm->name[0] == '\0' && win[w].name[0]) strlcpy(lm->name, win[w].name, LM_NAME);
        if (lm->scans_seen >= LM_CONFIRM_SCANS) lm->flags |= LM_F_CONFIRMED;
    }
}

static void place_enroll(const win_unit_t *win, int win_n)
{
    if (win_n < PLACE_MIN_UNITS) { P.sim = 0; P.is_new = false; return; }

    if (L.target < 0) {
        int idx;
        if (!L.fresh && P.cur >= 0 && P.cur < P.count) {
            idx = P.cur; P.is_new = false;
        } else {
            if (P.count < PLACE_MAX) idx = P.count++;
            else { idx = 0; uint32_t o = P.places[0].last_seq;
                   for (int i = 1; i < P.count; i++)
                       if (P.places[i].last_seq < o) { o = P.places[i].last_seq; idx = i; } }
            memset(&P.places[idx], 0, sizeof(place_t));
            P.places[idx].born_boot = B.born_boot;
            P.is_new = true;
        }
        L.target = (int8_t)idx;
    }

    place_t *pl = &P.places[L.target];
    pl->scans++;
    pl->last_seq = ++P.seq;
    place_absorb(pl, win, win_n);
    L.done++;

    P.cur = L.target;
    P.sim = 100;
    P.known = (lm_confirmed(pl) >= PLACE_MIN_DISTINCT);

    if (L.done >= L.want) {
        if (L.reposition) {
            place_prune_enroll(pl, L.want);
            pl->quality = 100;
        } else {
            pl->quality = 55;
        }
        P.known = (lm_confirmed(pl) >= PLACE_MIN_DISTINCT);
        ESP_LOGI(TAG, "enroll done: env[%d] %u landmarks (%s, q=%u)",
                 L.target, lm_confirmed(pl), L.reposition ? "repositioned" : "stationary",
                 pl->quality);
        L.active = false; L.target = -1;
        persist_save();
    }
}

static void place_fold(const win_unit_t *win, int win_n)
{
    if (L.active) { place_enroll(win, win_n); return; }
    if (win_n < PLACE_MIN_UNITS) { P.sim = 0; P.is_new = false; return; }

    int best = -1, best_sim = -1, best_distinct = 0;
    for (int i = 0; i < P.count; i++) {
        place_t *p = &P.places[i];
        int inter = 0, distinct = 0, wsum_win = 0;
        for (int w = 0; w < win_n; w++) {
            int wt = unit_weight(win[w].unit);
            wsum_win += wt;
            landmark_t *lm = lm_find(p, win[w].unit);
            if (lm) {
                inter += wt;
                if ((lm->flags & LM_F_CONFIRMED) && unit_df(win[w].unit) <= 1) distinct++;
            }
        }
        int wsum_place_only = 0;
        for (int k = 0; k < p->lm_count; k++) {
            bool in_win = false;
            for (int w = 0; w < win_n; w++)
                if (win[w].unit == p->lm[k].unit) { in_win = true; break; }
            if (!in_win) wsum_place_only += unit_weight(p->lm[k].unit);
        }
        int uni = wsum_win + wsum_place_only;
        int sim = uni > 0 ? inter * 100 / uni : 0;
        if (sim > best_sim) { best_sim = sim; best = i; best_distinct = distinct; }
    }

    bool matched = (best >= 0 && best_sim >= PLACE_MATCH_PCT && best_distinct >= PLACE_MIN_DISTINCT);
    int idx;
    if (matched) {
        idx = best; P.is_new = false;
    } else {
        if (P.count < PLACE_MAX) {
            idx = P.count++;
        } else {
            idx = 0; uint32_t oldest = P.places[0].last_seq;
            for (int i = 1; i < P.count; i++)
                if (P.places[i].last_seq < oldest) { oldest = P.places[i].last_seq; idx = i; }
        }
        memset(&P.places[idx], 0, sizeof(place_t));
        P.places[idx].born_boot = B.born_boot;
        P.is_new = true;
    }

    place_t *pl = &P.places[idx];
    pl->scans++;
    pl->last_seq = ++P.seq;
    place_absorb(pl, win, win_n);

    if (pl->scans >= LM_PRUNE_AFTER) place_prune(pl);

    if (pl->quality < 90) {
        uint32_t q = pl->scans * 10; if (q > 90) q = 90;
        if ((uint8_t)q > pl->quality) pl->quality = (uint8_t)q;
    }

    P.cur   = (int8_t)idx;
    P.sim   = (uint8_t)(best_sim < 0 ? 0 : best_sim);
    P.known = (pl->scans >= PLACE_KNOWN_MIN && lm_confirmed(pl) >= PLACE_MIN_DISTINCT);
}

static int win_add(win_unit_t *win, int n, const char *line, int ll)
{
    char bssid[24], ssid[40], ieh[24];
    if (!find_str(line, ll, "\"bssid\":\"", bssid, sizeof bssid)) return n;
    uint8_t mac[6];
    if (!infra_parse_mac(bssid, (int)strlen(bssid), mac)) return n;
    int sl = find_str(line, ll, "\"ssid\":\"", ssid, sizeof ssid);
    uint32_t ie = 0;
    if (find_str(line, ll, "\"ie_pattern_hash\":", ieh, sizeof ieh))
        ie = (uint32_t)strtoul(ieh, NULL, 10);
    uint64_t u = infra_unit_key(mac, ie);
    for (int k = 0; k < n; k++)
        if (win[k].unit == u) { if (win[k].cnt < 0xFFFF) win[k].cnt++; return n; }
    if (n >= WIN_MAX) return n;
    win[n].unit = u; win[n].cnt = 1;
    if (sl > 0) strlcpy(win[n].name, ssid, LM_NAME);
    else snprintf(win[n].name, LM_NAME, "%02x:%02x:%02x\xC2\xB7unit", mac[0], mac[1], mac[2]);
    return n + 1;
}

bool epup_brain_init(uint32_t boot_count)
{
    memset(&B, 0, sizeof(B));
    B.born_boot = boot_count;

    uint32_t caps = MALLOC_CAP_SPIRAM;
    B.cm    = heap_caps_malloc(CM_DEPTH * CM_WIDTH * sizeof(uint16_t), caps);
    B.bloom = heap_caps_malloc(BLOOM_BITS / 8, caps);
    if (!B.cm || !B.bloom) {
        caps = MALLOC_CAP_8BIT;
        if (!B.cm)    B.cm    = heap_caps_malloc(CM_DEPTH * CM_WIDTH * sizeof(uint16_t), caps);
        if (!B.bloom) B.bloom = heap_caps_malloc(BLOOM_BITS / 8, caps);
    }
    if (!B.cm || !B.bloom) {
        ESP_LOGE(TAG, "model alloc failed — brain disabled (cm=%p bloom=%p)", B.cm, B.bloom);
        B.ready = false;
        return false;
    }
    memset(B.cm, 0, CM_DEPTH * CM_WIDTH * sizeof(uint16_t));
    memset(B.bloom, 0, BLOOM_BITS / 8);
    B.ready = true;

    uint32_t bc = boot_bump();
    s_boot_now = bc ? bc : boot_count;
    bool restored = persist_load();
    if (!restored) B.born_boot = bc ? bc : boot_count;
    place_persist_load();

    ESP_LOGI(TAG, "brain up: cm=%uKB bloom=%uKB (%s) boot=%lu %s scans=%lu uniq~%lu born=%lu",
             (unsigned)(CM_DEPTH * CM_WIDTH * sizeof(uint16_t) / 1024),
             (unsigned)(BLOOM_BITS / 8 / 1024),
             caps == MALLOC_CAP_SPIRAM ? "PSRAM" : "internal", (unsigned long)bc,
             restored ? "restored" : "fresh",
             (unsigned long)B.total_scans, (unsigned long)B.unique_est,
             (unsigned long)B.born_boot);
    return true;
}

void epup_brain_observe(const char *jsonl, size_t len)
{
    if (!B.ready || !jsonl || len == 0) return;

    uint32_t wifi = 0, ble = 0, newdev = 0, rows = 0;
    static win_unit_t win[WIN_MAX];
    int win_n = 0;
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && jsonl[j] != '\n') j++;
        int linelen = (int)(j - i);
        if (linelen > 0) {
            char key[72];
            bool is_wifi = false;
            int kl = line_key(jsonl + i, linelen, key, sizeof key, &is_wifi);
            if (kl > 0) {
                uint64_t h = fnv1a(key, kl);
                cm_add(h);
                if (bloom_touch(h)) { newdev++; B.unique_est++; }
                if (is_wifi) { wifi++; win_n = win_add(win, win_n, jsonl + i, linelen); }
                else ble++;
                rows++;
            }
        }
        i = j + 1;
    }

    place_fold(win, win_n);

    uint32_t total = wifi + ble;

    B.ema_total_x1000 += ((int32_t)(total * 1000) - B.ema_total_x1000) >> EMA_SHIFT;
    B.ema_wifi_x1000  += ((int32_t)(wifi  * 1000) - B.ema_wifi_x1000)  >> EMA_SHIFT;
    B.ema_ble_x1000   += ((int32_t)(ble   * 1000) - B.ema_ble_x1000)   >> EMA_SHIFT;

    B.last_wifi  = (uint16_t)wifi;
    B.last_ble   = (uint16_t)ble;
    B.last_new   = (uint16_t)newdev;
    B.last_total = (uint16_t)total;
    B.total_obs += rows;
    B.total_scans++;

    if (++s_dirty >= EPUP_FLUSH_EVERY || P.is_new) persist_save();

    ESP_LOGI(TAG, "observe #%lu: %lu rows (wifi=%lu ble=%lu new=%lu) uniq~%lu ema=%ld L%lu "
                  "place=%d/%u sim=%u%% %s%s",
             (unsigned long)B.total_scans, (unsigned long)rows,
             (unsigned long)wifi, (unsigned long)ble, (unsigned long)newdev,
             (unsigned long)B.unique_est, (long)(B.ema_total_x1000 / 1000),
             (unsigned long)isqrt32(B.total_scans),
             (int)P.cur, (unsigned)P.count, (unsigned)P.sim,
             P.known ? "known" : "new-ish", P.is_new ? " *NEW*" : "");
}

static epup_title_t title_for_scans(uint32_t n)
{
    if (n >= 40000) return EPUP_TITLE_LEGEND;
    if (n >= 12000) return EPUP_TITLE_VETERAN;
    if (n >=  3000) return EPUP_TITLE_ADULT;
    if (n >=   500) return EPUP_TITLE_YOUNG;
    return EPUP_TITLE_PUPPY;
}

void epup_brain_get(epup_summary_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->magic       = EPUP_SUMMARY_MAGIC;
    out->schema_ver  = EPUP_SCHEMA_VER;
    out->title       = (uint8_t)title_for_scans(B.total_scans);
    uint32_t conf    = B.ready ? (uint32_t)((uint64_t)B.total_scans * 100 / EPUP_MATURE_SCANS) : 0;
    out->confidence  = (uint8_t)(conf > 100 ? 100 : conf);
    out->level       = isqrt32(B.total_scans);
    out->total_scans = B.total_scans;
    out->born_boot   = B.born_boot;
    out->boot_now    = s_boot_now < B.born_boot ? B.born_boot : s_boot_now;
    out->total_obs   = B.total_obs;
    out->unique_est  = B.unique_est;
    out->last_wifi   = B.last_wifi;
    out->last_ble    = B.last_ble;
    out->last_new    = B.last_new;
    out->ema_total   = (uint16_t)(B.ema_total_x1000 / 1000);

    out->place_cur   = P.cur;
    out->place_count = P.count;
    out->place_sim   = P.sim;
    out->place_flags = (uint8_t)((P.known ? EPUP_PLACE_KNOWN : 0) |
                                 (P.is_new ? EPUP_PLACE_NEW : 0));
    if (P.cur >= 0 && P.cur < P.count) {
        out->place_scans = P.places[P.cur].scans;
        memcpy(out->place_label, P.places[P.cur].label, sizeof(out->place_label));
        out->place_label[sizeof(out->place_label) - 1] = '\0';
    }
    out->crc = cl_crc16((const uint8_t *)out, sizeof(*out) - sizeof(out->crc));
}

void epup_brain_place(epup_place_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->cur        = P.cur;
    out->count      = P.count;
    out->similarity = P.sim;
    out->known      = P.known;
    out->is_new     = P.is_new;
    if (P.cur >= 0 && P.cur < P.count) {
        const place_t *pl = &P.places[P.cur];
        out->scans = pl->scans;
        memcpy(out->label, pl->label, sizeof(out->label));
        out->label[sizeof(out->label) - 1] = '\0';
    }
}

void epup_brain_places(cl_places_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    uint8_t n = P.count; if (n > CL_PLACE_MAX) n = CL_PLACE_MAX;
    out->count = n;
    out->cur   = P.cur;
    for (uint8_t i = 0; i < n; i++) {
        const place_t *pl = &P.places[i];
        cl_place_entry_t *e = &out->entries[i];
        memcpy(e->label, pl->label, sizeof(e->label));
        e->label[sizeof(e->label) - 1] = '\0';
        e->scans     = pl->scans;
        e->landmarks = (uint16_t)lm_confirmed(pl);
        e->idx       = i;
        uint8_t f = 0;
        if (pl->scans >= PLACE_KNOWN_MIN && lm_confirmed(pl) >= PLACE_MIN_DISTINCT)
            f |= CL_PLACE_F_KNOWN;
        if (P.cur == (int8_t)i)           f |= CL_PLACE_F_CURRENT;
        e->flags = f;
    }
    cl_places_seal(out);
}

void epup_brain_place_label(int i, const char *label)
{
    if (i < 0) i = P.cur;
    if (i < 0 || i >= P.count || !label) return;
    snprintf(P.places[i].label, sizeof(P.places[i].label), "%s", label);
    persist_save();
    ESP_LOGI(TAG, "place[%d] labelled \"%s\"", i, P.places[i].label);
}

int epup_brain_place_detail(int idx, epup_landmark_t *out, int max)
{
    if (idx < 0 || idx >= P.count || !out || max <= 0) return 0;
    place_t *p = &P.places[idx];
    int n = p->lm_count < max ? p->lm_count : max;
    for (int i = 0; i < n; i++) {
        out[i].unit       = p->lm[i].unit;
        out[i].hits       = p->lm[i].hits;
        out[i].scans_seen = p->lm[i].scans_seen;
        out[i].flags      = p->lm[i].flags;
        strlcpy(out[i].name, p->lm[i].name, sizeof out[i].name);
    }
    return n;
}

int epup_brain_place_quality(int idx)
{
    if (idx < 0 || idx >= P.count) return 0;
    return P.places[idx].quality;
}

void epup_brain_landmark_pin(int place, uint64_t unit, bool pin)
{
    if (place < 0 || place >= P.count) return;
    landmark_t *l = lm_find(&P.places[place], unit);
    if (!l) return;
    if (pin) l->flags |= LM_F_PINNED; else l->flags &= (uint8_t)~LM_F_PINNED;
    persist_save();
    ESP_LOGI(TAG, "place[%d] landmark %s", place, pin ? "pinned" : "unpinned");
}

void epup_brain_landmark_delete(int place, uint64_t unit)
{
    if (place < 0 || place >= P.count) return;
    place_t *p = &P.places[place];
    for (int i = 0; i < p->lm_count; i++) {
        if (p->lm[i].unit != unit) continue;
        for (int k = i + 1; k < p->lm_count; k++) p->lm[k - 1] = p->lm[k];
        p->lm_count--;
        persist_save();
        ESP_LOGI(TAG, "place[%d] landmark deleted (%d left)", place, p->lm_count);
        return;
    }
}

void epup_brain_place_delete(int idx)
{
    if (idx < 0 || idx >= P.count) return;
    for (int k = idx + 1; k < P.count; k++) P.places[k - 1] = P.places[k];
    P.count--;
    memset(&P.places[P.count], 0, sizeof(place_t));
    if (P.cur == idx) P.cur = -1;
    else if (P.cur > idx) P.cur--;

    if (L.active) {
        if (L.target == idx) { L.active = false; L.target = -1; }
        else if (L.target > idx) L.target--;
    }
    persist_save();
    ESP_LOGW(TAG, "environment %d forgotten (%u left)", idx, P.count);
}

void epup_brain_learn_start(int want_scans, bool reposition, bool fresh)
{
    if (want_scans < 1) want_scans = 1;
    if (want_scans > 20) want_scans = 20;
    L.active = true;
    L.target = -1;
    L.want = (uint8_t)want_scans;
    L.done = 0;
    L.reposition = reposition;
    L.fresh = fresh;
    ESP_LOGI(TAG, "learn start: %d scans, %s%s", want_scans,
             reposition ? "reposition between scans" : "stationary",
             fresh ? ", new environment" : ", current environment");
}

void epup_brain_learn_cancel(void)
{
    if (!L.active) return;
    L.active = false; L.target = -1;
    ESP_LOGW(TAG, "learn cancelled");
}

void epup_brain_learn_status(epup_learn_t *out)
{
    if (!out) return;
    out->active     = L.active;
    out->want       = L.want;
    out->done       = L.done;
    out->reposition = L.reposition;
    out->target     = L.target;
}

#define EPUP_CKPT_MAGIC   0x504B4345u
#define EPUP_CKPT_SCHEMA  2u
#define CM_BYTES     (CM_DEPTH * CM_WIDTH * (uint32_t)sizeof(uint16_t))
#define BLOOM_BYTES  (BLOOM_BITS / 8u)

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t schema_ver;
    uint16_t place_max;
    uint32_t cm_bytes;
    uint32_t bloom_bytes;
    uint32_t total_len;

    uint32_t born_boot, total_scans;
    uint64_t total_obs;
    uint32_t unique_est;
    int32_t  ema_total_x1000, ema_wifi_x1000, ema_ble_x1000;
    uint16_t last_wifi, last_ble, last_new, last_total;

    uint8_t  place_count; int8_t place_cur; uint8_t place_sim;
    uint8_t  place_known, place_is_new; uint8_t _pad[3];
    uint32_t place_seq;
    place_t  places[PLACE_MAX];

} epup_ckpt_hdr_t;

size_t epup_brain_ckpt_size(void)
{
    return sizeof(epup_ckpt_hdr_t) + CM_BYTES + BLOOM_BYTES + sizeof(uint16_t);
}

size_t epup_brain_ckpt_save(uint8_t *out, size_t cap)
{
    size_t need = epup_brain_ckpt_size();
    if (!B.ready || !out || cap < need) return 0;

    epup_ckpt_hdr_t *h = (epup_ckpt_hdr_t *)out;
    memset(h, 0, sizeof(*h));
    h->magic       = EPUP_CKPT_MAGIC;
    h->schema_ver  = EPUP_CKPT_SCHEMA;
    h->place_max   = PLACE_MAX;
    h->cm_bytes    = CM_BYTES;
    h->bloom_bytes = BLOOM_BYTES;
    h->total_len   = (uint32_t)need;
    h->born_boot   = B.born_boot;
    h->total_scans = B.total_scans;
    h->total_obs   = B.total_obs;
    h->unique_est  = B.unique_est;
    h->ema_total_x1000 = B.ema_total_x1000;
    h->ema_wifi_x1000  = B.ema_wifi_x1000;
    h->ema_ble_x1000   = B.ema_ble_x1000;
    h->last_wifi = B.last_wifi; h->last_ble = B.last_ble;
    h->last_new  = B.last_new;  h->last_total = B.last_total;
    h->place_count = P.count; h->place_cur = P.cur; h->place_sim = P.sim;
    h->place_known = P.known ? 1 : 0; h->place_is_new = P.is_new ? 1 : 0;
    h->place_seq = P.seq;
    memcpy(h->places, P.places, sizeof(h->places));

    uint8_t *p = out + sizeof(*h);
    memcpy(p, B.cm, CM_BYTES);        p += CM_BYTES;
    memcpy(p, B.bloom, BLOOM_BYTES);  p += BLOOM_BYTES;
    uint16_t crc = cl_crc16(out, need - sizeof(uint16_t));
    memcpy(p, &crc, sizeof(crc));
    return need;
}

bool epup_brain_ckpt_load(const uint8_t *in, size_t len)
{
    size_t need = epup_brain_ckpt_size();
    if (!B.ready || !in || len != need) return false;
    const epup_ckpt_hdr_t *h = (const epup_ckpt_hdr_t *)in;
    if (h->magic != EPUP_CKPT_MAGIC || h->schema_ver != EPUP_CKPT_SCHEMA ||
        h->place_max != PLACE_MAX || h->cm_bytes != CM_BYTES ||
        h->bloom_bytes != BLOOM_BYTES || h->total_len != need) {
        ESP_LOGW(TAG, "ckpt: header mismatch — ignored (firmware/model changed?)");
        return false;
    }
    uint16_t want; memcpy(&want, in + need - sizeof(uint16_t), sizeof(want));
    if (cl_crc16(in, need - sizeof(uint16_t)) != want) {
        ESP_LOGW(TAG, "ckpt: bad CRC — ignored");
        return false;
    }

    B.born_boot   = h->born_boot;
    B.total_scans = h->total_scans;
    B.total_obs   = h->total_obs;
    B.unique_est  = h->unique_est;
    B.ema_total_x1000 = h->ema_total_x1000;
    B.ema_wifi_x1000  = h->ema_wifi_x1000;
    B.ema_ble_x1000   = h->ema_ble_x1000;
    B.last_wifi = h->last_wifi; B.last_ble = h->last_ble;
    B.last_new  = h->last_new;  B.last_total = h->last_total;
    const uint8_t *p = in + sizeof(*h);
    memcpy(B.cm, p, CM_BYTES);        p += CM_BYTES;
    memcpy(B.bloom, p, BLOOM_BYTES);
    P.count = h->place_count > PLACE_MAX ? PLACE_MAX : h->place_count;
    P.cur   = h->place_cur; P.sim = h->place_sim;
    P.known = h->place_known != 0; P.is_new = h->place_is_new != 0;
    P.seq   = h->place_seq;
    memcpy(P.places, h->places, sizeof(P.places));

    persist_save();
    ESP_LOGI(TAG, "ckpt: restored full model — scans=%lu uniq~%lu places=%u",
             (unsigned long)B.total_scans, (unsigned long)B.unique_est, (unsigned)P.count);
    return true;
}

void epup_brain_reset(void)
{
    uint32_t born = B.born_boot;
    uint16_t *cm = B.cm; uint8_t *bloom = B.bloom; bool ready = B.ready;
    memset(&B, 0, sizeof(B));
    B.born_boot = born; B.cm = cm; B.bloom = bloom; B.ready = ready;
    if (B.cm)    memset(B.cm, 0, CM_DEPTH * CM_WIDTH * sizeof(uint16_t));
    if (B.bloom) memset(B.bloom, 0, BLOOM_BITS / 8);
    memset(&P, 0, sizeof(P)); P.cur = -1;
    persist_save();
    ESP_LOGW(TAG, "brain reset — fresh puppy");
}
