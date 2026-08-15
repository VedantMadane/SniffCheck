#include "env_learn.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
#include "nvs.h"
#include "infra_cluster.h"

static const char *TAG = "sc_env";

#define ENV_NVS_NS      "envlearn"
#define ENV_NVS_BLOB    "envs"

#define WIN_MAX            48
#define ENV_MIN_UNITS      2
#define ENV_MATCH_PCT      35
#define ENV_MIN_DISTINCT   2
#define ENV_KNOWN_MIN      3
#define LM_CONFIRM_SCANS   2
#define LM_PRUNE_AFTER     6
#define LM_PRUNE_PCT       15

#define ENV_SCHEMA_VER     2
#define ENV_MAGIC          0xE7

typedef struct __attribute__((packed)) {
    uint64_t unit;
    uint16_t hits;
    uint8_t  scans_seen;
    uint8_t  flags;
    char     name[ENV_LM_NAME];
} landmark_t;

typedef struct __attribute__((packed)) {
    landmark_t lm[ENV_LM_MAX];
    uint8_t    lm_count;
    uint8_t    quality;
    char       label[ENV_LABEL_MAX];
    uint32_t   scans;
    uint32_t   born_boot;
    uint32_t   last_seq;
} place_t;

typedef struct { uint64_t unit; uint16_t cnt; char name[ENV_LM_NAME]; } win_unit_t;

static struct {
    place_t  places[ENV_MAX];
    uint8_t  count;
    int8_t   cur;
    uint8_t  sim;
    bool     known;
    bool     is_new;
    uint32_t seq;
    uint32_t born_boot;
} P = { .cur = -1 };

static struct {
    bool    active;
    int8_t  target;
    uint8_t want, done;
    bool    reposition;
    bool    fresh;
    char    label[ENV_LABEL_MAX];
} L = { .target = -1 };

static win_unit_t s_win[WIN_MAX];
static int        s_win_n;
static bool       s_win_open;

static uint16_t env_crc16(const uint8_t *d, size_t n)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint16_t)d[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

typedef struct __attribute__((packed)) {
    uint8_t  magic, schema_ver, count;
    int8_t   cur;
    uint32_t seq;
    place_t  places[ENV_MAX];
    uint16_t crc;
} env_persist_t;

static void persist_save(void)
{
    nvs_handle_t h;
    if (nvs_open(ENV_NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    env_persist_t *pp = calloc(1, sizeof(*pp));
    if (!pp) { nvs_close(h); return; }
    pp->magic = ENV_MAGIC; pp->schema_ver = ENV_SCHEMA_VER;
    pp->count = P.count; pp->cur = P.cur; pp->seq = P.seq;
    memcpy(pp->places, P.places, sizeof(pp->places));
    pp->crc = env_crc16((const uint8_t *)pp, sizeof(*pp) - sizeof(pp->crc));

    esp_err_t err = nvs_set_blob(h, ENV_NVS_BLOB, pp, sizeof(*pp));
    if (err == ESP_OK) err = nvs_commit(h);
    if (err != ESP_OK)
        ESP_LOGE(TAG, "environment persist FAILED (%s) — places will not survive "
                      "a reboot; nvs partition is %u B and this blob is %u B",
                 esp_err_to_name(err), (unsigned)0x6000, (unsigned)sizeof(*pp));
    nvs_close(h);
    free(pp);
}

static void persist_load(void)
{
    nvs_handle_t h;
    if (nvs_open(ENV_NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    env_persist_t *pp = calloc(1, sizeof(*pp));
    if (!pp) { nvs_close(h); return; }
    size_t sz = sizeof(*pp);
    esp_err_t e = nvs_get_blob(h, ENV_NVS_BLOB, pp, &sz);
    nvs_close(h);
    if (e == ESP_OK && sz == sizeof(*pp) &&
        pp->magic == ENV_MAGIC && pp->schema_ver == ENV_SCHEMA_VER &&
        env_crc16((const uint8_t *)pp, sizeof(*pp) - sizeof(pp->crc)) == pp->crc &&
        pp->count <= ENV_MAX) {
        P.count = pp->count;
        P.seq   = pp->seq;

        P.cur = -1;
        memcpy(P.places, pp->places, sizeof(P.places));
    }
    free(pp);
}

static void label_copy(char *dst, size_t dstsz, const char *src)
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

static landmark_t *lm_find(place_t *p, uint64_t unit)
{
    for (int i = 0; i < p->lm_count; i++) if (p->lm[i].unit == unit) return &p->lm[i];
    return NULL;
}

static int lm_confirmed(const place_t *p)
{
    int c = 0;
    for (int i = 0; i < p->lm_count; i++) if (p->lm[i].flags & ENV_LM_CONFIRMED) c++;
    return c;
}

static int unit_df(uint64_t unit)
{
    int df = 0;
    for (int i = 0; i < P.count; i++) if (lm_find(&P.places[i], unit)) df++;
    return df;
}

static int unit_weight(uint64_t unit) { return 100 / (unit_df(unit) + 1); }

static landmark_t *lm_weakest(place_t *p)
{
    landmark_t *w = NULL;
    for (int i = 0; i < p->lm_count; i++) {
        landmark_t *l = &p->lm[i];
        if (l->flags & ENV_LM_PINNED) continue;
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
        bool keep = (l->flags & (ENV_LM_PINNED | ENV_LM_CONFIRMED)) ||
                    ((uint32_t)l->scans_seen * 100 >= p->scans * LM_PRUNE_PCT);
        if (keep) { if (o != i) p->lm[o] = *l; o++; }
    }
    p->lm_count = (uint8_t)o;
}

static void place_prune_enroll(place_t *p, int want)
{
    int need = (want + 1) / 2; if (need < 1) need = 1;
    int o = 0;
    for (int i = 0; i < p->lm_count; i++) {
        landmark_t *l = &p->lm[i];
        if ((l->flags & ENV_LM_PINNED) || l->scans_seen >= need) {
            if (o != i) p->lm[o] = *l;
            o++;
        }
    }
    p->lm_count = (uint8_t)o;
}

static void place_absorb(place_t *pl, const win_unit_t *win, int win_n)
{
    for (int w = 0; w < win_n; w++) {
        landmark_t *lm = lm_find(pl, win[w].unit);
        if (!lm) {
            lm = (pl->lm_count < ENV_LM_MAX) ? &pl->lm[pl->lm_count++] : lm_weakest(pl);
            if (!lm) continue;
            if (lm->unit != win[w].unit) { memset(lm, 0, sizeof(*lm)); lm->unit = win[w].unit; }
        }
        if (lm->hits < 0xFFFF) lm->hits = (uint16_t)(lm->hits + win[w].cnt);
        if (lm->scans_seen < 0xFF) lm->scans_seen++;
        if (lm->name[0] == '\0' && win[w].name[0]) {
            snprintf(lm->name, ENV_LM_NAME, "%s", win[w].name);
        }
        if (lm->scans_seen >= LM_CONFIRM_SCANS) lm->flags |= ENV_LM_CONFIRMED;
    }
}

static int place_new_slot(void)
{
    int idx;
    if (P.count < ENV_MAX) {
        idx = P.count++;
    } else {
        idx = 0;
        uint32_t oldest = P.places[0].last_seq;
        for (int i = 1; i < P.count; i++)
            if (P.places[i].last_seq < oldest) { oldest = P.places[i].last_seq; idx = i; }
    }
    memset(&P.places[idx], 0, sizeof(place_t));
    P.places[idx].born_boot = P.born_boot;
    return idx;
}

static int place_best_match(const win_unit_t *win, int win_n, int *sim_out)
{
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

                if (unit_df(win[w].unit) <= 1) distinct++;
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

    if (sim_out) *sim_out = best_sim < 0 ? 0 : best_sim;
    bool matched = (best >= 0 && best_sim >= ENV_MATCH_PCT &&
                    best_distinct >= ENV_MIN_DISTINCT);
    return matched ? best : -1;
}

static void place_enroll(const win_unit_t *win, int win_n)
{
    if (win_n < ENV_MIN_UNITS) { P.sim = 0; P.is_new = false; return; }

    if (L.target < 0) {
        int idx;

        int found = (!L.fresh && P.cur < 0) ? place_best_match(win, win_n, NULL) : -1;
        if (!L.fresh && P.cur >= 0 && P.cur < P.count) {
            idx = P.cur; P.is_new = false;
        } else if (found >= 0) {
            idx = found; P.is_new = false;
        } else {
            idx = place_new_slot();
            P.is_new = true;
        }
        L.target = (int8_t)idx;

        if (L.label[0]) snprintf(P.places[idx].label, ENV_LABEL_MAX, "%s", L.label);
    }

    place_t *pl = &P.places[L.target];
    pl->scans++;
    pl->last_seq = ++P.seq;
    place_absorb(pl, win, win_n);
    L.done++;

    P.cur   = L.target;
    P.sim   = 100;
    P.known = (lm_confirmed(pl) >= ENV_MIN_DISTINCT);

    if (L.done >= L.want) {
        if (L.reposition) {
            place_prune_enroll(pl, L.want);
            pl->quality = 100;
        } else {
            pl->quality = 55;
        }
        P.known = (lm_confirmed(pl) >= ENV_MIN_DISTINCT);
        ESP_LOGI(TAG, "learn done: env[%d] \"%s\" %d fixtures (%s, q=%u)",
                 L.target, pl->label, lm_confirmed(pl),
                 L.reposition ? "repositioned" : "stationary", (unsigned)pl->quality);
        L.active = false; L.target = -1;
    }
    persist_save();
}

static void place_fold(const win_unit_t *win, int win_n)
{
    if (L.active) { place_enroll(win, win_n); return; }
    if (win_n < ENV_MIN_UNITS) { P.sim = 0; P.is_new = false; return; }

    int best_sim = 0;
    int best = place_best_match(win, win_n, &best_sim);

    int idx;
    if (best >= 0) {
        idx = best; P.is_new = false;
    } else {
        idx = place_new_slot();
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
    P.known = (pl->scans >= ENV_KNOWN_MIN && lm_confirmed(pl) >= ENV_MIN_DISTINCT);

    persist_save();
}

void env_learn_init(uint32_t boot_count)
{
    P.born_boot = boot_count;
    persist_load();
    ESP_LOGI(TAG, "environments: %u stored", (unsigned)P.count);
}

void env_learn_scan_begin(void)
{
    s_win_n = 0;
    s_win_open = true;
}

void env_learn_scan_ap(const uint8_t bssid[6], const char *ssid)
{
    if (!s_win_open || !bssid) return;

    uint64_t u = infra_place_key(bssid);
    for (int k = 0; k < s_win_n; k++)
        if (s_win[k].unit == u) {
            if (s_win[k].cnt < 0xFFFF) s_win[k].cnt++;
            return;
        }
    if (s_win_n >= WIN_MAX) return;

    s_win[s_win_n].unit = u;
    s_win[s_win_n].cnt  = 1;
    if (ssid && ssid[0]) {
        label_copy(s_win[s_win_n].name, ENV_LM_NAME, ssid);
    } else {

        snprintf(s_win[s_win_n].name, ENV_LM_NAME, "%02x:%02x:%02x\xC2\xB7unit",
                 bssid[0], bssid[1], bssid[2]);
    }
    s_win_n++;
}

void env_learn_scan_end(void)
{
    if (!s_win_open) return;
    s_win_open = false;

    place_fold(s_win, s_win_n);

    ESP_LOGI(TAG, "fold: %d units -> env %d/%u sim=%u%% %s%s",
             s_win_n, (int)P.cur, (unsigned)P.count, (unsigned)P.sim,
             P.known ? "known" : "new-ish", P.is_new ? " *NEW*" : "");
}

void env_learn_status(env_status_t *out)
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
        out->scans   = pl->scans;
        out->quality = pl->quality;
        snprintf(out->label, sizeof(out->label), "%s", pl->label);
    }
}

int env_learn_list(env_entry_t *out, int max)
{
    if (!out || max <= 0) return 0;
    int n = P.count < max ? P.count : max;
    for (int i = 0; i < n; i++) {
        const place_t *pl = &P.places[i];
        out[i].idx       = (uint8_t)i;
        out[i].landmarks = (uint8_t)lm_confirmed(pl);
        out[i].quality   = pl->quality;
        out[i].scans     = pl->scans;
        out[i].known     = (pl->scans >= ENV_KNOWN_MIN &&
                            lm_confirmed(pl) >= ENV_MIN_DISTINCT);
        out[i].current   = (P.cur == (int8_t)i);
        snprintf(out[i].label, sizeof(out[i].label), "%s", pl->label);
    }
    return n;
}

int env_learn_detail(int idx, env_landmark_t *out, int max)
{
    if (idx < 0 || idx >= P.count || !out || max <= 0) return 0;
    place_t *p = &P.places[idx];
    int n = p->lm_count < max ? p->lm_count : max;
    for (int i = 0; i < n; i++) {
        out[i].unit       = p->lm[i].unit;
        out[i].hits       = p->lm[i].hits;
        out[i].scans_seen = p->lm[i].scans_seen;
        out[i].flags      = p->lm[i].flags;
        snprintf(out[i].name, sizeof(out[i].name), "%s", p->lm[i].name);
    }
    return n;
}

void env_learn_label(int idx, const char *label)
{
    if (idx < 0) idx = P.cur;
    if (idx < 0 || idx >= P.count || !label) return;
    label_copy(P.places[idx].label, ENV_LABEL_MAX, label);
    persist_save();
    ESP_LOGI(TAG, "env[%d] named \"%s\"", idx, P.places[idx].label);
}

void env_learn_forget(int idx)
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
    ESP_LOGW(TAG, "environment %d forgotten (%u left)", idx, (unsigned)P.count);
}

void env_learn_landmark_pin(int idx, uint64_t unit, bool pin)
{
    if (idx < 0 || idx >= P.count) return;
    landmark_t *l = lm_find(&P.places[idx], unit);
    if (!l) return;
    if (pin) l->flags |= ENV_LM_PINNED;
    else     l->flags &= (uint8_t)~ENV_LM_PINNED;
    persist_save();
}

void env_learn_landmark_delete(int idx, uint64_t unit)
{
    if (idx < 0 || idx >= P.count) return;
    place_t *p = &P.places[idx];
    for (int i = 0; i < p->lm_count; i++) {
        if (p->lm[i].unit != unit) continue;
        for (int k = i + 1; k < p->lm_count; k++) p->lm[k - 1] = p->lm[k];
        p->lm_count--;
        persist_save();
        return;
    }
}

bool env_learn_is_fixture(uint64_t unit)
{
    if (P.cur < 0 || P.cur >= (int)P.count) return false;
    const landmark_t *lm = lm_find(&P.places[P.cur], unit);
    return lm && (lm->flags & (ENV_LM_CONFIRMED | ENV_LM_PINNED)) != 0;
}

void env_learn_reset(void)
{
    memset(&P.places, 0, sizeof(P.places));
    P.count = 0; P.cur = -1; P.sim = 0; P.known = false; P.is_new = false;
    L.active = false; L.target = -1;
    persist_save();
    ESP_LOGW(TAG, "all environments forgotten");
}

void env_learn_start(int want_scans, bool reposition, bool fresh,
                     const char *label)
{
    if (want_scans < 1)  want_scans = 1;
    if (want_scans > 20) want_scans = 20;
    L.active     = true;
    L.target     = -1;
    L.want       = (uint8_t)want_scans;
    L.done       = 0;
    L.reposition = reposition;
    L.fresh      = fresh;
    if (label && label[0]) label_copy(L.label, sizeof(L.label), label);
    else                   L.label[0] = '\0';
    ESP_LOGI(TAG, "learn start: %d scans, %s, %s environment%s%s", want_scans,
             reposition ? "repositioning" : "stationary",
             fresh ? "new" : "current",
             L.label[0] ? " named " : "", L.label);
}

void env_learn_cancel(void)
{
    if (!L.active) return;
    L.active = false; L.target = -1;
    ESP_LOGW(TAG, "learn cancelled");
    persist_save();
}

void env_learn_run_status(env_run_t *out)
{
    if (!out) return;
    out->active     = L.active;
    out->want       = L.want;
    out->done       = L.done;
    out->reposition = L.reposition;
    out->target     = L.target;
}
