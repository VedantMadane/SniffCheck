#include "passive_correlation.h"

#include <string.h>
#include <stdio.h>

#include "esp_attr.h"
#include "esp_log.h"

#include "env_learn.h"
#include "infra_cluster.h"

static const char *TAG = "sc_corr";

#define PC_MAX_NODES      384
#define PC_MAX_EDGES     2048
#define PC_WIN_MAX         64

#define PC_MIN_WINDOWS      3
#define PC_MIN_DIRECTION   60
#define PC_MISS_WINDOWS     2
#define PC_EDGE_TTL        24

#define PC_STABLE_MIN_WINDOWS 8
#define PC_STABLE_PCT        90

typedef struct {
    uint8_t  addr[6];
    uint8_t  radio;
    uint8_t  flags;
    uint16_t label_id;
    uint16_t windows_seen;
    uint16_t first_window;
    uint16_t last_window;
    uint16_t arrive_window;
    int8_t   env_idx;
    uint8_t  rssi_now;
    uint8_t  rssi_prev;
    bool     present;
    bool     was_present;
    bool     used;
} pc_node_t;

#define PC_NF_RANDOMIZED  0x01
#define PC_NF_INFRA       0x02
#define PC_NF_STABLE      0x04
#define PC_NF_WAS_ABSENT  0x08

typedef struct {
    uint16_t a, b;
    uint16_t together;
    uint16_t a_windows;
    uint16_t b_windows;
    uint16_t apart;
    uint16_t arrivals, arrive_events;
    uint16_t departures, depart_events;
    uint16_t trend_match, trend_samples;
    uint16_t last_window;
    bool     used;
} pc_edge_t;

static EXT_RAM_BSS_ATTR pc_node_t s_nodes[PC_MAX_NODES];
static EXT_RAM_BSS_ATTR pc_edge_t s_edges[PC_MAX_EDGES];

static uint16_t s_window;
static uint16_t s_node_count, s_edge_count, s_edges_dropped;
static uint16_t s_label_seq[3];
static bool     s_window_open;
static int8_t   s_env_now;

void pc_init(void) { pc_reset(); }

void pc_reset(void)
{
    memset(s_nodes, 0, sizeof(s_nodes));
    memset(s_edges, 0, sizeof(s_edges));
    memset(s_label_seq, 0, sizeof(s_label_seq));
    s_window = s_node_count = s_edge_count = s_edges_dropped = 0;
    s_window_open = false;
    s_env_now = -1;
}

static pc_rssi_bucket_t rssi_bucket(int8_t rssi)
{
    if (rssi >= -50) return PC_RSSI_VERY_STRONG;
    if (rssi >= -62) return PC_RSSI_STRONG;
    if (rssi >= -74) return PC_RSSI_MEDIUM;
    if (rssi >= -85) return PC_RSSI_WEAK;
    return PC_RSSI_VERY_WEAK;
}

static int node_find_or_add(const uint8_t addr[6], pc_radio_t radio, uint8_t flags)
{
    for (int i = 0; i < s_node_count; i++) {
        if (s_nodes[i].used && s_nodes[i].radio == (uint8_t)radio &&
            memcmp(s_nodes[i].addr, addr, 6) == 0) return i;
    }
    if (s_node_count >= PC_MAX_NODES) return -1;

    int idx = s_node_count++;
    pc_node_t *n = &s_nodes[idx];
    memset(n, 0, sizeof(*n));
    memcpy(n->addr, addr, 6);
    n->radio    = (uint8_t)radio;
    n->flags    = flags;
    n->used     = true;
    n->label_id = ++s_label_seq[radio];
    n->first_window = n->last_window = n->arrive_window = s_window;
    n->env_idx  = s_env_now;
    n->rssi_now = n->rssi_prev = PC_RSSI_MEDIUM;
    return idx;
}

static void node_label(const pc_node_t *n, char *out, int outsz)
{
    static const char *kind[3] = { "WIFI_AP", "WIFI_DEVICE", "BLE_DEVICE" };
    snprintf(out, outsz, "%s_%u", kind[n->radio < 3 ? n->radio : 2], (unsigned)n->label_id);
}

static pc_edge_t *edge_find_or_add(uint16_t a, uint16_t b)
{
    if (a > b) { uint16_t t = a; a = b; b = t; }
    for (int i = 0; i < s_edge_count; i++)
        if (s_edges[i].used && s_edges[i].a == a && s_edges[i].b == b) return &s_edges[i];

    if (s_edge_count < PC_MAX_EDGES) {
        pc_edge_t *e = &s_edges[s_edge_count++];
        memset(e, 0, sizeof(*e));
        e->a = a; e->b = b; e->used = true;
        e->last_window = s_window;
        return e;
    }

    int worst = -1; uint32_t worst_score = 0xFFFFFFFFu;
    for (int i = 0; i < PC_MAX_EDGES; i++) {
        uint32_t sc = (uint32_t)s_edges[i].together * 1000u + s_edges[i].last_window;
        if (sc < worst_score) { worst_score = sc; worst = i; }
    }
    if (worst < 0) return NULL;
    s_edges_dropped++;
    pc_edge_t *e = &s_edges[worst];
    memset(e, 0, sizeof(*e));
    e->a = a; e->b = b; e->used = true;
    e->last_window = s_window;
    return e;
}

void pc_window_begin(void)
{
    if (s_window_open) return;
    s_window_open = true;

    env_status_t st;
    env_learn_status(&st);
    s_env_now = st.cur;

    for (int i = 0; i < s_node_count; i++) {
        s_nodes[i].was_present = s_nodes[i].present;
        s_nodes[i].present     = false;
    }
}

static void observe(const uint8_t addr[6], pc_radio_t radio, uint8_t flags, int8_t rssi)
{
    if (!s_window_open || !addr) return;
    int idx = node_find_or_add(addr, radio, flags);
    if (idx < 0) return;

    pc_node_t *n = &s_nodes[idx];
    if (!n->present) {
        n->present = true;
        n->windows_seen++;
        n->last_window = s_window;
        if (!n->was_present) n->arrive_window = s_window;
        n->rssi_prev = n->rssi_now;
        n->rssi_now  = (uint8_t)rssi_bucket(rssi);

        if (n->env_idx != -2 && n->env_idx != s_env_now) n->env_idx = -2;

        if (n->windows_seen >= PC_STABLE_MIN_WINDOWS &&
            (uint32_t)n->windows_seen * 100u >= (uint32_t)(s_window + 1) * PC_STABLE_PCT)
            n->flags |= PC_NF_STABLE;
    }
}

void pc_observe_wifi_ap(const uint8_t bssid[6], int8_t rssi)
{

    uint8_t flags = env_learn_is_fixture(infra_place_key(bssid)) ? PC_NF_INFRA : 0;
    observe(bssid, PC_RADIO_WIFI_AP, flags, rssi);
}

void pc_observe_wifi_sta(const uint8_t mac[6], bool randomized, int8_t rssi)
{
    observe(mac, PC_RADIO_WIFI_STA, randomized ? PC_NF_RANDOMIZED : 0, rssi);
}

void pc_observe_ble(const uint8_t addr[6], uint8_t addr_subtype, int8_t rssi)
{

    bool rnd = (addr_subtype >= 1);
    observe(addr, PC_RADIO_BLE, rnd ? PC_NF_RANDOMIZED : 0, rssi);
}

void pc_window_end(void)
{
    if (!s_window_open) return;
    s_window_open = false;

    uint16_t win[PC_WIN_MAX];
    int wn = 0;
    for (int i = 0; i < s_node_count && wn < PC_WIN_MAX; i++) {
        if (!s_nodes[i].present) continue;
        if (s_nodes[i].flags & PC_NF_INFRA) continue;
        win[wn++] = (uint16_t)i;
    }

    for (int x = 0; x < wn; x++) {
        for (int y = x + 1; y < wn; y++) {
            pc_node_t *na = &s_nodes[win[x]], *nb = &s_nodes[win[y]];
            if ((na->flags & PC_NF_STABLE) && (nb->flags & PC_NF_STABLE)) continue;

            pc_edge_t *e = edge_find_or_add(win[x], win[y]);
            if (!e) continue;
            e->together++;
            e->a_windows++;
            e->b_windows++;
            e->last_window = s_window;

            bool a_new = (na->arrive_window == s_window) && (na->flags & PC_NF_WAS_ABSENT);
            bool b_new = (nb->arrive_window == s_window) && (nb->flags & PC_NF_WAS_ABSENT);
            if (a_new || b_new) {
                e->arrive_events++;
                if (a_new && b_new) e->arrivals++;
            }

            if (na->rssi_now != na->rssi_prev || nb->rssi_now != nb->rssi_prev) {
                int da = (int)na->rssi_now - (int)na->rssi_prev;
                int db = (int)nb->rssi_now - (int)nb->rssi_prev;
                e->trend_samples++;
                if ((da > 0 && db > 0) || (da < 0 && db < 0)) e->trend_match++;
            }
        }
    }

    for (int i = 0; i < s_edge_count; i++) {
        pc_edge_t *e = &s_edges[i];
        if (!e->used || e->last_window == s_window) continue;
        pc_node_t *na = &s_nodes[e->a], *nb = &s_nodes[e->b];
        if (na->present || nb->present) {
            e->apart++;
            if (na->present) e->a_windows++;
            if (nb->present) e->b_windows++;

            bool a_gone = (!na->present && na->was_present);
            bool b_gone = (!nb->present && nb->was_present);
            if (a_gone || b_gone) {
                e->depart_events++;
                if (a_gone && b_gone) e->departures++;
            }
        }
    }

    for (int i = 0; i < s_node_count; i++)
        if (s_nodes[i].used && !s_nodes[i].present && s_window > 0)
            s_nodes[i].flags |= PC_NF_WAS_ABSENT;

    for (int i = 0; i < s_edge_count; i++) {
        pc_edge_t *e = &s_edges[i];
        if (!e->used) continue;
        uint16_t age = (uint16_t)(s_window - e->last_window);
        if (age > PC_EDGE_TTL + e->together * 2) e->used = false;
    }

    s_window++;
}

static uint8_t pc_score(const pc_edge_t *e, const pc_node_t *na, const pc_node_t *nb,
                        uint8_t *pba, uint8_t *pab, bool *trend, bool *same_env)
{
    uint32_t a_n = e->a_windows ? e->a_windows : 1;
    uint32_t b_n = e->b_windows ? e->b_windows : 1;
    uint32_t p1 = (uint32_t)e->together * 100u / a_n;
    uint32_t p2 = (uint32_t)e->together * 100u / b_n;
    if (p1 > 100) p1 = 100;
    if (p2 > 100) p2 = 100;

    uint32_t copres = p1 < p2 ? p1 : p2;

    uint32_t arr = e->arrive_events ? (uint32_t)e->arrivals * 100u / e->arrive_events : 0;
    uint32_t dep = e->depart_events ? (uint32_t)e->departures * 100u / e->depart_events : 0;
    uint32_t trn = e->trend_samples ? (uint32_t)e->trend_match * 100u / e->trend_samples : 0;

    bool env_ok = (na->env_idx >= 0 && na->env_idx == nb->env_idx);
    uint32_t env = env_ok ? 100u : 0u;

    uint32_t score = (41u * copres + 18u * arr + 18u * dep + 12u * trn + 11u * env) / 100u;

    if (pba)      *pba = (uint8_t)p1;
    if (pab)      *pab = (uint8_t)p2;
    if (trend)    *trend = (e->trend_samples > 0 && trn >= 60);
    if (same_env) *same_env = env_ok;
    return (uint8_t)(score > 100 ? 100 : score);
}

void pc_get_stats(pc_stats_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->windows       = s_window;
    out->nodes         = s_node_count;
    out->edges_dropped = s_edges_dropped;

    for (int i = 0; i < s_node_count; i++)
        if (s_nodes[i].used && (s_nodes[i].flags & PC_NF_INFRA)) out->infrastructure++;

    for (int i = 0; i < s_edge_count; i++) {
        pc_edge_t *e = &s_edges[i];
        if (!e->used) continue;
        out->edges++;
        uint8_t p1, p2; bool tr, se;
        pc_score(e, &s_nodes[e->a], &s_nodes[e->b], &p1, &p2, &tr, &se);
        if (e->together >= PC_MIN_WINDOWS && p1 >= PC_MIN_DIRECTION &&
            p2 >= PC_MIN_DIRECTION && (e->arrivals || e->departures))
            out->surfaced++;
    }
}

int pc_top_pairs(pc_pair_t *out, int max)
{
    if (!out || max <= 0) return 0;
    int n = 0;

    for (int i = 0; i < s_edge_count; i++) {
        pc_edge_t *e = &s_edges[i];
        if (!e->used) continue;

        uint8_t p1, p2; bool tr, se;
        pc_node_t *na = &s_nodes[e->a], *nb = &s_nodes[e->b];
        uint8_t conf = pc_score(e, na, nb, &p1, &p2, &tr, &se);

        if (e->together < PC_MIN_WINDOWS) continue;
        if (p1 < PC_MIN_DIRECTION || p2 < PC_MIN_DIRECTION) continue;

        if (e->arrivals == 0 && e->departures == 0) continue;

        pc_pair_t p;
        memset(&p, 0, sizeof(p));
        node_label(na, p.a_label, sizeof(p.a_label));
        node_label(nb, p.b_label, sizeof(p.b_label));
        p.confidence  = conf;
        p.together    = e->together;
        p.a_windows   = e->a_windows;
        p.b_windows   = e->b_windows;
        p.apart       = e->apart;
        p.arrivals    = e->arrivals;
        p.departures  = e->departures;
        p.p_b_given_a = p1;
        p.p_a_given_b = p2;
        p.rssi_trend_similar = tr;
        p.same_environment   = se;

        int at = n;
        while (at > 0 && out[at - 1].confidence < p.confidence) {
            if (at < max) out[at] = out[at - 1];
            at--;
        }
        if (at < max) {
            out[at] = p;
            if (n < max) n++;
        }
    }

    ESP_LOGD(TAG, "pairs: %d surfaced of %u edges, %u windows", n,
             (unsigned)s_edge_count, (unsigned)s_window);
    return n;
}
