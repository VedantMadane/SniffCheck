#pragma once

#include "wifi_scanner.h"
#include "ble_scanner.h"
#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#define ANALYZER_MAX_APS  WIFI_SCAN_MAX_APS

#define VERDICT_GREEN   0
#define VERDICT_YELLOW  1
#define VERDICT_ORANGE  2
#define VERDICT_RED     3

#define SCORE_TIER_ENTERPRISE  0
#define SCORE_TIER_KNOWN       1
#define SCORE_TIER_ACCEPTABLE  2
#define SCORE_TIER_SUSPECT     3
#define SCORE_TIER_AVOID       4

#define THREAT_NONE    0
#define THREAT_LOW     1
#define THREAT_MEDIUM  2
#define THREAT_HIGH    3

#define AP_MAX_SIBLINGS  16
typedef struct {
    uint8_t bssid[6];
    int8_t  rssi;
    uint8_t channel;
    bool    band_5g;
} radio_sibling_t;

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    char     vendor[64];
    uint16_t eui_flags;
    uint8_t  device_class;
    int8_t   rssi;
    uint8_t  channel;
    bool     band_5g;

    uint8_t  base_quality;
    uint8_t  hygiene;
    uint8_t  identity_score;
    uint8_t  identity_conf;
    uint8_t  threat_level;

    bool     auto_fail;
    bool     vendor_mismatch;
    bool     twin_detected;
    bool     open_clone;
    bool     deauth_flood;
    bool     karma_suspect;
    bool     pwnagotchi;
    bool     pmkid_exposed;

    wifi_auth_mode_t auth;
    bool     has_wps;
    bool     has_rsn;
    bool     rsn_pmf_required;
    uint16_t beacon_interval;
    uint8_t  vendor_ie_ouis[4][3];
    uint8_t  vendor_ie_count;
    uint8_t  lldp_count;
    uint8_t  cdp_count;
    uint8_t  dhcp_count;

    uint8_t  mac_match_len;
    const char *vendor_ie_names[4];
    char     cdp_device_id[33];
    char     lldp_system_name[33];
    char     dhcp_vendor_class[33];
    uint16_t l2l3_flags;
    uint8_t  l2l3_class;
    uint8_t  l2l3_signal_count;

    char     wps_manufacturer[33];
    char     wps_model_name[33];
    char     country_code[3];
    uint32_t ie_pattern_hash;
    uint8_t  rsn_group_oui[3];
    uint8_t  rsn_group_suite;

    uint8_t  radio_count;
    bool     same_oui_multiband;

    bool     sibling_service_peer;
    uint8_t  sibling_service_bssid[6];

    radio_sibling_t siblings[AP_MAX_SIBLINGS];
    uint8_t  sibling_count;

    bool     suppressed;

    int16_t  ble_match;
    uint8_t  ble_match_conf;

    uint16_t first_seen_scan;
    uint16_t last_seen_scan;
    uint16_t hit_count;
} ap_score_t;

esp_err_t analyzer_run(const scan_results_t *results,
                        const ble_results_t *ble,
                        ap_score_t *scores, uint16_t *count_out);

const ap_score_t *analyzer_best(const ap_score_t *scores, uint16_t count);

void analyzer_xref_ble(ap_score_t *scores, uint16_t count, ble_results_t *ble);

const char *analyzer_verdict_label(uint8_t v);
const char *analyzer_tier_label(uint8_t tier);
const char *analyzer_threat_label(uint8_t lvl);
uint8_t analyzer_threat_to_verdict(uint8_t threat_level);

const char *analyzer_twin_class(const ap_score_t *s);


typedef enum {
    TWIN_TRIGGER_NONE = 0,
    TWIN_TRIGGER_OPEN_CLONE,
    TWIN_TRIGGER_TIER1_SCORE,
    TWIN_TRIGGER_TIER2_FINGERPRINT,
    TWIN_TRIGGER_RELATIONSHIP_ONLY,
} twin_trigger_t;

typedef enum {
    TWIN_REL_UNKNOWN_SAME_SSID_PEER = 0,
    TWIN_REL_LIKELY_SIBLING_VIRTUAL_BSSID,
    TWIN_REL_LIKELY_MANAGED_ESS_PEER,
    TWIN_REL_KNOWN_SERVICE_FAMILY_PEER,
    TWIN_REL_UNRELATED_SAME_SSID_PEER,
} twin_relationship_t;

typedef enum {
    TWIN_DECISION_NO_EVIDENCE = 0,
    TWIN_DECISION_SUSPECT,
    TWIN_DECISION_HIGH_CONFIDENCE,
} twin_decision_t;

#define TWIN_EV_EXACT_SSID_MATCH         (1u <<  0)
#define TWIN_EV_SECURITY_MISMATCH        (1u <<  2)
#define TWIN_EV_SAME_CHANNEL             (1u <<  3)
#define TWIN_EV_CONSERVED_MAC_STRUCTURE  (1u <<  4)
#define TWIN_EV_SAME_PUBLIC_OUI          (1u <<  5)
#define TWIN_EV_SAME_VENDOR_FAMILY       (1u <<  6)
#define TWIN_EV_BOTH_LAA                 (1u <<  7)
#define TWIN_EV_CHAIN_SSID               (1u <<  8)
#define TWIN_EV_RSSI_GAP                 (1u <<  9)
#define TWIN_EV_SUFFIX_DELTA             (1u << 10)
#define TWIN_EV_RSN_MISMATCH             (1u << 11)
#define TWIN_EV_PMF_MISMATCH             (1u << 12)
#define TWIN_EV_WPS_MISMATCH             (1u << 13)
#define TWIN_EV_BEACON_INTERVAL_CONFLICT (1u << 14)
#define TWIN_EV_SAME_BEACON_INTERVAL     (1u << 15)

typedef struct {
    uint8_t  target[6];
    uint8_t  peer[6];
    uint8_t  trigger;
    uint8_t  relationship;
    uint8_t  decision;
    bool     symmetric;
    uint32_t evidence;
    int16_t  weight;
} twin_finding_t;

uint16_t analyzer_twin_finding_count(void);
const twin_finding_t *analyzer_twin_finding(uint16_t idx);

const twin_finding_t *analyzer_twin_finding_for(const uint8_t bssid[6],
                                                 twin_trigger_t trigger);

const char *analyzer_twin_trigger_label(uint8_t t);
const char *analyzer_twin_relationship_label(uint8_t r);
const char *analyzer_twin_decision_label(uint8_t d);

typedef enum {
    CROWD_QUIET = 0,
    CROWD_FEW,
    CROWD_SOME,
    CROWD_BUSY,
    CROWD_CROWDED,
} crowd_bucket_t;

typedef struct {
    uint16_t ble_person_devices;
    uint16_t wifi_stations;
    uint16_t probe_reqs;
    uint16_t device_evidence;
    uint16_t people_low;
    uint16_t people_high;
    crowd_bucket_t bucket;
} crowd_estimate_t;

void analyzer_crowd_estimate(const ble_results_t *ble, uint16_t wifi_stations,
                             uint16_t probe_reqs, crowd_estimate_t *out);

const crowd_estimate_t *analyzer_last_crowd(void);

const char *analyzer_crowd_bucket_label(crowd_bucket_t b);
