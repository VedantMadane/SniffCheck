#include "infra_cluster.h"

#include <string.h>

static inline int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool infra_parse_mac(const char *s, int n, uint8_t out[6])
{
    int got = 0, hi = -1;
    for (int i = 0; i < n && got < 6; i++) {
        char c = s[i];
        if (c == ':' || c == '-') continue;
        int v = hexval(c);
        if (v < 0) return false;
        if (hi < 0) { hi = v; }
        else { out[got++] = (uint8_t)((hi << 4) | v); hi = -1; }
    }
    return got == 6 && hi < 0;
}

static uint64_t mix(uint64_t h)
{
    h ^= h >> 30; h *= 0xBF58476D1CE4E5B9ULL;
    h ^= h >> 27; h *= 0x94D049BB133111EBULL;
    h ^= h >> 31;
    return h;
}

static uint64_t fold(uint64_t h, uint64_t v)
{
    h ^= v; h *= 1099511628211ULL;
    return h;
}

uint64_t infra_unit_key(const uint8_t mac[6], uint32_t ie_pattern_hash)
{

    uint8_t b0 = (uint8_t)(mac[0] & ~0x02u);
    uint64_t h = 1469598103934665603ULL;
    h = fold(h, b0);
    h = fold(h, mac[1]);
    h = fold(h, mac[2]);
    h = fold(h, mac[3]);
    h = fold(h, mac[4]);
    h = fold(h, ie_pattern_hash);
    return mix(h);
}

uint64_t infra_system_key(const uint8_t mac[6], const char *ssid, int ssid_len,
                          uint32_t ie_pattern_hash)
{

    while (ssid_len > 0 && (ssid[0] == ' ')) { ssid++; ssid_len--; }
    while (ssid_len > 0 && (ssid[ssid_len - 1] == ' ')) ssid_len--;
    if (ssid_len <= 0) return infra_unit_key(mac, ie_pattern_hash);

    uint8_t b0 = (uint8_t)(mac[0] & ~0x02u);
    uint64_t h = 1469598103934665603ULL;
    h = fold(h, b0);
    h = fold(h, mac[1]);
    h = fold(h, mac[2]);
    for (int i = 0; i < ssid_len; i++) h = fold(h, (uint8_t)ssid[i]);
    return mix(h);
}
