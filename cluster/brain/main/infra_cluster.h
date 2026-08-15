#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

bool infra_parse_mac(const char *s, int n, uint8_t out[6]);

uint64_t infra_unit_key(const uint8_t mac[6], uint32_t ie_pattern_hash);

uint64_t infra_place_key(const uint8_t mac[6]);

uint64_t infra_system_key(const uint8_t mac[6], const char *ssid, int ssid_len,
                          uint32_t ie_pattern_hash);

#ifdef __cplusplus
}
#endif
