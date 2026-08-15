#pragma once

#include <stdint.h>

uint8_t arm_addr_claim(void);

void arm_addr_forget(void);

void arm_addr_node_id(uint8_t out[3]);
