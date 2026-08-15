#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_http_server.h"

bool viewer_gz_ready(void);

esp_err_t viewer_gz_begin(httpd_req_t *req, bool no_store);

esp_err_t viewer_gz_island(httpd_req_t *req, const void *data, size_t len);

esp_err_t viewer_gz_finish(httpd_req_t *req);

uint32_t viewer_gz_crc32(uint32_t crc, const void *data, size_t len);
uint32_t viewer_gz_crc32_combine(uint32_t crc1, uint32_t crc2, uint32_t len2);
