#include "viewer_gz.h"

#include <string.h>

#include "esp_log.h"

#include "viewer_gz_meta.h"

static const char *TAG = "viewer_gz";

#ifndef VIEWER_GZ_TEST_BLOBS
extern const uint8_t _binary_viewer_head_deflate_start[];
extern const uint8_t _binary_viewer_head_deflate_end[];
extern const uint8_t _binary_viewer_tail_deflate_start[];
extern const uint8_t _binary_viewer_tail_deflate_end[];
#endif

#define STORED_MAX 65535u

static uint32_t s_isl_crc;
static uint32_t s_isl_len;

static const uint32_t CRC_NIB[16] = {
    0x00000000u, 0x1db71064u, 0x3b6e20c8u, 0x26d930acu,
    0x76dc4190u, 0x6b6b51f4u, 0x4db26158u, 0x5005713cu,
    0xedb88320u, 0xf00f9344u, 0xd6d6a3e8u, 0xcb61b38cu,
    0x9b64c2b0u, 0x86d3d2d4u, 0xa00ae278u, 0xbdbdf21cu,
};

uint32_t viewer_gz_crc32(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    crc = ~crc;
    while (len--) {
        crc ^= *p++;
        crc = (crc >> 4) ^ CRC_NIB[crc & 0x0Fu];
        crc = (crc >> 4) ^ CRC_NIB[crc & 0x0Fu];
    }
    return ~crc;
}

static uint32_t gf2_times(const uint32_t *mat, uint32_t vec)
{
    uint32_t sum = 0;
    int i = 0;
    while (vec) {
        if (vec & 1u) sum ^= mat[i];
        vec >>= 1;
        i++;
    }
    return sum;
}

static void gf2_square(uint32_t *dst, const uint32_t *src)
{
    for (int n = 0; n < 32; n++) dst[n] = gf2_times(src, src[n]);
}

uint32_t viewer_gz_crc32_combine(uint32_t crc1, uint32_t crc2, uint32_t len2)
{
    if (len2 == 0) return crc1;

    uint32_t odd[32], even[32];
    odd[0] = 0xedb88320u;
    uint32_t row = 1;
    for (int n = 1; n < 32; n++) { odd[n] = row; row <<= 1; }

    gf2_square(even, odd);
    gf2_square(odd, even);

    for (;;) {
        gf2_square(even, odd);
        if (len2 & 1u) crc1 = gf2_times(even, crc1);
        len2 >>= 1;
        if (len2 == 0) break;
        gf2_square(odd, even);
        if (len2 & 1u) crc1 = gf2_times(odd, crc1);
        len2 >>= 1;
        if (len2 == 0) break;
    }
    return crc1 ^ crc2;
}

static size_t head_z_len(void)
{
    return (size_t)(_binary_viewer_head_deflate_end -
                    _binary_viewer_head_deflate_start);
}

static size_t tail_z_len(void)
{
    return (size_t)(_binary_viewer_tail_deflate_end -
                    _binary_viewer_tail_deflate_start);
}

bool viewer_gz_ready(void)
{
    return head_z_len() > 0 && tail_z_len() > 0;
}

esp_err_t viewer_gz_begin(httpd_req_t *req, bool no_store)
{
    if (!viewer_gz_ready()) return ESP_ERR_INVALID_STATE;

    s_isl_crc = 0;
    s_isl_len = 0;

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");

    httpd_resp_set_hdr(req, "Vary", "Accept-Encoding");
    if (no_store) httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    static const char GZ_HDR[10] = {
        '\x1f', '\x8b', 8, 0, 0, 0, 0, 0, 2, '\xff'
    };
    if (httpd_resp_send_chunk(req, GZ_HDR, sizeof GZ_HDR) != ESP_OK)
        return ESP_FAIL;

    return httpd_resp_send_chunk(req,
                                 (const char *)_binary_viewer_head_deflate_start,
                                 head_z_len());
}

esp_err_t viewer_gz_island(httpd_req_t *req, const void *data, size_t len)
{
    if (len == 0) return ESP_OK;

    const uint8_t *p = (const uint8_t *)data;
    size_t left = len;

    while (left) {
        uint16_t n = (left > STORED_MAX) ? (uint16_t)STORED_MAX : (uint16_t)left;

        uint8_t hdr[5];
        hdr[0] = 0x00;
        hdr[1] = (uint8_t)(n & 0xFFu);
        hdr[2] = (uint8_t)(n >> 8);
        hdr[3] = (uint8_t)(~n & 0xFFu);
        hdr[4] = (uint8_t)((~n >> 8) & 0xFFu);

        if (httpd_resp_send_chunk(req, (const char *)hdr, sizeof hdr) != ESP_OK)
            return ESP_FAIL;
        if (httpd_resp_send_chunk(req, (const char *)p, n) != ESP_OK)
            return ESP_FAIL;

        s_isl_crc = viewer_gz_crc32(s_isl_crc, p, n);
        s_isl_len += n;
        p += n;
        left -= n;
    }
    return ESP_OK;
}

esp_err_t viewer_gz_finish(httpd_req_t *req)
{
    if (httpd_resp_send_chunk(req,
                              (const char *)_binary_viewer_tail_deflate_start,
                              tail_z_len()) != ESP_OK)
        return ESP_FAIL;

    uint32_t crc = viewer_gz_crc32_combine(VIEWER_GZ_HEAD_RAW_CRC,
                                           s_isl_crc, s_isl_len);
    crc = viewer_gz_crc32_combine(crc, VIEWER_GZ_TAIL_RAW_CRC,
                                  VIEWER_GZ_TAIL_RAW_LEN);

    uint32_t isize = VIEWER_GZ_HEAD_RAW_LEN + s_isl_len + VIEWER_GZ_TAIL_RAW_LEN;

    uint8_t trailer[8];
    for (int i = 0; i < 4; i++) trailer[i]     = (uint8_t)(crc   >> (8 * i));
    for (int i = 0; i < 4; i++) trailer[4 + i] = (uint8_t)(isize >> (8 * i));

    if (httpd_resp_send_chunk(req, (const char *)trailer, sizeof trailer) != ESP_OK)
        return ESP_FAIL;

    ESP_LOGD(TAG, "gz: %u island bytes, %u uncompressed total",
             (unsigned)s_isl_len, (unsigned)isize);

    s_isl_crc = 0;
    s_isl_len = 0;
    return httpd_resp_send_chunk(req, NULL, 0);
}
