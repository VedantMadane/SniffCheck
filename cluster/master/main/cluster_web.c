#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_http_server.h"

#include "cluster_web.h"
#include "master_shim.h"

static const char *TAG = "cluster-web";

#define DEV_LINE_STREAM_MAX 3200

extern const char _binary_dogpark_dashboard_html_start[];

static esp_err_t dogpark_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");

    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, _binary_dogpark_dashboard_html_start, HTTPD_RESP_USE_STRLEN);
}

static double   s_lat = NAN, s_lon = NAN;
static float    s_acc = 0;
static int64_t  s_wall_base_ms = 0;
static int64_t  s_wall_base_us = 0;
static bool     s_have_time = false;

bool cluster_web_gps(double *lat, double *lon, float *acc, int64_t *wall_ms)
{
    if (!s_have_time) return false;
    if (wall_ms) *wall_ms = s_wall_base_ms + (esp_timer_get_time() - s_wall_base_us) / 1000;
    if (lat) *lat = s_lat;
    if (lon) *lon = s_lon;
    if (acc) *acc = s_acc;
    return true;
}

static bool json_num(const char *body, const char *key, double *out)
{
    char pat[24];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return false;
    p = strchr(p + strlen(pat), ':');
    if (!p) return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "null", 4) == 0) return false;
    char *end = NULL;
    double v = strtod(p, &end);
    if (end == p) return false;
    *out = v;
    return true;
}

static esp_err_t gps_post(httpd_req_t *req)
{
    char buf[256];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';

    double ts, lat, lon, acc;
    if (!json_num(buf, "ts", &ts)) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"ts required\"}");
        return ESP_OK;
    }
    s_wall_base_ms = (int64_t)ts;
    s_wall_base_us = esp_timer_get_time();
    s_have_time    = true;
    if (json_num(buf, "lat", &lat) && json_num(buf, "lon", &lon)) {
        s_lat = lat; s_lon = lon;
        s_acc = json_num(buf, "acc", &acc) ? (float)acc : 0.0f;
    } else {
        s_lat = s_lon = NAN;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t status_get(httpd_req_t *req)
{

    char body[1536], fix[160];
    master_cluster_status_json(body, sizeof(body));

    size_t len = strlen(body);
    if (len && body[len - 1] == '}') body[len - 1] = '\0';
    double lat, lon; float acc; int64_t wall;
    if (cluster_web_gps(&lat, &lon, &acc, &wall)) {
        if (isnan(lat))
            snprintf(fix, sizeof(fix), ",\"gps\":{\"fix\":false,\"time\":true,\"wall_ms\":%lld}}",
                     (long long)wall);
        else
            snprintf(fix, sizeof(fix),
                ",\"gps\":{\"fix\":true,\"lat\":%.6f,\"lon\":%.6f,\"acc\":%.1f,\"wall_ms\":%lld}}",
                lat, lon, acc, (long long)wall);
    } else {
        snprintf(fix, sizeof(fix), ",\"gps\":{\"fix\":false,\"time\":false}}");
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, fix, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t log_get(httpd_req_t *req)
{
    static char body[3072];
    master_cluster_log_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t sentinel_get(httpd_req_t *req)
{
    static char body[2048];
    master_cluster_sentinel_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t sentinel_post(httpd_req_t *req)
{
    char buf[320];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_sentinel_cfg(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t tracker_get(httpd_req_t *req)
{
    static char body[2560];
    master_cluster_tracker_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static int recv_body(httpd_req_t *req, char *buf, int cap)
{
    int n = req->content_len < cap - 1 ? req->content_len : cap - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    buf[got] = '\0';
    return got;
}

static esp_err_t tracker_sound_post(httpd_req_t *req)
{
    char buf[256];
    int got = recv_body(req, buf, sizeof buf);
    if (got < 0) { httpd_resp_send_500(req); return ESP_FAIL; }
    master_on_tracker_sound(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t tracker_burst_post(httpd_req_t *req)
{
    char buf[1024];
    int got = recv_body(req, buf, sizeof buf);
    if (got < 0) { httpd_resp_send_500(req); return ESP_FAIL; }
    master_on_tracker_burst(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t tracker_burst_stop_post(httpd_req_t *req)
{
    master_on_tracker_burst_stop();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t scan_post(httpd_req_t *req)
{
    master_on_rescan_request();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true,\"disconnecting\":false}");
    return ESP_OK;
}

static esp_err_t walk_post(httpd_req_t *req)
{
    char q[32]; bool start = true;
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char v[8];
        if (httpd_query_key_value(q, "start", v, sizeof(v)) == ESP_OK)
            start = (v[0] == '1');
    }
    master_on_walk_request(start);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, start ? "{\"ok\":true,\"walking\":true,\"disconnecting\":false}"
                                  : "{\"ok\":true,\"walking\":false,\"disconnecting\":false}");
    return ESP_OK;
}

static esp_err_t epup_label_post(httpd_req_t *req)
{
    char buf[48];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_epup_label(buf);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t places_get(httpd_req_t *req)
{
    static char body[2048];
    master_cluster_places_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t infra_get(httpd_req_t *req)
{
    static char body[4096];
    master_cluster_infra_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t place_detail_get(httpd_req_t *req)
{
    int idx = 0;
    char q[24], sv[8];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK &&
        httpd_query_key_value(q, "idx", sv, sizeof(sv)) == ESP_OK)
        idx = atoi(sv);
    static char body[3072];
    master_cluster_place_detail_json(idx, body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t landmark_edit_post(httpd_req_t *req)
{
    char buf[128];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_landmark_edit(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t learn_post(httpd_req_t *req)
{
    char buf[128];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_learn(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t place_label_post(httpd_req_t *req)
{
    char buf[96];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_place_label(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t hits_get(httpd_req_t *req)
{
    static char body[4096];
    master_cluster_hits_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t devices_get(httpd_req_t *req)
{
    uint32_t since = 0;
    char q[24], sv[16];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK &&
        httpd_query_key_value(q, "since", sv, sizeof(sv)) == ESP_OK)
        since = (uint32_t)strtoul(sv, NULL, 10);

    char hmerge[12];
    snprintf(hmerge, sizeof(hmerge), "%lu", (unsigned long)master_cluster_merge_count());
    httpd_resp_set_type(req, "application/x-ndjson");
    httpd_resp_set_hdr(req, "X-SC-Merge", hmerge);
    httpd_resp_set_hdr(req, "X-SC-Session", master_cluster_session_id());

    static char line[DEV_LINE_STREAM_MAX];
    int n = master_cluster_device_count(), sent = 0;
    for (int i = 0; i < n; i++) {
        int l = master_cluster_device_json(i, since, line, sizeof(line));
        if (l > 0) {
            line[l] = '\n';
            httpd_resp_send_chunk(req, line, l + 1);
            sent++;
        }
    }
    httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "/api/cluster/devices?since=%lu -> %d/%d devices",
             (unsigned long)since, sent, n);
    return ESP_OK;
}

static esp_err_t time_post(httpd_req_t *req)
{
    char buf[24];
    int n = req->content_len < (int)sizeof(buf) - 1 ? req->content_len : (int)sizeof(buf) - 1;
    int got = 0;
    while (got < n) {
        int r = httpd_req_recv(req, buf + got, n - got);
        if (r <= 0) { httpd_resp_send_500(req); return ESP_FAIL; }
        got += r;
    }
    buf[got] = '\0';
    master_on_settime((uint32_t)strtoul(buf, NULL, 10));
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t brain_reset_post(httpd_req_t *req)
{
    master_on_brain_reset();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t locate_start_post(httpd_req_t *req)
{
    char buf[256];
    int got = recv_body(req, buf, sizeof buf);
    if (got < 0) { httpd_resp_send_500(req); return ESP_FAIL; }
    master_on_locate_start(buf, got);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}
static esp_err_t locate_stop_post(httpd_req_t *req)
{
    master_on_locate_stop();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}
static esp_err_t locate_get(httpd_req_t *req)
{
    static char body[256];
    master_locate_json(body, sizeof(body));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

esp_err_t cluster_web_start(httpd_handle_t server)
{
    if (!server) return ESP_ERR_INVALID_STATE;
    static const httpd_uri_t routes[] = {
        { .uri = "/dogpark",            .method = HTTP_GET,  .handler = dogpark_get },
        { .uri = "/api/gps",            .method = HTTP_POST, .handler = gps_post },
        { .uri = "/api/cluster/status", .method = HTTP_GET,  .handler = status_get },
        { .uri = "/api/cluster/devices", .method = HTTP_GET, .handler = devices_get },
        { .uri = "/api/cluster/log",    .method = HTTP_GET,  .handler = log_get },
        { .uri = "/api/cluster/sentinel", .method = HTTP_GET,  .handler = sentinel_get },
        { .uri = "/api/cluster/sentinel", .method = HTTP_POST, .handler = sentinel_post },
        { .uri = "/api/cluster/scan",   .method = HTTP_POST, .handler = scan_post },
        { .uri = "/api/cluster/walk",   .method = HTTP_POST, .handler = walk_post },
        { .uri = "/api/cluster/epup/label", .method = HTTP_POST, .handler = epup_label_post },
        { .uri = "/api/cluster/places", .method = HTTP_GET,  .handler = places_get },
        { .uri = "/api/cluster/infra",  .method = HTTP_GET,  .handler = infra_get },
        { .uri = "/api/cluster/place/detail", .method = HTTP_GET,  .handler = place_detail_get },
        { .uri = "/api/cluster/place/landmark", .method = HTTP_POST, .handler = landmark_edit_post },
        { .uri = "/api/cluster/learn", .method = HTTP_POST, .handler = learn_post },
        { .uri = "/api/cluster/place/label", .method = HTTP_POST, .handler = place_label_post },
        { .uri = "/api/cluster/sentinel/hits", .method = HTTP_GET, .handler = hits_get },
        { .uri = "/api/cluster/tracker",            .method = HTTP_GET,  .handler = tracker_get },
        { .uri = "/api/cluster/tracker/sound",      .method = HTTP_POST, .handler = tracker_sound_post },
        { .uri = "/api/cluster/tracker/burst",      .method = HTTP_POST, .handler = tracker_burst_post },
        { .uri = "/api/cluster/tracker/burst/stop", .method = HTTP_POST, .handler = tracker_burst_stop_post },
        { .uri = "/api/cluster/time",   .method = HTTP_POST, .handler = time_post },
        { .uri = "/api/cluster/brain/reset", .method = HTTP_POST, .handler = brain_reset_post },
        { .uri = "/api/cluster/locate",       .method = HTTP_GET,  .handler = locate_get },
        { .uri = "/api/cluster/locate/start", .method = HTTP_POST, .handler = locate_start_post },
        { .uri = "/api/cluster/locate/stop",  .method = HTTP_POST, .handler = locate_stop_post },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        esp_err_t e = httpd_register_uri_handler(server, &routes[i]);
        if (e != ESP_OK) ESP_LOGE(TAG, "register %s: %s", routes[i].uri, esp_err_to_name(e));
    }
    ESP_LOGI(TAG, "cluster routes registered (/api/gps, /api/cluster/*)");
    return ESP_OK;
}
