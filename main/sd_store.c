#include "sd_store.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

static const char *TAG = "sc_sd";

#define SD_CS_PIN        23
#define SD_SPI_CLOCK_HZ  (5 * 1000 * 1000)

#define SD_MAX_WRITE_FAILS 4

#define SD_MOUNT         "/sdcard"
#define SD_ROOT          SD_MOUNT "/sniffcheck"
#define SD_SESSIONS      SD_ROOT  "/sessions"
#define SD_INDEX         SD_ROOT  "/index.jsonl"

#define SD_RESERVE_BYTES   SD_ARCHIVE_RESERVE_BYTES
#define SD_FREE_CHECK_US   (10LL * 1000 * 1000)
#define SD_FLUSH_RECORDS   32

#define SD_META_REFRESH_US (30LL * 1000 * 1000)

#define SD_META_MAX        640

static sdmmc_card_t     *s_card;
static FILE             *s_fp;
static sd_store_stats_t  s_st;
static SemaphoreHandle_t s_lock;
static int64_t           s_last_free_us;
static uint32_t          s_unflushed;
static uint32_t          s_write_fails;
static void            (*s_post_write_cb)(void);

static char     s_sess_id[SD_SESSION_ID_MAX];
static char     s_sess_kind[16];
static char     s_sess_fw[24];
static char     s_sess_schema[16];

static char     s_sess_series[SD_SERIES_MAX];
static char     s_sess_orig[SD_SESSION_ID_MAX];
static int64_t  s_sess_open_us;
static int64_t  s_last_meta_us;
static sd_session_summary_t s_sess_sum;

static bool     s_sess_pending;

static uint32_t s_sess_pre_records;
static bool     s_sess_content;

static void (*s_bus_lock_cb)(void);
static void (*s_bus_unlock_cb)(void);

void sd_store_set_bus_cbs(void (*lock_cb)(void), void (*unlock_cb)(void))
{
    s_bus_lock_cb   = lock_cb;
    s_bus_unlock_cb = unlock_cb;
}

static inline void bus_lock(void)   { if (s_bus_lock_cb)   s_bus_lock_cb(); }
static inline void bus_unlock(void) { if (s_bus_unlock_cb) s_bus_unlock_cb(); }

static inline bool lock(void)
{
    if (!s_lock || xSemaphoreTake(s_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return false;
    bus_lock();
    return true;
}
static inline void unlock(void)
{
    bus_unlock();
    if (s_lock) xSemaphoreGive(s_lock);
}

bool sd_store_ok(void)
{
    return s_st.mounted && s_fp && !s_st.full;
}

void sd_store_set_post_write_cb(void (*cb)(void))
{
    s_post_write_cb = cb;
}

static void post_write(void)
{
    if (s_post_write_cb) s_post_write_cb();
}

static void refresh_free(void)
{
    uint64_t total = 0, freeb = 0;
    if (esp_vfs_fat_info(SD_MOUNT, &total, &freeb) != ESP_OK) return;
    s_st.free_bytes   = freeb;

    s_st.volume_bytes = total;

    bool was_full = s_st.full;
    s_st.full = s_st.free_bytes < SD_RESERVE_BYTES;
    if (s_st.full && !was_full) {
        ESP_LOGW(TAG, "card near full (%.1f MB free < %u MB reserve) — archive paused, "
                 "scanning continues", (double)s_st.free_bytes / 1e6,
                 (unsigned)(SD_RESERVE_BYTES / (1024 * 1024)));
    } else if (!s_st.full && was_full) {
        ESP_LOGI(TAG, "card space recovered (%.1f MB free) — archive resumed",
                 (double)s_st.free_bytes / 1e6);
    }
    s_last_free_us = esp_timer_get_time();
}

esp_err_t sd_store_init(spi_host_device_t host)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
        if (!s_lock) return ESP_ERR_NO_MEM;
    }
    memset(&s_st, 0, sizeof(s_st));

    sdmmc_host_t hcfg = SDSPI_HOST_DEFAULT();
    hcfg.slot         = host;
    hcfg.max_freq_khz = SD_SPI_CLOCK_HZ / 1000;

    sdspi_device_config_t slot = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot.gpio_cs = SD_CS_PIN;
    slot.host_id = host;

    esp_vfs_fat_sdmmc_mount_config_t mcfg = {
        .format_if_mount_failed = false,
        .max_files              = 4,
        .allocation_unit_size   = 8 * 1024,
    };

    bus_lock();
    esp_err_t err = esp_vfs_fat_sdspi_mount(SD_MOUNT, &hcfg, &slot, &mcfg, &s_card);
    bus_unlock();
    post_write();
    if (err != ESP_OK) {

        if (err == ESP_FAIL) {
            s_st.card_present    = true;
            s_st.card_unreadable = true;
            ESP_LOGW(TAG, "SD card is present but has no readable filesystem — "
                          "it must be FAT32 (exFAT, which 128 GB cards ship with, "
                          "is not supported). Archive off, live capture unchanged.");
        } else {

            ESP_LOGI(TAG, "no usable SD card (%s) — archive off, live capture unchanged",
                     esp_err_to_name(err));
        }
        return ESP_ERR_NOT_FOUND;
    }

    s_st.card_present = true;
    s_st.mounted      = true;
    s_st.card_bytes   = (uint64_t)s_card->csd.capacity * s_card->csd.sector_size;
    ESP_LOGI(TAG, "SD mounted: %s %.1f GB", s_card->cid.name,
             (double)s_st.card_bytes / 1e9);

    bus_lock();
    mkdir(SD_ROOT, 0777);
    mkdir(SD_SESSIONS, 0777);
    refresh_free();
    bus_unlock();
    ESP_LOGI(TAG, "SD volume: %.2f GB free of %.2f GB (card is %.2f GB physical)",
             (double)s_st.free_bytes / 1e9, (double)s_st.volume_bytes / 1e9,
             (double)s_st.card_bytes / 1e9);

    if (s_st.volume_bytes && s_st.card_bytes &&
        s_st.volume_bytes < s_st.card_bytes / 2) {
        ESP_LOGW(TAG, "only %.2f GB of this %.2f GB card is the mounted FAT volume — "
                 "the rest is in other partitions this firmware cannot see "
                 "(reformat the whole card as one FAT32 volume to use it all)",
                 (double)s_st.volume_bytes / 1e9, (double)s_st.card_bytes / 1e9);
    }

    sd_store_prune_empty(NULL);

    post_write();
    return ESP_OK;
}

static void copy_json_safe(char *dst, size_t dstsz, const char *src)
{
    size_t i = 0;
    if (dstsz == 0) return;
    for (; src && src[i] && i + 1 < dstsz; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (c < 0x20 || c > 0x7e || c == '"' || c == '\\') ? '_' : (char)c;
    }
    dst[i] = '\0';
}

bool sd_store_id_valid(const char *id)
{
    if (!id || !id[0]) return false;
    size_t n = strlen(id);
    if (n >= SD_SESSION_ID_MAX) return false;

    if (id[0] == '.') return false;
    for (size_t i = 0; i < n; i++) {
        char c = id[i];
        if (!isalnum((unsigned char)c) && c != '-' && c != '_' && c != '.')
            return false;
    }
    return true;
}

bool sd_store_session_is_open(void)
{
    return s_fp != NULL || s_sess_pending;
}

static void sync_locked(void)
{
    if (!s_fp) return;
    fflush(s_fp);
    fsync(fileno(s_fp));
    s_unflushed = 0;
}

static void write_meta_locked(bool complete, const char *reason)
{
    if (!s_sess_id[0]) return;

    char safe_reason[24], path[128];
    copy_json_safe(safe_reason, sizeof(safe_reason), reason ? reason : "");
    snprintf(path, sizeof(path), SD_SESSIONS "/%s.meta", s_sess_id);

    FILE *m = fopen(path, "w");
    if (!m) { s_st.write_errors++; return; }

    fprintf(m,
        "{\"type\":\"session_meta\",\"id\":\"%s\",\"kind\":\"%s\","
        "\"series\":\"%s\",\"orig\":\"%s\","
        "\"file\":\"sessions/%s.jsonl\",\"fw\":\"%s\",\"schema\":\"%s\","
        "\"complete\":%s,\"end_reason\":\"%s\","
        "\"open_us\":%lld,\"close_us\":%lld,"
        "\"content\":%s,\"records\":%u,\"bytes\":%llu,"
        "\"wifi_aps\":%u,\"ble_devices\":%u,\"trackers\":%u,"
        "\"probe_reqs\":%u,\"alerts\":%u,\"scans\":%u,"
        "\"worst_threat\":%u,\"env\":\"%s\"}\n",
        s_sess_id, s_sess_kind, s_sess_series, s_sess_orig,
        s_sess_id, s_sess_fw, s_sess_schema,
        complete ? "true" : "false", safe_reason,
        (long long)s_sess_open_us,
        (long long)(complete ? esp_timer_get_time() : 0),
        s_sess_content ? "true" : "false",
        (unsigned)s_st.records, (unsigned long long)s_st.written_bytes,
        (unsigned)s_sess_sum.wifi_aps, (unsigned)s_sess_sum.ble_devices,
        (unsigned)s_sess_sum.trackers, (unsigned)s_sess_sum.probe_reqs,
        (unsigned)s_sess_sum.alerts, (unsigned)s_sess_sum.scans,
        (unsigned)s_sess_sum.worst_threat, s_sess_sum.env_label);

    fclose(m);
    s_last_meta_us = esp_timer_get_time();
}

static bool session_materialize_locked(void)
{
    if (s_fp) return true;
    if (!s_sess_pending || !s_sess_id[0]) return false;

    snprintf(s_st.path, sizeof(s_st.path), SD_SESSIONS "/%s.jsonl", s_sess_id);
    s_fp = fopen(s_st.path, "a");
    if (!s_fp) {
        ESP_LOGE(TAG, "cannot open %s", s_st.path);
        s_st.path[0] = '\0';
        return false;
    }
    s_sess_pending = false;

    FILE *ix = fopen(SD_INDEX, "a");
    if (ix) {
        fprintf(ix, "{\"type\":\"session\",\"id\":\"%s\",\"kind\":\"%s\","
                    "\"file\":\"sessions/%s.jsonl\",\"open_us\":%lld}\n",
                s_sess_id, s_sess_kind, s_sess_id, (long long)s_sess_open_us);
        fclose(ix);
    }

    write_meta_locked(false, "");

    s_unflushed = 0;
    ESP_LOGI(TAG, "archive session open: %s (%s)", s_st.path, s_sess_kind);
    return true;
}

esp_err_t sd_store_session_open(const char *id, const char *kind,
                                const char *fw, const char *schema)
{
    if (!s_st.mounted || !sd_store_id_valid(id)) return ESP_ERR_INVALID_STATE;
    if (!lock()) return ESP_ERR_TIMEOUT;

    if (s_fp) { fclose(s_fp); s_fp = NULL; }

    s_st.path[0] = '\0';

    copy_json_safe(s_sess_id,     sizeof(s_sess_id),     id);
    copy_json_safe(s_sess_kind,   sizeof(s_sess_kind),   kind   ? kind   : "scan");
    copy_json_safe(s_sess_fw,     sizeof(s_sess_fw),     fw     ? fw     : "");
    copy_json_safe(s_sess_schema, sizeof(s_sess_schema), schema ? schema : "");
    s_sess_series[0] = '\0';

    snprintf(s_sess_orig, sizeof(s_sess_orig), "%s", s_sess_id);
    memset(&s_sess_sum, 0, sizeof(s_sess_sum));
    s_sess_open_us = esp_timer_get_time();
    s_st.records = 0;
    s_st.written_bytes = 0;
    s_unflushed = 0;
    s_sess_pending = true;
    s_sess_pre_records = 0;
    s_sess_content = false;

    unlock();
    post_write();
    ESP_LOGD(TAG, "archive session declared: %s (%s) — file on first record",
             s_sess_id, s_sess_kind);
    return ESP_OK;
}

void sd_store_session_mark_preamble_end(void)
{
    if (!lock()) return;
    if (!s_sess_content) s_sess_pre_records = s_st.records;
    unlock();
}

void sd_store_session_summary(const sd_session_summary_t *s)
{
    if (!s) return;
    if (!lock()) return;
    s_sess_sum = *s;
    copy_json_safe(s_sess_sum.env_label, sizeof(s_sess_sum.env_label), s->env_label);
    unlock();
}

void sd_store_session_close(const char *reason)
{
    if (!lock()) return;
    if (s_fp && !s_sess_content) {

        fclose(s_fp);
        s_fp = NULL;
        char path[128];
        snprintf(path, sizeof(path), SD_SESSIONS "/%s.jsonl", s_sess_id);
        unlink(path);
        snprintf(path, sizeof(path), SD_SESSIONS "/%s.meta", s_sess_id);
        unlink(path);
        ESP_LOGD(TAG, "archive session dropped, nothing captured: %s", s_sess_id);
    } else if (s_fp) {
        sync_locked();
        fclose(s_fp);
        s_fp = NULL;
        write_meta_locked(true, reason ? reason : "done");

        FILE *ix = fopen(SD_INDEX, "a");
        if (ix) {
            fprintf(ix, "{\"type\":\"session_end\",\"id\":\"%s\",\"reason\":\"%s\","
                        "\"records\":%u,\"bytes\":%llu,\"close_us\":%lld}\n",
                    s_sess_id, reason ? reason : "done", (unsigned)s_st.records,
                    (unsigned long long)s_st.written_bytes,
                    (long long)esp_timer_get_time());
            fclose(ix);
        }
        ESP_LOGI(TAG, "archive session closed (%s): %u records, %llu B",
                 reason ? reason : "done", (unsigned)s_st.records,
                 (unsigned long long)s_st.written_bytes);
    } else if (s_sess_pending) {

        ESP_LOGD(TAG, "archive session dropped unwritten (%s): %s",
                 reason ? reason : "done", s_sess_id);
    }
    s_sess_pending = false;
    s_sess_content = false;
    s_sess_pre_records = 0;
    s_st.path[0] = '\0';
    s_sess_id[0] = '\0';
    unlock();
    post_write();
}

void sd_store_append(const char *line, size_t len)
{
    if (!line || len == 0) return;
    if (!s_st.mounted || s_st.full) return;
    if (!s_fp && !s_sess_pending) return;
    if (!lock()) return;

    if (!s_fp && !session_materialize_locked()) { unlock(); return; }
    if (!s_fp) { unlock(); return; }

    size_t w = fwrite(line, 1, len, s_fp);
    if (w != len) {
        s_st.write_errors++;

        if (++s_write_fails >= SD_MAX_WRITE_FAILS) {
            ESP_LOGW(TAG, "%u consecutive write failures — card gone or failed; "
                     "archive off, scanning continues", (unsigned)s_write_fails);
            fclose(s_fp);
            s_fp = NULL;
            s_st.mounted = false;
            s_st.card_present = false;
            s_st.path[0] = '\0';
        }
        unlock();
        post_write();
        return;
    }
    s_write_fails = 0;
    fputc('\n', s_fp);
    s_st.written_bytes += len + 1;
    s_st.records++;

    bool flushed = false;

    if (!s_sess_content && s_st.records > s_sess_pre_records) {
        s_sess_content = true;
        sync_locked();
        write_meta_locked(false, "");
        flushed = true;
    }
    if (++s_unflushed >= SD_FLUSH_RECORDS) {
        fflush(s_fp);
        s_unflushed = 0;
        flushed = true;

        if (esp_timer_get_time() - s_last_meta_us > SD_META_REFRESH_US) {
            sync_locked();
            write_meta_locked(false, "");
        }
    }
    if (esp_timer_get_time() - s_last_free_us > SD_FREE_CHECK_US) refresh_free();
    unlock();

    if (flushed) post_write();
}

void sd_store_flush(void)
{
    if (!lock()) return;
    if (s_fp) {
        sync_locked();
        write_meta_locked(false, "");
    }
    unlock();
    post_write();
}

void sd_store_get_stats(sd_store_stats_t *out)
{
    if (!out) return;
    if (lock()) { *out = s_st; unlock(); }
    else        { *out = s_st; }
}

static bool name_to_id(const char *name, char *id, size_t idsz)
{
    size_t n = strlen(name);
    const char *ext = ".jsonl";
    size_t e = strlen(ext);
    if (n <= e || strcasecmp(name + n - e, ext) != 0) return false;
    if (n - e >= idsz) return false;
    memcpy(id, name, n - e);
    id[n - e] = '\0';
    return sd_store_id_valid(id);
}

size_t sd_store_list_sessions(sd_session_row_t *out, size_t max)
{
    if (!out || max == 0 || !s_st.mounted) return 0;

    bus_lock();
    DIR *d = opendir(SD_SESSIONS);
    if (!d) { bus_unlock(); return 0; }

    size_t n = 0;
    struct dirent *de;
    while (n < max && (de = readdir(d)) != NULL) {
        sd_session_row_t *row = &out[n];
        memset(row, 0, sizeof(*row));
        if (!name_to_id(de->d_name, row->id, sizeof(row->id))) continue;

        char path[128];
        struct stat sb;
        snprintf(path, sizeof(path), SD_SESSIONS "/%s.jsonl", row->id);
        row->bytes = (stat(path, &sb) == 0) ? (uint64_t)sb.st_size : 0;

        snprintf(path, sizeof(path), SD_SESSIONS "/%s.meta", row->id);
        row->has_meta = (stat(path, &sb) == 0);

        row->current = (s_sess_id[0] && strcmp(row->id, s_sess_id) == 0);
        n++;
    }
    closedir(d);
    bus_unlock();
    return n;
}

size_t sd_store_read_meta(const char *id, char *buf, size_t buflen)
{
    if (!buf || buflen == 0) return 0;
    buf[0] = '\0';
    if (!s_st.mounted || !sd_store_id_valid(id)) return 0;

    if (s_sess_id[0] && strcmp(id, s_sess_id) == 0 && lock()) {
        if (s_fp) { sync_locked(); write_meta_locked(false, ""); }
        unlock();
        post_write();
    }

    char path[128];
    snprintf(path, sizeof(path), SD_SESSIONS "/%s.meta", id);
    bus_lock();
    FILE *m = fopen(path, "r");
    if (!m) { bus_unlock(); return 0; }
    size_t r = fread(buf, 1, buflen - 1, m);
    fclose(m);
    bus_unlock();
    buf[r] = '\0';
    while (r && (buf[r - 1] == '\n' || buf[r - 1] == '\r')) buf[--r] = '\0';
    return r;
}

void *sd_store_reader_open(const char *id)
{
    if (!s_st.mounted || !sd_store_id_valid(id)) return NULL;

    if (s_sess_id[0] && strcmp(id, s_sess_id) == 0) sd_store_flush();

    char path[128];
    snprintf(path, sizeof(path), SD_SESSIONS "/%s.jsonl", id);
    bus_lock();
    FILE *f = fopen(path, "r");
    bus_unlock();
    return f;
}

size_t sd_store_reader_next(void *h, char *buf, size_t buflen)
{
    if (!h || !buf || buflen < 2) return 0;
    for (;;) {
        bus_lock();
        char *got = fgets(buf, (int)buflen, (FILE *)h);
        bus_unlock();
        if (!got) return 0;
        size_t n = strlen(buf);
        while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
        if (n) return n;
    }
}

void sd_store_reader_close(void *h)
{
    if (!h) return;
    bus_lock();
    fclose((FILE *)h);
    bus_unlock();
}

esp_err_t sd_store_delete_session(const char *id)
{
    if (!s_st.mounted) return ESP_ERR_INVALID_STATE;
    if (!sd_store_id_valid(id)) return ESP_ERR_INVALID_ARG;
    if (s_sess_id[0] && strcmp(id, s_sess_id) == 0) return ESP_ERR_INVALID_STATE;

    char path[128];
    bus_lock();
    snprintf(path, sizeof(path), SD_SESSIONS "/%s.jsonl", id);
    if (unlink(path) != 0) { bus_unlock(); return ESP_ERR_NOT_FOUND; }
    snprintf(path, sizeof(path), SD_SESSIONS "/%s.meta", id);
    unlink(path);

    refresh_free();
    bus_unlock();
    post_write();
    ESP_LOGI(TAG, "archive session deleted: %s", id);
    return ESP_OK;
}

bool sd_store_sanitize_name(const char *name, char *out, size_t outsz)
{
    if (!out || outsz == 0) return false;
    out[0] = '\0';
    if (!name) return false;

    size_t o = 0;
    size_t cap = outsz < SD_SESSION_ID_MAX ? outsz : SD_SESSION_ID_MAX;
    bool last_dash = false;
    for (size_t i = 0; name[i] && o + 1 < cap; i++) {
        unsigned char c = (unsigned char)name[i];
        if (isalnum(c) || c == '.' || c == '_') {

            if (c == '.' && o == 0) continue;
            out[o++] = (char)c;
            last_dash = false;
        } else {

            if (o == 0 || last_dash) continue;
            out[o++] = '-';
            last_dash = true;
        }
    }
    while (o > 0 && out[o - 1] == '-') o--;
    out[o] = '\0';
    return o > 0 && sd_store_id_valid(out);
}

static bool json_set_str(char *line, size_t cap, const char *key, const char *val)
{
    char pat[24];
    int pl = snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    if (pl <= 0 || (size_t)pl >= sizeof(pat)) return false;

    char *at = strstr(line, pat);
    if (!at) return false;
    char *vs = at + pl;
    char *ve = strchr(vs, '"');
    if (!ve) return false;

    size_t vlen = strlen(val);
    size_t oldlen = (size_t)(ve - vs);
    size_t total = strlen(line);
    if (total - oldlen + vlen + 1 > cap) return false;

    memmove(vs + vlen, ve, strlen(ve) + 1);
    memcpy(vs, val, vlen);
    return true;
}

static bool json_add_str(char *line, size_t cap, const char *key, const char *val)
{
    char *end = strrchr(line, '}');
    if (!end) return false;
    char add[96];
    int n = snprintf(add, sizeof(add), ",\"%s\":\"%s\"", key, val);
    if (n <= 0 || (size_t)n >= sizeof(add)) return false;
    if (strlen(line) + (size_t)n + 1 > cap) return false;
    memmove(end + n, end, strlen(end) + 1);
    memcpy(end, add, (size_t)n);
    return true;
}

static void json_put_str(char *line, size_t cap, const char *key, const char *val)
{
    if (!json_set_str(line, cap, key, val)) json_add_str(line, cap, key, val);
}

static void meta_rename_locked(const char *old_id, const char *new_id,
                               const char *series)
{
    char path[128];
    snprintf(path, sizeof(path), SD_SESSIONS "/%s.meta", new_id);

    static char line[SD_META_MAX];
    FILE *m = fopen(path, "r");
    if (!m) return;
    size_t r = fread(line, 1, sizeof(line) - 1, m);
    fclose(m);
    line[r] = '\0';
    while (r && (line[r - 1] == '\n' || line[r - 1] == '\r')) line[--r] = '\0';
    if (!r || line[0] != '{') return;

    char file_val[SD_SESSION_ID_MAX + 16];
    snprintf(file_val, sizeof(file_val), "sessions/%s.jsonl", new_id);

    if (!strstr(line, "\"orig\":\"")) json_put_str(line, sizeof(line), "orig", old_id);

    json_put_str(line, sizeof(line), "id", new_id);
    json_put_str(line, sizeof(line), "file", file_val);
    if (series) json_put_str(line, sizeof(line), "series", series);

    m = fopen(path, "w");
    if (!m) { s_st.write_errors++; return; }
    fprintf(m, "%s\n", line);
    fclose(m);
}

static bool unique_id_locked(const char *base, char *out, size_t outsz)
{
    char path[128];
    struct stat sb;

    snprintf(out, outsz, "%s", base);
    snprintf(path, sizeof(path), SD_SESSIONS "/%s.jsonl", out);
    if (stat(path, &sb) != 0) return sd_store_id_valid(out);

    for (int n = 2; n <= 99; n++) {

        char stem[SD_SESSION_ID_MAX];
        size_t room = SD_SESSION_ID_MAX - 1 - (n < 10 ? 2 : 3);
        snprintf(stem, room + 1, "%s", base);
        while (room > 0 && stem[room - 1] == '-') stem[--room] = '\0';
        if (!room) return false;
        snprintf(out, outsz, "%s-%d", stem, n);
        snprintf(path, sizeof(path), SD_SESSIONS "/%s.jsonl", out);
        if (stat(path, &sb) != 0) return sd_store_id_valid(out);
    }
    return false;
}

esp_err_t sd_store_rename_session(const char *id, const char *want_name,
                                  const char *series,
                                  char *final_id, size_t final_sz)
{
    if (final_id && final_sz) final_id[0] = '\0';
    if (!s_st.mounted) return ESP_ERR_INVALID_STATE;
    if (!sd_store_id_valid(id)) return ESP_ERR_INVALID_ARG;

    char base[SD_SESSION_ID_MAX];
    bool renaming = (want_name && want_name[0]);
    if (renaming) {
        if (!sd_store_sanitize_name(want_name, base, sizeof(base)))
            return ESP_ERR_INVALID_ARG;
    } else {
        snprintf(base, sizeof(base), "%s", id);
    }

    char safe_series[SD_SERIES_MAX];
    if (series) copy_json_safe(safe_series, sizeof(safe_series), series);
    else        safe_series[0] = '\0';

    if (!lock()) return ESP_ERR_TIMEOUT;
    bus_lock();

    bool live = (s_sess_id[0] && strcmp(id, s_sess_id) == 0);
    char new_id[SD_SESSION_ID_MAX];
    esp_err_t err = ESP_OK;

    if (strcmp(base, id) == 0) {
        snprintf(new_id, sizeof(new_id), "%s", id);
    } else if (!unique_id_locked(base, new_id, sizeof(new_id))) {
        err = ESP_ERR_INVALID_ARG;
    }

    bool live_pending = (live && s_sess_pending);

    if (err == ESP_OK && strcmp(new_id, id) != 0 && !live_pending) {
        char from[128], to[128];
        struct stat sb;

        if (live && s_fp) { sync_locked(); fclose(s_fp); s_fp = NULL; }

        snprintf(from, sizeof(from), SD_SESSIONS "/%s.jsonl", id);
        snprintf(to,   sizeof(to),   SD_SESSIONS "/%s.jsonl", new_id);
        if (stat(from, &sb) != 0)      err = ESP_ERR_NOT_FOUND;
        else if (rename(from, to) != 0) err = ESP_FAIL;

        if (err == ESP_OK) {
            snprintf(from, sizeof(from), SD_SESSIONS "/%s.meta", id);
            snprintf(to,   sizeof(to),   SD_SESSIONS "/%s.meta", new_id);
            if (stat(from, &sb) == 0) rename(from, to);
        }

        if (live) {

            const char *keep = (err == ESP_OK) ? new_id : id;
            snprintf(s_st.path, sizeof(s_st.path), SD_SESSIONS "/%s.jsonl", keep);
            s_fp = fopen(s_st.path, "a");
            if (!s_fp) {
                ESP_LOGE(TAG, "rename: cannot reopen %s — archive stopped", s_st.path);
                s_st.path[0] = '\0';
                s_sess_id[0] = '\0';
                err = ESP_FAIL;
            }
        }
    }

    if (err == ESP_OK) {
        if (live && s_sess_id[0]) {
            if (!s_sess_orig[0]) snprintf(s_sess_orig, sizeof(s_sess_orig), "%s", s_sess_id);
            copy_json_safe(s_sess_id, sizeof(s_sess_id), new_id);
            if (series) snprintf(s_sess_series, sizeof(s_sess_series), "%s", safe_series);

            if (!s_sess_pending) write_meta_locked(false, "");
        } else {
            meta_rename_locked(id, new_id, series ? safe_series : NULL);
        }
        if (final_id && final_sz) snprintf(final_id, final_sz, "%s", new_id);
    }

    bus_unlock();
    unlock();
    post_write();

    if (err == ESP_OK)
        ESP_LOGI(TAG, "archive session renamed: %s -> %s%s%s", id, new_id,
                 safe_series[0] ? " series=" : "", safe_series);
    else
        ESP_LOGW(TAG, "archive rename failed: %s (0x%x)", id, (unsigned)err);
    return err;
}

#define PRUNE_PEEK_MAX 16384

static char s_prune_path[128];
static char s_prune_line[256];
static char s_prune_ids[8][SD_SESSION_ID_MAX];

static bool file_has_content(const char *id)
{
    snprintf(s_prune_path, sizeof(s_prune_path), SD_SESSIONS "/%s.jsonl", id);
    FILE *f = fopen(s_prune_path, "r");
    if (!f) return true;

    bool content = false, at_start = true;
    char *line = s_prune_line;
    while (fgets(line, sizeof(s_prune_line), f)) {
        bool ends = (strchr(line, '\n') != NULL);
        if (at_start) {
            const char *t = strstr(line, "\"type\":\"");
            if (!t) { content = true; break; }
            t += 8;
            if (strncmp(t, "header\"", 7) != 0 &&
                strncmp(t, "codebook\"", 9) != 0) { content = true; break; }
        }
        at_start = ends;
    }
    fclose(f);
    return content;
}

esp_err_t sd_store_prune_empty(uint32_t *deleted_out)
{
    if (deleted_out) *deleted_out = 0;
    if (!s_st.mounted) return ESP_ERR_INVALID_STATE;

    if (!lock()) return ESP_ERR_TIMEOUT;

    uint32_t killed = 0;

    const size_t batch = sizeof(s_prune_ids) / sizeof(s_prune_ids[0]);
    for (;;) {
        size_t found = 0;

        bus_lock();
        DIR *d = opendir(SD_SESSIONS);
        if (!d) { bus_unlock(); break; }
        struct dirent *de;
        while (found < batch && (de = readdir(d)) != NULL) {
            struct stat sb;
            if (!name_to_id(de->d_name, s_prune_ids[found],
                            sizeof(s_prune_ids[found]))) continue;

            if (s_sess_id[0] && strcmp(s_prune_ids[found], s_sess_id) == 0) continue;

            snprintf(s_prune_path, sizeof(s_prune_path),
                     SD_SESSIONS "/%s.jsonl", s_prune_ids[found]);
            if (stat(s_prune_path, &sb) != 0) continue;
            if (sb.st_size == 0 ||
                (sb.st_size <= PRUNE_PEEK_MAX && !file_has_content(s_prune_ids[found])))
                found++;
        }
        closedir(d);
        bus_unlock();
        if (!found) break;

        bool failed = false;
        for (size_t i = 0; i < found; i++) {
            if (sd_store_delete_session(s_prune_ids[i]) != ESP_OK) { failed = true; break; }
            killed++;
        }
        vTaskDelay(1);
        if (failed) break;
    }

    unlock();

    if (deleted_out) *deleted_out = killed;
    if (killed)
        ESP_LOGI(TAG, "archive: pruned %u empty session%s",
                 (unsigned)killed, killed == 1 ? "" : "s");
    return ESP_OK;
}

esp_err_t sd_store_wipe(uint32_t *deleted_out)
{
    if (deleted_out) *deleted_out = 0;
    if (!s_st.mounted) return ESP_ERR_INVALID_STATE;

    if (s_fp) return ESP_ERR_INVALID_STATE;

    uint32_t killed = 0;

    for (;;) {
        char id[SD_SESSION_ID_MAX];
        bool found = false;

        bus_lock();
        DIR *d = opendir(SD_SESSIONS);
        if (!d) { bus_unlock(); break; }
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (name_to_id(de->d_name, id, sizeof(id))) { found = true; break; }
        }
        closedir(d);
        bus_unlock();
        if (!found) break;

        if (sd_store_delete_session(id) != ESP_OK) break;
        killed++;
        if (killed % 8 == 0) vTaskDelay(1);
    }

    bus_lock();
    unlink(SD_INDEX);
    refresh_free();
    bus_unlock();
    post_write();
    if (deleted_out) *deleted_out = killed;
    ESP_LOGI(TAG, "archive wiped: %u sessions deleted", (unsigned)killed);
    return ESP_OK;
}

bool sd_store_path_ok(const char *rel, char *abs, size_t abssz)
{
    if (!abs || abssz < sizeof(SD_MOUNT) + 1) return false;
    if (!rel) rel = "/";

    size_t n = strlcpy(abs, SD_MOUNT, abssz);
    if (n >= abssz) return false;

    const char *p = rel;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;

        const char *start = p;
        while (*p && *p != '/') p++;
        size_t clen = (size_t)(p - start);
        if (clen > 63) return false;

        if (clen == 1 && start[0] == '.') continue;
        if (clen == 2 && start[0] == '.' && start[1] == '.') return false;

        for (size_t i = 0; i < clen; i++) {
            unsigned char c = (unsigned char)start[i];
            if (c < 0x20 || c == 0x7f || c == '\\') return false;
        }

        if (n + 1 + clen >= abssz) return false;
        abs[n++] = '/';
        memcpy(abs + n, start, clen);
        n += clen;
        abs[n] = '\0';
    }
    return true;
}

size_t sd_store_list_dir(const char *rel, sd_dir_entry_t *out, size_t max,
                         size_t *total_out)
{
    if (total_out) *total_out = 0;
    if (!out || max == 0 || !s_st.mounted) return 0;

    char dir[160];
    if (!sd_store_path_ok(rel, dir, sizeof(dir))) return 0;

    bool in_sessions = (strcmp(dir, SD_SESSIONS) == 0);

    bus_lock();
    DIR *d = opendir(dir);
    if (!d) { bus_unlock(); return 0; }

    #define SD_DIR_SCAN_MAX 512

    size_t n = 0, seen = 0;
    struct dirent *de;
    while (seen < SD_DIR_SCAN_MAX && (de = readdir(d)) != NULL) {
        if (de->d_name[0] == '\0') continue;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        seen++;
        if (n >= max) continue;

        sd_dir_entry_t *e = &out[n];
        memset(e, 0, sizeof(*e));
        strlcpy(e->name, de->d_name, sizeof(e->name));

        char path[224];
        struct stat sb;
        snprintf(path, sizeof(path), "%s/%s", dir, e->name);
        if (stat(path, &sb) == 0) {
            e->is_dir = S_ISDIR(sb.st_mode);
            e->bytes  = e->is_dir ? 0 : (uint64_t)sb.st_size;
        } else {
            e->is_dir = (de->d_type == DT_DIR);
        }

        if (!e->is_dir && in_sessions) {
            e->is_session = name_to_id(e->name, e->id, sizeof(e->id));
            e->current    = e->is_session && s_sess_id[0] && strcmp(e->id, s_sess_id) == 0;
        }
        n++;

    }
    closedir(d);
    bus_unlock();

    if (total_out) *total_out = seen;
    return n;
}

bool sd_store_dir_exists(const char *rel)
{
    if (!s_st.mounted) return false;

    char abs[160];
    if (!sd_store_path_ok(rel, abs, sizeof(abs))) return false;

    struct stat sb;
    bus_lock();
    bool ok = (stat(abs, &sb) == 0) && S_ISDIR(sb.st_mode);
    bus_unlock();
    return ok;
}

void *sd_store_file_open(const char *rel, uint64_t *size_out)
{
    if (size_out) *size_out = 0;
    if (!s_st.mounted) return NULL;

    char path[160];
    if (!sd_store_path_ok(rel, path, sizeof(path))) return NULL;

    struct stat sb;
    bus_lock();
    if (stat(path, &sb) != 0 || S_ISDIR(sb.st_mode)) { bus_unlock(); return NULL; }
    FILE *f = fopen(path, "rb");
    bus_unlock();
    if (f && size_out) *size_out = (uint64_t)sb.st_size;
    return f;
}

size_t sd_store_file_read(void *h, void *buf, size_t len)
{
    if (!h || !buf || len == 0) return 0;
    bus_lock();
    size_t r = fread(buf, 1, len, (FILE *)h);
    bus_unlock();
    return r;
}

void sd_store_file_close(void *h)
{
    if (!h) return;
    bus_lock();
    fclose((FILE *)h);
    bus_unlock();
}

esp_err_t sd_store_selftest(void)
{
    if (!s_st.mounted) return ESP_ERR_INVALID_STATE;

    static const char *probe = SD_ROOT "/.probe";
    static const char *text  = "sniffcheck sd probe";

    bus_lock();
    FILE *f = fopen(probe, "w");
    if (!f) { bus_unlock(); ESP_LOGE(TAG, "selftest: cannot create %s", probe); return ESP_FAIL; }
    size_t n = fwrite(text, 1, strlen(text), f);
    fflush(f);
    fclose(f);
    post_write();
    if (n != strlen(text)) { bus_unlock(); ESP_LOGE(TAG, "selftest: short write"); return ESP_FAIL; }

    char back[64] = {0};
    f = fopen(probe, "r");
    if (!f) { bus_unlock(); ESP_LOGE(TAG, "selftest: cannot reopen probe"); return ESP_FAIL; }
    size_t r = fread(back, 1, sizeof(back) - 1, f);
    fclose(f);
    post_write();

    if (r != strlen(text) || strcmp(back, text) != 0) {
        bus_unlock();
        ESP_LOGE(TAG, "selftest: readback mismatch (%u B: '%s')", (unsigned)r, back);
        return ESP_FAIL;
    }
    unlink(probe);
    refresh_free();
    bus_unlock();
    ESP_LOGI(TAG, "selftest: write/readback/delete OK on %s", SD_MOUNT);
    post_write();
    return ESP_OK;
}
