#pragma once

#include "driver/spi_master.h"
#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    bool     card_present;
    bool     mounted;

    bool     card_unreadable;
    bool     full;
    uint64_t card_bytes;
    uint64_t volume_bytes;
    uint64_t free_bytes;
    uint64_t written_bytes;
    uint32_t records;
    uint32_t write_errors;
    char     path[96];
} sd_store_stats_t;

esp_err_t sd_store_init(spi_host_device_t host);

bool sd_store_ok(void);

#define SD_SESSION_ID_MAX  40

typedef struct {
    uint32_t wifi_aps;
    uint32_t ble_devices;
    uint32_t trackers;
    uint32_t probe_reqs;
    uint32_t alerts;
    uint32_t scans;
    uint8_t  worst_threat;
    char     env_label[32];
} sd_session_summary_t;

esp_err_t sd_store_session_open(const char *id, const char *kind,
                                const char *fw, const char *schema);

void sd_store_session_summary(const sd_session_summary_t *s);

void sd_store_session_close(const char *reason);

bool sd_store_session_is_open(void);

void sd_store_append(const char *line, size_t len);

void sd_store_flush(void);
void sd_store_get_stats(sd_store_stats_t *out);

void sd_store_set_post_write_cb(void (*cb)(void));

void sd_store_set_bus_cbs(void (*lock_cb)(void), void (*unlock_cb)(void));

esp_err_t sd_store_selftest(void);

typedef struct {
    char     id[SD_SESSION_ID_MAX];
    uint64_t bytes;
    bool     has_meta;
    bool     current;
} sd_session_row_t;

size_t sd_store_list_sessions(sd_session_row_t *out, size_t max);

size_t sd_store_read_meta(const char *id, char *buf, size_t buflen);

bool sd_store_id_valid(const char *id);

void  *sd_store_reader_open(const char *id);
size_t sd_store_reader_next(void *h, char *buf, size_t buflen);
void   sd_store_reader_close(void *h);

esp_err_t sd_store_delete_session(const char *id);

#define SD_ARCHIVE_REL_PATH  "/sniffcheck/sessions"

#define SD_ARCHIVE_RESERVE_BYTES  (8ULL * 1024 * 1024)

typedef struct {
    char     name[64];
    uint64_t bytes;
    bool     is_dir;
    bool     is_session;
    bool     current;
    char     id[SD_SESSION_ID_MAX];
} sd_dir_entry_t;

bool sd_store_path_ok(const char *rel, char *abs, size_t abssz);

size_t sd_store_list_dir(const char *rel, sd_dir_entry_t *out, size_t max,
                         size_t *total_out);

bool sd_store_dir_exists(const char *rel);

void  *sd_store_file_open(const char *rel, uint64_t *size_out);
size_t sd_store_file_read(void *h, void *buf, size_t len);
void   sd_store_file_close(void *h);

esp_err_t sd_store_wipe(uint32_t *deleted_out);
