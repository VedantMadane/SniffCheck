#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

esp_err_t download_http_start(void);

void download_http_stop(void);

httpd_handle_t download_http_server(void);

void  *sc_durable_open(void);
size_t sc_durable_next(void *h, char *buf, size_t bufsz);
void   sc_durable_close(void *h);
