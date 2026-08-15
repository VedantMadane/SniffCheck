#include "download_http.h"

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "capture_ring.h"
#include "capture_writer.h"
#include "download_mode.h"
#include "app_settings.h"
#include "virtual_pup.h"
#include "virtual_pup_walk.h"
#if SC_EPUP_BRAIN
#include "epup_brain.h"
#endif
#include "sta_tracker.h"
#include "wifi_csi_probe.h"
#include "pcap_capture.h"

static const char *TAG = "sc_dlhttp";

#ifndef SC_CLUSTER_HEAD
#define SC_CLUSTER_HEAD 0
#endif

#define SC_SD_ARCHIVE (!SC_CLUSTER_HEAD)
#if SC_SD_ARCHIVE
#include "sd_store.h"
#endif

#define SC_ENV_LEARN (!SC_CLUSTER_HEAD)
#if SC_ENV_LEARN
#include "env_learn.h"
#endif

#define SC_TRACKER_SOUND (!SC_CLUSTER_HEAD)
#if SC_TRACKER_SOUND
#include "tracker_sound.h"
#endif

#ifndef SC_EPUP_BRAIN
#define SC_EPUP_BRAIN 0
#endif

static httpd_handle_t s_server = NULL;

#define STREAM_LINE_MAX 4200

static void *serve_buf_alloc(size_t sz)
{
    void *p = heap_caps_malloc(sz, MALLOC_CAP_SPIRAM);
    if (!p) p = heap_caps_malloc(sz, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    return p;
}

static void *serve_buf_calloc(size_t sz)
{
    void *p = heap_caps_calloc(1, sz, MALLOC_CAP_SPIRAM);
    if (!p) p = heap_caps_calloc(1, sz, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    return p;
}

#include "viewer_gz.h"

extern const unsigned char _binary_webap_logo_png_start[];
extern const unsigned char _binary_webap_logo_png_end[];
extern const unsigned char _binary_webap_favicon_png_start[];
extern const unsigned char _binary_webap_favicon_png_end[];
extern const unsigned char _binary_webap_pup_png_start[];
extern const unsigned char _binary_webap_pup_png_end[];
#if SC_EPUP_BRAIN

extern const unsigned char _binary_epup_sprites_png_start[];
extern const unsigned char _binary_epup_sprites_png_end[];
#endif

static bool s_gz_open;

static esp_err_t rsp_chunk(httpd_req_t *req, const char *buf, size_t len)
{
    if (s_gz_open) return viewer_gz_island(req, buf, len);
    return httpd_resp_send_chunk(req, buf, len);
}

static esp_err_t send_json(httpd_req_t *req, const char *json)
{
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json);
}

static esp_err_t send_chunk_escaped(httpd_req_t *req, const char *p, size_t len)
{
    size_t i = 0, seg = 0;
    while (i + 1 < len) {
        if (p[i] == '<' && p[i + 1] == '/') {
            if (rsp_chunk(req, p + seg, i + 1 - seg) != ESP_OK)
                return ESP_FAIL;
            if (rsp_chunk(req, "\\", 1) != ESP_OK)
                return ESP_FAIL;
            seg = i + 1;
            i += 2;
        } else {
            i++;
        }
    }
    if (len > seg && rsp_chunk(req, p + seg, len - seg) != ESP_OK)
        return ESP_FAIL;
    return ESP_OK;
}

static esp_err_t stream_ring(httpd_req_t *req, bool escaped, size_t skip, size_t *count_out)
{
    char *buf = serve_buf_alloc(STREAM_LINE_MAX + 1);
    if (!buf) return ESP_ERR_NO_MEM;

    capture_ring_reader_t r;
    capture_ring_reader_open(&r);

    size_t seen = 0, emitted = 0;
    esp_err_t err = ESP_OK;
    for (;;) {
        size_t len = capture_ring_reader_next(&r, buf, STREAM_LINE_MAX);
        if (len == 0) break;
        if (seen++ < skip) {
            if (seen % 64 == 0) vTaskDelay(1);
            continue;
        }
        buf[len++] = '\n';
        err = escaped ? send_chunk_escaped(req, buf, len)
                      : rsp_chunk(req, buf, len);
        if (err != ESP_OK) { err = ESP_FAIL; break; }
        if (++emitted % 32 == 0) vTaskDelay(1);
    }
    heap_caps_free(buf);
    if (count_out) *count_out = emitted;
    return err;
}

__attribute__((weak)) void  *sc_durable_open(void)                        { return NULL; }
__attribute__((weak)) size_t sc_durable_next(void *h, char *b, size_t n)  { (void)h; (void)b; (void)n; return 0; }
__attribute__((weak)) void   sc_durable_close(void *h)                    { (void)h; }

static esp_err_t stream_records(httpd_req_t *req, bool escaped, size_t skip, size_t *count_out)
{
    void *dh = sc_durable_open();
    if (!dh) return stream_ring(req, escaped, skip, count_out);
    (void)skip;

    char *buf = serve_buf_alloc(STREAM_LINE_MAX + 1);
    if (!buf) { sc_durable_close(dh); return ESP_ERR_NO_MEM; }

    size_t emitted = 0;
    esp_err_t err = ESP_OK;
    for (;;) {
        size_t len = sc_durable_next(dh, buf, STREAM_LINE_MAX);
        if (len == 0) break;
        buf[len++] = '\n';
        err = escaped ? send_chunk_escaped(req, buf, len)
                      : rsp_chunk(req, buf, len);
        if (err != ESP_OK) { err = ESP_FAIL; break; }
        if (++emitted % 32 == 0) vTaskDelay(1);
    }
    heap_caps_free(buf);
    sc_durable_close(dh);
    if (count_out) *count_out = emitted;
    return err;
}

static const char DASH_HTML[] =
"<!DOCTYPE html><html><head><meta charset=utf-8>"
"<meta name=viewport content=\"width=device-width,initial-scale=1\">"
"<title>SniffCheck</title><link rel=icon type=\"image/png\" href=\"/favicon.ico\">"
"<link rel=\"apple-touch-icon\" href=\"/favicon.ico\">"
"<meta name=\"apple-mobile-web-app-capable\" content=\"yes\">"
"<meta name=\"apple-mobile-web-app-title\" content=\"SniffCheck\">"
"<meta name=\"mobile-web-app-capable\" content=\"yes\">"
"<meta name=\"theme-color\" content=\"#ffd93b\"><style>"

":root{--bg:#ffd93b;--panel:#fff7d6;--panelw:#ffc24a;--ink:#3f2a14;--line:#3f2a14;"
"--muted:#7a5a34;--sh:#3f2a14;--accent:#ff8a1e;--pname:#e0701a;--safe:#2fa85a;"
"--ok:#e0a500;--caution:#e5701a;--avoid:#d63838;--trk:#fff;--onacc:#3f2a14;"

"--s1:#2f7fd6;--s2:#7a52d6;--s3:#e5701a;--s4:#d6489a;--s5:#2fa85a;--s6:#0f9b9b;"

"--cbs:solid;--cbw:3px;--cardr:12px;--panelop:100%;--panelblur:0px;"
"--bgsize:cover;--bgpos:center;--bgrep:no-repeat;--bgdim:0;--bgblur:0px}"
"body.dark{--bg:#241a0e;--panel:#3a2a18;--panelw:#4a3620;--ink:#f3e4bf;--line:#c8a25a;"
"--muted:#c9ac7e;--sh:#100a04;--accent:#ffcf4a;--pname:#ffb14a;--safe:#5ec98a;"
"--ok:#ffc94a;--caution:#ff9f5e;--avoid:#ff6b6b;--trk:#0f0a04;"
"--s1:#6db3f2;--s2:#b79cf0;--s3:#ffab5e;--s4:#f07ac0;--s5:#5ec98a;--s6:#4fd0d0}"
"body{font:15px/1.35 system-ui,sans-serif;background:var(--bg);color:var(--ink);"
"margin:0 auto;padding:12px;max-width:480px}"
"h1{margin:2px 0}h1 img{display:block;height:44px;width:auto;max-width:100%;"
"border:3px solid var(--line);border-radius:11px;background:var(--panel);padding:3px 6px;"
"box-shadow:3px 3px 0 var(--sh)}"
".m{color:var(--muted);font-size:13px;font-weight:700;margin:6px 0 8px}"
"#card{background:var(--panel);border:3px solid var(--line);border-radius:12px;"
"padding:10px 12px;margin:8px 0;font-size:14px;box-shadow:4px 4px 0 var(--sh)}"
"#card div{display:flex;justify-content:space-between;gap:10px;padding:2px 0}"
"#card b{color:var(--muted);font-weight:700}"
"#rem{font-size:20px;font-weight:900;color:var(--safe)}"
"a.b,button{display:block;width:100%;box-sizing:border-box;margin:6px 0;"
"padding:9px;border:2px solid var(--line);border-radius:9px;font-size:15px;font-weight:800;"
"text-align:center;text-decoration:none;background:var(--accent);color:var(--onacc);cursor:pointer;"
"box-shadow:3px 3px 0 var(--sh)}"
"a.b:active,button:active{transform:translate(2px,2px);box-shadow:0 0 0 var(--sh)}"
".rep{background:var(--accent);color:var(--onacc)}"
".dl{background:var(--safe);color:var(--onacc)}"
".ext{background:var(--pname);color:var(--onacc)}"
".cl,.off{background:var(--panel);color:var(--accent)}"
"button[data-armed]{outline:3px solid var(--line);outline-offset:2px}"
"h2{font-size:13px;margin:12px 0 4px;color:var(--hdr,var(--ink));font-weight:900;"
"text-transform:uppercase;letter-spacing:.6px}"
"b,strong{color:var(--bold,inherit)}i,em{color:var(--ital,inherit)}"
".set label{display:flex;justify-content:space-between;align-items:center;"
"gap:10px;margin:8px 0;font-size:14px}"
".set select{font:15px system-ui;padding:8px;border-radius:8px;font-weight:700;"
"border:2px solid var(--line);background:var(--panel);color:var(--ink);min-width:108px}"
".ex{color:var(--muted);font-size:12px;margin:-1px 0 8px}"
".hot{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}"
".hotlbl{width:100%;font-size:14px;font-weight:700}"
".set label.hotck{display:inline-flex;justify-content:flex-start;gap:6px;margin:0;"
"font-size:13px;font-weight:700;padding:6px 10px;border:2px solid var(--line);"
"border-radius:8px;background:var(--panel);cursor:pointer}"
".hotck input{width:16px;height:16px;accent-color:var(--accent)}"
".dz{margin-top:14px;border-top:2px solid var(--line);padding-top:4px}"
"#pcard{background:var(--panel);border:3px solid var(--line);border-radius:12px;"
"padding:10px 12px;margin:8px 0;font-size:14px;box-shadow:4px 4px 0 var(--sh)}"
"#pcard>div{display:flex;justify-content:space-between;gap:10px;"
"align-items:center;margin:4px 0}"
"#pname{color:var(--pname);font-size:16px;font-weight:900}"
".pm{color:var(--muted);font-size:12px;text-transform:capitalize}"
".dimx{color:var(--muted);font-size:12px}"
"#pcard .pbar{display:block;height:9px;background:var(--trk);"
"border:2px solid var(--line);border-radius:5px;overflow:hidden;margin:6px 0}"
"#pcard .pbar i{display:block;height:100%;background:var(--safe)}"
".pstat{color:var(--muted);font-size:12px}"
"#nav{display:flex;gap:8px;margin:6px 0 4px}"
"#nav button{margin:0;padding:8px;font-size:14px;background:var(--panel);color:var(--ink)}"
"#nav button.act{background:var(--accent);color:var(--onacc)}"
".view{display:none}.view.act{display:block}"
".bytypes{margin:8px 0 10px;padding-left:20px;color:var(--muted);font-size:13px}"
"#byname,#bystat{color:var(--muted);font-size:13px;margin:6px 0}"
"#dig{position:fixed;inset:0;background:rgba(20,14,6,.93);display:none;z-index:9;"
"align-items:center;justify-content:center;text-align:center;padding:20px;color:#ffd93b;font-weight:800}"
"#dig span{display:block;color:#fff7d6;font-size:14px;font-weight:600;margin-top:8px}"
".wc{background:var(--panel);border:3px solid var(--safe);border-radius:12px;"
"padding:10px 12px;margin:8px 0;font-size:14px;display:none;box-shadow:4px 4px 0 var(--sh)}"
".wc h3{margin:0 0 6px;color:var(--safe);font-size:15px}"
".wc .wr{display:flex;justify-content:space-between;gap:10px;padding:1px 0;color:var(--muted)}"
".wc .wr b{color:var(--ink);font-weight:700}"
".wc.alert{border-color:#e5701a}.wc.alert h3{color:#e5701a}"

#if SC_SD_ARCHIVE

"#sdwrap{display:flex;gap:12px;align-items:center;background:var(--panel);"
"border:3px solid var(--line);border-radius:12px;padding:10px 12px;margin:8px 0;"
"box-shadow:4px 4px 0 var(--sh)}"
"#sdpie{width:96px;height:96px;flex:none}"
"#sdpie circle{fill:none;stroke-width:5}"
"#sdpie .trk{stroke:var(--trk)}"
"#sdpie .use{stroke:var(--accent);transition:stroke-dasharray .4s}"
"#sdpie text{font:700 7px system-ui;fill:var(--ink);text-anchor:middle}"
"#sdpie .sub{font-size:3.4px;fill:var(--muted)}"
"#sdfacts{flex:1;min-width:0;font-size:13px}"
"#sdfacts div{display:flex;justify-content:space-between;gap:10px;margin:3px 0;color:var(--muted)}"
"#sdfacts b{color:var(--ink);font-weight:800;white-space:nowrap}"
"#sdstate{font-weight:900;font-size:14px;margin-bottom:4px;color:var(--safe)}"
"#sdstate.bad{color:var(--avoid,#d64545)}#sdstate.warn{color:var(--caution,#d99a1e)}"
"#sdcrumb{display:flex;flex-wrap:wrap;gap:4px;align-items:center;font-size:12px;margin:8px 0 4px}"
"#sdcrumb button{margin:0;padding:4px 8px;font-size:12px;font-weight:700;"
"background:var(--panel);color:var(--ink);box-shadow:2px 2px 0 var(--sh)}"
"#sdcrumb span{color:var(--muted)}"
"#sdlist{border:3px solid var(--line);border-radius:12px;background:var(--panel);"
"box-shadow:4px 4px 0 var(--sh);overflow:hidden}"
".sdrow{display:flex;align-items:center;gap:8px;padding:8px 10px;font-size:13px;"
"border-top:1px solid var(--line);text-align:left}"
".sdrow:first-child{border-top:0}"
".sdrow.pick{background:var(--trk)}"
".sdrow .si{width:18px;height:18px;flex:none;color:var(--accent)}"
".sdrow .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
"font-weight:700;color:var(--ink)}"
".sdrow .sz{color:var(--muted);font-size:12px;white-space:nowrap}"
".sdrow input{width:17px;height:17px;flex:none;accent-color:var(--accent)}"
".sdrow.nav{cursor:pointer}"
".sdmeta{padding:0 10px 8px 36px;font-size:11px;color:var(--muted);margin-top:-4px}"
".sdmeta.warn{color:var(--caution,#d99a1e)}"
"#sdempty{padding:14px 12px;font-size:13px;color:var(--muted);text-align:center}"
"#sdscans{border:3px solid var(--line);border-radius:12px;background:var(--panel);"
"box-shadow:4px 4px 0 var(--sh);overflow:hidden;margin-bottom:4px}"
".sdgrp{padding:6px 10px;font-size:12px;font-weight:900;letter-spacing:.4px;"
"text-transform:uppercase;color:var(--onacc);background:var(--accent);"
"border-top:1px solid var(--line)}"
".sdgrp:first-child{border-top:0}"
".sdgrp span{font-weight:700;text-transform:none;letter-spacing:0;opacity:.8}"
"h2.fold{cursor:pointer;display:flex;align-items:center;gap:6px;user-select:none}"
"h2.fold .tw{width:16px;height:16px;flex:none;transition:transform .15s}"
"h2.fold .tw.open{transform:rotate(90deg)}"

"h2.fold .cnt{margin-left:auto;font-size:12px;font-weight:700;color:var(--muted)}"
"#sdsel{position:sticky;bottom:0;margin:8px 0 0;padding:8px;border:3px solid var(--line);"
"border-radius:12px;background:var(--panel);box-shadow:4px 4px 0 var(--sh);display:none}"
"#sdsel.on{display:block}"
"#sdsel .cnt{font-size:13px;font-weight:800;margin-bottom:6px;color:var(--ink)}"
"#sdsel button{margin:0 0 6px;padding:9px}"
"#sdsel button:disabled{opacity:.45;cursor:not-allowed;box-shadow:none}"
#endif

#if SC_TRACKER_SOUND

"#tkcard{background:var(--panel);border:3px solid var(--line);border-radius:12px;"
"padding:10px 12px;margin:8px 0;box-shadow:4px 4px 0 var(--sh)}"
"#tkstate{font-size:15px;font-weight:900;color:var(--accent);margin-bottom:6px}"
"#tkcard button{width:100%;box-sizing:border-box}"
"#tkcard button:disabled{opacity:.45;cursor:not-allowed;box-shadow:none}"
"label.tkarm{display:flex;align-items:center;gap:8px;margin:6px 0;padding:6px 8px;"
"border:2px dashed var(--caution,#d99a1e);border-radius:9px;font-size:13px;font-weight:700}"
"label.tkarm input{width:18px;height:18px;flex:none;accent-color:var(--caution,#d99a1e)}"
"label.tkarm b{color:var(--caution,#d99a1e)}"
".tkrow{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px;"
"border-top:1px solid var(--line)}"
".tkrow .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
"font-weight:700;color:var(--ink)}"
".tkrow .sz{color:var(--muted);font-size:11px;white-space:nowrap}"
".tkrow button{width:auto;margin:0;padding:4px 10px;font-size:12px;font-weight:800;"
"background:var(--caution,#d99a1e);color:var(--onacc,#3f2a14);box-shadow:2px 2px 0 var(--sh)}"
"#tkstop{display:none}"
#endif

#if SC_ENV_LEARN

"#envcard{background:var(--panel);border:3px solid var(--line);border-radius:12px;"
"padding:10px 12px;margin:8px 0;box-shadow:4px 4px 0 var(--sh)}"
"#envhere{font-size:16px;font-weight:900;color:var(--accent);margin-bottom:2px}"
"#envcard button{width:100%;box-sizing:border-box}"
"#envcard button:disabled{opacity:.45;cursor:not-allowed;box-shadow:none}"
".envrow{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px;"
"border-top:1px solid var(--line)}"
".envrow .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
"font-weight:700;color:var(--ink)}"
".envrow.cur .nm{color:var(--safe)}"
".envrow .sz{color:var(--muted);font-size:12px;white-space:nowrap}"
".envrow button{width:auto;margin:0;padding:3px 8px;font-size:11px;font-weight:700;"
"background:var(--panel);color:var(--muted);box-shadow:2px 2px 0 var(--sh)}"
#endif
"#themebtn{position:fixed;top:10px;right:10px;z-index:15;width:42px;height:42px;"
"display:flex;align-items:center;justify-content:center;padding:0;margin:0;cursor:pointer;"
"color:var(--ink);background:var(--panel);border:3px solid var(--line);border-radius:11px;"
"box-shadow:3px 3px 0 var(--sh)}"
"#themebtn svg{width:22px;height:22px}"
"#themebtn .moon{display:none}body.dark #themebtn .sun{display:none}"
"body.dark #themebtn .moon{display:inline}"

"#pupimg{display:block;height:120px;width:auto;margin:2px auto 6px}"
#if SC_CLUSTER_HEAD

"#pgwrap{margin:2px 0 6px}"
"#pgcanvas{display:block;width:100%;max-width:360px;margin:0 auto;background:var(--panel);"
"border:3px solid var(--line);border-radius:12px;image-rendering:pixelated;cursor:pointer}"
".pgbar{display:flex;justify-content:space-between;max-width:360px;margin:6px auto 4px;"
"font-weight:800;color:var(--muted);font-size:13px}"
"#pgbtn{width:100%}"
#endif
"#splash{position:fixed;inset:0;background:var(--bg);display:flex;z-index:20;"
"align-items:center;justify-content:center;transition:opacity .45s}"
"#splash img{width:68%;max-width:300px;height:auto;"
"filter:drop-shadow(4px 4px 0 var(--sh))}"
"#splash.hide{opacity:0;pointer-events:none}"
"@media(prefers-reduced-motion:reduce){#splash{transition:none}}"

"#rcov{position:fixed;inset:0;z-index:30;display:none;align-items:center;"
"justify-content:center;padding:20px;background:rgba(20,14,6,.93)}"
"#rcov.on{display:flex}"
"#rcbox{background:var(--panel);border:3px solid var(--line);border-radius:14px;"
"box-shadow:4px 4px 0 var(--sh);max-width:340px;width:100%;padding:20px 18px;text-align:center}"
"#rcbox h3{margin:0 0 6px;font-size:16px;color:var(--accent)}"
"#rcmsg{color:var(--muted);font-size:13px;line-height:1.4;margin:0 0 12px}"
"#rcnum{font-size:38px;font-weight:900;margin:6px 0;color:var(--ink)}"
"#rcbtn{display:block;width:100%;box-sizing:border-box;margin:14px 0 0;padding:11px;"
"border:2px solid var(--line);border-radius:9px;font-size:15px;font-weight:800;"
"cursor:not-allowed;background:var(--trk);color:var(--muted);box-shadow:3px 3px 0 var(--sh)}"
"#rcbtn.ready{cursor:pointer;background:var(--safe);color:#0c2a16}"
"#rcbtn.ready:active{transform:translate(2px,2px);box-shadow:0 0 0 var(--sh)}"

"body{font-family:var(--font,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif)}"
".m{color:var(--hdr,var(--accent))}"
"h2{color:var(--hdr,var(--accent))}"
".ex{color:var(--muted)}"
"strong,b{color:var(--bold,var(--accent))}"
"em,i{color:var(--ital,var(--pname))}"
"#card span{color:var(--pname);font-weight:800}"
"#card #rem{color:var(--safe)}"
"#card #cli{color:var(--accent)}"
".set label>.lb{display:inline-flex;align-items:center;gap:8px;font-weight:700}"
".set .si{width:18px;height:18px;color:var(--accent);flex:none}"
"#customwrap{border:2px dashed var(--line);border-radius:10px;padding:6px 10px;margin:2px 0 8px}"
"#customwrap label{margin:6px 0}"

".set .chd{font-weight:800;font-size:11px;text-transform:uppercase;letter-spacing:.5px;"
"margin:10px 0 2px;padding-top:6px;border-top:1px solid var(--line);color:var(--muted)}"
"#customwrap .chd:first-child{border-top:0;padding-top:0;margin-top:2px}"
".set input[type=color]{width:46px;height:28px;padding:0;border:2px solid var(--line);"
"border-radius:6px;background:var(--panel);cursor:pointer}"
".set input[type=file]{font-size:12px;max-width:172px}"
".set input[type=range]{width:150px;accent-color:var(--accent);flex:none}"
".set label>.lb .ex{font-size:11px;font-weight:700;color:var(--muted);margin:0}"

"#card,#pcard,.wc,#sdwrap,#sdlist,#sdscans,#sdsel,#tkcard,#envcard,#rcbox,"
"#pgcanvas,#customwrap,.set,.dz{border-style:var(--cbs,solid);"
"border-width:var(--cbw,3px);border-radius:var(--cardr,12px)}"

".set,.dz{border-color:var(--line);background:var(--panel);padding:10px 12px;"
"margin:8px 0;box-shadow:3px 3px 0 var(--sh)}"
".dz{border-color:var(--avoid,#d63838)}"

"#tour{position:fixed;left:0;right:0;bottom:0;z-index:60;display:flex;"
"justify-content:center;padding:10px;pointer-events:none}"
"#tour[hidden]{display:none}"
"#tourbox{pointer-events:auto;width:100%;max-width:460px;background:var(--panel);"
"border:3px solid var(--line);border-radius:14px;padding:13px 15px;"
"box-shadow:0 6px 0 var(--sh),0 0 0 100vmax rgba(0,0,0,.28)}"
"#tourbox .tstep{font-size:10px;font-weight:800;letter-spacing:.6px;"
"text-transform:uppercase;color:var(--muted)}"
"#tourbox h3{margin:3px 0 5px;font-size:17px;color:var(--hdr,var(--accent))}"
"#tourtxt{font-size:13.5px;line-height:1.45}"
"#tourtxt b{color:var(--accent)}"
"#tournav{display:flex;gap:7px;margin-top:12px;align-items:center}"
"#tournav button{margin:0;padding:9px 13px;font-size:13.5px;font-weight:800;"
"border:2px solid var(--line);border-radius:9px;background:var(--panel);"
"color:var(--ink);cursor:pointer;box-shadow:2px 2px 0 var(--sh)}"
"#tournav button:active{transform:translate(2px,2px);box-shadow:0 0 0 var(--sh)}"
"#tournav .prim{background:var(--accent);color:var(--onacc);margin-left:auto}"
"#tournav #tourskip{border-color:var(--line2,var(--muted));background:none;"
"box-shadow:none;font-weight:700;color:var(--muted)}"
"#tournav button[hidden]{display:none}"

"body.hasbg::before{content:'';position:fixed;inset:-4%;z-index:-2;background-image:var(--bgimg);"
"background-size:var(--bgsize,cover);background-position:var(--bgpos,center);"
"background-repeat:var(--bgrep,no-repeat);background-attachment:fixed;"
"filter:blur(var(--bgblur,0px))}"
"body.hasbg::after{content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;"
"background:var(--bg);opacity:calc(var(--bgdim,0)/100)}"
"body.hasbg{--panelop:92%;--panelblur:7px}"
"body.hasbg #card,body.hasbg #pcard,body.hasbg .wc,body.hasbg #sdwrap,"
"body.hasbg #sdlist,body.hasbg #sdscans,body.hasbg #sdsel,body.hasbg #tkcard,"
"body.hasbg #envcard,body.hasbg #rcbox,body.hasbg .set,body.hasbg #customwrap,"
"body.hasbg #nav button,body.hasbg h1 img{background:var(--panel);"
"background:color-mix(in srgb,var(--panel) var(--panelop,92%),transparent);"
"backdrop-filter:blur(var(--panelblur,7px));"
"-webkit-backdrop-filter:blur(var(--panelblur,7px))}"
"</style></head><body>"

"<script>var TH={'sniffcheck':[0],'sniffcheck-dark':[1],"
"'hacker-green':[1,'#000000','#0a140a','#39ff14','#1f5f1f','#2fae2f','#000000','#39ff14','#7dff5a','#39ff14','#001a00','#001100'],"
"'hacker-red':[1,'#0a0000','#180404','#ff5a5a','#5a1414','#b02a2a','#000000','#ff1a1a','#ff8080','#ff4d4d','#200000','#200000'],"
"'midnight-blue':[1,'#0a1428','#12203c','#cfe0ff','#2a4a7a','#8aa6d0','#04070f','#4a90ff','#7db4ff','#5ec98a','#0a1a33','#04122a'],"
"'neon-purple':[1,'#140a24','#221238','#ede0ff','#4a2a7a','#b79ad6','#0a0416','#b14aff','#d18cff','#7dffb0','#1a0a33','#12042a']};"
"var THV=['bg','panel','ink','line','muted','sh','accent','pname','safe','trk','onacc'],"
"curth='sniffcheck';"
"function applyth(id){if(id==='custom'){applycustom();return}"
"if(!TH[id])id='sniffcheck';var t=TH[id],"
"s=document.body.style,i;"
"for(i=0;i<THV.length;i++){if(t[i+1])s.setProperty('--'+THV[i],t[i+1]);"
"else s.removeProperty('--'+THV[i])}"
"s.removeProperty('--bold');s.removeProperty('--ital');s.removeProperty('--hdr');s.removeProperty('--bgimg');"
"['caution','avoid','wifi','ble','track','drone'].forEach(function(k){s.removeProperty('--'+k)});"
"document.body.classList.remove('hasbg');"
"document.body.classList.toggle('dark',!!t[0]);applyopts();curth=id;"
"var e=document.getElementById('thm');if(e)e.value=id}"
"function customGet(){try{var c=JSON.parse(localStorage.getItem('sc-custom'));if(c&&c.v)return c}catch(e){}"
"return {d:document.body.classList.contains('dark')?1:0,v:{},img:''}}"
"function customSet(c){try{localStorage.setItem('sc-custom',JSON.stringify(c))}catch(e){}}"
"function applycustom(){var c=customGet(),s=document.body.style,i,"
"keys=['bg','panel','panelw','ink','line','accent','pname','onacc','sh','bold','ital','hdr','muted',"
"'safe','ok','caution','avoid','wifi','ble','track','drone','s1','s2','s3','s4','s5','s6'];"
"for(i=0;i<THV.length;i++)s.removeProperty('--'+THV[i]);"
"document.body.classList.toggle('dark',!!c.d);"
"for(i=0;i<keys.length;i++){if(c.v[keys[i]])s.setProperty('--'+keys[i],c.v[keys[i]]);"
"else s.removeProperty('--'+keys[i])}"
"if(c.img){s.setProperty('--bgimg','url('+c.img+')');document.body.classList.add('hasbg')}"
"else{s.removeProperty('--bgimg');document.body.classList.remove('hasbg')}"
"applyopts();"
"curth='custom';var e=document.getElementById('thm');if(e)e.value='custom'}"

"var OPTD={bs:'solid',bw:2.5,rad:12,op:92,pblur:7,fit:'cover',pos:'center',dim:35,iblur:0};"
"function optGet(){var c=customGet(),o=(c.o&&typeof c.o==='object')?c.o:{},k,r={};"
"for(k in OPTD)r[k]=(o[k]===undefined||o[k]===null)?OPTD[k]:o[k];return r}"
"function applyopts(){var o=optGet(),s=document.body.style;"
"s.setProperty('--cbs',o.bs);s.setProperty('--cbw',(+o.bw||OPTD.bw)+'px');"
"s.setProperty('--cardr',(+o.rad||0)+'px');"
"s.setProperty('--panelop',(+o.op||OPTD.op)+'%');"
"s.setProperty('--panelblur',(+o.pblur||0)+'px');"
"s.setProperty('--bgsize',o.fit==='tile'?'auto':o.fit==='contain'?'contain':'cover');"
"s.setProperty('--bgrep',o.fit==='tile'?'repeat':'no-repeat');"
"s.setProperty('--bgpos',o.pos||'center');"
"s.setProperty('--bgdim',String(+o.dim||0));"
"s.setProperty('--bgblur',(+o.iblur||0)+'px')}"
"function setthm(id){applyth(id);if(window.custSync)custSync();"
"try{localStorage.setItem('sc-theme',curth)}catch(e){}}"
"try{var t0=localStorage.getItem('sc-theme');"
"applyth(t0==='dark'?'sniffcheck-dark':t0==='light'?'sniffcheck':t0||'sniffcheck')}"
"catch(e){}</script>"
"<svg width=0 height=0 style=position:absolute aria-hidden=true><defs>"
"<symbol id=ic-mode viewBox=\"0 0 24 24\"><g fill=none stroke=currentColor stroke-width=2 stroke-linecap=round><path d=\"M4 8h10\"/><path d=\"M4 16h6\"/></g><g fill=currentColor><circle cx=18 cy=8 r=2.6/><circle cx=14 cy=16 r=2.6/></g></symbol>"
"<symbol id=ic-bri viewBox=\"0 0 24 24\"><circle cx=12 cy=12 r=4.4 fill=currentColor/><g stroke=currentColor stroke-width=2 stroke-linecap=round><path d=\"M12 2v3\"/><path d=\"M12 19v3\"/><path d=\"M2 12h3\"/><path d=\"M19 12h3\"/><path d=\"M4.6 4.6l2 2\"/><path d=\"M17.4 17.4l2 2\"/><path d=\"M19.4 4.6l-2 2\"/><path d=\"M6.6 17.4l-2 2\"/></g></symbol>"
"<symbol id=ic-led viewBox=\"0 0 24 24\"><path d=\"M12 3a6 6 0 0 0-3 11.2V17h6v-2.8A6 6 0 0 0 12 3Z\" fill=currentColor/><rect x=9 y=18 width=6 height=2.4 rx=1.2 fill=currentColor/></symbol>"
"<symbol id=ic-tmo viewBox=\"0 0 24 24\"><circle cx=12 cy=13 r=8 fill=none stroke=currentColor stroke-width=2/><path d=\"M12 9v4l3 2\" fill=none stroke=currentColor stroke-width=2 stroke-linecap=round/><path d=\"M9 2h6\" stroke=currentColor stroke-width=2 stroke-linecap=round/></symbol>"
"<symbol id=ic-palette viewBox=\"0 0 24 24\"><path d=\"M12 3a9 9 0 1 0 0 18c1.7 0 2-1.2 1.2-2.1-.8-.9-.5-2.1.9-2.1H17a4 4 0 0 0 4-4c0-4.9-4-7.7-9-7.7Z\" fill=none stroke=currentColor stroke-width=1.8/><g fill=currentColor><circle cx=8 cy=11 r=1.2/><circle cx=12 cy=8 r=1.2/><circle cx=16 cy=11 r=1.2/></g></symbol>"
"<symbol id=ic-font viewBox=\"0 0 24 24\"><path d=\"M5 19 10 5h2l5 14h-2.2l-1.3-3.8H8.5L7.2 19Zm4.1-5.6h4.2L11.2 7.4Z\" fill=currentColor/></symbol>"
#if SC_SD_ARCHIVE
"<symbol id=ic-folder viewBox=\"0 0 24 24\"><path fill=currentColor d=\"M3 6.5A1.5 1.5 0 0 1 4.5 5h4.2l1.8 2h9A1.5 1.5 0 0 1 21 8.5v9A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5v-11Z\"/></symbol>"
"<symbol id=ic-file viewBox=\"0 0 24 24\"><g fill=none stroke=currentColor stroke-width=1.8 stroke-linejoin=round><path d=\"M6.5 3.5h7l5 5v12h-12v-17Z\"/><path d=\"M13.5 3.5v5h5\"/></g></symbol>"
"<symbol id=ic-caret viewBox=\"0 0 24 24\"><path fill=currentColor d=\"M9 5.5 16.5 12 9 18.5Z\"/></symbol>"
"<symbol id=ic-scan viewBox=\"0 0 24 24\"><g fill=none stroke=currentColor stroke-width=2 stroke-linecap=round><path d=\"M3 8V5.5A2.5 2.5 0 0 1 5.5 3H8\"/><path d=\"M16 3h2.5A2.5 2.5 0 0 1 21 5.5V8\"/><path d=\"M21 16v2.5a2.5 2.5 0 0 1-2.5 2.5H16\"/><path d=\"M8 21H5.5A2.5 2.5 0 0 1 3 18.5V16\"/><path d=\"M7 12h10\"/></g></symbol>"
#endif
"<symbol id=ic-tabs viewBox=\"0 0 24 24\"><g fill=currentColor><rect x=3 y=3 width=7.5 height=7.5 rx=1.6/><rect x=13.5 y=3 width=7.5 height=7.5 rx=1.6/><rect x=3 y=13.5 width=7.5 height=7.5 rx=1.6/><rect x=13.5 y=13.5 width=7.5 height=7.5 rx=1.6/></g></symbol>"
"</defs></svg>"
"<div id=splash><img alt=\"SniffCheck\" src=\"/logo.png\"></div>"
"<script>setTimeout(function(){var s=document.getElementById('splash');"
"if(s){s.classList.add('hide');setTimeout(function(){s.style.display='none'},450)}},1200);</script>"
"<button id=themebtn type=button title=\"Quick light/dark flip (full theme list in Settings)\" aria-label=\"Toggle dark mode\">"
"<svg class=sun viewBox=\"0 0 24 24\" aria-hidden=true><circle cx=12 cy=12 r=5 fill=currentColor/>"
"<g stroke=currentColor stroke-width=2 stroke-linecap=round><path d=\"M12 1.5v3\"/><path d=\"M12 19.5v3\"/>"
"<path d=\"M1.5 12h3\"/><path d=\"M19.5 12h3\"/><path d=\"M4.2 4.2l2.1 2.1\"/><path d=\"M17.7 17.7l2.1 2.1\"/>"
"<path d=\"M19.8 4.2l-2.1 2.1\"/><path d=\"M6.3 17.7l-2.1 2.1\"/></g></svg>"
"<svg class=moon viewBox=\"0 0 24 24\" aria-hidden=true><path fill=currentColor d=\"M21 14.3A8.5 8.5 0 0 1 9.7 3 7.5 7.5 0 1 0 21 14.3z\"/></svg>"
"</button>"

"<script>document.getElementById('themebtn').onclick=function(){"
"setthm(document.body.classList.contains('dark')?'sniffcheck':'sniffcheck-dark')};</script>"
"<h1><img alt=\"SniffCheck\" src=\"/logo.png\"></h1>"
"<div class=m id=ssid>SniffCheck AP</div>"
"<div id=nav>"
"<button id=nv-home class=act onclick=\"nav('home')\">Home</button>"
"<button id=nv-pup onclick=\"nav('pup')\">Pup</button>"
#if SC_SD_ARCHIVE
"<button id=nv-sd onclick=\"nav('sd')\">SD Card</button>"
#endif
"<button id=nv-settings onclick=\"nav('settings')\">Settings</button>"
"</div>"

"<div class=\"view act\" id=v-home>"
"<div id=card>"
"<div><b>time remaining</b><span id=rem>–:––</span></div>"
"<div><b>capture</b><span id=recs>…</span></div>"
"<div><b>scans</b><span id=scans>…</span></div>"
"<div><b>clients</b><span id=cli>…</span></div>"
"<div><b>session</b><span id=sid>…</span></div>"
"<div><b>firmware</b><span id=fw>…</span></div>"
"</div>"
"<h2>Results</h2>"
"<a class=\"b rep\" href=\"/report.html\">View report</a>"
"<a class=\"b rep\" href=\"/report.html?dl=1\">Save report (.html)</a>"
"<a class=\"b dl\" href=\"/api/captures/live.jsonl\">Download data (.jsonl)</a>"
"<button class=dl onclick=\"savesd(this)\">Save to SD card</button>"
"<div class=ex id=sdex>Writes the capture to a microSD card in the master T-Dongle.</div>"
#if SC_TRACKER_SOUND
"<h2>Trackers nearby</h2>"
"<div id=tkcard>"
"<div id=tkstate>Checking\xe2\x80\xa6</div>"
"<label class=tkarm><input type=checkbox id=tkarm onchange=\"tkArm(this.checked)\">"
"<span>Allow safety sound <b>(transmits)</b></span></label>"
"<div class=ex>Off until you turn it on, and off again after a restart. Everything else "
"SniffCheck does only listens.</div>"
"<div id=tklist></div>"
"<button class=dl id=tkhowl onclick=\"tkHowl()\">Howl \xe2\x80\x94 ring them all</button>"
"<button class=off id=tkstop onclick=\"tkStop()\">Stop</button>"
"<div class=ex><b>Bark</b> rings one tracker, <b>Howl</b> rings each in turn. This is the "
"anti-stalking sound the Find My and DULT specs define \xe2\x80\x94 it is what lets you find "
"something that has been following you. A Find My accessory can only be rung while it is "
"<i>separated from its owner</i>; tags still with their owner, and Tiles (whose sound is "
"owner-only), are listed elsewhere but cannot be rung at all. Other trackers are worth "
"trying but many have no sound command and will simply not answer. A command that is "
"accepted is <i>not</i> proof the tracker made a noise.</div>"
"<div class=ex id=tkmsg></div>"
"</div>"
#endif

#if SC_ENV_LEARN
"<h2>Where you are</h2>"
"<div id=envcard>"
"<div id=envhere>Checking\xe2\x80\xa6</div>"
"<div class=ex id=envnote></div>"
"<div id=envlist></div>"
"<button class=ext id=envname onclick=\"envName()\">Name this place</button>"
"<button class=dl id=envlearn onclick=\"envLearn(true)\">Learn this place (walk around)</button>"
"<button class=ext id=envlearn2 onclick=\"envLearn(false)\">Learn from here (stay put)</button>"
"<div class=ex>A learn run takes several scans in a row and folds them into one place. "
"Walking a few steps between them is what separates the fixtures that define a room from "
"whatever happened to be passing. The AP closes while it scans and comes back when it "
"finishes.</div>"
"</div>"
#endif

"<h2>Session</h2>"
"<button class=ext onclick=\"post('/api/download/extend')\">Keep awake +15 min</button>"
"<button class=off onclick=\"arm(this,'/api/download/disable')\">Close AP</button>"
"<div class=dz><h2>Danger zone</h2>"
"<button class=cl onclick=\"arm(this,'/api/captures/clear-volatile')\">Clear capture</button>"
#if SC_CLUSTER_HEAD
"<button class=cl onclick=\"arm(this,'/api/cluster/brain/reset')\">Reset brain</button>"
"<div class=ex>Wipes the ePup brain's entire learned model and remembered environments, then restarts it. This cannot be undone.</div>"
#endif
"</div>"
"</div>"

"<div class=view id=v-pup>"
"<h2>Virtual Pup</h2>"
"<img id=pupimg alt=\"Suz the pup\" src=\"/pup.png\">"
"<div id=pcard>"
"<div><span id=pname>Suz</span><span class=pm id=pmood>curious</span></div>"
"<div><span id=plvl>Level &ndash;</span><span class=dimx id=pxp></span></div>"
"<div class=pbar><i id=pbarf style=width:0></i></div>"
"<div class=pstat><span id=pscan>&ndash; scans</span><span id=ppt></span></div>"
"</div>"
"<button class=ext onclick=\"ppost('/api/pup/pet')\">Pet</button>"
"<button class=ext onclick=\"ppost('/api/pup/treat')\">Give treat</button>"
"<button class=ext onclick=\"prename()\">Rename</button>"
"<div class=ex>XP comes from real scans and walks. Petting and treats are just for fun.</div>"
#if SC_CLUSTER_HEAD
"<h2>Fetch Runner</h2>"
"<div id=pgwrap>"
"<canvas id=pgcanvas width=360 height=200></canvas>"
"<div class=pgbar><span id=pgscore>0</span><span id=pgbest>best &ndash;</span></div>"
"<button class=dl id=pgbtn onclick=\"pgTap()\">Jump</button>"
"<div class=ex>Tap Jump (or press Space) to hop over the low blocks &mdash; but stay grounded when a block hangs from the top. Grab the floating gadget tokens for bonus points. Playing counts as time with your pup, and your best score is saved to it.</div>"
"</div>"
#endif
"<h2>Sniff Walk</h2>"
"<div class=wc id=wcard2></div>"
#if !SC_CLUSTER_HEAD
"<button class=dl onclick=\"armwalk(this)\">Start Sniff Walk</button>"
"<div class=ex>The walk scans Wi-Fi &amp; BLE while you carry SniffCheck, so this AP closes. End the walk on the device button &mdash; the AP re-opens with the walk summary.</div>"
#else
"<div class=ex>Start and stop the walk from the brain's on-device button or the Dog Park dashboard &mdash; the AP stays up and keeps streaming.</div>"
#endif
"<button class=off onclick=\"armpup(this)\">Reset Pup</button>"
"</div>"

#if SC_SD_ARCHIVE
"<div class=view id=v-sd>"
"<h2>Card</h2>"
"<div id=sdwrap>"
"<svg id=sdpie viewBox=\"0 0 42 42\" role=img aria-labelledby=sdpietitle>"
"<title id=sdpietitle>Card space used</title>"

"<circle class=trk cx=21 cy=21 r=15.9155></circle>"
"<circle class=use cx=21 cy=21 r=15.9155 stroke-dasharray=\"0 100\" "
"transform=\"rotate(-90 21 21)\" stroke-linecap=butt></circle>"
"<text x=21 y=21 id=sdpct>&ndash;</text>"
"<text x=21 y=26 class=sub id=sdpcts>used</text>"
"</svg>"
"<div id=sdfacts>"
"<div id=sdstate>Checking\xe2\x80\xa6</div>"
"<div><span>used</span><b id=sdused>&ndash;</b></div>"
"<div><span>free</span><b id=sdfree>&ndash;</b></div>"
"<div><span>volume</span><b id=sdvol>&ndash;</b></div>"
"<div><span>archive</span><b id=sdarch>&ndash;</b></div>"
"</div></div>"
"<div class=ex id=sdnote></div>"

"<h2 class=fold id=sdscansh onclick=\"sdScansFold()\">"
"<svg class=\"si tw\" id=sdstw><use href=\"#ic-caret\"/></svg>Saved scans"
"<span class=cnt id=sdscnt></span></h2>"
"<div id=sdscanswrap hidden>"
"<div id=sdscans><div id=sdempty>Loading\xe2\x80\xa6</div></div>"
"<div class=ex>Tick one to open it in the report, or tick two to compare them. "
"Rename a scan and the file on the card is renamed too, so the card still makes sense "
"on a computer.</div>"
"</div>"

"<h2 class=fold id=sdfoldh onclick=\"sdFold()\">"
"<svg class=\"si tw\" id=sdtw><use href=\"#ic-caret\"/></svg>Browse the whole card</h2>"
"<div id=sdbrowse hidden>"
"<div id=sdcrumb></div>"
"<div id=sdlist><div id=sdempty>Loading\xe2\x80\xa6</div></div>"
"<div class=ex>Everything on the card, read-only. Saved scans live in "
"<b>/sniffcheck/sessions</b>.</div>"
"</div>"

"<div id=sdsel>"
"<div class=cnt id=sdcnt></div>"
"<button class=rep id=sdopen onclick=\"sdOpen()\">Open in report</button>"
"<button class=dl id=sdcmp onclick=\"sdCompare()\">Compare the two</button>"
"<button class=ext id=sdren onclick=\"sdRename()\">Rename</button>"
"<button class=ext id=sdser onclick=\"sdSeries()\">Group as a series\xe2\x80\xa6</button>"
"<button class=ext onclick=\"sdClear()\">Clear selection</button>"
"<button class=cl id=sddel onclick=\"armfn(this,'sddel',sdDelete)\">Delete selected</button>"
"</div>"

"<div class=dz><h2>Danger zone</h2>"
"<button class=cl onclick=\"armfn(this,'sdwipe',sdWipe)\">Erase all saved scans</button>"
"<div class=ex>Deletes every session in the archive. The scan running right now is kept. "
"This cannot be undone.</div>"
"</div>"
"</div>"
#endif

"<div class=view id=v-settings>"
"<div class=set>"
"<h2>Settings</h2>"
#if !SC_CLUSTER_HEAD
"<label><span class=lb><svg class=si><use href=\"#ic-mode\"/></svg>Mode</span><select id=mode onchange=\"sset('/api/settings/mode',{mode:this.value})\">"
"<option value=lite>Lite</option><option value=adv>Adv</option></select></label>"
"<div class=ex>Lite is a quick glance verdict. Adv is the full audit with drill-down. Applies on the next scan.</div>"
"<label><span class=lb><svg class=si><use href=\"#ic-bri\"/></svg>Brightness</span><select id=bri onchange=\"sset('/api/settings/brightness',{pct:+this.value})\">"
"<option value=25>25%</option><option value=50>50%</option>"
"<option value=75>75%</option><option value=100>100%</option></select></label>"
"<div class=ex>Screen backlight level.</div>"
"<label><span class=lb><svg class=si><use href=\"#ic-led\"/></svg>LED</span><select id=led onchange=\"sset('/api/settings/led',{enabled:this.value=='1'})\">"
"<option value=1>On</option><option value=0>Off</option></select></label>"
"<div class=ex>Status light on the dongle.</div>"
"<label><span class=lb><svg class=si><use href=\"#ic-tmo\"/></svg>AP timeout</span><select id=tmo onchange=\"sset('/api/settings/download-timeout',{minutes:+this.value})\">"
"<option value=15>15 min</option><option value=30>30 min</option>"
"<option value=60>60 min</option></select></label>"
"<div class=ex>How long the SniffCheck AP stays open.</div>"
#endif

"<label><span class=lb><svg class=si><use href=\"#ic-font\"/></svg>Font</span><select id=fnt onchange=\"setfont(this.value)\">"
"<option value=system>System</option>"
"<option value=rounded>Rounded</option>"
"<option value=serif>Serif</option>"
"<option value=mono>Monospace</option>"
"<option value=condensed>Condensed</option>"
"<option value=comic>Comic</option></select></label>"
"<div class=ex>Page font, saved in this browser.</div>"
"<label><span class=lb><svg class=si><use href=\"#ic-palette\"/></svg>Theme</span><select id=thm onchange=\"setthm(this.value)\">"
"<option value=sniffcheck>SniffCheck Yellow</option>"
"<option value=sniffcheck-dark>SniffCheck Dark</option>"
"<option value=hacker-green>Hacker &mdash; Neon Green</option>"
"<option value=hacker-red>Hacker &mdash; Blood Red</option>"
"<option value=midnight-blue>Midnight Blue</option>"
"<option value=neon-purple>Neon Purple</option>"
"<option value=custom>Custom&hellip;</option></select></label>"
"<div class=ex>WebUI colors, saved in this browser and shared with the report page.</div>"
"<div id=customwrap style=display:none>"
"<div class=chd>Core</div>"
"<label><span class=lb>Background</span><input type=color id=cc-bg oninput=\"cust('bg',this.value)\"></label>"
"<label><span class=lb>Panels</span><input type=color id=cc-panel oninput=\"cust('panel',this.value)\"></label>"
"<label><span class=lb>Panel tint</span><input type=color id=cc-panelw oninput=\"cust('panelw',this.value)\"></label>"
"<label><span class=lb>Body text</span><input type=color id=cc-ink oninput=\"cust('ink',this.value)\"></label>"
"<label><span class=lb>Headings</span><input type=color id=cc-hdr oninput=\"cust('hdr',this.value)\"></label>"
"<label><span class=lb>Descriptions</span><input type=color id=cc-muted oninput=\"cust('muted',this.value)\"></label>"
"<label><span class=lb>Borders</span><input type=color id=cc-line oninput=\"cust('line',this.value)\"></label>"
"<div class=chd>Accent</div>"
"<label><span class=lb>Highlight</span><input type=color id=cc-accent oninput=\"cust('accent',this.value)\"></label>"
"<label><span class=lb>Links / secondary</span><input type=color id=cc-pname oninput=\"cust('pname',this.value)\"></label>"
"<label><span class=lb>Button text</span><input type=color id=cc-onacc oninput=\"cust('onacc',this.value)\"></label>"
"<label><span class=lb>Shadow</span><input type=color id=cc-sh oninput=\"cust('sh',this.value)\"></label>"
"<div class=chd>Text style</div>"
"<label><span class=lb>Bold text</span><input type=color id=cc-bold oninput=\"cust('bold',this.value)\"></label>"
"<label><span class=lb>Italic text</span><input type=color id=cc-ital oninput=\"cust('ital',this.value)\"></label>"
"<div class=chd>Status</div>"
"<label><span class=lb>Success</span><input type=color id=cc-safe oninput=\"cust('safe',this.value)\"></label>"
"<label><span class=lb>Notice</span><input type=color id=cc-ok oninput=\"cust('ok',this.value)\"></label>"
"<label><span class=lb>Caution</span><input type=color id=cc-caution oninput=\"cust('caution',this.value)\"></label>"
"<label><span class=lb>Danger</span><input type=color id=cc-avoid oninput=\"cust('avoid',this.value)\"></label>"
"<div class=chd>Device (report page)</div>"
"<label><span class=lb>Wi-Fi</span><input type=color id=cc-wifi oninput=\"cust('wifi',this.value)\"></label>"
"<label><span class=lb>BLE</span><input type=color id=cc-ble oninput=\"cust('ble',this.value)\"></label>"
"<label><span class=lb>Tracker</span><input type=color id=cc-track oninput=\"cust('track',this.value)\"></label>"
"<label><span class=lb>Drone</span><input type=color id=cc-drone oninput=\"cust('drone',this.value)\"></label>"

"<div class=chd>Chart series (report page)</div>"
"<label><span class=lb>Series 1</span><input type=color id=cc-s1 oninput=\"cust('s1',this.value)\"></label>"
"<label><span class=lb>Series 2</span><input type=color id=cc-s2 oninput=\"cust('s2',this.value)\"></label>"
"<label><span class=lb>Series 3</span><input type=color id=cc-s3 oninput=\"cust('s3',this.value)\"></label>"
"<label><span class=lb>Series 4</span><input type=color id=cc-s4 oninput=\"cust('s4',this.value)\"></label>"
"<label><span class=lb>Series 5</span><input type=color id=cc-s5 oninput=\"cust('s5',this.value)\"></label>"
"<label><span class=lb>Series 6</span><input type=color id=cc-s6 oninput=\"cust('s6',this.value)\"></label>"
"<div class=chd>Base</div>"
"<label><span class=lb>Dark base</span><input type=checkbox id=cc-dark onchange=\"custDark(this.checked)\"></label>"
"</div>"

"<div class=chd>Blocks</div>"
"<label><span class=lb>Border style</span><select id=co-bs onchange=\"custO('bs',this.value)\">"
"<option value=solid>Solid</option><option value=dashed>Dashed</option>"
"<option value=dotted>Dotted</option><option value=double>Double</option></select></label>"
"<label><span class=lb>Border weight</span><select id=co-bw onchange=\"custO('bw',+this.value)\">"
"<option value=1.5>Hairline</option><option value=2.5>Normal</option>"
"<option value=3>Bold</option><option value=4>Heavy</option></select></label>"
"<label><span class=lb>Corners</span><select id=co-rad onchange=\"custO('rad',+this.value)\">"
"<option value=0>Square</option><option value=6>Slight</option>"
"<option value=12>Rounded</option><option value=20>Pill</option></select></label>"
"<div class=ex>Applies to every card and block here and on the report page.</div>"

"<div class=chd>Background image</div>"
"<label><span class=lb>Image</span><input type=file id=cc-img accept=image/* onchange=\"custImg(this)\"></label>"
"<label><span class=lb>Fit</span><select id=co-fit onchange=\"custO('fit',this.value)\">"
"<option value=cover>Fill screen</option><option value=contain>Fit whole image</option>"
"<option value=tile>Tile</option></select></label>"
"<label><span class=lb>Position</span><select id=co-pos onchange=\"custO('pos',this.value)\">"
"<option value=center>Center</option><option value=\"center top\">Top</option>"
"<option value=\"center bottom\">Bottom</option><option value=\"left center\">Left</option>"
"<option value=\"right center\">Right</option></select></label>"
"<label><span class=lb>Fade image <span id=co-dimv class=ex></span></span>"
"<input type=range id=co-dim min=0 max=90 step=5 oninput=\"custO('dim',+this.value)\"></label>"
"<label><span class=lb>Blur image <span id=co-iblurv class=ex></span></span>"
"<input type=range id=co-iblur min=0 max=12 step=1 oninput=\"custO('iblur',+this.value)\"></label>"
"<label><span class=lb>Text panel opacity <span id=co-opv class=ex></span></span>"
"<input type=range id=co-op min=60 max=100 step=2 oninput=\"custO('op',+this.value)\"></label>"
"<label><span class=lb>Frost behind panels <span id=co-pblurv class=ex></span></span>"
"<input type=range id=co-pblur min=0 max=16 step=1 oninput=\"custO('pblur',+this.value)\"></label>"
"<button class=off onclick=\"custClearImg()\">Remove background image</button>"
"<div class=ex>Fade and blur push the picture back; panel opacity and frost keep "
"results and body text readable on top of it. Saved in this browser and shared "
"with the report page.</div>"

"<div class=hot><span class=hotlbl><svg class=si style=\"color:var(--accent);vertical-align:-3px\"><use href=\"#ic-tabs\"/></svg> Quick tabs</span>"
"<label class=hotck><input type=checkbox value=s-wifi onchange=\"savehot()\">Wi-Fi</label>"
"<label class=hotck><input type=checkbox value=s-ble onchange=\"savehot()\">BLE</label>"
"<label class=hotck><input type=checkbox value=s-clusters onchange=\"savehot()\">Clusters</label>"
"<label class=hotck><input type=checkbox value=s-channel onchange=\"savehot()\">Channels</label>"
"<label class=hotck><input type=checkbox value=s-trackers onchange=\"savehot()\">Trackers</label>"
"<label class=hotck><input type=checkbox value=s-alerts onchange=\"savehot()\">Notifications</label>"
"<label class=hotck><input type=checkbox value=s-privacy onchange=\"savehot()\">Privacy</label>"
"<label class=hotck><input type=checkbox value=s-banner onchange=\"savehot()\">Summary</label>"
"<label class=hotck><input type=checkbox value=s-raw onchange=\"savehot()\">Raw</label>"
"<label class=hotck><input type=checkbox value=s-drones onchange=\"savehot()\">Drones</label>"
"</div>"
"<div class=ex>The report page's apps-grid button jumps to these tabs. Saved in this browser and shared with the report page.</div>"

"<div class=chd>Walkthrough</div>"
"<button class=off onclick=\"tourStart()\">Show the walkthrough again</button>"
"<div class=ex>The first-boot tour of this dashboard. It is dismissed per browser, "
"so a phone that has never seen it still gets it.</div>"
"</div>"
"</div>"
"<script>"
"var rem=0;function el(i){return document.getElementById(i)}"
"function fmt(s){var m=Math.floor(s/60),x=s%60;return m+':'+(x<10?'0':'')+x}"
"function refresh(){fetch('/api/status').then(function(r){return r.json()})"
".then(function(j){el('ssid').textContent=j.ssid||'SniffCheck AP';"
"el('recs').textContent=j.records+' records / '+Math.round(j.bytes/1024)+' KB'"
"+(j.dropped?' / '+j.dropped+' dropped':'');"
"el('scans').textContent=j.scans;el('cli').textContent=j.clients;"
"el('sid').textContent=j.session_id;"
"el('fw').textContent=j.fw_version+' / schema '+j.schema_version;"
"rem=j.seconds_remaining;el('rem').textContent=fmt(rem)})"
".catch(function(){})}"
"refresh();setInterval(refresh,5000);"
#if SC_ENV_LEARN

"setTimeout(function(){envPoll();setInterval(envPoll,5000)},0);"
#endif
#if SC_TRACKER_SOUND

"setTimeout(function(){tkPoll();setInterval(tkPoll,3000)},0);"
#endif
"setInterval(function(){if(rem>0){rem--;el('rem').textContent=fmt(rem)}},1000);"
"function post(u){fetch(u,{method:'POST'}).then(refresh)}"
"function applyset(j){if(!j)return;var e;"
"if(e=el('mode'))e.value=j.advisor_mode;"
"if(e=el('bri'))e.value=j.brightness_pct;"
"if(e=el('led'))e.value=j.led_enabled?'1':'0';"
"if(e=el('tmo'))e.value=j.download_timeout_min}"
"function loadset(){fetch('/api/settings').then(function(r){return r.json()})"
".then(applyset).catch(function(){})}"
"function sset(u,b){fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify(b)}).then(function(r){return r.json()}).then(applyset)"
".catch(function(){})}"
"loadset();"
"el('thm').value=curth;"

"function loadhot(){var a=['s-wifi','s-ble','s-clusters','s-channel'];"
"try{var v=JSON.parse(localStorage.getItem('sc-hotlist'));"
"if(v&&v.length)a=v}catch(e){}"
"var c=document.querySelectorAll('.hotck input'),i;"
"for(i=0;i<c.length;i++)c[i].checked=a.indexOf(c[i].value)>=0}"
"function savehot(){var c=document.querySelectorAll('.hotck input'),o=[],i;"
"for(i=0;i<c.length;i++)if(c[i].checked)o.push(c[i].value);"
"try{localStorage.setItem('sc-hotlist',JSON.stringify(o))}catch(e){}}"
"loadhot();"
"function applypup(j){if(!j)return;el('pname').textContent=j.name;"
"el('pmood').textContent=j.mood;el('plvl').textContent='Level '+j.level;"
"el('pxp').textContent=j.xp+' / '+j.xp_next+' xp';"
"el('pbarf').style.width=(j.xp_next?Math.min(100,Math.round(j.xp/j.xp_next*100)):0)+'%';"
"el('pscan').textContent=j.lifetime_scans+' scans \\u00b7 +'+j.last_scan_xp+' last';"
"el('ppt').textContent=j.pets+' pets \\u00b7 '+j.treats+' treats';"
"if(window.pgOnStatus)pgOnStatus(j)}"
"function loadpup(){fetch('/api/pup/status').then(function(r){return r.json()})"
".then(applypup).catch(function(){})}"
"function ppost(u){fetch(u,{method:'POST'}).then(function(r){return r.json()})"
".then(applypup).catch(function(){})}"
"function prename(){var n=prompt('Name your pup:',el('pname').textContent);"
"if(n===null)return;fetch('/api/pup/name',{method:'POST',"
"headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})})"
".then(function(r){return r.json()}).then(applypup).catch(function(){})}"
"function armpup(b){if(b.getAttribute('data-armed')){clearTimeout(tm['pr']);"
"disarm(b);ppost('/api/pup/reset');return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again to reset';tm['pr']=setTimeout(function(){disarm(b)},3000)}"
#if SC_CLUSTER_HEAD

"var pgBest=0;"
"function pgOnStatus(j){pgBest=j.high_score||0;var b=el('pgbest');if(b)b.textContent='best '+pgBest;}"
"(function(){var cv=el('pgcanvas');if(!cv)return;var cx=cv.getContext('2d');"
"var W=cv.width,H=cv.height,GY=H-24,SZ=48,G=0.6,JMP=-8.4;"
"var sheet=new Image(),sheetOk=false;sheet.onload=function(){sheetOk=true};"
"sheet.src='/epup_sprites.png';"
"var st='idle',score=0,gads=0,spd=2.4,py=GY,vy=0,obs=[],toks=[],frame=0,acc=0,spawn=60,tacc=0,tspawn=90,happy=0;"
"var raf=null,last=0,lag=0,STEP=33;"
"var GAD=['router','cam','tag','ant','ctl','chip'];"
"var TCOL={router:'#4bd6c9',cam:'#c9a34b',tag:'#8bb0ff',ant:'#7bd06a',ctl:'#d07bd0',chip:'#e8b84b'};"
"function reset(){score=0;gads=0;spd=2.4;py=GY;vy=0;obs=[];toks=[];frame=0;acc=0;spawn=60;tacc=0;tspawn=90;happy=0;st='run';}"
"function over(){st='over';stopLoop();draw();var s=Math.floor(score);"
"fetch('/api/pup/play',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({score:s})}).then(function(r){return r.json()}).then(applypup).catch(function(){});}"
"function px2(){return 48;}"

"function loop(ts){if(raf===null)return;var dt=ts-last;last=ts;if(dt>250)dt=250;lag+=dt;"
"while(lag>=STEP){tick();lag-=STEP;if(st!=='run')break;}draw();"
"if(st==='run')raf=requestAnimationFrame(loop);else raf=null;}"
"function startLoop(){if(raf!==null)return;last=performance.now();lag=0;raf=requestAnimationFrame(loop);}"
"function stopLoop(){if(raf!==null){cancelAnimationFrame(raf);raf=null;}}"
"window.pgTap=function(){if(st==='run'){if(py>=GY-0.5)vy=JMP;}"
"else if(st==='paused'){st='run';startLoop();}else{reset();startLoop();}};"
"window.pgPause=function(){if(st==='run'){st='paused';stopLoop();draw();}};"
"cv.addEventListener('pointerdown',function(e){e.preventDefault();window.pgTap();});"
"document.addEventListener('keydown',function(e){if(e.code==='Space'||e.key===' '){"
"var pv=el('v-pup');if(pv&&pv.classList.contains('act')){e.preventDefault();window.pgTap();}}});"
"document.addEventListener('visibilitychange',function(){if(document.hidden)window.pgPause();});"
"function spawnObs(){if(Math.random()<0.4)obs.push({x:W+8,top:true,w:16,h:104});"
"else obs.push({x:W+8,top:false,w:16,h:22+(Math.random()*22|0)});}"

"function spawnTok(){var ty=GY-(20+(Math.random()*36|0)),tx=W+8,i,o;"
"for(i=0;i<obs.length;i++){o=obs[i];if(tx+8>o.x&&tx-8<o.x+o.w)return;}"
"toks.push({x:tx,y:ty,r:8,k:GAD[(Math.random()*GAD.length)|0]});}"
"function tick(){score+=spd*0.05;spd+=0.0016;"
"vy+=G;py+=vy;if(py>GY){py=GY;vy=0;}if(happy>0)happy--;"
"acc++;if(acc>=spawn){acc=0;spawn=48+(Math.random()*46|0);spawnObs();}"
"tacc++;if(tacc>=tspawn){tacc=0;tspawn=80+(Math.random()*70|0);spawnTok();}"
"var i,o,t,pl=px2(),pr=pl+SZ-18,ptp=py-SZ+6,pbt=py-3;"
"for(i=obs.length-1;i>=0;i--){o=obs[i];o.x-=spd;if(o.x+o.w<0){obs.splice(i,1);continue;}"
"var ot=o.top?0:GY-o.h,ob=o.top?o.h:GY;"
"if(pr>o.x&&pl<o.x+o.w&&pbt>ot&&ptp<ob){over();return;}}"
"for(i=toks.length-1;i>=0;i--){t=toks[i];t.x-=spd;if(t.x+t.r<0){toks.splice(i,1);continue;}"
"if(pr>t.x-t.r&&pl<t.x+t.r&&pbt>t.y-t.r&&ptp<t.y+t.r){toks.splice(i,1);gads++;score+=5;happy=10;}}"
"frame++;}"
"function drawTok(t){var x=t.x,y=t.y;cx.fillStyle=TCOL[t.k]||'#e8b84b';"
"cx.strokeStyle='rgba(0,0,0,.4)';cx.lineWidth=1;"
"if(t.k==='router'){cx.fillRect(x-7,y-2,14,6);cx.beginPath();cx.moveTo(x-3,y-2);cx.lineTo(x-5,y-9);"
"cx.moveTo(x+3,y-2);cx.lineTo(x+5,y-9);cx.stroke();}"
"else if(t.k==='cam'){cx.fillRect(x-7,y-5,14,10);cx.fillStyle='#20303a';cx.beginPath();cx.arc(x+1,y,3,0,6.28);cx.fill();}"
"else if(t.k==='tag'){cx.beginPath();cx.arc(x,y,7,0,6.28);cx.fill();cx.fillStyle='#20303a';cx.beginPath();cx.arc(x,y,2.5,0,6.28);cx.fill();}"
"else if(t.k==='ant'){cx.beginPath();cx.moveTo(x,y-8);cx.lineTo(x+6,y+6);cx.lineTo(x-6,y+6);cx.closePath();cx.fill();}"
"else if(t.k==='ctl'){cx.fillRect(x-8,y-4,16,8);cx.fillStyle='#20303a';cx.fillRect(x-5,y-1,2,2);cx.fillRect(x+3,y-1,2,2);}"
"else{cx.fillRect(x-6,y-6,12,12);cx.beginPath();"
"cx.moveTo(x-6,y-3);cx.lineTo(x-9,y-3);cx.moveTo(x-6,y+3);cx.lineTo(x-9,y+3);"
"cx.moveTo(x+6,y-3);cx.lineTo(x+9,y-3);cx.moveTo(x+6,y+3);cx.lineTo(x+9,y+3);cx.stroke();}}"
"function draw(){cx.clearRect(0,0,W,H);"
"cx.strokeStyle='#7a6a3a';cx.lineWidth=2;cx.beginPath();cx.moveTo(0,GY+2);cx.lineTo(W,GY+2);cx.stroke();"
"cx.fillStyle='#c9483b';var i,o;for(i=0;i<obs.length;i++){o=obs[i];"
"if(o.top)cx.fillRect(o.x,0,o.w,o.h);else cx.fillRect(o.x,GY-o.h,o.w,o.h);}"
"for(i=0;i<toks.length;i++)drawTok(toks[i]);"
"var row=(py<GY-1)?3:1,col=(row===1)?(Math.floor(frame/6)%2):0;"
"if(sheetOk)cx.drawImage(sheet,col*160,row*160,160,160,40,py-SZ,SZ,SZ);"
"else{cx.fillStyle='#e8b84b';cx.fillRect(40,py-SZ,SZ,SZ);}"
"if(happy>0){cx.strokeStyle='#fff7d6';cx.lineWidth=2;cx.beginPath();cx.arc(64,py-SZ/2,SZ*0.6,0,6.28);cx.stroke();}"
"cx.fillStyle='#111';cx.textAlign='left';cx.font='bold 12px system-ui';cx.fillText('\\u25c8 '+gads,6,16);"
"var sc=el('pgscore');if(sc)sc.textContent=Math.floor(score);"
"if(st!=='run'){cx.fillStyle='rgba(0,0,0,.5)';cx.fillRect(0,0,W,H);"
"cx.fillStyle='#fff7d6';cx.textAlign='center';cx.font='bold 17px system-ui';"
"cx.fillText(st==='over'?('Score '+Math.floor(score)):(st==='paused'?'Paused':'Fetch Runner'),W/2,H/2-4);"
"cx.font='bold 12px system-ui';"
"cx.fillText(st==='over'?('Gadgets '+gads+' \\u00b7 Tap Jump to replay'):(st==='paused'?'Tap Jump to resume':'Tap Jump to start'),W/2,H/2+16);"
"cx.textAlign='left';}}"
"draw();})();"
#endif
"loadpup();"
"var tm={};"
"function disarm(b){b.removeAttribute('data-armed');"
"var l=b.getAttribute('data-l');if(l)b.textContent=l}"
"function arm(b,u){if(b.getAttribute('data-armed')){clearTimeout(tm[u]);"
"disarm(b);post(u);return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again to confirm';"
"tm[u]=setTimeout(function(){disarm(b)},3000)}"
"function rcReconnect(){var b=el('rcbtn');b.disabled=true;b.textContent='Checking\\u2026';"
"fetch('/api/status',{cache:'no-store'}).then(function(r){if(r.ok){location.reload();return}"
"throw 0}).catch(function(){b.disabled=false;b.className='ready';"
"b.textContent='Not back yet \\u2014 rejoin the Wi-Fi, then tap'})}"
"var rcTk=null;"

"function rcStart(eta,title,msg){var total=Math.max(1,eta|0)+10,left=total;"
"el('rctitle').textContent=title||'Scan running';"
"if(msg)el('rcmsg').textContent=msg+' It relaunches with the same Wi-Fi password \\u2014 when "
"the timer ends, rejoin the AP and tap below.';"
"else el('rcmsg').innerHTML='The SniffCheck AP drops while the radio scans, then relaunches with the '"
"+'<b>same Wi-Fi password</b>. When the timer ends, rejoin the AP and tap below to load the new results.';"
"var b=el('rcbtn');b.disabled=true;b.className='';b.textContent='Reconnect \\u0026 refresh';"
"el('rcov').classList.add('on');"
"function paint(){el('rcnum').textContent=left>0?left+'s':'Ready'}paint();"
"if(rcTk)clearInterval(rcTk);"
"rcTk=setInterval(function(){left--;if(left<=0){left=0;paint();clearInterval(rcTk);rcTk=null;"
"b.disabled=false;b.className='ready'}else paint()},1000)}"
"function armscan(b){if(b.getAttribute('data-armed')){disarm(b);"
"b.textContent='Scan starting. Check SniffCheck.';b.disabled=true;"
"fetch('/api/scan/start',{method:'POST'}).then(function(r){return r.json()})"
".then(function(j){rcStart(j&&j.eta_seconds!=null?j.eta_seconds:60)})"
".catch(function(){rcStart(60)});return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again \\u2014 page will disconnect';"
"setTimeout(function(){disarm(b)},3000)}"
"function nav(v){["
#if SC_SD_ARCHIVE
"'sd',"
#endif
"'home','pup','settings'].forEach(function(n){"
"el('v-'+n).classList.toggle('act',n===v);"
"el('nv-'+n).classList.toggle('act',n===v)});"
#if SC_SD_ARCHIVE

"if(v==='sd'&&window.sdShow)sdShow();"
#endif
"if(v!=='pup'&&window.pgPause)window.pgPause();}"

"function walkhtml(w){var r=function(k,v){return '<div class=wr><span>'+k+"
"'</span><b>'+v+'</b></div>'};var mm=Math.floor(w.duration_sec/60),"
"ss=w.duration_sec%60;return '<h3>'+w.pup_name+'\\u2019s walk</h3>'+"
"r('time',mm+'m '+(ss<10?'0':'')+ss+'s')+"
"r('Wi-Fi',w.wifi_unique_bssid+' APs / '+w.wifi_unique_ssid+' networks')+"
"r('BLE',w.ble_unique_devices+' devices')+"
"(w.threat_events?r('caution',w.threat_events+' signals'):'')+"
"r('XP','+'+w.xp_awarded)+r('mood',w.mood)}"
"function applywalk(j){if(!j||!j.walk_id){return}"
"var h=walkhtml(j),cl='wc'+(j.threat_events>0?' alert':'');"
"var c=el('wcard2');if(c){c.innerHTML=h;c.className=cl;c.style.display='block'}}"
"function loadwalk(){fetch('/api/pup/walk/last').then(function(r){return r.json()})"
".then(applywalk).catch(function(){})}"
"loadwalk();"
"function armwalk(b){if(b.getAttribute('data-armed')){disarm(b);"
"b.textContent='Walk starting. Check SniffCheck.';b.disabled=true;"
"fetch('/api/pup/walk/start',{method:'POST'}).catch(function(){});return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again \\u2014 AP will close';"
"setTimeout(function(){disarm(b)},3000)}"

"var FONTS={system:\"system-ui,-apple-system,'Segoe UI',Roboto,sans-serif\","
"rounded:\"ui-rounded,'SF Pro Rounded','Segoe UI Rounded',Nunito,system-ui,sans-serif\","
"serif:\"Georgia,'Times New Roman',serif\","
"mono:\"ui-monospace,Menlo,Consolas,'Courier New',monospace\","
"condensed:\"'Roboto Condensed','Arial Narrow',system-ui,sans-serif\","
"comic:\"'Comic Sans MS','Comic Neue',cursive\"};"
"function applyfont(id){var f=FONTS[id]||FONTS.system;document.body.style.setProperty('--font',f);"
"var e=el('fnt');if(e)e.value=FONTS[id]?id:'system'}"
"function setfont(id){applyfont(id);try{localStorage.setItem('sc-font',id)}catch(e){}}"
"try{applyfont(localStorage.getItem('sc-font')||'system')}catch(e){}"

"function cust(k,v){var c=customGet();c.v[k]=v;customSet(c);setthm('custom')}"
"function custDark(on){var c=customGet();c.d=on?1:0;customSet(c);setthm('custom')}"

"function custImg(inp){var f=inp.files&&inp.files[0];if(!f)return;var r=new FileReader();"
"r.onload=function(){var c=customGet();c.img=String(r.result||'');"
"if(!c.o)c.o={dim:35,op:92,pblur:7,fit:'cover',pos:'center'};"
"customSet(c);setthm('custom');optSeed()};r.readAsDataURL(f)}"
"function custClearImg(){var c=customGet();c.img='';customSet(c);setthm('custom');var e=el('cc-img');if(e)e.value=''}"
"function custO(k,v){var c=customGet();if(!c.o)c.o={};c.o[k]=v;customSet(c);"
"applyopts();optSeed()}"
"function custSeed(){var c=customGet(),"
"D={bg:'#ffd93b',panel:'#fff7d6',panelw:'#ffc24a',ink:'#3f2a14',line:'#3f2a14',hdr:'#ff8a1e',"
"muted:'#7a5a34',accent:'#ff8a1e',pname:'#e0701a',onacc:'#3f2a14',sh:'#3f2a14',"
"bold:'#ff8a1e',ital:'#e0701a',safe:'#2fa85a',ok:'#e0a500',caution:'#d99a1e',avoid:'#d64545',"
"wifi:'#2a6cd6',ble:'#6a4ce0',track:'#d98a1e',drone:'#1ea6a6',"
"s1:'#2f7fd6',s2:'#7a52d6',s3:'#e5701a',s4:'#d6489a',s5:'#2fa85a',s6:'#0f9b9b'};"
"Object.keys(D).forEach(function(k){var e=el('cc-'+k);if(e)e.value=(c.v[k]||D[k])});"
"var d=el('cc-dark');if(d)d.checked=!!c.d}"

"function optSeed(){var o=optGet(),k,e,"
"S={bs:'co-bs',bw:'co-bw',rad:'co-rad',fit:'co-fit',pos:'co-pos',dim:'co-dim',"
"iblur:'co-iblur',op:'co-op',pblur:'co-pblur'};"
"for(k in S){e=el(S[k]);if(e)e.value=o[k]}"
"e=el('co-dimv');if(e)e.textContent=o.dim+'%';"
"e=el('co-iblurv');if(e)e.textContent=o.iblur+'px';"
"e=el('co-opv');if(e)e.textContent=o.op+'%';"
"e=el('co-pblurv');if(e)e.textContent=o.pblur+'px'}"
"function custSync(){var cw=el('customwrap');if(!cw)return;cw.style.display=(curth==='custom')?'':'none';if(curth==='custom')custSeed()}"
"custSync();optSeed();"

#if SC_SD_ARCHIVE

"function sdB(n){n=+n||0;if(n<1024)return n+' B';"
"var u=['KB','MB','GB','TB'],i=-1;do{n/=1024;i++}while(n>=1024&&i<3);"
"return (n<10?n.toFixed(1):Math.round(n))+' '+u[i]}"
"function sdEsc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){"
"return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]})}"

"var SDPATH='/sniffcheck/sessions',SDSEL={},SDBUSY=false,SDUNREAD=false;"

"function sdStat(){return fetch('/api/archive',{cache:'no-store'})"
".then(function(r){return r.json()}).then(function(j){"
"var st=el('sdstate'),note=el('sdnote');SDUNREAD=!!j.card_unreadable;"
"var vol=+j.volume_bytes||0,free=+j.free_bytes||0,used=vol>free?vol-free:0;"
"var pct=vol?Math.round(used*100/vol):0;"
"el('sdused').textContent=vol?sdB(used):'\\u2013';"
"el('sdfree').textContent=vol?sdB(free):'\\u2013';"
"el('sdvol').textContent=vol?sdB(vol)+(j.card_bytes>vol*1.5?' of a '+sdB(j.card_bytes)+' card':''):'\\u2013';"
"el('sdarch').textContent=j.session_open?(j.session_records|0)+' records saving now':"
"(j.mounted?'idle':'off');"
"var pie=document.querySelector('#sdpie .use');"
"pie.setAttribute('stroke-dasharray',(vol?pct:0)+' '+(100-(vol?pct:0)));"
"el('sdpct').textContent=vol?pct+'%':'\\u2013';"
"el('sdpcts').textContent=vol?'used':'no card';"
"st.className='';note.textContent='';"

"if(j.card_unreadable){st.textContent='Card unreadable \\u2014 wrong format';st.className='bad';"
"note.textContent='A card is in the slot and responding, but it has no filesystem SniffCheck can '"
"+'read. It must be formatted FAT32. Cards of 64 GB and up ship as exFAT, and Windows and phones '"
"+'reformat them back to exFAT, which is not supported. Reformat as FAT32, then restart SniffCheck. '"
"+'Scanning is unaffected either way.'}"
"else if(!j.card_present||!j.mounted){st.textContent='No card detected';st.className='bad';"
"note.textContent='Insert a microSD card (FAT32) and restart SniffCheck. '"
"+'Scanning works without one \\u2014 results just stay in memory until the stick is unplugged.'}"
"else if(j.full){st.textContent='Card full \\u2014 saving paused';st.className='bad';"
"note.textContent='Saving stops with '+sdB(j.reserve_bytes)+' left so the card cannot be corrupted. '"
"+'Scanning carries on as normal. Delete some sessions to resume.'}"
"else if(j.write_errors){st.textContent='Card connected \\u2014 '+j.write_errors+' write errors';"
"st.className='warn';"
"note.textContent='Some writes failed. If the card was removed and re-seated, restart SniffCheck to remount it.'}"
"else{st.textContent='Card connected';"
"if(j.card_bytes&&vol&&vol<j.card_bytes/2)"
"note.textContent='Only '+sdB(vol)+' of this '+sdB(j.card_bytes)+' card is the readable volume \\u2014 '"
"+'the rest is in partitions this firmware cannot see. Reformat the whole card as one FAT32 volume to use it all.'}"
"}).catch(function(){el('sdstate').textContent='Could not read the card';"
"el('sdstate').className='bad'})}"

"function sdCrumb(p){var parts=String(p||'/').split('/').filter(Boolean),h='',acc='';"
"h+='<button onclick=\"sdGo(\\'/\\')\">Card</button>';"
"for(var i=0;i<parts.length;i++){acc+='/'+parts[i];"
"h+='<span>&rsaquo;</span><button onclick=\"sdGo(\\''+sdEsc(acc)+'\\')\">'+sdEsc(parts[i])+'</button>'}"
"el('sdcrumb').innerHTML=h}"

"function sdRow(e,path){"
"var sel=SDSEL[e.id]?' pick':'';"
"var ic=e.dir?'ic-folder':(e.session?'ic-scan':'ic-file');"
"var h='<div class=\"sdrow'+(e.dir?' nav':'')+sel+'\"'"
"+(e.dir?' onclick=\"sdGo(\\''+sdEsc(path==='/'?'/'+e.name:path+'/'+e.name)+'\\')\"':'')+'>';"
"if(e.session)h+='<input type=checkbox '+(SDSEL[e.id]?'checked ':'')"
"+'onclick=\"event.stopPropagation();sdPick(\\''+sdEsc(e.id)+'\\',this.checked)\" '"
"+'aria-label=\"Select '+sdEsc(e.name)+'\">';"
"else h+='<span style=width:17px;flex:none></span>';"
"h+='<svg class=si><use href=\"#'+ic+'\"/></svg>';"
"h+='<span class=nm>'+sdEsc(e.name)+(e.current?' (saving now)':'')+'</span>';"
"h+='<span class=sz>'+(e.dir?'':sdB(e.bytes))+'</span>';"
"if(!e.dir&&!e.session)h+='<a class=sz href=\"/api/sd/file?path='"
"+encodeURIComponent(path==='/'?'/'+e.name:path+'/'+e.name)+'\">save</a>';"
"h+='</div>';"
"h+=sdMeta(e);return h}"

"function sdMeta(e){if(!e.session)return '';var m=e.meta;"
"if(!m)return '<div class=\"sdmeta warn\">No summary saved \\u2014 this run was cut short before '"
"+'its first checkpoint. The records are still there and it will still open.</div>';"
"var bits=[];"
"if(m.kind)bits.push(m.kind==='learn_env'?'environment':m.kind);"
"bits.push((m.records|0)+' records');"
"if(m.wifi_aps)bits.push(m.wifi_aps+' Wi-Fi');"
"if(m.ble_devices)bits.push(m.ble_devices+' BLE');"
"if(m.trackers)bits.push(m.trackers+' trackers');"
"if(m.env)bits.push(sdEsc(m.env));"
"if(m.complete&&m.close_us>m.open_us)"
"bits.push(Math.round((m.close_us-m.open_us)/1e6)+'s');"
"var warn=!m.complete;"
"return '<div class=\"sdmeta'+(warn?' warn':'')+'\">'+bits.join(' \\u00b7 ')"
"+(warn?' \\u00b7 interrupted (unplugged or reset) \\u2014 kept as far as it got':'')+'</div>'}"

"function sdLs(p){if(SDBUSY)return;SDBUSY=true;"
"fetch('/api/sd/ls?path='+encodeURIComponent(p),{cache:'no-store'})"
".then(function(r){return r.json()}).then(function(j){SDBUSY=false;"
"SDPATH=j.path||p;sdCrumb(SDPATH);"
"var box=el('sdlist');"
"if(!j.mounted){box.innerHTML='<div id=sdempty>'+(SDUNREAD?"
"'The card in the slot is not FAT32, so its contents cannot be listed.'"
":'No card \\u2014 nothing to browse.')+'</div>';return}"
"if(!j.exists){box.innerHTML='<div id=sdempty>That folder is not on this card.</div>';return}"
"var es=(j.entries||[]).slice().sort(function(a,b){"
"if(a.dir!==b.dir)return a.dir?-1:1;"
"return String(b.name).localeCompare(String(a.name))});"
"if(!es.length){box.innerHTML='<div id=sdempty>'"
"+(SDPATH===j.sessions_path?'No saved scans yet. Finish a scan with the card in and it lands here.'"
":'This folder is empty.')+'</div>';return}"
"box.innerHTML=es.map(function(e){return sdRow(e,SDPATH)}).join('')"
"+(j.truncated?'<div id=sdempty>Showing '+es.length+' of '+j.total"
"+' items \\u2014 open a subfolder to see the rest.</div>':'')})"
".catch(function(){SDBUSY=false;"
"el('sdlist').innerHTML='<div id=sdempty>Could not read the card.</div>'})}"

"var SDROWS=[];"
"function sdScans(){return fetch('/api/captures',{cache:'no-store'})"
".then(function(r){return r.json()}).then(function(j){"
"SDROWS=(j||[]).filter(function(e){return e.kind==='archive'});"
"var box=el('sdscans'),c=el('sdscnt');"
"if(c)c.textContent=SDROWS.length?SDROWS.length+(SDROWS.length===1?' scan':' scans'):'';"
"if(!SDROWS.length){box.innerHTML='<div id=sdempty>No saved scans yet. Finish a scan with the "
"card in and it lands here.</div>';sdSelBar();return}"

"var gs={},order=[];"
"SDROWS.slice().sort(function(a,b){return String(b.id).localeCompare(String(a.id))})"
".forEach(function(e){var s=(e.meta&&e.meta.series)||'';"
"if(!gs[s]){gs[s]=[];order.push(s)}gs[s].push(e)});"
"var h='';"
"order.forEach(function(s){"
"if(s)h+='<div class=sdgrp>'+sdEsc(s)+' <span>'+gs[s].length+' scans</span></div>';"
"gs[s].forEach(function(e){h+=sdScanRow(e)})});"
"box.innerHTML=h;sdSelBar()})"
".catch(function(){el('sdscans').innerHTML="
"'<div id=sdempty>Could not read the archive.</div>'})}"

"function sdScanRow(e){var m=e.meta;"
"var h='<div class=\"sdrow'+(SDSEL[e.id]?' pick':'')+'\">';"
"h+='<input type=checkbox '+(SDSEL[e.id]?'checked ':'')"
"+'onclick=\"sdPick(\\''+sdEsc(e.id)+'\\',this.checked)\" '"
"+'aria-label=\"Select '+sdEsc(e.id)+'\">';"
"h+='<svg class=si><use href=\"#ic-scan\"/></svg>';"
"h+='<span class=nm>'+sdEsc(e.id)+(e.current?' (saving now)':'')+'</span>';"
"h+='<span class=sz>'+sdB(e.bytes)+'</span>';"
"h+='</div>';"
"h+=sdMeta({session:true,meta:m});return h}"

"function sdFold(){var b=el('sdbrowse'),open=b.hasAttribute('hidden');"
"if(open){b.removeAttribute('hidden');el('sdtw').classList.add('open');"
"if(!SDBROWSED){SDBROWSED=true;sdLs(SDPATH)}}"
"else{b.setAttribute('hidden','');el('sdtw').classList.remove('open')}}"
"var SDBROWSED=false;"

"function sdScansSet(on){var w=el('sdscanswrap'),t=el('sdstw');if(!w)return;"
"if(on){w.removeAttribute('hidden');if(t)t.classList.add('open')}"
"else{w.setAttribute('hidden','');if(t)t.classList.remove('open')}"
"try{localStorage.setItem('sc-sd-scans',on?'1':'0')}catch(e){}}"
"function sdScansFold(){sdScansSet(el('sdscanswrap').hasAttribute('hidden'))}"

"function sdRenameOne(id,name,series){"
"var b={id:id};if(name!=null)b.name=name;if(series!=null)b.series=series;"
"return fetch('/api/archive/rename',{method:'POST',"
"headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})"
".then(function(r){return r.json()})}"

"function sdRename(){var k=sdKeys();"
"if(k.length!==1){alert('Pick exactly one scan to rename.');return}"
"var cur=k[0],name=prompt('Name for this scan',cur);"
"if(name===null)return;name=name.trim();if(!name)return;"
"sdRenameOne(cur,name,null).then(function(j){"
"if(!j.ok){alert(j.error||'Rename failed.');return}"
"SDSEL={};if(j.id&&j.id!==name)"
"alert('Saved as \\u201c'+j.id+'\\u201d \\u2014 the name was adjusted to fit a filename.');"
"sdSelBar();sdScans();if(SDBROWSED)sdLs(SDPATH)})"
".catch(function(){alert('Rename failed.')})}"

"function sdSeries(){var k=sdKeys();"
"if(!k.length){alert('Pick the scans to group first.');return}"
"var s=prompt('Series name for '+k.length+' scan'+(k.length===1?'':'s'),'');"
"if(s===null)return;s=s.trim();"
"var ord=SDROWS.filter(function(e){return SDSEL[e.id]})"
".map(function(e){return e.id}).reverse();"
"if(!ord.length)ord=k;"
"var i=0,fail=0;(function step(){"
"if(i>=ord.length){SDSEL={};sdSelBar();sdScans();if(SDBROWSED)sdLs(SDPATH);"
"if(fail)alert(fail+' scan'+(fail===1?'':'s')+' could not be renamed.');return}"
"var n=s?s+'-'+('0'+(i+1)).slice(-2):null;"
"sdRenameOne(ord[i],n,s).then(function(j){if(!j.ok)fail++})"
".catch(function(){fail++}).then(function(){i++;step()})})()}"

"function sdGo(p){sdLs(p)}"
"function sdPick(id,on){if(on)SDSEL[id]=1;else delete SDSEL[id];sdSelBar();"
"sdScans();if(SDBROWSED)sdLs(SDPATH)}"
"function sdClear(){SDSEL={};sdSelBar();sdScans();if(SDBROWSED)sdLs(SDPATH)}"
"function sdKeys(){return Object.keys(SDSEL)}"
"function sdSelBar(){var k=sdKeys(),bar=el('sdsel');"
"bar.classList.toggle('on',k.length>0);if(!k.length)return;"
"el('sdcnt').textContent=k.length+(k.length===1?' scan selected':' scans selected');"
"el('sdcmp').disabled=(k.length!==2);"
"el('sdcmp').textContent=k.length===2?'Compare the two':'Compare (pick exactly 2)';"
"el('sdren').disabled=(k.length!==1);"
"el('sdren').textContent=k.length===1?'Rename':'Rename (pick exactly 1)';"
"el('sdser').textContent=k.length===1?'Put in a series\\u2026'"
":'Group these '+k.length+' as a series\\u2026';"
"el('sdopen').textContent=k.length===1?'Open in report':'Open all '+k.length+' together'}"

"function sdOpen(){var k=sdKeys();if(!k.length)return;"
"location.href='/report.html?load='+encodeURIComponent(k.join(','))}"
"function sdCompare(){var k=sdKeys();if(k.length!==2)return;"
"location.href='/report.html?compare='+encodeURIComponent(k.join(','))}"

"function sdDelete(){var k=sdKeys();if(!k.length)return;"
"var n=0;(function step(i){if(i>=k.length){SDSEL={};sdSelBar();sdStat();sdScans();"
"if(SDBROWSED)sdLs(SDPATH);return}"
"fetch('/api/archive/delete',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({id:k[i]})}).then(function(){n++}).catch(function(){})"
".then(function(){step(i+1)})})(0)}"
"function sdWipe(){fetch('/api/archive/wipe',{method:'POST'}).then(function(){"
"SDSEL={};sdSelBar();sdStat();sdScans();if(SDBROWSED)sdLs(SDPATH)}).catch(function(){})}"

"function armfn(b,k,fn){if(b.getAttribute('data-armed')){clearTimeout(tm[k]);disarm(b);fn();return}"
"b.setAttribute('data-armed','1');b.setAttribute('data-l',b.textContent);"
"b.textContent='tap again to confirm';"
"tm[k]=setTimeout(function(){disarm(b)},3000)}"

"var sdSeen=false;"
"function sdShow(){sdStat();sdScans();if(SDBROWSED)sdLs(SDPATH);"
"var o=false;try{o=localStorage.getItem('sc-sd-scans')==='1'}catch(e){}"
"sdScansSet(o);"
"if(!sdSeen){sdSeen=true;setInterval(function(){"
"if(el('v-sd').classList.contains('act'))sdStat()},5000)}}"
#endif

#if SC_TRACKER_SOUND

"function tkEsc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){"
"return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]})}"

"function tkDraw(j){"
"var st=el('tkstate'),n=(j.targets||[]).length;"
"el('tkarm').checked=!!j.armed;"
"var howl=(j.howl||{});"
"if(howl.active)st.textContent='Ringing \\u2014 '+(howl.done|0)+' of '+(howl.total|0);"
"else if(!n)st.textContent='Nothing ringable nearby';"
"else st.textContent=n+' tracker'+(n===1?'':'s')+' can be rung';"
"var h='';"
"(j.targets||[]).forEach(function(t){"
"h+='<div class=tkrow><span class=nm>'+tkEsc(t.name||t.mac)+'</span>'"
"+'<span class=sz>'+tkEsc(t.kind==='find_my_other'?'separated Find My'"
":t.kind==='generic'?'unknown tracker \\u2014 may not respond':t.kind)"
"+' \\u00b7 '+(t.rssi|0)+' dBm</span>'"
"+'<button onclick=\"tkBark(\\''+tkEsc(t.mac)+'\\')\"'+(j.armed?'':' disabled')"
"+'>Bark</button></div>';"
"if(!t.name)return});"
"el('tklist').innerHTML=h;"
"el('tkhowl').disabled=(!j.armed||!n||!!howl.active);"
"el('tkstop').style.display=howl.active?'':'none'}"

"function tkPoll(){return fetch('/api/trackers',{cache:'no-store'})"
".then(function(r){return r.json()}).then(tkDraw).catch(function(){})}"

"function tkArm(on){"

"if(on&&!confirm('Allow SniffCheck to transmit?\\n\\nIt will connect to a tracker that is "
"separated from its owner and send the documented anti-stalking sound command. It never "
"pairs and never reads owner data. Turning this on is the only way SniffCheck transmits.'))"
"{el('tkarm').checked=false;return}"
"fetch('/api/trackers/arm',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({armed:!!on})}).then(tkPoll).catch(function(){})}"

"function tkSay(m){var e=el('tkmsg');if(e)e.textContent=m||''}"

"function tkBark(mac){"
"if(!confirm('Bark at '+mac+'?\\n\\nThis transmits a sound command. Best effort \\u2014 an "
"accepted command is not proof the tracker made a noise.'))return;"
"tkSay('Sending\\u2026');"
"fetch('/api/trackers/bark',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({mac:mac})}).then(function(r){return r.json()})"
".then(function(j){tkSay((j&&(j.message||j.error))||'');tkPoll()})"
".catch(function(){tkSay('Could not send.')})}"

"function tkHowl(){"
"if(!confirm('Ring every tracker that can be rung, one at a time?\\n\\nThis transmits. You "
"can stop at any point.'))return;"
"fetch('/api/trackers/howl',{method:'POST'}).then(function(r){return r.json()})"
".then(function(j){tkSay((j&&(j.message||j.error))||'');tkPoll()})"
".catch(function(){tkSay('Could not start.')})}"

"function tkStop(){fetch('/api/trackers/stop',{method:'POST'})"
".then(function(){tkSay('Stopping after the current tracker.');tkPoll()})"
".catch(function(){})}"
#endif

#if SC_ENV_LEARN

"function envEsc(s){return String(s==null?'':s).replace(/[&<>\"']/g,function(c){"
"return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]})}"
"var ENV={cur:-1,count:0,envs:[]};"

"function envDraw(j){ENV=j||ENV;"
"var here=el('envhere'),note=el('envnote'),run=(j&&j.run)||{};"
"if(run.active){"
"here.textContent='Learning \\u2014 scan '+((run.done|0)+1)+' of '+(run.want|0);"
"note.textContent=run.waiting?('Move a few steps. Next scan in '+(run.next_in|0)+'s.')"
":'Scanning. The AP is down until the run finishes.';"
"}else if(j.cur<0){"
"here.textContent='Not placed yet';"
"note.textContent='Run a scan first \\u2014 a place is recognised from the Wi-Fi "
"infrastructure around it.';"
"}else{"
"here.textContent=j.label||('Place '+(j.cur+1));"
"var bits=[];"
"bits.push(j.known?'recognised':'not seen enough times to be sure');"
"bits.push(j.similarity+'% match');"
"if(j.quality)bits.push(j.quality+'% spatial confidence');"
"if(j.is_new)bits.push('this looks like somewhere new');"
"note.textContent=bits.join(' \\u00b7 ')+'.';"
"}"
"var h='';(j.envs||[]).forEach(function(e){"
"h+='<div class=\"envrow'+(e.current?' cur':'')+'\">'"
"+'<span class=nm>'+envEsc(e.label||('Place '+(e.idx+1)))+'</span>'"
"+'<span class=sz>'+e.scans+' scans \\u00b7 '+e.landmarks+' fixtures</span>'"
"+'<button onclick=\"envForget('+e.idx+')\" aria-label=\"Forget\">forget</button></div>'});"
"el('envlist').innerHTML=h;"
"var busy=!!run.active;"
"['envname','envlearn','envlearn2'].forEach(function(id){el(id).disabled=busy})}"

"function envPoll(){return fetch('/api/env',{cache:'no-store'})"
".then(function(r){return r.json()}).then(envDraw).catch(function(){})}"

"function envName(){var cur=ENV.label||'';"
"var n=prompt('What is this place called?',cur);"
"if(n===null)return;n=n.trim();if(!n)return;"
"fetch('/api/env/label',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({idx:ENV.cur,label:n})}).then(envPoll).catch(function(){})}"

"function envForget(i){if(!confirm('Forget this place? Its landmarks are deleted.'))return;"
"fetch('/api/env/forget',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({idx:i})}).then(envPoll).catch(function(){})}"

"function envLearn(move){"
"var n=prompt('Name this place (optional)','');"
"if(n===null)return;"
"fetch('/api/env/learn/start',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({scans:move?4:3,reposition:!!move,name:n.trim()})})"
".then(function(r){return r.json()}).then(function(j){"
"if(!j.ok){alert(j.error||'Could not start.');return}"
"rcStart(j.eta_seconds||120,'Learning this place',"
"(move?'Walk a few steps between scans. ':'')+'The AP is closed while it scans and will "
"come back when the run finishes.')})"
".catch(function(){alert('Could not start.')})}"
#endif

"function savesd(b){var o=b.textContent;b.disabled=true;b.textContent='Saving to SD\\u2026';"
"fetch('/api/captures/save-sd',{method:'POST'}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})"
".then(function(x){var m=el('sdex');if(m)m.textContent=(x.j&&(x.j.message||x.j.error))||(x.ok?'Saved to SD card.':'SD save failed.');"
"b.textContent=o;b.disabled=false})"
".catch(function(){var m=el('sdex');if(m)m.textContent='SD save failed.';b.textContent=o;b.disabled=false})}"
"</script>"
"<div id=rcov><div id=rcbox>"
"<h3 id=rctitle>Scan running</h3>"
"<div id=rcmsg></div>"
"<div id=rcnum>\xe2\x80\x93</div>"
"<button id=rcbtn disabled onclick=\"rcReconnect()\">Reconnect &amp; refresh</button>"
"</div></div>"
"<div id=dig>SniffCheck is digging<span>Decoding and scoring uploaded MACs on-device...</span></div>"

"<div id=tour hidden><div id=tourbox>"
"<div class=tstep id=tourstep></div>"
"<h3 id=tourttl></h3>"
"<div id=tourtxt></div>"
"<div id=tournav>"
"<button id=tourskip onclick=\"tourEnd()\">Skip</button>"
"<button id=tourback onclick=\"tourGo(-1)\">Back</button>"
"<button id=tournext class=prim onclick=\"tourGo(1)\">Next</button>"
"</div></div></div>"

"<script>"

"var TOUR=["
"{v:'home',t:'Welcome to SniffCheck',"
"b:'This stick <b>listens</b> to the Wi-Fi and Bluetooth around you and tells you what it hears. "
"It never transmits at anything and never phones home \\u2014 there is no account, no cloud, no uplink. "
"Everything you are about to see was worked out on the device itself.'},"
"{v:'home',t:'The Home tab',"
"b:'The card at the top is the live state: how long this access point stays up, how many records "
"have been captured, how many scans have run. <b>Time remaining</b> is a battery-saving timeout \\u2014 "
"when it runs out the AP closes and scanning carries on without it.'},"
"{v:'home',t:'Getting your results out',"
"b:'<b>View report</b> opens the full analysis in your browser. <b>Save report</b> writes that same page "
"to a file you can keep or send on, and <b>Download data</b> gives you the raw capture as JSONL. "
"Nothing is uploaded anywhere \\u2014 these all save to whatever device you are reading this on.'},"
"{v:'home',t:'The report is the real tool',"
"b:'The report page opens on the <b>RF Env Summary</b>: a verdict, count tiles, and blocks for spectrum, "
"security posture, vendors and device mix. Tap any number to drill into the exact records behind it. "
"<b>Customize</b> lets you group those blocks into your own tabs.'},"
"{v:'pup',t:'The Pup',"
"b:'Your pup levels up as the stick sees new things, and earns trophies for the unusual ones. "
"A <b>Sniff Walk</b> is a walking survey \\u2014 start one, carry the stick around, and end it when you are "
"done. It is saved on its own so you can open just that walk later.'},"
#if SC_SD_ARCHIVE
"{v:'sd',t:'The SD card',"
"b:'With a FAT32 card in the slot, every scan and walk is written to it as it happens \\u2014 so a capture "
"survives being unplugged. <b>Saved scans</b> starts folded; open it to pick a run and view it in the "
"report, or tick two to compare them. Scans that captured nothing are cleaned up on their own.'},"
#endif
"{v:'settings',t:'Make it yours',"
"b:'Settings holds the display mode, brightness and screen timeout, plus themes and a <b>Custom</b> palette "
"where every colour is yours to set. <b>Blocks</b> changes the frame around every card, and you can drop in "
"a background image and fade it until the text on top stays readable.'},"
"{v:'home',t:'That is the tour',"
"b:'Everything here works with no internet and no app. If you want this walkthrough again it is at the "
"bottom of <b>Settings</b>.'}"
"];"
"var tourAt=0;"
"function tourPaint(){var s=TOUR[tourAt];if(!s)return tourEnd();"
"if(s.v)nav(s.v);"
"el('tourstep').textContent='Step '+(tourAt+1)+' of '+TOUR.length;"
"el('tourttl').textContent=s.t;"
"el('tourtxt').innerHTML=s.b;"
"el('tourback').hidden=(tourAt===0);"
"var last=(tourAt===TOUR.length-1);"
"el('tournext').textContent=last?'Got it \\u2014 hide this':'Next';"
"el('tourskip').hidden=last;"
"window.scrollTo(0,0)}"
"function tourGo(d){"

"if(d>0&&tourAt===TOUR.length-1)return tourEnd();"
"tourAt=Math.max(0,tourAt+d);tourPaint()}"
"function tourEnd(){el('tour').hidden=true;"
"try{localStorage.setItem('sc-tour','1')}catch(e){}}"
"function tourStart(){tourAt=0;el('tour').hidden=false;tourPaint()}"

"try{if(localStorage.getItem('sc-tour')!=='1')tourStart()}catch(e){}"
"</script>"
"</body></html>";

static esp_err_t root_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");

    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, DASH_HTML, sizeof(DASH_HTML) - 1);
}

static esp_err_t logo_get(httpd_req_t *req)
{
    size_t len = (size_t)(_binary_webap_logo_png_end - _binary_webap_logo_png_start);
    httpd_resp_set_type(req, "image/png");
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    return httpd_resp_send(req, (const char *)_binary_webap_logo_png_start, len);
}

static esp_err_t favicon_get(httpd_req_t *req)
{
    size_t len = (size_t)(_binary_webap_favicon_png_end - _binary_webap_favicon_png_start);
    httpd_resp_set_type(req, "image/png");
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    return httpd_resp_send(req, (const char *)_binary_webap_favicon_png_start, len);
}

static esp_err_t pup_get(httpd_req_t *req)
{
    size_t len = (size_t)(_binary_webap_pup_png_end - _binary_webap_pup_png_start);
    httpd_resp_set_type(req, "image/png");
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    return httpd_resp_send(req, (const char *)_binary_webap_pup_png_start, len);
}

#if SC_EPUP_BRAIN
static esp_err_t epup_sprites_get(httpd_req_t *req)
{
    size_t len = (size_t)(_binary_epup_sprites_png_end - _binary_epup_sprites_png_start);
    httpd_resp_set_type(req, "image/png");
    httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    return httpd_resp_send(req, (const char *)_binary_epup_sprites_png_start, len);
}
#endif

static esp_err_t status_get(httpd_req_t *req)
{
    capture_ring_stats_t st;
    capture_ring_get_stats(&st);

    char json[400];

    snprintf(json, sizeof(json),
        "{\"records\":%u,\"bytes\":%u,\"dropped\":%u,\"scans\":%u,"
        "\"session_id\":\"%s\",\"fw_version\":\"%s\",\"schema_version\":\"%s\","
        "\"seconds_remaining\":%u,\"clients\":%u,\"timeout_min\":%u,"
        "\"capture_disabled\":%s,"
        "\"ssid\":\"%s\"}",
        (unsigned)st.records_current, (unsigned)st.bytes_used,
        (unsigned)st.records_dropped, (unsigned)capture_writer_last_scan(),
        capture_writer_session_id(), capture_writer_fw_version(),
        capture_writer_schema_version(),
        (unsigned)download_mode_get_seconds_remaining(),
        (unsigned)download_mode_get_client_count(),
        (unsigned)download_mode_get_timeout_minutes(),
        capture_writer_emits_disabled() ? "true" : "false",
        download_mode_get_ssid());
    return send_json(req, json);
}

static const char *const k_stack_probe[] = {
    "sc_wdog", "httpd", "sc_sttwin",
    "sc_scan", "sc_capture", "sc_btn", "sc_anim", "sc_echo", "sc_dl", "sc_tsnd",
    "brain_bus", "brain_menu", "brain_web", "brain_log",
    "s3_ui", "s3_ingest", "s3_sniff", "s3_status", "s3_tx",
    "main", "tiT", "wifi", "IDLE",
};

static esp_err_t system_memory_get(httpd_req_t *req)
{

    char json[320];
    int n = snprintf(json, sizeof(json),
        "{\"heap_free\":%u,\"heap_min\":%u,"
        "\"internal_free\":%u,\"internal_largest\":%u,\"internal_total\":%u,"
        "\"psram_free\":%u,\"psram_largest\":%u,\"psram_total\":%u,"
        "\"stack_unit\":\"bytes_free_min\",\"stacks\":{",
        (unsigned)esp_get_free_heap_size(),
        (unsigned)esp_get_minimum_free_heap_size(),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_total_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM),
        (unsigned)heap_caps_get_total_size(MALLOC_CAP_SPIRAM));

    if (n < 0 || n >= (int)sizeof(json))
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "memory json overflow");

    httpd_resp_set_type(req, "application/json");
    if (httpd_resp_send_chunk(req, json, n) != ESP_OK) return ESP_FAIL;

    char row[64];
    const char *sep = "";
    for (size_t i = 0; i < sizeof(k_stack_probe) / sizeof(k_stack_probe[0]); i++) {
        TaskHandle_t h = xTaskGetHandle(k_stack_probe[i]);
        if (!h) continue;
        n = snprintf(row, sizeof(row), "%s\"%s\":%u", sep, k_stack_probe[i],
                     (unsigned)uxTaskGetStackHighWaterMark(h));
        if (httpd_resp_send_chunk(req, row, n) != ESP_OK) return ESP_FAIL;
        sep = ",";
    }

    if (httpd_resp_send_chunk(req, "},\"stacks_absent\":[", 19) != ESP_OK) return ESP_FAIL;
    sep = "";
    for (size_t i = 0; i < sizeof(k_stack_probe) / sizeof(k_stack_probe[0]); i++) {
        if (xTaskGetHandle(k_stack_probe[i])) continue;
        n = snprintf(row, sizeof(row), "%s\"%s\"", sep, k_stack_probe[i]);
        if (httpd_resp_send_chunk(req, row, n) != ESP_OK) return ESP_FAIL;
        sep = ",";
    }

    if (httpd_resp_send_chunk(req, "]}", 2) != ESP_OK) return ESP_FAIL;
    return httpd_resp_send_chunk(req, NULL, 0);
}

#if SC_SD_ARCHIVE

#define ARCHIVE_LIST_MAX 64

static esp_err_t send_archive_row(httpd_req_t *req, const sd_session_row_t *row,
                                  char *meta, size_t metasz, bool first)
{
    size_t mlen = sd_store_read_meta(row->id, meta, metasz);

    char head[320];
    int n = snprintf(head, sizeof(head),
        "%s{\"id\":\"%s\",\"name\":\"%s.jsonl\",\"kind\":\"archive\","
        "\"bytes\":%llu,\"current\":%s,\"complete_known\":%s,"
        "\"endpoints\":[\"/api/captures/session/%s.jsonl\"],\"meta\":",
        first ? "" : ",", row->id, row->id,
        (unsigned long long)row->bytes,
        row->current ? "true" : "false",
        mlen ? "true" : "false", row->id);
    if (httpd_resp_send_chunk(req, head, n) != ESP_OK) return ESP_FAIL;

    if (mlen) {
        if (httpd_resp_send_chunk(req, meta, mlen) != ESP_OK) return ESP_FAIL;
    } else {
        if (httpd_resp_send_chunk(req, "null", 4) != ESP_OK) return ESP_FAIL;
    }
    return httpd_resp_send_chunk(req, "}", 1);
}
#endif

static esp_err_t captures_get(httpd_req_t *req)
{
    capture_ring_stats_t st;
    capture_ring_get_stats(&st);

    char json[320];
    int n = snprintf(json, sizeof(json),
        "[{\"id\":\"live\",\"name\":\"live.jsonl\",\"kind\":\"volatile\","
        "\"records\":%u,\"bytes\":%u,\"dropped\":%u,"
        "\"endpoints\":[\"/api/captures/live.jsonl\",\"/api/captures/live.json\"]}",
        (unsigned)st.records_current,
        (unsigned)st.bytes_used,
        (unsigned)st.records_dropped);

    httpd_resp_set_type(req, "application/json");
    if (httpd_resp_send_chunk(req, json, n) != ESP_OK) return ESP_FAIL;

#if SC_SD_ARCHIVE

    sd_session_row_t *rows = serve_buf_calloc(sizeof(sd_session_row_t) * ARCHIVE_LIST_MAX);
    char *meta = rows ? serve_buf_alloc(1024) : NULL;
    if (rows && meta) {
        size_t count = sd_store_list_sessions(rows, ARCHIVE_LIST_MAX);
        for (size_t i = 0; i < count; i++) {
            if (send_archive_row(req, &rows[i], meta, 1024, false) != ESP_OK) break;
            if ((i & 7) == 7) vTaskDelay(1);
        }
    }
    if (meta) heap_caps_free(meta);
    if (rows) heap_caps_free(rows);
#endif

    if (httpd_resp_send_chunk(req, "]", 1) != ESP_OK) return ESP_FAIL;
    return httpd_resp_send_chunk(req, NULL, 0);
}

#if SC_SD_ARCHIVE

static esp_err_t session_jsonl_get(httpd_req_t *req)
{
    const char *tail = strrchr(req->uri, '/');
    char id[SD_SESSION_ID_MAX] = {0};
    if (tail) {
        const char *q = strchr(++tail, '?');
        size_t n = q ? (size_t)(q - tail) : strlen(tail);
        const char *ext = ".jsonl";
        size_t e = strlen(ext);
        if (n > e && strncasecmp(tail + n - e, ext, e) == 0) n -= e;
        if (n && n < sizeof(id)) memcpy(id, tail, n);
    }

    if (!sd_store_id_valid(id)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad session id");
        return ESP_FAIL;
    }

    void *h = sd_store_reader_open(id);
    if (!h) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no such session");
        return ESP_FAIL;
    }

    char *buf = serve_buf_alloc(STREAM_LINE_MAX + 1);
    if (!buf) {
        sd_store_reader_close(h);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    size_t skip = 0;
    char q[24], sv[16];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK &&
        httpd_query_key_value(q, "since", sv, sizeof(sv)) == ESP_OK)
        skip = (size_t)strtoul(sv, NULL, 10);

    char disp[96];
    snprintf(disp, sizeof(disp), "attachment; filename=\"sniffcheck-%s.jsonl\"", id);
    httpd_resp_set_type(req, "application/x-ndjson");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    httpd_resp_set_hdr(req, "X-SC-Base", "0");
    httpd_resp_set_hdr(req, "X-SC-Session", id);

    size_t seen = 0, emitted = 0;
    esp_err_t err = ESP_OK;
    for (;;) {
        size_t len = sd_store_reader_next(h, buf, STREAM_LINE_MAX);
        if (len == 0) break;
        if (seen++ < skip) {
            if (seen % 64 == 0) vTaskDelay(1);
            continue;
        }
        buf[len++] = '\n';
        if (httpd_resp_send_chunk(req, buf, len) != ESP_OK) { err = ESP_FAIL; break; }
        if (++emitted % 32 == 0) vTaskDelay(1);
    }

    heap_caps_free(buf);
    sd_store_reader_close(h);
    if (err == ESP_OK) httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "session %s: %u records streamed", id, (unsigned)emitted);
    return err;
}

static esp_err_t archive_get(httpd_req_t *req)
{
    sd_store_stats_t sd;
    sd_store_get_stats(&sd);

    char json[440];
    snprintf(json, sizeof(json),
        "{\"card_present\":%s,\"mounted\":%s,\"card_unreadable\":%s,"
        "\"full\":%s,\"session_open\":%s,"
        "\"card_bytes\":%llu,\"volume_bytes\":%llu,\"free_bytes\":%llu,"
        "\"reserve_bytes\":%llu,\"session_bytes\":%llu,"
        "\"session_records\":%u,\"write_errors\":%u,\"file\":\"%s\"}",
        sd.card_present ? "true" : "false",
        sd.mounted ? "true" : "false",
        sd.card_unreadable ? "true" : "false",
        sd.full ? "true" : "false",
        sd_store_session_is_open() ? "true" : "false",
        (unsigned long long)sd.card_bytes,

        (unsigned long long)sd.volume_bytes,
        (unsigned long long)sd.free_bytes,
        (unsigned long long)SD_ARCHIVE_RESERVE_BYTES,
        (unsigned long long)sd.written_bytes,
        (unsigned)sd.records, (unsigned)sd.write_errors,
        sd.path);
    return send_json(req, json);
}

static void url_decode(char *s)
{
    char *w = s;
    for (const char *r = s; *r; r++) {
        if (*r == '%' && isxdigit((unsigned char)r[1]) && isxdigit((unsigned char)r[2])) {
            char hex[3] = { r[1], r[2], 0 };
            *w++ = (char)strtol(hex, NULL, 16);
            r += 2;
        } else if (*r == '+') {
            *w++ = ' ';
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
}

static bool query_path(httpd_req_t *req, const char *key, char *out, size_t outsz)
{
    out[0] = '\0';
    char q[256];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) != ESP_OK) return false;
    if (httpd_query_key_value(q, key, out, outsz) != ESP_OK) return false;
    url_decode(out);
    return true;
}

static esp_err_t send_json_str(httpd_req_t *req, const char *s)
{
    char buf[128];
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (n + 8 >= sizeof(buf)) {
            if (httpd_resp_send_chunk(req, buf, n) != ESP_OK) return ESP_FAIL;
            n = 0;
        }
        if (*p == '"' || *p == '\\') { buf[n++] = '\\'; buf[n++] = (char)*p; }
        else if (*p < 0x20)          { n += snprintf(buf + n, sizeof(buf) - n, "\\u%04x", *p); }
        else                          { buf[n++] = (char)*p; }
    }
    return n ? httpd_resp_send_chunk(req, buf, n) : ESP_OK;
}

#define SD_LS_MAX 96

static esp_err_t sd_ls_get(httpd_req_t *req)
{
    char path[192];
    if (!query_path(req, "path", path, sizeof(path)) || !path[0])
        strlcpy(path, "/", sizeof(path));

    char abs[160];
    if (!sd_store_path_ok(path, abs, sizeof(abs))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }

    sd_store_stats_t sd;
    sd_store_get_stats(&sd);

    sd_dir_entry_t *ents = serve_buf_calloc(sizeof(sd_dir_entry_t) * SD_LS_MAX);
    char *meta = ents ? serve_buf_alloc(1024) : NULL;
    if (!ents || !meta) {
        if (ents) heap_caps_free(ents);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    size_t total = 0;
    size_t n = sd_store_list_dir(path, ents, SD_LS_MAX, &total);

    bool exists = (n > 0 || total > 0 || !sd.mounted) ? true : sd_store_dir_exists(path);

    char head[320];
    int hn = snprintf(head, sizeof(head),
        "{\"mounted\":%s,\"exists\":%s,\"total\":%u,\"truncated\":%s,"
        "\"sessions_path\":\"%s\",\"path\":\"",
        sd.mounted ? "true" : "false",
        exists ? "true" : "false",
        (unsigned)total, (total > n) ? "true" : "false",
        SD_ARCHIVE_REL_PATH);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    if (httpd_resp_send_chunk(req, head, hn) != ESP_OK) goto fail;
    if (send_json_str(req, path) != ESP_OK) goto fail;
    if (httpd_resp_send_chunk(req, "\",\"entries\":[", 13) != ESP_OK) goto fail;

    for (size_t i = 0; i < n; i++) {
        const sd_dir_entry_t *e = &ents[i];
        if (httpd_resp_send_chunk(req, i ? ",{\"name\":\"" : "{\"name\":\"", i ? 10 : 9) != ESP_OK) goto fail;
        if (send_json_str(req, e->name) != ESP_OK) goto fail;

        char row[224];
        int rn = snprintf(row, sizeof(row),
            "\",\"dir\":%s,\"bytes\":%llu,\"session\":%s,\"id\":\"%s\",\"current\":%s,\"meta\":",
            e->is_dir ? "true" : "false",
            (unsigned long long)e->bytes,
            e->is_session ? "true" : "false", e->id,
            e->current ? "true" : "false");
        if (httpd_resp_send_chunk(req, row, rn) != ESP_OK) goto fail;

        size_t mlen = e->is_session ? sd_store_read_meta(e->id, meta, 1024) : 0;
        if (httpd_resp_send_chunk(req, mlen ? meta : "null", mlen ? mlen : 4) != ESP_OK) goto fail;
        if (httpd_resp_send_chunk(req, "}", 1) != ESP_OK) goto fail;
        if ((i & 7) == 7) vTaskDelay(1);
    }

    heap_caps_free(meta);
    heap_caps_free(ents);
    if (httpd_resp_send_chunk(req, "]}", 2) != ESP_OK) return ESP_FAIL;
    return httpd_resp_send_chunk(req, NULL, 0);

fail:
    heap_caps_free(meta);
    heap_caps_free(ents);
    return ESP_FAIL;
}

static esp_err_t sd_file_get(httpd_req_t *req)
{
    char path[192];
    if (!query_path(req, "path", path, sizeof(path))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no path");
        return ESP_FAIL;
    }

    uint64_t size = 0;
    void *h = sd_store_file_open(path, &size);
    if (!h) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no such file");
        return ESP_FAIL;
    }

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    char safe[72];
    strlcpy(safe, base, sizeof(safe));
    for (char *c = safe; *c; c++) if (*c == '"' || *c == '\\') *c = '_';

    char disp[128];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", safe);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    char *buf = serve_buf_alloc(2048);
    if (!buf) {
        sd_store_file_close(h);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    esp_err_t err = ESP_OK;
    for (unsigned chunk = 0;; chunk++) {
        size_t r = sd_store_file_read(h, buf, 2048);
        if (r == 0) break;
        if (httpd_resp_send_chunk(req, buf, r) != ESP_OK) { err = ESP_FAIL; break; }
        if ((chunk & 7) == 7) vTaskDelay(1);
    }

    heap_caps_free(buf);
    sd_store_file_close(h);
    if (err == ESP_OK) httpd_resp_send_chunk(req, NULL, 0);
    return err;
}

#endif

static esp_err_t live_jsonl_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/x-ndjson");
    char disp[80];
    snprintf(disp, sizeof(disp),
             "attachment; filename=\"sniffcheck-%s.jsonl\"",
             capture_writer_session_id());
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    capture_ring_stats_t rst;
    capture_ring_get_stats(&rst);
    uint32_t base  = rst.records_total - rst.records_current;
    uint32_t total = rst.records_total;
    size_t   skip  = 0;

    char q[24], sv[16];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK &&
        httpd_query_key_value(q, "since", sv, sizeof(sv)) == ESP_OK) {
        uint32_t since = (uint32_t)strtoul(sv, NULL, 10);
        if (since > 0 && since < base) httpd_resp_set_hdr(req, "X-SC-Gap", "1");
        else if (since >= base && since <= total) skip = (size_t)(since - base);
    }

    char hbase[12], htotal[12];
    snprintf(hbase,  sizeof(hbase),  "%u", (unsigned)base);
    snprintf(htotal, sizeof(htotal), "%u", (unsigned)total);
    httpd_resp_set_hdr(req, "X-SC-Base", hbase);
    httpd_resp_set_hdr(req, "X-SC-Total", htotal);
    httpd_resp_set_hdr(req, "X-SC-Session", capture_writer_session_id());

    size_t emitted = 0;
    esp_err_t err = stream_records(req, false, skip, &emitted);
    if (err == ESP_ERR_NO_MEM) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }
    if (err == ESP_OK) httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "live.jsonl: %u records streamed", (unsigned)emitted);
    return err;
}

static esp_err_t live_json_get(httpd_req_t *req)
{

    char *buf = serve_buf_alloc(STREAM_LINE_MAX + 2);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"live.json\"");

    capture_ring_reader_t r;
    capture_ring_reader_open(&r);

    httpd_resp_send_chunk(req, "[", 1);

    size_t emitted = 0;
    esp_err_t err = ESP_OK;
    for (;;) {

        size_t len = capture_ring_reader_next(&r, buf + 2, STREAM_LINE_MAX);
        if (len == 0) break;
        char *out;
        size_t out_len;
        if (emitted == 0) {
            buf[1] = '\n';
            out = buf + 1; out_len = len + 1;
        } else {
            buf[0] = ','; buf[1] = '\n';
            out = buf; out_len = len + 2;
        }
        if (httpd_resp_send_chunk(req, out, out_len) != ESP_OK) {
            err = ESP_FAIL;
            break;
        }
        if (++emitted % 32 == 0) vTaskDelay(1);
    }

    heap_caps_free(buf);
    if (err == ESP_OK) {
        httpd_resp_send_chunk(req, "\n]\n", 3);
        httpd_resp_send_chunk(req, NULL, 0);
    }
    ESP_LOGI(TAG, "live.json: %u records streamed", (unsigned)emitted);
    return err;
}

static esp_err_t report_get(httpd_req_t *req)
{
    if (!viewer_gz_ready()) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "viewer asset missing");
        return ESP_FAIL;
    }

    char query[192], dl[4];
    char disp[80];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "dl", dl, sizeof(dl)) == ESP_OK &&
        dl[0] == '1') {
        snprintf(disp, sizeof(disp),
                 "attachment; filename=\"sniffcheck-%s.html\"",
                 capture_writer_session_id());
        httpd_resp_set_hdr(req, "Content-Disposition", disp);
    }

    if (viewer_gz_begin(req, true) != ESP_OK)
        return ESP_FAIL;

    s_gz_open = true;
    size_t emitted = 0;
    esp_err_t err = stream_records(req, true, 0, &emitted);
    s_gz_open = false;

    if (err != ESP_OK) {

        if (err == ESP_ERR_NO_MEM)
            ESP_LOGE(TAG, "report.html: out of memory mid-stream");
        return ESP_FAIL;
    }

    if (viewer_gz_finish(req) != ESP_OK)
        return ESP_FAIL;
    ESP_LOGI(TAG, "report.html: %u records spliced (gzip)", (unsigned)emitted);
    return ESP_OK;
}

static esp_err_t viewer_get(httpd_req_t *req)
{

    if (!viewer_gz_ready()) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "viewer asset missing");
        return ESP_FAIL;
    }
    if (viewer_gz_begin(req, true) != ESP_OK)
        return ESP_FAIL;
    return viewer_gz_finish(req);
}

static esp_err_t clear_post(httpd_req_t *req)
{
    capture_ring_clear_volatile();
    ESP_LOGI(TAG, "ring cleared by client");
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t save_sd_post(httpd_req_t *req)
{
#if SC_SD_ARCHIVE

    sd_store_stats_t sd;
    sd_store_get_stats(&sd);
    if (!sd.mounted)
        return send_json(req,
            "{\"ok\":false,\"error\":\"No SD card is inserted, so this scan is only "
            "in volatile memory. Download it before powering off.\"}");

    sd_store_flush();
    sd_store_get_stats(&sd);

    char json[240];
    snprintf(json, sizeof(json),
        "{\"ok\":true,\"archiving\":true,\"file\":\"%s\",\"records\":%u,"
        "\"bytes\":%llu,\"full\":%s}",
        sd.path, (unsigned)sd.records, (unsigned long long)sd.written_bytes,
        sd.full ? "true" : "false");
    ESP_LOGI(TAG, "save-to-SD: flushed %u records to %s",
             (unsigned)sd.records, sd.path[0] ? sd.path : "(no session)");
    return send_json(req, json);
#else
    ESP_LOGI(TAG, "save-to-SD requested (no archive on this build)");
    return send_json(req,
        "{\"ok\":false,\"error\":\"SD card storage isn't available on this build yet.\"}");
#endif
}

static esp_err_t extend_post(httpd_req_t *req)
{
    uint32_t rem = download_mode_extend_seconds(15 * 60);
    char json[64];
    snprintf(json, sizeof(json),
             "{\"ok\":%s,\"seconds_remaining\":%u}",
             rem ? "true" : "false", (unsigned)rem);
    ESP_LOGI(TAG, "extend requested: %u s remaining", (unsigned)rem);
    return send_json(req, json);
}

static esp_err_t disable_post(httpd_req_t *req)
{

    esp_err_t rc = send_json(req, "{\"ok\":true}");
    ESP_LOGI(TAG, "disable requested by client");
    download_mode_request_disable(CAP_END_USER_DISABLE);
    return rc;
}

static int read_body(httpd_req_t *req, char *buf, size_t buflen)
{
    size_t total = req->content_len;
    if (total > buflen - 1) total = buflen - 1;
    size_t got = 0;
    while (got < total) {
        int r = httpd_req_recv(req, buf + got, total - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    buf[got] = '\0';
    return (int)got;
}

static esp_err_t send_bad(httpd_req_t *req, const char *err)
{
    httpd_resp_set_status(req, "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    char j[128];
    snprintf(j, sizeof(j), "{\"ok\":false,\"error\":\"%s\"}", err);
    return httpd_resp_sendstr(req, j);
}

#if SC_SD_ARCHIVE || SC_ENV_LEARN

static bool json_str(const char *body, const char *key, char *out, size_t outsz)
{
    out[0] = '\0';
    char pat[24];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return false;
    p = strchr(p + strlen(pat), ':');
    if (!p) return false;
    p = strchr(p, '"');
    if (!p) return false;
    p++;
    size_t i = 0;
    while (p[i] && p[i] != '"' && i + 1 < outsz) { out[i] = p[i]; i++; }
    out[i] = '\0';
    return i > 0;
}
#endif

#if SC_SD_ARCHIVE
static esp_err_t archive_delete_post(httpd_req_t *req)
{
    char body[160];
    int n = read_body(req, body, sizeof(body));
    char id[SD_SESSION_ID_MAX] = {0};
    if (n > 0) json_str(body, "id", id, sizeof(id));

    esp_err_t rc = sd_store_delete_session(id);
    if (rc != ESP_OK) {
        char json[160];
        snprintf(json, sizeof(json), "{\"ok\":false,\"error\":\"%s\"}",
                 rc == ESP_ERR_INVALID_STATE
                     ? "That session is still being recorded."
                     : rc == ESP_ERR_INVALID_ARG ? "Bad session id."
                     : rc == ESP_ERR_NOT_FOUND   ? "No such session."
                                                 : "No SD card.");
        return send_json(req, json);
    }
    ESP_LOGI(TAG, "archive session deleted via WebAP: %s", id);
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t archive_rename_post(httpd_req_t *req)
{
    char body[320];
    int n = read_body(req, body, sizeof(body));
    if (n <= 0) return send_bad(req, "Empty request.");

    char id[SD_SESSION_ID_MAX] = {0};
    char name[96] = {0};
    char series[SD_SERIES_MAX] = {0};
    if (!json_str(body, "id", id, sizeof(id))) return send_bad(req, "No session id.");
    json_str(body, "name", name, sizeof(name));

    bool has_series = json_str(body, "series", series, sizeof(series)) ||
                      strstr(body, "\"series\"") != NULL;

    char final_id[SD_SESSION_ID_MAX] = {0};
    esp_err_t rc = sd_store_rename_session(id, name, has_series ? series : NULL,
                                           final_id, sizeof(final_id));
    if (rc != ESP_OK) {
        char json[200];
        snprintf(json, sizeof(json), "{\"ok\":false,\"error\":\"%s\"}",
                 rc == ESP_ERR_INVALID_ARG
                     ? "That name has no letters or numbers in it."
                     : rc == ESP_ERR_NOT_FOUND   ? "No such session."
                     : rc == ESP_ERR_TIMEOUT     ? "The card is busy. Try again."
                     : rc == ESP_ERR_INVALID_STATE ? "No SD card."
                                                   : "The card refused the rename.");
        return send_json(req, json);
    }

    char json[160];
    snprintf(json, sizeof(json), "{\"ok\":true,\"id\":\"%s\",\"series\":\"%s\"}",
             final_id, series);
    ESP_LOGI(TAG, "archive session renamed via WebAP: %s -> %s", id, final_id);
    return send_json(req, json);
}

static esp_err_t archive_wipe_post(httpd_req_t *req)
{
    uint32_t killed = 0;
    esp_err_t rc = sd_store_wipe(&killed);
    if (rc != ESP_OK)
        return send_json(req, "{\"ok\":false,\"error\":\"A scan is still recording. "
                              "End it first, then clear the archive.\"}");
    char json[80];
    snprintf(json, sizeof(json), "{\"ok\":true,\"deleted\":%u}", (unsigned)killed);
    ESP_LOGW(TAG, "archive wiped via WebAP: %u sessions", (unsigned)killed);
    return send_json(req, json);
}
#endif

static esp_err_t send_settings(httpd_req_t *req)
{
    char buf[192];
    app_settings_get_json(buf, sizeof(buf));
    return send_json(req, buf);
}

static bool json_int(const char *body, const char *key, int *out)
{
    const char *p = strstr(body, key);
    if (!p) return false;
    p = strchr(p + strlen(key), ':');
    if (!p) return false;
    *out = atoi(p + 1);
    return true;
}

static esp_err_t settings_get(httpd_req_t *req)
{
    return send_settings(req);
}

static esp_err_t settings_mode_post(httpd_req_t *req)
{
    char body[64];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");
    bool adv;
    if (strstr(body, "\"adv\""))       adv = true;
    else if (strstr(body, "\"lite\"")) adv = false;
    else return send_bad(req, "mode must be lite or adv");
    app_settings_set_mode(adv);
    return send_settings(req);
}

static esp_err_t settings_brightness_post(httpd_req_t *req)
{
    char body[64];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");
    int pct;
    if (!json_int(body, "\"pct\"", &pct)) return send_bad(req, "pct required");
    if (!app_settings_set_brightness_pct(pct))
        return send_bad(req, "pct must be 25/50/75/100");
    return send_settings(req);
}

static esp_err_t settings_led_post(httpd_req_t *req)
{
    char body[64];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");
    bool en;
    if (strstr(body, "true"))       en = true;
    else if (strstr(body, "false")) en = false;
    else return send_bad(req, "enabled must be true or false");
    app_settings_set_led(en);
    return send_settings(req);
}

static esp_err_t settings_timeout_post(httpd_req_t *req)
{
    char body[64];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");
    int m;
    if (!json_int(body, "\"minutes\"", &m)) return send_bad(req, "minutes required");
    if (m != 15 && m != 30 && m != 60)
        return send_bad(req, "minutes must be 15/30/60");
    download_mode_set_timeout_minutes((uint8_t)m);
    return send_settings(req);
}

static esp_err_t scan_start_post(httpd_req_t *req)
{

    char json[128];
    snprintf(json, sizeof(json),
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"scan_start\","
        "\"eta_seconds\":%d}", app_scan_eta_seconds());
    esp_err_t rc = send_json(req, json);
    ESP_LOGI(TAG, "scan-start requested by client");
    app_request_scan_after_download();
    return rc;
}

static esp_err_t send_pup(httpd_req_t *req)
{
    vp_status_t st;
#if SC_EPUP_BRAIN

    { epup_summary_t ep; epup_brain_get(&ep); virtual_pup_sync_level((uint16_t)ep.level, ep.total_scans); }
#endif
    virtual_pup_get(&st);
    char json[288];
    snprintf(json, sizeof(json),
        "{\"name\":\"%s\",\"level\":%u,\"xp\":%llu,\"xp_next\":%llu,"
        "\"mood\":\"%s\",\"lifetime_scans\":%u,\"last_scan_xp\":%u,"
        "\"pets\":%u,\"treats\":%u,\"high_score\":%u,\"plays\":%u}",
        virtual_pup_name(), (unsigned)st.level,
        (unsigned long long)st.xp_into_level, (unsigned long long)st.xp_for_level,
        virtual_pup_mood_label(), (unsigned)st.lifetime_scans,
        (unsigned)st.last_scan_xp, (unsigned)st.pets, (unsigned)st.treats,
        (unsigned)st.high_score, (unsigned)st.plays);
    return send_json(req, json);
}

static esp_err_t pup_status_get(httpd_req_t *req){ return send_pup(req); }

static esp_err_t pup_play_post(httpd_req_t *req)
{
    char body[64];
    int score = 0;
    if (read_body(req, body, sizeof(body)) >= 0)
        json_int(body, "\"score\"", &score);
    if (score < 0) score = 0;
    virtual_pup_record_play((uint32_t)score);
    return send_pup(req);
}

static esp_err_t pup_pet_post(httpd_req_t *req)
{
    virtual_pup_pet();
    return send_pup(req);
}

static esp_err_t pup_treat_post(httpd_req_t *req)
{
    virtual_pup_treat();
    return send_pup(req);
}

static esp_err_t pup_name_post(httpd_req_t *req)
{
    char body[96];
    if (read_body(req, body, sizeof(body)) < 0) return send_bad(req, "body");

    char *p = strstr(body, "\"name\"");
    if (p) p = strchr(p + 6, ':');
    if (p) p = strchr(p, '"');
    if (!p) return send_bad(req, "name required");
    char name[VP_NAME_MAX]; size_t j = 0;
    for (p++; *p && *p != '"' && j < sizeof(name) - 1; p++) name[j++] = *p;
    name[j] = '\0';
    virtual_pup_set_name(name);
    return send_pup(req);
}

static esp_err_t pup_reset_post(httpd_req_t *req)
{
    virtual_pup_reset();
    return send_pup(req);
}

static esp_err_t pup_walk_last_get(httpd_req_t *req)
{
    pup_walk_summary_t w;
    virtual_pup_walk_get_last(&w);

    char json[512];
    snprintf(json, sizeof(json),
        "{\"walk_id\":%u,\"pup_name\":\"%s\",\"duration_sec\":%u,"
        "\"wifi_sweeps\":%u,\"ble_windows\":%u,\"wifi_unique_bssid\":%u,"
        "\"wifi_unique_ssid\":%u,\"ble_unique_devices\":%u,\"threat_events\":%u,"
        "\"safe_networks\":%u,\"interesting_sniffs\":%u,\"xp_awarded\":%u,"
        "\"mood\":\"%s\"}",
        (unsigned)w.walk_id, virtual_pup_name(), (unsigned)w.duration_sec,
        (unsigned)w.wifi_sweeps, (unsigned)w.ble_windows,
        (unsigned)w.wifi_unique_bssid, (unsigned)w.wifi_unique_ssid,
        (unsigned)w.ble_unique_devices, (unsigned)w.threat_events,
        (unsigned)w.safe_networks, (unsigned)w.interesting_sniffs,
        (unsigned)w.xp_awarded, w.mood);
    return send_json(req, json);
}

static esp_err_t pup_walk_start_post(httpd_req_t *req)
{
    esp_err_t rc = send_json(req,
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"walk_start\","
        "\"message\":\"Sniff Walk starting. This AP will close.\"}");
    ESP_LOGI(TAG, "walk-start requested by client");
    app_request_walk_after_download();
    return rc;
}

#if SC_ENV_LEARN
static esp_err_t env_get(httpd_req_t *req)
{

    char json[1200];
    app_learn_env_status_json(json, sizeof(json));
    return send_json(req, json);
}

static int env_json_int(const char *body, const char *key, int def)
{
    char pat[24];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return def;
    p = strchr(p + strlen(pat), ':');
    if (!p) return def;
    p++;
    while (*p == ' ') p++;
    if (*p < '0' || *p > '9') return def;
    return atoi(p);
}

static bool env_json_bool(const char *body, const char *key, bool def)
{
    char pat[24];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return def;
    p = strchr(p + strlen(pat), ':');
    if (!p) return def;
    p++;
    while (*p == ' ') p++;
    if (strncmp(p, "true", 4) == 0)  return true;
    if (strncmp(p, "false", 5) == 0) return false;
    return def;
}

static esp_err_t env_learn_start_post(httpd_req_t *req)
{
    char body[256] = {0};
    read_body(req, body, sizeof(body));

    int  scans      = env_json_int(body, "scans", 4);
    bool reposition = env_json_bool(body, "reposition", true);
    bool fresh      = env_json_bool(body, "fresh", false);
    char name[32]   = {0};
    json_str(body, "name", name, sizeof(name));

    if (scans < 1) scans = 1;
    if (scans > 8) scans = 8;

    if (app_learn_env_running())
        return send_bad(req, "A Learn Environment run is already going.");

    char json[220];
    snprintf(json, sizeof(json),
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"learn_start\","
        "\"scans\":%d,\"reposition\":%s,\"eta_seconds\":%d,"
        "\"message\":\"Learning this place. This AP will close while it scans.\"}",
        scans, reposition ? "true" : "false",
        app_learn_env_seconds(scans, reposition));
    esp_err_t rc = send_json(req, json);

    ESP_LOGI(TAG, "learn-env requested by client: %d scans, %s, \"%s\"",
             scans, reposition ? "repositioning" : "stationary", name);
    app_request_learn_env_after_download(scans, reposition, fresh, name);
    return rc;
}

static esp_err_t env_learn_cancel_post(httpd_req_t *req)
{
    if (!app_learn_env_running())
        return send_json(req, "{\"ok\":true,\"active\":false}");
    app_learn_env_cancel();
    return send_json(req, "{\"ok\":true,\"active\":false}");
}

static esp_err_t env_label_post(httpd_req_t *req)
{
    char body[160] = {0};
    if (read_body(req, body, sizeof(body)) <= 0) return send_bad(req, "Empty request.");

    int  idx = env_json_int(body, "idx", -1);
    char label[ENV_LABEL_MAX] = {0};
    json_str(body, "label", label, sizeof(label));
    if (!label[0]) return send_bad(req, "No name given.");

    env_learn_label(idx, label);
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t env_forget_post(httpd_req_t *req)
{
    char body[120] = {0};
    if (read_body(req, body, sizeof(body)) <= 0) return send_bad(req, "Empty request.");

    int idx = env_json_int(body, "idx", -1);
    if (idx < 0) return send_bad(req, "Which environment?");

    env_learn_forget(idx);
    ESP_LOGW(TAG, "environment %d forgotten via WebAP", idx);
    return send_json(req, "{\"ok\":true}");
}
#endif

#if SC_TRACKER_SOUND
static esp_err_t trackers_get(httpd_req_t *req)
{
    char json[1400];
    tracker_sound_status_json(json, sizeof(json));
    return send_json(req, json);
}

static esp_err_t trackers_arm_post(httpd_req_t *req)
{
    char body[96] = {0};
    read_body(req, body, sizeof(body));
    bool on = env_json_bool(body, "armed", false);
    tracker_sound_set_armed(on);

    char json[96];
    snprintf(json, sizeof(json), "{\"ok\":true,\"armed\":%s}", on ? "true" : "false");
    return send_json(req, json);
}

static esp_err_t trackers_bark_post(httpd_req_t *req)
{
    char body[128] = {0};
    if (read_body(req, body, sizeof(body)) <= 0) return send_bad(req, "Empty request.");

    char mac_s[24] = {0};
    if (!json_str(body, "mac", mac_s, sizeof(mac_s))) return send_bad(req, "No address.");

    unsigned m[6];
    if (sscanf(mac_s, "%2x:%2x:%2x:%2x:%2x:%2x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return send_bad(req, "That is not a Bluetooth address.");
    uint8_t mac[6];
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];

    if (!tracker_sound_armed())
        return send_bad(req, "Safety sound is off. Turn it on first — it transmits.");
    if (!tracker_sound_bark(mac))
        return send_bad(req, "That tracker is not in the latest scan, or one is already "
                             "being rung. Rescan and try again.");

    return send_json(req, "{\"ok\":true,\"message\":\"Sound command sent. Only the "
                          "tracker decides whether it makes a noise.\"}");
}

static esp_err_t trackers_howl_post(httpd_req_t *req)
{
    if (!tracker_sound_armed())
        return send_bad(req, "Safety sound is off. Turn it on first — it transmits.");

    int n = tracker_sound_howl_start();
    if (n <= 0)
        return send_bad(req, "Nothing ringable nearby. Only trackers separated from "
                             "their owner can be rung — run a scan first.");

    char json[160];
    snprintf(json, sizeof(json),
             "{\"ok\":true,\"queued\":%d,\"message\":\"Ringing %d tracker(s), "
             "one at a time.\"}", n, n);
    return send_json(req, json);
}

static esp_err_t trackers_stop_post(httpd_req_t *req)
{
    tracker_sound_howl_stop();
    return send_json(req, "{\"ok\":true}");
}
#endif

static esp_err_t sta_get(httpd_req_t *req)
{
    const size_t cap = 16384;
    char *buf = serve_buf_alloc(cap);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }
    uint16_t n = sta_tracker_entry_count();
    size_t o = 0;
    o += snprintf(buf + o, cap - o,
                  "{\"count\":%u,\"cameras\":%u,\"stations\":[",
                  (unsigned)n, (unsigned)sta_tracker_camera_count());
    for (uint16_t i = 0; i < n; i++) {
        const sta_entry_t *e = sta_tracker_at(i);
        if (!e) continue;
        if (o > cap - 400) break;
        o += snprintf(buf + o, cap - o,
            "%s{\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"vendor\":\"%s\","
            "\"class\":%u,\"frames\":%u,\"up\":%u,\"dn\":%u,\"randomized\":%s,"
            "\"camera\":%s,\"rssi_last\":%d,\"rssi_best\":%d,\"channel\":%u,"
            "\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"dur_ms\":%lu}",
            i ? "," : "",
            e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5],
            e->vendor ? e->vendor : "", (unsigned)e->device_class,
            (unsigned)e->frames, (unsigned)e->frames_uplink,
            (unsigned)e->frames_downlink, e->randomized ? "true" : "false",
            e->is_camera ? "true" : "false", (int)e->rssi_last, (int)e->rssi_best,
            (unsigned)e->channel,
            e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5],
            (unsigned long)(e->last_seen_ms - e->first_seen_ms));
    }
    o += snprintf(buf + o, cap - o, "]}");
    httpd_resp_set_type(req, "application/json");
    esp_err_t rc = httpd_resp_send(req, buf, o);
    heap_caps_free(buf);
    return rc;
}

static esp_err_t scan_channels_get(httpd_req_t *req)
{
    char json[1536];
    app_scan_channels_json(json, sizeof(json));
    return send_json(req, json);
}

static esp_err_t csi_get(httpd_req_t *req)
{
    const wifi_csi_result_t *r = wifi_csi_probe_last();
    char json[256];

    if (!r) {
        return send_json(req,
            "{\"supported\":false,\"ran\":false,\"channel\":0,\"window_ms\":0,"
            "\"cb_count\":0,\"len_min\":0,\"len_max\":0,\"len_last\":0,"
            "\"fwi_count\":0,\"rssi_last\":0}");
    }
    snprintf(json, sizeof(json),
        "{\"supported\":%s,\"ran\":%s,\"channel\":%u,\"window_ms\":%u,"
        "\"cb_count\":%u,\"len_min\":%u,\"len_max\":%u,\"len_last\":%u,"
        "\"fwi_count\":%u,\"rssi_last\":%d}",
        r->supported ? "true" : "false", r->ran ? "true" : "false",
        (unsigned)r->channel, (unsigned)r->window_ms, (unsigned)r->cb_count,
        (unsigned)r->len_min, (unsigned)r->len_max, (unsigned)r->len_last,
        (unsigned)r->fwi_count, (int)r->rssi_last);
    return send_json(req, json);
}

static void read_chan_secs(httpd_req_t *req, int *ch, int *sec)
{
    char body[96];
    *ch = 6; *sec = 5;
    if (read_body(req, body, sizeof(body)) > 0) {
        json_int(body, "\"channel\"", ch);
        json_int(body, "\"seconds\"", sec);
    }
}

static esp_err_t sta_capture_post(httpd_req_t *req)
{
    int ch, sec;
    read_chan_secs(req, &ch, &sec);
    char json[128];
    snprintf(json, sizeof(json),
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"sta_capture\","
        "\"eta_seconds\":%d}", sec);
    esp_err_t rc = send_json(req, json);
    ESP_LOGI(TAG, "sta-capture requested: ch=%d sec=%d", ch, sec);
    app_request_sta_capture_after_download((uint8_t)ch, (uint16_t)sec);
    return rc;
}

static esp_err_t csi_run_post(httpd_req_t *req)
{
    int ch, sec;
    read_chan_secs(req, &ch, &sec);
    char json[128];
    snprintf(json, sizeof(json),
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"csi_run\","
        "\"eta_seconds\":%d}", sec);
    esp_err_t rc = send_json(req, json);
    ESP_LOGI(TAG, "csi-run requested: ch=%d sec=%d", ch, sec);
    app_request_csi_after_download((uint8_t)ch, (uint16_t)sec);
    return rc;
}

static const char *pcap_status_str(pcap_status_t s)
{
    switch (s) {
        case PCAP_RUNNING:      return "running";
        case PCAP_READY:        return "ready";
        case PCAP_PARTIAL:      return "partial";
        case PCAP_FAILED:       return "failed";
        default:                return "idle";
    }
}

static uint8_t parse_channels(const char *body, uint8_t *out, uint8_t max)
{
    const char *p = strstr(body, "\"channels\"");
    if (!p) return 0;
    p = strchr(p, '[');
    if (!p) return 0;
    p++;
    uint8_t n = 0;
    while (*p && *p != ']' && n < max) {
        while (*p == ' ' || *p == ',') p++;
        if (*p == ']' || !*p) break;
        if (*p >= '0' && *p <= '9') {
            int v = atoi(p);
            if (v >= 1 && v <= 177) out[n++] = (uint8_t)v;
            while (*p >= '0' && *p <= '9') p++;
        } else {
            p++;
        }
    }
    return n;
}

static esp_err_t pcap_run_post(httpd_req_t *req)
{
    char body[512];
    uint8_t chans[PCAP_MAX_CHANNELS];
    uint8_t n = 0;
    if (read_body(req, body, sizeof(body)) > 0)
        n = parse_channels(body, chans, PCAP_MAX_CHANNELS);
    if (n == 0)
        return send_bad(req, "no valid channels");

    char json[128];
    snprintf(json, sizeof(json),
        "{\"ok\":true,\"disconnecting\":true,\"reason\":\"pcap_run\","
        "\"eta_seconds\":%u}", (unsigned)n * 10u);
    esp_err_t rc = send_json(req, json);
    ESP_LOGI(TAG, "pcap-run requested: %u channels, 10s each", (unsigned)n);
    app_request_pcap_after_download(chans, n);
    return rc;
}

static esp_err_t pcap_status_get(httpd_req_t *req)
{
    const pcap_meta_t *m = pcap_capture_meta();
    char json[640];

    if (!m) {
        return send_json(req,
            "{\"ran\":false,\"status\":\"idle\",\"seconds_per_channel\":0,"
            "\"duration_s\":0,\"packets\":0,\"dropped\":0,\"truncated\":0,"
            "\"bytes\":0,\"scan_id\":0,\"download\":\"/api/pcap/latest\",\"channels\":[]}");
    }
    int o = snprintf(json, sizeof(json),
        "{\"ran\":%s,\"status\":\"%s\",\"seconds_per_channel\":%u,"
        "\"duration_s\":%lu,\"packets\":%lu,\"dropped\":%lu,\"truncated\":%lu,"
        "\"bytes\":%lu,\"scan_id\":%lu,\"download\":\"/api/pcap/latest\","
        "\"channels\":[",
        m->ran ? "true" : "false", pcap_status_str(m->status),
        (unsigned)m->seconds_per_channel, (unsigned long)m->duration_s,
        (unsigned long)m->packets, (unsigned long)m->dropped,
        (unsigned long)m->truncated, (unsigned long)m->bytes,
        (unsigned long)m->scan_id);
    for (uint8_t i = 0; i < m->channel_count && o < (int)sizeof(json) - 8; i++)
        o += snprintf(json + o, sizeof(json) - o, "%s%u",
                      i ? "," : "", (unsigned)m->channels[i]);
    o += snprintf(json + o, sizeof(json) - o, "]}");
    return send_json(req, json);
}

static esp_err_t pcap_latest_get(httpd_req_t *req)
{
    size_t len = 0;
    const uint8_t *data = pcap_capture_data(&len);
    if (!data || len == 0) {
        httpd_resp_set_status(req, "404 Not Found");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req,
            "{\"ok\":false,\"error\":\"no capture\"}");
    }
    const pcap_meta_t *m = pcap_capture_meta();
    char disp[80];
    snprintf(disp, sizeof(disp),
             "attachment; filename=\"sniffcheck-packets-scan%04lu.pcap\"",
             (unsigned long)m->scan_id);
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    size_t off = 0;
    while (off < len) {
        size_t seg = len - off;
        if (seg > 4096) seg = 4096;
        if (httpd_resp_send_chunk(req, (const char *)data + off, seg) != ESP_OK)
            return ESP_FAIL;
        off += seg;
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

#define BYOS_MAX_RECS          4096
#define BYOS_UPLOAD_MAX_BYTES  (192 * 1024)
#define BYOS_TEXT_MAX          32
#define BYOS_AUTH_MAX          23
#define BYOS_SRCID_MAX         16
#define BYOS_LINE_MAX          256

typedef struct {
    uint8_t  mac[6];
    char     type;
    uint8_t  channel;
    char     text[BYOS_TEXT_MAX + 1];
    char     auth[BYOS_AUTH_MAX + 1];

    capture_byos_sight_t sight[CAPTURE_BYOS_MAX_SIGHT];
    uint8_t  n_sight;
    uint8_t  sight_overflow;
} byos_rec_t;

typedef struct {
    byos_rec_t rec[BYOS_MAX_RECS];
    uint16_t   count;
    uint32_t   duplicates;
    uint32_t   invalid;
    uint32_t   overflow;
} byos_import_t;

static int byos_hex(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool byos_parse_mac_line(const char *line, uint8_t out[6])
{
    char hex[12];
    uint8_t n = 0;
    for (const char *p = line; *p; p++) {
        if (byos_hex((unsigned char)*p) >= 0) {
            if (n >= sizeof(hex)) return false;
            hex[n++] = *p;
        }
    }
    if (n != 12) return false;
    for (uint8_t i = 0; i < 6; i++) {
        int hi = byos_hex((unsigned char)hex[i * 2]);
        int lo = byos_hex((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void byos_setstr(char *dst, size_t cap, const char *src)
{
    size_t i = 0;
    for (; src && src[i] && i < cap - 1; i++) dst[i] = src[i];
    dst[i] = '\0';
}

static int byos_clamp(int v, int lo, int hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

static bool byos_parse_deg_e7(const char *s, int32_t *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    double deg = strtod(s, &end);
    if (end == s || deg < -180.0 || deg > 180.0) return false;
    *out = (int32_t)llround(deg * 1e7);
    return true;
}

static bool byos_parse_epoch(const char *s, uint32_t *out)
{
    if (!s || !*s) return false;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s) return false;
    *out = (uint32_t)v;
    return true;
}

static void byos_add_record(byos_import_t *im, char *line)
{
    while (*line && isspace((unsigned char)*line)) line++;
    if (!*line) return;

    char *f[10] = {0};
    int nf = 0;
    f[nf++] = line;
    for (char *p = line; *p && nf < 10; p++) {
        if (*p == '\t') { *p = '\0'; f[nf++] = p + 1; }
    }

    byos_rec_t rec;
    memset(&rec, 0, sizeof(rec));
    capture_byos_sight_t sg;
    memset(&sg, 0, sizeof(sg));
    strcpy(sg.source_id, "local");

    bool structured = (f[0][0] && f[0][1] == '\0' &&
                       (f[0][0] == 'W' || f[0][0] == 'B' || f[0][0] == 'M'));
    const char *macstr;
    if (structured) {
        rec.type = f[0][0];
        macstr = (nf > 1) ? f[1] : "";
    } else {
        rec.type = 'M';
        macstr = line;
    }
    if (!byos_parse_mac_line(macstr, rec.mac)) { im->invalid++; return; }

    int tail = 0;
    if (rec.type == 'W') {
        if (nf > 2) byos_setstr(rec.text, sizeof(rec.text), f[2]);
        if (nf > 3) rec.channel = (uint8_t)byos_clamp(atoi(f[3]), 0, 255);
        if (nf > 4) sg.rssi = (int8_t)byos_clamp(atoi(f[4]), -128, 127);
        if (nf > 5) byos_setstr(rec.auth, sizeof(rec.auth), f[5]);
        tail = 6;
    } else if (rec.type == 'B') {
        if (nf > 2) byos_setstr(rec.text, sizeof(rec.text), f[2]);
        if (nf > 3) sg.rssi = (int8_t)byos_clamp(atoi(f[3]), -128, 127);
        tail = 4;
    } else {
        tail = 2;
    }
    if (nf > tail && f[tail][0]) byos_setstr(sg.source_id, sizeof(sg.source_id), f[tail]);

    if (nf > tail + 2) {
        bool have_lat = byos_parse_deg_e7(f[tail + 1], &sg.lat_e7);
        bool have_lon = byos_parse_deg_e7(f[tail + 2], &sg.lon_e7);
        sg.has_pos = have_lat && have_lon;
    }
    if (nf > tail + 3) sg.has_ts = byos_parse_epoch(f[tail + 3], &sg.ts_s);

    for (uint16_t i = 0; i < im->count; i++) {
        byos_rec_t *ex = &im->rec[i];
        if (memcmp(ex->mac, rec.mac, 6) != 0) continue;

        if (!ex->text[0] && rec.text[0]) byos_setstr(ex->text, sizeof(ex->text), rec.text);
        if (!ex->auth[0] && rec.auth[0]) byos_setstr(ex->auth, sizeof(ex->auth), rec.auth);
        if (!ex->channel && rec.channel) ex->channel = rec.channel;
        if (ex->type == 'M' && rec.type != 'M') ex->type = rec.type;
        for (uint8_t s = 0; s < ex->n_sight; s++) {
            if (strcmp(ex->sight[s].source_id, sg.source_id) == 0) {
                if (sg.rssi > ex->sight[s].rssi) ex->sight[s].rssi = sg.rssi;
                if (sg.has_pos && !ex->sight[s].has_pos) {
                    ex->sight[s].lat_e7 = sg.lat_e7; ex->sight[s].lon_e7 = sg.lon_e7;
                    ex->sight[s].has_pos = true;
                }
                if (sg.has_ts && !ex->sight[s].has_ts) {
                    ex->sight[s].ts_s = sg.ts_s; ex->sight[s].has_ts = true;
                }
                im->duplicates++;
                return;
            }
        }
        if (ex->n_sight < CAPTURE_BYOS_MAX_SIGHT) ex->sight[ex->n_sight++] = sg;
        else ex->sight_overflow++;
        return;
    }
    if (im->count >= BYOS_MAX_RECS) { im->overflow++; return; }
    rec.sight[0] = sg;
    rec.n_sight = 1;
    im->rec[im->count++] = rec;
}

static esp_err_t byos_sniffcheck_post(httpd_req_t *req)
{
    if (req->content_len == 0) return send_bad(req, "empty upload");
    if (req->content_len > BYOS_UPLOAD_MAX_BYTES) return send_bad(req, "scan too large");

    byos_import_t *im = serve_buf_calloc(sizeof(*im));
    if (!im) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    char chunk[512];
    char line[BYOS_LINE_MAX];
    size_t got = 0;
    size_t li = 0;
    bool line_trunc = false;
    while (got < req->content_len) {
        size_t want = req->content_len - got;
        if (want > sizeof(chunk)) want = sizeof(chunk);
        int r = httpd_req_recv(req, chunk, want);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) {
            heap_caps_free(im);
            return ESP_FAIL;
        }
        got += (size_t)r;
        for (int i = 0; i < r; i++) {
            char c = chunk[i];
            if (c == '\n' || c == '\r') {
                if (li > 0 && !line_trunc) {
                    line[li] = '\0';
                    byos_add_record(im, line);
                } else if (line_trunc) {
                    im->invalid++;
                }
                li = 0;
                line_trunc = false;
            } else if (!line_trunc) {
                if (li < sizeof(line) - 1) line[li++] = c;
                else line_trunc = true;
            }
        }
    }
    if (li > 0 && !line_trunc) {
        line[li] = '\0';
        byos_add_record(im, line);
    } else if (line_trunc) {
        im->invalid++;
    }

    if (im->count == 0) {
        heap_caps_free(im);
        return send_bad(req, "no records found");
    }

    capture_ring_stats_t rst;
    capture_ring_get_stats(&rst);
    bool fresh = (rst.records_current == 0);
    if (fresh) {
        capture_emit_header();
        capture_emit_codebook();
    }
    uint16_t scan_index = fresh ? 1 : (uint16_t)(capture_writer_last_scan() + 1);
    uint32_t import_id = (uint32_t)(esp_timer_get_time() / 1000);
    uint32_t wifi_n = 0, ble_n = 0, mac_n = 0;
    for (uint16_t i = 0; i < im->count; i++) {
        const byos_rec_t *rc = &im->rec[i];
        uint16_t idx = (uint16_t)(i + 1);
        switch (rc->type) {
        case 'W':
            capture_emit_byos_wifi(rc->mac, scan_index, import_id, idx,
                                   rc->text, rc->channel, rc->auth,
                                   rc->sight, rc->n_sight);
            wifi_n++;
            break;
        case 'B':
            capture_emit_byos_ble(rc->mac, scan_index, import_id, idx,
                                  rc->text[0] ? rc->text : NULL,
                                  rc->sight, rc->n_sight);
            ble_n++;
            break;
        default:
            capture_emit_byos_mac(rc->mac, scan_index, import_id, idx,
                                  rc->sight, rc->n_sight);
            mac_n++;
            break;
        }
        if ((i & 31) == 31) vTaskDelay(1);
    }
    capture_emit_footer(CAP_END_IMPORT, wifi_n, ble_n, 0, 0, 0, 1);

    char json[256];
    snprintf(json, sizeof(json),
             "{\"ok\":true,\"records\":%u,\"wifi\":%u,\"ble\":%u,\"mac_only\":%u,"
             "\"duplicates\":%u,\"invalid\":%u,\"overflow\":%u,"
             "\"import_id\":%u,\"report\":\"/report.html\"}",
             (unsigned)im->count, (unsigned)wifi_n, (unsigned)ble_n, (unsigned)mac_n,
             (unsigned)im->duplicates, (unsigned)im->invalid, (unsigned)im->overflow,
             (unsigned)import_id);
    ESP_LOGI(TAG, "BYOS import decoded: recs=%u wifi=%u ble=%u mac=%u dup=%u invalid=%u overflow=%u",
             (unsigned)im->count, (unsigned)wifi_n, (unsigned)ble_n, (unsigned)mac_n,
             (unsigned)im->duplicates, (unsigned)im->invalid, (unsigned)im->overflow);
    heap_caps_free(im);
    return send_json(req, json);
}

static void register_handlers(void)
{
    static const httpd_uri_t uris[] = {
        { .uri = "/",                          .method = HTTP_GET,  .handler = root_get },
        { .uri = "/logo.png",                  .method = HTTP_GET,  .handler = logo_get },
        { .uri = "/favicon.ico",               .method = HTTP_GET,  .handler = favicon_get },
        { .uri = "/pup.png",                   .method = HTTP_GET,  .handler = pup_get },
#if SC_EPUP_BRAIN
        { .uri = "/epup_sprites.png",          .method = HTTP_GET,  .handler = epup_sprites_get },
#endif
        { .uri = "/generate_204",              .method = HTTP_GET,  .handler = root_get },
        { .uri = "/hotspot-detect.html",       .method = HTTP_GET,  .handler = root_get },
        { .uri = "/connecttest.txt",           .method = HTTP_GET,  .handler = root_get },
        { .uri = "/report.html",               .method = HTTP_GET,  .handler = report_get },
        { .uri = "/viewer",                    .method = HTTP_GET,  .handler = viewer_get },
        { .uri = "/api/status",                .method = HTTP_GET,  .handler = status_get },
        { .uri = "/api/system/memory",         .method = HTTP_GET,  .handler = system_memory_get },
        { .uri = "/api/captures",              .method = HTTP_GET,  .handler = captures_get },
        { .uri = "/api/captures/live.jsonl",   .method = HTTP_GET,  .handler = live_jsonl_get },
        { .uri = "/api/captures/live.json",    .method = HTTP_GET,  .handler = live_json_get },
        { .uri = "/api/captures/clear-volatile", .method = HTTP_POST, .handler = clear_post },
        { .uri = "/api/captures/save-sd",        .method = HTTP_POST, .handler = save_sd_post },
#if SC_SD_ARCHIVE

        { .uri = "/api/captures/session/*",     .method = HTTP_GET,  .handler = session_jsonl_get },
        { .uri = "/api/archive",               .method = HTTP_GET,  .handler = archive_get },
        { .uri = "/api/archive/delete",        .method = HTTP_POST, .handler = archive_delete_post },
        { .uri = "/api/archive/rename",        .method = HTTP_POST, .handler = archive_rename_post },
        { .uri = "/api/archive/wipe",          .method = HTTP_POST, .handler = archive_wipe_post },
        { .uri = "/api/sd/ls",                 .method = HTTP_GET,  .handler = sd_ls_get },
        { .uri = "/api/sd/file",               .method = HTTP_GET,  .handler = sd_file_get },
#endif
        { .uri = "/api/download/extend",       .method = HTTP_POST, .handler = extend_post },
        { .uri = "/api/download/disable",      .method = HTTP_POST, .handler = disable_post },
        { .uri = "/api/settings",              .method = HTTP_GET,  .handler = settings_get },
        { .uri = "/api/settings/mode",         .method = HTTP_POST, .handler = settings_mode_post },
        { .uri = "/api/settings/brightness",   .method = HTTP_POST, .handler = settings_brightness_post },
        { .uri = "/api/settings/led",          .method = HTTP_POST, .handler = settings_led_post },
        { .uri = "/api/settings/download-timeout", .method = HTTP_POST, .handler = settings_timeout_post },
        { .uri = "/api/scan/start",            .method = HTTP_POST, .handler = scan_start_post },
        { .uri = "/api/pup/status",            .method = HTTP_GET,  .handler = pup_status_get },
        { .uri = "/api/pup/pet",               .method = HTTP_POST, .handler = pup_pet_post },
        { .uri = "/api/pup/treat",             .method = HTTP_POST, .handler = pup_treat_post },
        { .uri = "/api/pup/play",              .method = HTTP_POST, .handler = pup_play_post },
        { .uri = "/api/pup/name",              .method = HTTP_POST, .handler = pup_name_post },
        { .uri = "/api/pup/reset",             .method = HTTP_POST, .handler = pup_reset_post },
        { .uri = "/api/pup/walk/last",         .method = HTTP_GET,  .handler = pup_walk_last_get },
        { .uri = "/api/pup/walk/start",        .method = HTTP_POST, .handler = pup_walk_start_post },
#if SC_ENV_LEARN
        { .uri = "/api/env",                   .method = HTTP_GET,  .handler = env_get },
        { .uri = "/api/env/learn/start",       .method = HTTP_POST, .handler = env_learn_start_post },
        { .uri = "/api/env/learn/cancel",      .method = HTTP_POST, .handler = env_learn_cancel_post },
        { .uri = "/api/env/label",             .method = HTTP_POST, .handler = env_label_post },
        { .uri = "/api/env/forget",            .method = HTTP_POST, .handler = env_forget_post },
#endif
#if SC_TRACKER_SOUND
        { .uri = "/api/trackers",              .method = HTTP_GET,  .handler = trackers_get },
        { .uri = "/api/trackers/arm",          .method = HTTP_POST, .handler = trackers_arm_post },
        { .uri = "/api/trackers/bark",         .method = HTTP_POST, .handler = trackers_bark_post },
        { .uri = "/api/trackers/howl",         .method = HTTP_POST, .handler = trackers_howl_post },
        { .uri = "/api/trackers/stop",         .method = HTTP_POST, .handler = trackers_stop_post },
#endif
        { .uri = "/api/sta",                   .method = HTTP_GET,  .handler = sta_get },
        { .uri = "/api/sta/capture",           .method = HTTP_POST, .handler = sta_capture_post },
        { .uri = "/api/csi",                   .method = HTTP_GET,  .handler = csi_get },
        { .uri = "/api/csi/run",               .method = HTTP_POST, .handler = csi_run_post },
        { .uri = "/api/byos/sniffcheck",       .method = HTTP_POST, .handler = byos_sniffcheck_post },
        { .uri = "/api/scan/channels",         .method = HTTP_GET,  .handler = scan_channels_get },
        { .uri = "/api/pcap/run",              .method = HTTP_POST, .handler = pcap_run_post },
        { .uri = "/api/pcap/status",           .method = HTTP_GET,  .handler = pcap_status_get },
        { .uri = "/api/pcap/latest",           .method = HTTP_GET,  .handler = pcap_latest_get },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(s_server, &uris[i]);
    }
}

esp_err_t download_http_start(void)
{
    if (s_server) return ESP_OK;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();

    cfg.max_open_sockets = SC_CLUSTER_HEAD ? 12 : 7;
    cfg.lru_purge_enable = true;
    cfg.max_uri_handlers = 68;

    cfg.stack_size = 8192;

    cfg.uri_match_fn = httpd_uri_match_wildcard;

    esp_err_t err = httpd_start(&s_server, &cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        s_server = NULL;
        return err;
    }
    register_handlers();
    ESP_LOGI(TAG, "HTTP server up on AP netif");
    return ESP_OK;
}

void download_http_stop(void)
{
    if (!s_server) return;
    httpd_stop(s_server);
    s_server = NULL;
    ESP_LOGI(TAG, "HTTP server stopped");
}

httpd_handle_t download_http_server(void)
{
    return s_server;
}
