#include "download_http.h"

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
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
#include "sta_tracker.h"
#include "wifi_csi_probe.h"
#include "pcap_capture.h"

static const char *TAG = "sc_dlhttp";

#ifndef SC_CLUSTER_HEAD
#define SC_CLUSTER_HEAD 0
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

extern const char _binary_capture_viewer_html_start[];
extern const unsigned char _binary_webap_logo_png_start[];
extern const unsigned char _binary_webap_logo_png_end[];
extern const unsigned char _binary_webap_favicon_png_start[];
extern const unsigned char _binary_webap_favicon_png_end[];
extern const unsigned char _binary_webap_pup_png_start[];
extern const unsigned char _binary_webap_pup_png_end[];
#if SC_CLUSTER_HEAD
extern const unsigned char _binary_epup_sprites_png_start[];
extern const unsigned char _binary_epup_sprites_png_end[];
#endif

#define ISLAND_MARKER "<!--SC_DATA_ISLAND-->"

static const char *s_view_head;
static size_t      s_view_head_len;
static const char *s_view_tail;
static size_t      s_view_tail_len;

static void viewer_locate_marker(void)
{
    if (s_view_head) return;
    const char *blob = _binary_capture_viewer_html_start;
    const char *mark = strstr(blob, ISLAND_MARKER);
    if (!mark) {
        ESP_LOGE(TAG, "viewer asset has no data-island marker — report route off");
        return;
    }
    s_view_head     = blob;
    s_view_head_len = (size_t)(mark - blob);
    s_view_tail     = mark + strlen(ISLAND_MARKER);
    s_view_tail_len = strlen(s_view_tail);
    ESP_LOGI(TAG, "viewer asset: %u + %u bytes around data island",
             (unsigned)s_view_head_len, (unsigned)s_view_tail_len);
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
            if (httpd_resp_send_chunk(req, p + seg, i + 1 - seg) != ESP_OK)
                return ESP_FAIL;
            if (httpd_resp_send_chunk(req, "\\", 1) != ESP_OK)
                return ESP_FAIL;
            seg = i + 1;
            i += 2;
        } else {
            i++;
        }
    }
    if (len > seg && httpd_resp_send_chunk(req, p + seg, len - seg) != ESP_OK)
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
                      : httpd_resp_send_chunk(req, buf, len);
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
                      : httpd_resp_send_chunk(req, buf, len);
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

":root{--bg:#ffd93b;--panel:#fff7d6;--ink:#3f2a14;--line:#3f2a14;--muted:#7a5a34;"
"--sh:#3f2a14;--accent:#ff8a1e;--pname:#e0701a;--safe:#2fa85a;--trk:#fff;"
"--onacc:#3f2a14}"
"body.dark{--bg:#241a0e;--panel:#3a2a18;--ink:#f3e4bf;--line:#c8a25a;--muted:#c9ac7e;"
"--sh:#100a04;--accent:#ffcf4a;--pname:#ffb14a;--safe:#5ec98a;--trk:#0f0a04}"
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
"#customwrap .chd{font-weight:800;font-size:11px;text-transform:uppercase;letter-spacing:.5px;"
"margin:10px 0 2px;padding-top:6px;border-top:1px solid var(--line);color:var(--muted)}"
"#customwrap .chd:first-child{border-top:0;padding-top:0;margin-top:2px}"
"#customwrap input[type=color]{width:46px;height:28px;padding:0;border:2px solid var(--line);"
"border-radius:6px;background:var(--panel);cursor:pointer}"
"#customwrap input[type=file]{font-size:12px;max-width:172px}"
"body.hasbg::before{content:'';position:fixed;inset:0;z-index:-1;background-image:var(--bgimg);"
"background-size:cover;background-position:center;background-attachment:fixed}"
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
"document.body.classList.toggle('dark',!!t[0]);curth=id;"
"var e=document.getElementById('thm');if(e)e.value=id}"
"function customGet(){try{var c=JSON.parse(localStorage.getItem('sc-custom'));if(c&&c.v)return c}catch(e){}"
"return {d:document.body.classList.contains('dark')?1:0,v:{},img:''}}"
"function customSet(c){try{localStorage.setItem('sc-custom',JSON.stringify(c))}catch(e){}}"
"function applycustom(){var c=customGet(),s=document.body.style,i,"
"keys=['bg','panel','ink','line','accent','pname','onacc','sh','bold','ital','hdr','muted',"
"'safe','caution','avoid','wifi','ble','track','drone'];"
"for(i=0;i<THV.length;i++)s.removeProperty('--'+THV[i]);"
"document.body.classList.toggle('dark',!!c.d);"
"for(i=0;i<keys.length;i++){if(c.v[keys[i]])s.setProperty('--'+keys[i],c.v[keys[i]]);"
"else s.removeProperty('--'+keys[i])}"
"if(c.img){s.setProperty('--bgimg','url('+c.img+')');document.body.classList.add('hasbg')}"
"else{s.removeProperty('--bgimg');document.body.classList.remove('hasbg')}"
"curth='custom';var e=document.getElementById('thm');if(e)e.value='custom'}"
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
"<div class=ex>Tap Jump (or press Space) to hop over the low blocks &mdash; but stay grounded when a block hangs from the top. Playing counts as time with your pup, and your best score is saved to it.</div>"
"</div>"
#endif
"<h2>Sniff Walk</h2>"
"<div class=wc id=wcard2></div>"
"<button class=dl onclick=\"armwalk(this)\">Start Sniff Walk</button>"
"<div class=ex>The walk scans Wi-Fi &amp; BLE while you carry SniffCheck, so this AP closes. End the walk on the device button &mdash; the AP re-opens with the walk summary.</div>"
"<button class=off onclick=\"armpup(this)\">Reset Pup</button>"
"</div>"

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
"<label><span class=lb>Caution</span><input type=color id=cc-caution oninput=\"cust('caution',this.value)\"></label>"
"<label><span class=lb>Danger</span><input type=color id=cc-avoid oninput=\"cust('avoid',this.value)\"></label>"
"<div class=chd>Device (report page)</div>"
"<label><span class=lb>Wi-Fi</span><input type=color id=cc-wifi oninput=\"cust('wifi',this.value)\"></label>"
"<label><span class=lb>BLE</span><input type=color id=cc-ble oninput=\"cust('ble',this.value)\"></label>"
"<label><span class=lb>Tracker</span><input type=color id=cc-track oninput=\"cust('track',this.value)\"></label>"
"<label><span class=lb>Drone</span><input type=color id=cc-drone oninput=\"cust('drone',this.value)\"></label>"
"<div class=chd>Base</div>"
"<label><span class=lb>Dark base</span><input type=checkbox id=cc-dark onchange=\"custDark(this.checked)\"></label>"
"<label><span class=lb>Background image</span><input type=file id=cc-img accept=image/* onchange=\"custImg(this)\"></label>"
"<button class=off onclick=\"custClearImg()\">Remove background image</button>"
"<div class=ex>Custom colors, fonts and background are saved in this browser.</div>"
"</div>"

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
"var st='idle',score=0,spd=2.4,py=GY,vy=0,obs=[],frame=0,acc=0,spawn=60;"
"function reset(){score=0;spd=2.4;py=GY;vy=0;obs=[];frame=0;acc=0;spawn=60;st='run';}"
"function over(){st='over';var s=Math.floor(score);"
"fetch('/api/pup/play',{method:'POST',headers:{'Content-Type':'application/json'},"
"body:JSON.stringify({score:s})}).then(function(r){return r.json()}).then(applypup).catch(function(){});}"
"window.pgTap=function(){if(st==='run'){if(py>=GY-0.5)vy=JMP;}else reset();};"
"cv.addEventListener('pointerdown',function(e){e.preventDefault();pgTap();});"
"document.addEventListener('keydown',function(e){if(e.code==='Space'||e.key===' '){"
"var pv=el('v-pup');if(pv&&pv.classList.contains('act')){e.preventDefault();pgTap();}}});"
"function spawnObs(){if(Math.random()<0.4)obs.push({x:W+8,top:true,w:16,h:104});"
"else obs.push({x:W+8,top:false,w:16,h:22+(Math.random()*22|0)});}"
"function step(){if(st==='run'){score+=spd*0.05;spd+=0.0016;"
"vy+=G;py+=vy;if(py>GY){py=GY;vy=0;}"
"acc++;if(acc>=spawn){acc=0;spawn=48+(Math.random()*46|0);spawnObs();}"
"var i,o,pl=px2(),pr=pl+SZ-18,ptp=py-SZ+6,pbt=py-3;"
"for(i=obs.length-1;i>=0;i--){o=obs[i];o.x-=spd;if(o.x+o.w<0){obs.splice(i,1);continue;}"
"var ot=o.top?0:GY-o.h,ob=o.top?o.h:GY;"
"if(pr>o.x&&pl<o.x+o.w&&pbt>ot&&ptp<ob){over();}}frame++;}draw();}"
"function px2(){return 40+8;}"
"function draw(){cx.clearRect(0,0,W,H);"
"cx.strokeStyle='#7a6a3a';cx.lineWidth=2;cx.beginPath();cx.moveTo(0,GY+2);cx.lineTo(W,GY+2);cx.stroke();"
"cx.fillStyle='#c9483b';var i,o;for(i=0;i<obs.length;i++){o=obs[i];"
"if(o.top)cx.fillRect(o.x,0,o.w,o.h);else cx.fillRect(o.x,GY-o.h,o.w,o.h);}"
"var row=(py<GY-1)?3:1,col=(row===1)?(Math.floor(frame/6)%2):0;"
"if(sheetOk)cx.drawImage(sheet,col*160,row*160,160,160,40,py-SZ,SZ,SZ);"
"else{cx.fillStyle='#e8b84b';cx.fillRect(40,py-SZ,SZ,SZ);}"
"var sc=el('pgscore');if(sc)sc.textContent=Math.floor(score);"
"if(st!=='run'){cx.fillStyle='rgba(0,0,0,.5)';cx.fillRect(0,0,W,H);"
"cx.fillStyle='#fff7d6';cx.textAlign='center';cx.font='bold 17px system-ui';"
"cx.fillText(st==='over'?('Score '+Math.floor(score)):'Fetch Runner',W/2,H/2-4);"
"cx.font='bold 12px system-ui';cx.fillText(st==='over'?'Tap Jump to play again':'Tap Jump to start',W/2,H/2+16);"
"cx.textAlign='left';}}"
"setInterval(step,33);draw();})();"
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
"function rcStart(eta){var total=Math.max(1,eta|0)+10,left=total;"
"el('rcmsg').innerHTML='The SniffCheck AP drops while the radio scans, then relaunches with the '"
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
"function nav(v){['home','pup','settings'].forEach(function(n){"
"el('v-'+n).classList.toggle('act',n===v);"
"el('nv-'+n).classList.toggle('act',n===v)})}"

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
"r.onload=function(){var c=customGet();c.img=String(r.result||'');customSet(c);setthm('custom')};r.readAsDataURL(f)}"
"function custClearImg(){var c=customGet();c.img='';customSet(c);setthm('custom');var e=el('cc-img');if(e)e.value=''}"
"function custSeed(){var c=customGet(),"
"D={bg:'#ffd93b',panel:'#fff7d6',ink:'#3f2a14',line:'#3f2a14',hdr:'#ff8a1e',muted:'#7a5a34',"
"accent:'#ff8a1e',pname:'#e0701a',onacc:'#3f2a14',sh:'#3f2a14',bold:'#ff8a1e',ital:'#e0701a',"
"safe:'#2fa85a',caution:'#d99a1e',avoid:'#d64545',wifi:'#2a6cd6',ble:'#6a4ce0',track:'#d98a1e',drone:'#1ea6a6'};"
"Object.keys(D).forEach(function(k){var e=el('cc-'+k);if(e)e.value=(c.v[k]||D[k])});"
"var d=el('cc-dark');if(d)d.checked=!!c.d}"
"function custSync(){var cw=el('customwrap');if(!cw)return;cw.style.display=(curth==='custom')?'':'none';if(curth==='custom')custSeed()}"
"custSync();"

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
"<div id=dig>SniffCheck is digging<span>Decoding and scoring uploaded MACs on-device...</span></div></body></html>";

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

#if SC_CLUSTER_HEAD
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

    char json[360];
    snprintf(json, sizeof(json),
        "{\"records\":%u,\"bytes\":%u,\"dropped\":%u,\"scans\":%u,"
        "\"session_id\":\"%s\",\"fw_version\":\"%s\",\"schema_version\":\"%s\","
        "\"seconds_remaining\":%u,\"clients\":%u,\"timeout_min\":%u,"
        "\"ssid\":\"%s\"}",
        (unsigned)st.records_current, (unsigned)st.bytes_used,
        (unsigned)st.records_dropped, (unsigned)capture_writer_last_scan(),
        capture_writer_session_id(), capture_writer_fw_version(),
        capture_writer_schema_version(),
        (unsigned)download_mode_get_seconds_remaining(),
        (unsigned)download_mode_get_client_count(),
        (unsigned)download_mode_get_timeout_minutes(),
        download_mode_get_ssid());
    return send_json(req, json);
}

static esp_err_t captures_get(httpd_req_t *req)
{
    capture_ring_stats_t st;
    capture_ring_get_stats(&st);

    char json[320];
    snprintf(json, sizeof(json),
        "[{\"id\":\"live\",\"name\":\"live.jsonl\",\"kind\":\"volatile\","
        "\"records\":%u,\"bytes\":%u,\"dropped\":%u,"
        "\"endpoints\":[\"/api/captures/live.jsonl\",\"/api/captures/live.json\"]}]",
        (unsigned)st.records_current,
        (unsigned)st.bytes_used,
        (unsigned)st.records_dropped);
    return send_json(req, json);
}

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
    if (!s_view_head) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "viewer asset missing");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    char query[16], dl[4];
    char disp[80];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "dl", dl, sizeof(dl)) == ESP_OK &&
        dl[0] == '1') {
        snprintf(disp, sizeof(disp),
                 "attachment; filename=\"sniffcheck-%s.html\"",
                 capture_writer_session_id());
        httpd_resp_set_hdr(req, "Content-Disposition", disp);
    }

    if (httpd_resp_send_chunk(req, s_view_head, s_view_head_len) != ESP_OK)
        return ESP_FAIL;

    size_t emitted = 0;
    esp_err_t err = stream_records(req, true, 0, &emitted);
    if (err != ESP_OK) {
        if (err == ESP_ERR_NO_MEM)
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no mem");
        return ESP_FAIL;
    }

    if (httpd_resp_send_chunk(req, s_view_tail, s_view_tail_len) != ESP_OK)
        return ESP_FAIL;
    httpd_resp_send_chunk(req, NULL, 0);
    ESP_LOGI(TAG, "report.html: %u records spliced", (unsigned)emitted);
    return ESP_OK;
}

static esp_err_t viewer_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, _binary_capture_viewer_html_start,
                           strlen(_binary_capture_viewer_html_start));
}

static esp_err_t clear_post(httpd_req_t *req)
{
    capture_ring_clear_volatile();
    ESP_LOGI(TAG, "ring cleared by client");
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t save_sd_post(httpd_req_t *req)
{
    ESP_LOGI(TAG, "save-to-SD requested (Phase 51 not yet implemented)");
    return send_json(req,
        "{\"ok\":false,\"error\":\"SD card storage isn't available on this build yet.\"}");
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
#if SC_CLUSTER_HEAD
        { .uri = "/epup_sprites.png",          .method = HTTP_GET,  .handler = epup_sprites_get },
#endif
        { .uri = "/generate_204",              .method = HTTP_GET,  .handler = root_get },
        { .uri = "/hotspot-detect.html",       .method = HTTP_GET,  .handler = root_get },
        { .uri = "/connecttest.txt",           .method = HTTP_GET,  .handler = root_get },
        { .uri = "/report.html",               .method = HTTP_GET,  .handler = report_get },
        { .uri = "/viewer",                    .method = HTTP_GET,  .handler = viewer_get },
        { .uri = "/api/status",                .method = HTTP_GET,  .handler = status_get },
        { .uri = "/api/captures",              .method = HTTP_GET,  .handler = captures_get },
        { .uri = "/api/captures/live.jsonl",   .method = HTTP_GET,  .handler = live_jsonl_get },
        { .uri = "/api/captures/live.json",    .method = HTTP_GET,  .handler = live_json_get },
        { .uri = "/api/captures/clear-volatile", .method = HTTP_POST, .handler = clear_post },
        { .uri = "/api/captures/save-sd",        .method = HTTP_POST, .handler = save_sd_post },
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

    viewer_locate_marker();

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();

    cfg.max_open_sockets = SC_CLUSTER_HEAD ? 12 : 7;
    cfg.lru_purge_enable = true;
    cfg.max_uri_handlers = 56;

    cfg.stack_size = 8192;

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
