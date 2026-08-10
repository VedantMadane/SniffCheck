#include <string.h>
#include <stdio.h>

#include "cluster_ui.h"
#include "node_display.h"
#include "qrcode.h"

#define QR_BOX_PX 72
#define QR_X0      4
#define QR_Y0      4
#define QR_RCOL   80

#define MENU_SEL_BG rgb565be(0x20, 0x24, 0x30)

static uint16_t s_qrbuf[QR_BOX_PX * QR_BOX_PX];

static void copy_field(char *dst, size_t cap, const char *src)
{
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void cl_ui_frame_reset(cl_uiframe_t *f, uint8_t screen, const char *title,
                       const char *hint)
{
    memset(f, 0, sizeof *f);
    f->screen = screen;
    f->sel    = -1;
    copy_field(f->title, CL_UI_TITLE, title);
    copy_field(f->hint,  CL_UI_HINT,  hint);
}

void cl_ui_frame_item(cl_uiframe_t *f, const char *text)
{
    if (f->n_items >= CL_UI_ITEMS) return;
    copy_field(f->items[f->n_items], CL_UI_ITEM, text);
    f->n_items++;
}

void cl_ui_frame_extra(cl_uiframe_t *f, const char *text, int ok)
{
    copy_field(f->extra, CL_UI_EXTRA, text);
    if (ok) f->flags |= CL_UI_F_EXTRA_OK;
    else    f->flags &= (uint8_t)~CL_UI_F_EXTRA_OK;
}

static void qr_draw_cb(esp_qrcode_handle_t qr)
{
    int size = esp_qrcode_get_size(qr);
    int border = 2, total = size + 2 * border;
    int scale = QR_BOX_PX / total; if (scale < 1) scale = 1;
    int px = total * scale; if (px > QR_BOX_PX) px = QR_BOX_PX;
    for (int i = 0; i < px * px; i++) s_qrbuf[i] = COLOR_WHITE;
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++)
            if (esp_qrcode_get_module(qr, x, y)) {
                int bx = (border + x) * scale, by = (border + y) * scale;
                for (int dy = 0; dy < scale && by + dy < px; dy++)
                    for (int dx = 0; dx < scale && bx + dx < px; dx++)
                        s_qrbuf[(by + dy) * px + (bx + dx)] = COLOR_BLACK;
            }
    display_draw_image(QR_X0, QR_Y0, px, px, s_qrbuf);
}

static void draw_extra_band(const cl_uiframe_t *f)
{
    if (!f->extra[0]) return;
    display_fill_rect(0, 70, DISPLAY_W, 10, COLOR_NEARBLACK);
    display_draw_string(2, 70, f->extra,
                        (f->flags & CL_UI_F_EXTRA_OK) ? COLOR_GREEN : COLOR_AMBER,
                        COLOR_NEARBLACK, 1);
}

static void draw_menu(const cl_uiframe_t *f)
{
    display_clear(COLOR_NEARBLACK);
    display_draw_string(2, 2, f->title, COLOR_HEADER, COLOR_NEARBLACK, 1);
    display_fill_rect(0, 11, DISPLAY_W, 1, COLOR_HEADER);

    int n  = f->n_items > CL_UI_ITEMS ? CL_UI_ITEMS : f->n_items;
    int y0 = (n >= 5) ? 14 : 16;
    int dy = (n >= 5) ? 11 : 12;

    for (int i = 0; i < n; i++) {
        int y = y0 + i * dy;
        int sel = (i == f->sel);
        uint16_t bg = sel ? MENU_SEL_BG : COLOR_NEARBLACK;
        if (sel) display_fill_rect(0, y - 1, DISPLAY_W, 10, bg);
        display_draw_string(4,  y, sel ? ">" : " ", COLOR_AMBER, bg, 1);
        display_draw_string(14, y, f->items[i], sel ? COLOR_WHITE : COLOR_AMBER, bg, 1);
    }

    if (f->extra[0])     draw_extra_band(f);
    else if (f->hint[0]) display_draw_string(2, DISPLAY_H - 8, f->hint,
                                             COLOR_GREEN, COLOR_NEARBLACK, 1);
}

static void draw_qr(const cl_uiframe_t *f)
{
    display_clear(COLOR_NEARBLACK);

    esp_qrcode_config_t qcfg = ESP_QRCODE_CONFIG_DEFAULT();
    qcfg.display_func       = qr_draw_cb;
    qcfg.max_qrcode_version = 4;
    qcfg.qrcode_ecc_level   = ESP_QRCODE_ECC_LOW;
    if (!f->qr[0] || esp_qrcode_generate(&qcfg, f->qr) != ESP_OK)
        display_draw_string(QR_X0, 34, "QR err", COLOR_RED, COLOR_NEARBLACK, 1);

    display_draw_string(QR_RCOL, 4, f->title, COLOR_HEADER, COLOR_NEARBLACK, 1);
    if (f->n_items > 0) display_draw_string(QR_RCOL, 16, f->items[0], COLOR_WHITE, COLOR_NEARBLACK, 1);
    if (f->n_items > 1) display_draw_string(QR_RCOL, 27, f->items[1], COLOR_AMBER, COLOR_NEARBLACK, 1);
    if (f->n_items > 2) display_draw_string(QR_RCOL, 42, f->items[2], COLOR_GREEN, COLOR_NEARBLACK, 1);
    if (f->hint[0])     display_draw_string(QR_RCOL, 54, f->hint,     COLOR_GREEN, COLOR_NEARBLACK, 1);

    draw_extra_band(f);
}

void cl_ui_draw(const cl_uiframe_t *f)
{
    if (f->screen == CL_UI_SCR_QR) draw_qr(f);
    else                           draw_menu(f);
}

static int only_extra_changed(const cl_uiframe_t *a, const cl_uiframe_t *b)
{
    cl_uiframe_t x = *a, y = *b;
    memset(x.extra, 0, sizeof x.extra);
    memset(y.extra, 0, sizeof y.extra);
    x.flags &= (uint8_t)~CL_UI_F_EXTRA_OK;
    y.flags &= (uint8_t)~CL_UI_F_EXTRA_OK;
    return memcmp(&x, &y, sizeof x) == 0;
}

int cl_ui_draw_diff(const cl_uiframe_t *now, const cl_uiframe_t *prev, int have_prev)
{
    if (have_prev && memcmp(now, prev, sizeof *now) == 0) return 0;

    if (have_prev && now->extra[0] && only_extra_changed(now, prev)) {
        draw_extra_band(now);
        return 1;
    }
    cl_ui_draw(now);
    return 1;
}
