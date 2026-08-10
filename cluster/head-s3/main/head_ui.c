#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/gpio.h"
#include "esp_timer.h"
#include "esp_log.h"

#include "head_ui.h"
#include "head_pins.h"
#include "cluster_ui.h"
#include "node_display.h"

static const char *TAG = "s3-ui";

#define UI_LONG_HOLD_MS  2500
#define UI_DBL_GAP_MS     450
#define UI_POLL_MS        400

#define UI_LINK_STALE_US  (6 * 1000000LL)

static SemaphoreHandle_t s_mux;
static cl_uiframe_t      s_frame;
static cl_uiframe_t      s_draw;
static cl_uiframe_t      s_last_drawn;
static bool              s_have_last;
static bool              s_screen_dirty;
static bool              s_dirty;
static int64_t           s_last_frame_us;
static volatile bool     s_ever_linked;
static bool              s_showing_link_lost;

static portMUX_TYPE s_ev_mux = portMUX_INITIALIZER_UNLOCKED;
static uint8_t      s_ev;
static uint32_t     s_ev_seq;

void head_ui_push_frame(const cl_uiframe_t *f)
{
    if (xSemaphoreTake(s_mux, pdMS_TO_TICKS(100)) != pdTRUE) return;
    memcpy(&s_frame, f, sizeof s_frame);
    s_dirty         = true;
    s_last_frame_us = esp_timer_get_time();
    s_ever_linked   = true;
    xSemaphoreGive(s_mux);
}

void head_ui_fill_event(cl_uievent_t *out)
{
    memset(out, 0, sizeof *out);
    portENTER_CRITICAL(&s_ev_mux);
    out->ev  = s_ev;
    out->seq = s_ev_seq;
    portEXIT_CRITICAL(&s_ev_mux);
    out->has_lcd = 1;
    cl_uievent_seal(out);
}

bool head_ui_linked(void)
{
    int64_t last;
    if (!s_ever_linked) return false;

    if (!s_mux || xSemaphoreTake(s_mux, pdMS_TO_TICKS(20)) != pdTRUE) return true;
    last = s_last_frame_us;
    xSemaphoreGive(s_mux);
    if (last == 0) return false;
    return (esp_timer_get_time() - last) < UI_LINK_STALE_US;
}

static uint8_t wait_button(uint32_t timeout_ms)
{
    uint32_t waited = 0;
    while (gpio_get_level(HEAD_BTN_GPIO) != 0) {
        vTaskDelay(pdMS_TO_TICKS(20));
        waited += 20;
        if (waited >= timeout_ms) return CL_UI_EV_NONE;
    }
    vTaskDelay(pdMS_TO_TICKS(30));
    if (gpio_get_level(HEAD_BTN_GPIO) != 0) return CL_UI_EV_NONE;

    uint32_t held = 0;
    while (gpio_get_level(HEAD_BTN_GPIO) == 0 && held < UI_LONG_HOLD_MS) {
        vTaskDelay(pdMS_TO_TICKS(20));
        held += 20;
    }
    if (gpio_get_level(HEAD_BTN_GPIO) == 0 && held >= UI_LONG_HOLD_MS) {
        while (gpio_get_level(HEAD_BTN_GPIO) == 0) vTaskDelay(pdMS_TO_TICKS(20));
        return CL_UI_EV_LONG;
    }
    uint32_t gap = 0;
    while (gap < UI_DBL_GAP_MS) {
        vTaskDelay(pdMS_TO_TICKS(20));
        gap += 20;
        if (gpio_get_level(HEAD_BTN_GPIO) == 0) {
            vTaskDelay(pdMS_TO_TICKS(30));
            if (gpio_get_level(HEAD_BTN_GPIO) != 0) continue;
            while (gpio_get_level(HEAD_BTN_GPIO) == 0) vTaskDelay(pdMS_TO_TICKS(20));
            return CL_UI_EV_DOUBLE;
        }
    }
    return CL_UI_EV_SINGLE;
}

static void draw_notice(const char *l0, const char *l1)
{
    cl_uiframe_t f;
    cl_ui_frame_reset(&f, CL_UI_SCR_MENU, "S3 NODE", NULL);
    cl_ui_frame_item(&f, l0);
    if (l1) cl_ui_frame_item(&f, l1);
    cl_ui_draw(&f);
    s_screen_dirty = true;
}

static void ui_task(void *arg)
{
    (void)arg;
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << HEAD_BTN_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);

    for (;;) {
        uint8_t ev = wait_button(UI_POLL_MS);
        if (ev != CL_UI_EV_NONE) {

            portENTER_CRITICAL(&s_ev_mux);
            s_ev = ev;
            s_ev_seq++;
            portEXIT_CRITICAL(&s_ev_mux);
            ESP_LOGD(TAG, "gesture %u", (unsigned)ev);
        }

        bool have = false;
        if (xSemaphoreTake(s_mux, pdMS_TO_TICKS(50)) == pdTRUE) {
            if (s_dirty) { memcpy(&s_draw, &s_frame, sizeof s_draw); s_dirty = false; have = true; }
            xSemaphoreGive(s_mux);
        }

        if (have) {

            cl_ui_draw_diff(&s_draw, &s_last_drawn, s_have_last && !s_screen_dirty);
            memcpy(&s_last_drawn, &s_draw, sizeof s_last_drawn);
            s_have_last     = true;
            s_screen_dirty  = false;
            s_showing_link_lost = false;
            continue;
        }

        if (s_ever_linked && !head_ui_linked() && !s_showing_link_lost) {
            draw_notice("brain link lost", "check Qwiic cable");
            s_showing_link_lost = true;
        }
    }
}

void head_ui_init(void)
{
    s_mux = xSemaphoreCreateMutex();
    draw_notice("waiting for brain", NULL);

    xTaskCreatePinnedToCore(ui_task, "s3_ui", 4096, NULL, 5, NULL, 0);
    ESP_LOGI(TAG, "remote head up — button GPIO%d, brain drives the screen", HEAD_BTN_GPIO);
}
