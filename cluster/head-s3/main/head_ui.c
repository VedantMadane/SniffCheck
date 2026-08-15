#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
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

#define UI_REFRESH_US    (2 * 1000000LL)

static head_ui_page_fn  s_compose;
static int              s_page;
static volatile bool    s_dirty = true;

static cl_uiframe_t     s_draw;
static cl_uiframe_t     s_last_drawn;
static bool             s_have_last;

void head_ui_mark_dirty(void) { s_dirty = true; }

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

    int64_t last_paint = 0;

    for (;;) {
        uint8_t ev = wait_button(UI_POLL_MS);
        switch (ev) {
        case CL_UI_EV_SINGLE: s_page = (s_page + 1) % HEAD_UI_PAGES;                  s_dirty = true; break;
        case CL_UI_EV_DOUBLE: s_page = (s_page + HEAD_UI_PAGES - 1) % HEAD_UI_PAGES;  s_dirty = true; break;
        case CL_UI_EV_LONG:   s_page = 0;                                             s_dirty = true; break;
        default: break;
        }

        int64_t now = esp_timer_get_time();
        if (!s_dirty && (now - last_paint) < UI_REFRESH_US) continue;
        s_dirty    = false;
        last_paint = now;

        if (!s_compose) continue;
        memset(&s_draw, 0, sizeof s_draw);
        s_compose(s_page, &s_draw);
        cl_ui_draw_diff(&s_draw, &s_last_drawn, s_have_last);
        memcpy(&s_last_drawn, &s_draw, sizeof s_last_drawn);
        s_have_last = true;
    }
}

void head_ui_init(head_ui_page_fn compose)
{
    s_compose = compose;

    xTaskCreatePinnedToCore(ui_task, "s3_ui", 4096, NULL, 5, NULL, 0);
    ESP_LOGI(TAG, "local UI up — button GPIO%d cycles %d pages",
             HEAD_BTN_GPIO, HEAD_UI_PAGES);
}
