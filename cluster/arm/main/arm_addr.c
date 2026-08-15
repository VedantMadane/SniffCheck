#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "driver/i2c_master.h"

#include "arm_addr.h"
#include "cluster_pins.h"

static const char *TAG = "arm-addr";

#define NVS_NS    "sccluster"
#define NVS_KEY   "arm_addr"

#define PROBE_TIMEOUT_MS  50

static const uint8_t POOL[CL_ARM_POOL_N] = CL_ARM_POOL;

void arm_addr_node_id(uint8_t out[3])
{
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    memcpy(out, mac + 3, 3);
}

static uint32_t mac_seed(void)
{
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    return ((uint32_t)mac[3] << 16) | ((uint32_t)mac[4] << 8) | mac[5];
}

static uint8_t nvs_get_addr(void)
{
    nvs_handle_t h;
    uint8_t v = 0;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return 0;
    if (nvs_get_u8(h, NVS_KEY, &v) != ESP_OK) v = 0;
    nvs_close(h);
    for (int i = 0; i < CL_ARM_POOL_N; i++) if (POOL[i] == v) return v;
    return 0;
}

static void nvs_put_addr(uint8_t addr)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_u8(h, NVS_KEY, addr);
    nvs_commit(h);
    nvs_close(h);
}

static void nvs_clear_addr(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_erase_key(h, NVS_KEY);
    nvs_commit(h);
    nvs_close(h);
}

static uint32_t probe_pool(void)
{
    i2c_master_bus_config_t bus = {
        .i2c_port                     = CL_I2C_PORT,
        .sda_io_num                   = CL_I2C_SDA_GPIO,
        .scl_io_num                   = CL_I2C_SCL_GPIO,
        .clk_source                   = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt            = 7,
        .flags.enable_internal_pullup = true,
    };
    i2c_master_bus_handle_t h;
    if (i2c_new_master_bus(&bus, &h) != ESP_OK) {
        ESP_LOGW(TAG, "no master bus for probe — keeping stored slot");
        return 0;
    }

    uint32_t taken = 0;
    for (int i = 0; i < CL_ARM_POOL_N; i++)
        if (i2c_master_probe(h, POOL[i], PROBE_TIMEOUT_MS) == ESP_OK)
            taken |= (1u << i);

    i2c_del_master_bus(h);
    return taken;
}

static uint8_t claim(bool fresh)
{
    if (!fresh) {
        uint8_t stored = nvs_get_addr();
        if (stored) {
            ESP_LOGI(TAG, "slot 0x%02X (stored)", stored);
            return stored;
        }
    }

    uint32_t delay_ms = (mac_seed() % 400) + (fresh ? (esp_random() % 400) : 0);
    vTaskDelay(pdMS_TO_TICKS(delay_ms));

    uint32_t taken = probe_pool();
    int pick = -1;
    for (int i = 0; i < CL_ARM_POOL_N; i++)
        if (!(taken & (1u << i))) { pick = i; break; }

    if (pick < 0) {
        ESP_LOGE(TAG, "arm pool full (%d slots all answered) — falling back to 0x%02X",
                 CL_ARM_POOL_N, POOL[0]);
        pick = 0;
    }

    vTaskDelay(pdMS_TO_TICKS(60 + (esp_random() % 120)));
    uint32_t again = probe_pool();
    if (again & (1u << pick)) {
        for (int i = 0; i < CL_ARM_POOL_N; i++)
            if (!(again & (1u << i))) { pick = i; break; }
        ESP_LOGW(TAG, "slot taken during claim — moved to 0x%02X", POOL[pick]);
    }

    nvs_put_addr(POOL[pick]);
    ESP_LOGI(TAG, "slot 0x%02X (claimed, %d pool slots busy)", POOL[pick],
             __builtin_popcount(again));
    return POOL[pick];
}

uint8_t arm_addr_claim(void)
{

    return claim(nvs_get_addr() == 0);
}

void arm_addr_forget(void) { nvs_clear_addr(); }
