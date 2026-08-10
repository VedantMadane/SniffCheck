idf_component_register(
    SRCS
        "head_main.c"
        "head_sd.c"
        "head_ui.c"
        "sentinel_registry.c"
        "action_sched.c"
        "driver_dult.c"
        "../../../main/led.c"
        "../../common/cluster_proto.c"
        "../../common/cluster_ui.c"
        "../../common/sentinel.c"
        "../../../dogpark-node/main/node_display.c"
    INCLUDE_DIRS
        "."
        "../../common"
        "../../../main"
        "../../../dogpark-node/main"
    PRIV_REQUIRES
        esp_driver_i2c esp_driver_spi esp_driver_gpio esp_driver_sdmmc esp_driver_ledc
        esp_lcd esp_timer fatfs nvs_flash esp_hw_support spi_flash driver
        esp_wifi esp_netif esp_event bt
    REQUIRES
        lcd_st7735
        qrcode
)

set_source_files_properties(
    "../../../dogpark-node/main/node_display.c"
    PROPERTIES COMPILE_DEFINITIONS
    "PIN_CS=4;PIN_DC=2;PIN_RST=1;PIN_BL=38;SC_LCD_MIRROR_X=false;SC_LCD_MIRROR_Y=true")
