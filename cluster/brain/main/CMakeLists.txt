idf_component_register(
    SRCS
        "brain_main.c"
        "epup_brain.c"
        "infra_cluster.c"
        "../../common/cluster_proto.c"
        "../../common/cluster_ui.c"
        "../../common/sentinel.c"
        "../../../dogpark-node/main/node_display.c"
        "../../../main/led.c"
        "../../master/main/cluster_web.c"
        "../../master/main/master_shim.c"
        "../../../main/download_http.c"
        "../../../main/viewer_gz.c"
        "../../../main/download_mode.c"
        "../../../main/capture_ring.c"
        "../../../main/virtual_pup.c"
        "../../../main/virtual_pup_walk.c"
        "../../../main/pup_trophy.c"
    INCLUDE_DIRS
        "."
        "../../common"
        "../../master/main"
        "../../../dogpark-node/main"
        "../../../main"
    PRIV_REQUIRES
        esp_driver_i2c
        esp_driver_spi
        esp_driver_gpio
        esp_lcd
        esp_timer
        esp_http_server
        esp_wifi
        esp_netif
        esp_event
        nvs_flash
        esp_psram
        esp_hw_support
        spi_flash
        driver
    REQUIRES
        lcd_st7735
        qrcode
)

set_source_files_properties(
    "../../../main/download_http.c"
    PROPERTIES COMPILE_DEFINITIONS "SC_CLUSTER_HEAD=1;SC_EPUP_BRAIN=1")

set(VIEWER_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/viewer_gen")
set(VIEWER_SRC     "${CMAKE_CURRENT_SOURCE_DIR}/../../../tools/capture_viewer/index.html")
set(VIEWER_GEN
    "${VIEWER_GEN_DIR}/viewer_head.deflate"
    "${VIEWER_GEN_DIR}/viewer_tail.deflate"
    "${VIEWER_GEN_DIR}/viewer_gz_meta.h")

add_custom_command(
    OUTPUT ${VIEWER_GEN}
    COMMAND ${CMAKE_COMMAND} -E env python3
            "${CMAKE_CURRENT_SOURCE_DIR}/../../../tools/gen_viewer_gz.py"
            "${VIEWER_SRC}" "${VIEWER_GEN_DIR}"
    DEPENDS "${VIEWER_SRC}"
            "${CMAKE_CURRENT_SOURCE_DIR}/../../../tools/gen_viewer_gz.py"
    COMMENT "Pre-compressing capture viewer (gzip, split at data island)"
    VERBATIM)

add_custom_target(viewer_gz_gen DEPENDS ${VIEWER_GEN})
add_dependencies(${COMPONENT_LIB} viewer_gz_gen)
target_include_directories(${COMPONENT_LIB} PRIVATE "${VIEWER_GEN_DIR}")

target_add_binary_data(${COMPONENT_LIB}
    "${VIEWER_GEN_DIR}/viewer_head.deflate" BINARY
    RENAME_TO viewer_head_deflate)
target_add_binary_data(${COMPONENT_LIB}
    "${VIEWER_GEN_DIR}/viewer_tail.deflate" BINARY
    RENAME_TO viewer_tail_deflate)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../master/main/dogpark_dashboard.html" TEXT
    RENAME_TO dogpark_dashboard_html)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../main/webap_logo.png" BINARY
    RENAME_TO webap_logo_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../main/webap_favicon.png" BINARY
    RENAME_TO webap_favicon_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../main/webap_pup.png" BINARY
    RENAME_TO webap_pup_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../main/epup_sprites.png" BINARY
    RENAME_TO epup_sprites_png)
