set(srcs
    "app_main.c"
    "ui_activity.c"
    "led.c"
    "display.c"
    "usb_console.c"
    "wifi_scanner.c"
    "eui_db.c"
    "frame_parser.c"
    "wifi_sniffer.c"
    "analyzer.c"
    "infra_cluster.c"
    "physical_device_cluster.c"
    "ble_scanner.c"
    "ble_advise.c"
    "drone_rid.c"
    "apple_continuity.c"
    "probe_req_log.c"
    "probe_frame_ring.c"
    "ble_adv_ring.c"
    "flock_detect.c"
    "public_safety_detect.c"
    "medical_responder_detect.c"
    "sta_tracker.c"
    "wifi_csi_probe.c"
    "pcap_capture.c"
    "seq_analyzer.c"
    "ie_signature.c"
    "anqp_analyzer.c"
    "vetter.c"
    "capture_ring.c"
    "sd_store.c"
    "env_learn.c"
    "passive_correlation.c"
    "tracker_sound.c"
    "../cluster/head-s3/main/action_sched.c"
    "../cluster/head-s3/main/driver_dult.c"
    "capture_writer.c"
    "download_mode.c"
    "download_http.c"
    "viewer_gz.c"
    "self_test.c"
    "virtual_pup.c"
    "virtual_pup_walk.c"
    "pup_trophy.c"
)

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "." "../cluster/head-s3/main"
    PRIV_REQUIRES
        esp_driver_spi
        esp_driver_sdspi
        sdmmc
        fatfs
        esp_driver_gpio
        esp_driver_ledc
        esp_lcd
        nvs_flash
        esp_wifi
        esp_event
        esp_netif
        esp_http_server
        esp_partition
        spi_flash
        esp_psram
        bt
        lwip
        mbedtls
        esp_timer
        esp_hw_support
        opendroneid
    REQUIRES
        lcd_st7735
)

set(VIEWER_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/viewer_gen")
set(VIEWER_SRC     "${CMAKE_CURRENT_SOURCE_DIR}/../tools/capture_viewer/index.html")
set(VIEWER_GEN
    "${VIEWER_GEN_DIR}/viewer_head.deflate"
    "${VIEWER_GEN_DIR}/viewer_tail.deflate"
    "${VIEWER_GEN_DIR}/viewer_gz_meta.h")

add_custom_command(
    OUTPUT ${VIEWER_GEN}
    COMMAND ${CMAKE_COMMAND} -E env python3
            "${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_viewer_gz.py"
            "${VIEWER_SRC}" "${VIEWER_GEN_DIR}"
    DEPENDS "${VIEWER_SRC}"
            "${CMAKE_CURRENT_SOURCE_DIR}/../tools/gen_viewer_gz.py"
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
    "${CMAKE_CURRENT_SOURCE_DIR}/webap_logo.png" BINARY
    RENAME_TO webap_logo_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/webap_favicon.png" BINARY
    RENAME_TO webap_favicon_png)
target_add_binary_data(${COMPONENT_LIB}
    "${CMAKE_CURRENT_SOURCE_DIR}/webap_pup.png" BINARY
    RENAME_TO webap_pup_png)
