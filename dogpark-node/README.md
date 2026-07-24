# SniffCheck Node (dogpark-node)

A slim, headless SniffCheck scanner node for the ESP32-C5. It sniffs Wi-Fi and
watches BLE (a baseline window learns the devices already present, then alerts on new
arrivals) and shows status and sniff/dig animations on the small LCD.

> **Status:** the standalone node app is on hold and is **not** in the web flasher
> right now — the current multi-board setup is the [Dog Park cluster](../DogParkClusterS3.md)
> (brain + arms + S3 node over I2C). This tree stays in the repo because the cluster
> builds share its `node_display.*` LCD driver + sprite source of truth.

This is a trimmed build of the full SniffCheck firmware: the display driver and sprite
assets are the same single source of truth as the main firmware, with the
analyzer/vetter/detail screens pruned.

## Layout

| File            | Job                                                       |
|-----------------|-----------------------------------------------------------|
| `app_main.c`    | boot, BLE baseline/alert loop, radio coexistence          |
| `dp_sniffer.*`  | Wi-Fi sniffer                                             |
| `dp_ble.*`      | BLE observer (NimBLE)                                     |
| `node_display.*`| LCD driver + boot splash + sniff/dig animations          |

## Build & flash (esp32c5)

```sh
idf.py -B ~/.cache/dogpark-node-build --preview set-target esp32c5
idf.py -B ~/.cache/dogpark-node-build build flash monitor
```

The build pulls a few shared sources by relative path from sibling trees:

- `../../main/led.c` and the `components/lcd_st7735` component (shared with the full
  firmware),
- `../../dogpark-x4/main/dp_espnow.*` — the shared ESP-NOW transport.

Those sibling files must be present alongside `dogpark-node/` for the build to resolve.
No pre-built image ships in the web flasher for this build right now (see Status above).
