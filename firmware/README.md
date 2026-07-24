# firmware/ — flasher assets

The web flasher loads `../manifest.json`, and the flash engine writes the referenced
`.bin` to the board over USB. Every image here is a **merged** one-shot image
(bootloader + partition table + app + data) flashed at offset 0, plus an app-only
`*-app.bin` for over-the-air style updates.

Images shipped here:

| Firmware                              | Board     | Merged image                              |
|---------------------------------------|-----------|-------------------------------------------|
| SniffCheck (standalone)               | ESP32-C5  | `sniffcheck-merged.bin`                   |
| Dog Park cluster — brain              | ESP32-C5  | `sniffcheck-cluster-brain-merged.bin`     |
| Dog Park cluster — arm                | ESP32-C5  | `sniffcheck-cluster-arm-merged.bin`       |
| Dog Park cluster — S3 node            | ESP32-S3  | `sniffcheck-cluster-s3node-merged.bin`    |

The cluster **arm** merged image bundles the vendor database (`data/eui.bin`) at
`0x310000`, so scanned devices resolve to real vendor names and categories.

`checksums.txt` holds a `sha256` for every `.bin`; the S3-node image is the only
ESP32-S3 build (the flasher checks the chip family before writing).

To publish a new build: rebuild the role, regenerate its merged (and app) image, drop
the `.bin` here, update `checksums.txt`, and bump `version` in `../manifest.json` (and
the matching `manifest-*.json`).
