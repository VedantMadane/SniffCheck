# firmware/ — flasher assets

The web flasher loads `../manifest.json`, and the flash engine writes the referenced
`.bin` to the board over USB. Every image here is a **merged** one-shot image
(bootloader + partition table + app + data) flashed at offset 0, plus an app-only
`*-app.bin` for over-the-air style updates.

Images shipped here:

| Firmware                     | Board     | Merged image                              |
|------------------------------|-----------|-------------------------------------------|
| SniffCheck (standalone)      | ESP32-C5  | `sniffcheck-merged.bin`                   |
| Dog Park cluster — brain     | ESP32-C5  | `sniffcheck-cluster-brain-merged.bin`     |
| Dog Park cluster — arm       | ESP32-C5  | `sniffcheck-cluster-arm-merged.bin`       |
| Dog Park cluster — S3 node   | ESP32-S3  | `sniffcheck-cluster-s3node-merged.bin`    |

The standalone and arm images embed the vendor identification database at
`0x310000`, so they scan correctly on first boot. The S3-node image is the only
ESP32-S3 build — the flasher checks the chip family before writing, and the S3's
bootloader sits at `0x0` where the C5's sits at `0x2000`.

A second arm needs its own build: `ARM_INDEX` defaults to 1 (I²C address `0x11`),
so arm 2 is `idf.py -DARM_INDEX=2 build`. Only the arm-1 image ships here.

`checksums.txt` holds a `sha256` for every `.bin`. Verify from this directory's
parent: `sha256sum -c firmware/checksums.txt`.

To publish a new build: rebuild the role, regenerate its merged (and app) image
with `tools/make-cluster-images.sh`, update `checksums.txt`, and bump `version` in
`../manifest.json` and the matching `manifest-*.json`.
