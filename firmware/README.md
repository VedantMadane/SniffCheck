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

> **The three Dog Park cluster images are from an earlier source snapshot than
> the `main/` source in this repo.** The cluster projects compile several files
> out of `main/` (the arm builds `analyzer.c`, `wifi_scanner.c` and others; the
> brain embeds the report viewer), and `main/` has moved ahead of them. Building
> a cluster role from this tree will therefore produce a binary that differs
> from the one shipped here. The standalone `sniffcheck-merged.bin` **is** built
> from the source in this repo. The cluster images will be refreshed in their
> own release, once they can be re-verified on the four-board rig.

`checksums.txt` holds a `sha256` for every `.bin`; the S3-node image is the only
ESP32-S3 build (the flasher checks the chip family before writing).

To publish a new build: rebuild the role, regenerate its merged (and app) image, drop
the `.bin` here, update `checksums.txt`, and bump `version` in `../manifest.json` (and
the matching `manifest-*.json`).
