# SniffCheck Cluster (Dog Park)

The cluster turns several ESP32 boards into one cooperating Dog Park scanner: a set
of headless scanning **arms**, a **brain** that masters the bus and hosts the web app,
and an **S3 node** that owns the microSD archive and the flagged-signature sentinel.

Each role is a standalone ESP-IDF project built out-of-tree (the shared driver and
web-app sources live in the main firmware tree and are pulled in by relative path).

## Roles

| Role      | Board            | Target   | Job                                                         |
|-----------|------------------|----------|-------------------------------------------------------------|
| `brain`   | LilyGO T-Dongle-C5 | esp32c5 | I2C master of the Qwiic bus + SoftAP/WebAP host (PSRAM report) |
| `head-s3` | LilyGO T-Dongle-S3 | esp32s3 | I2C slave service node: microSD durable store + sentinel + LCD |
| `arm`     | ESP32-C5         | esp32c5  | Headless scanner; reports its scanset to the brain over I2C |
| `master`  | ESP32-C5         | esp32c5  | Legacy pre-Phase-115 single-head master — not flashed any more |

`common/` holds the wire protocol (`cluster_proto`), the sentinel matcher, and the
shared pin map. Arms attach to the flat Qwiic bus (SDA/SCL) and are polled by the brain.

## How many arms

However many you have. Nothing about an arm's role is compiled in:

- At boot an arm briefly masters the bus, sees which slots of the arm pool
  (`0x11`, `0x12`, `0x14`, `0x15`, `0x16`, `0x17`) already answer, claims the lowest
  free one and keeps it in NVS. A board therefore keeps its number across reboots,
  and arms number in power-on order.
- The brain watches the whole pool, works with whoever answers, and hands each arm
  its share of the spectrum. One arm sweeps the entire channel union; two split it;
  three take a third each. The split is re-issued whenever an arm joins or drops.
- A merge window closes once every arm still present has delivered, or on a timeout,
  so unplugging an arm mid-scan cannot stall the pack.

If two arms ever end up on one slot, the brain sees the address answering under two
different node identities and tells that address to re-claim; both boards pick fresh
slots and the pack settles by itself.

The screens say what the brain assigned: a lone arm reads `2.4+5 full/BLE`, and in a
two-arm pack they read `2.4+5 1/2 BLE` and `2.4+5 2/2 BLE`.

## Build & flash

The build pulls shared sources from the sibling `main/`, `dogpark-node/`, and
`components/` trees, so build each role from its own directory into its own cache
(this repo lives on a filesystem that blocks in-tree symlinks):

```sh
# brain (esp32c5)
cd brain    && idf.py -B ~/.cache/sc-brain-build --preview set-target esp32c5 build flash

# S3 node (esp32s3)
cd head-s3  && idf.py -B ~/.cache/sc-s3-build set-target esp32s3 build flash

# arm (esp32c5) — the same image for every arm, flashed once per board
cd arm      && idf.py -B ~/.cache/sc-cluster-arm-build --preview set-target esp32c5 build
               idf.py -B ~/.cache/sc-cluster-arm-build -p /dev/ttyACM1 flash
```

Arms also need the vendor database written to `0x310000`, or every device resolves
as an unknown vendor:

```sh
python -m esptool --chip esp32c5 -p /dev/ttyACM1 --baud 460800 \
    write_flash --flash_size 16MB 0x310000 ../../data/eui.bin
```

`master/flash_all.sh` does all of that in one pass for a brain + two arms + S3 node.
Set `ARMS` to change the pack, and `PORT_*` to match your ports:

```sh
./flash_all.sh build                       # build every role, flash nothing
./flash_all.sh                             # build + flash the whole pack
ARMS="brain arm1 s3" ./flash_all.sh        # one-arm pack
./flash_all.sh monitor brain               # attach to a role
```

Pre-built images for all roles are on the web flasher (`docs/webflasher/`), including
merged one-shot images and app-only update images. There is one arm image; flash it
to as many boards as you want arms.
