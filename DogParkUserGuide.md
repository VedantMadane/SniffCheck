# SniffCheck Dog Park User Guide

Dog Park is the multi-board SniffCheck setup. Several boards share one bus so a
group of scanners covers more of the RF environment than a single dongle can, and
one board hosts a web app you open from your phone.

Simple version:

```text
Brain    (ESP32-C5)  = the I2C host; runs the web app and merges everyone's results
Arm      (ESP32-C5)  = a headless scanner; hands its scansets to the brain
S3 node  (ESP32-S3)  = the microSD record store, sentinel watchlist, and status LCD
```

It is still early firmware. It only listens. It does **not** deauth, jam, connect
to, pair with, or attack nearby devices.

For a short architecture overview see [`DogParkClusterS3.md`](DogParkClusterS3.md);
to build from source see [`cluster/README.md`](cluster/README.md).

---

## What you flash

| Firmware | Board | What it does |
|---|---|---|
| `Dog Park cluster — brain` | LilyGO T-Dongle C5 / ESP32-C5 | I2C host, aggregates results, serves the web app. |
| `Dog Park cluster — arm` | ESP32-C5 (T-Dongle C5 works) | Headless Wi-Fi + BLE scanner. One per arm. Vendor database bundled in. |
| `Dog Park cluster — S3 node` | LilyGO T-Dongle-S3 / ESP32-S3 | microSD record store, sentinel watchlist, status LCD. |

The smallest useful Dog Park is:

```text
1 board running Dog Park cluster — brain
1 or more boards running Dog Park cluster — arm
1 board running Dog Park cluster — S3 node   (optional but recommended: SD history + sentinel)
```

The brain is the only board your phone talks to. The arms and the S3 node are
slaves on the shared I2C bus and never touch your phone directly.

---

## Flashing from the web flasher

Open the web flasher (`index.html`) in Chrome or Edge on a desktop, then pick, in
order: **brand → device → firmware family → firmware**. For Dog Park pick the
`LilyGo` brand, the `ESP32-C5` device for the brain/arm or `ESP32-S3` for the S3
node, the `Dog Park cluster` family, then the role.

Plug in one board at a time, choose its firmware, and click Install. The flasher
checks the chip (C5 vs S3) against the picked firmware before writing, so a wrong
pick is refused rather than bricked. If a board isn't found, unplug it, hold
**BOOT**, plug it back in while holding, release, and click Install again.

The arm image already contains the vendor/device-type database, so scanned devices
resolve to real vendor names and categories with no extra step.

---

## Flashing from the command line

From a checkout with ESP-IDF v5.5 on your PATH, `cluster/flash_all.sh` builds and
flashes the C5 roles (brain and arms) in one pass and writes the vendor database to
each arm; the S3 node is built separately because it targets esp32s3. See
[`cluster/README.md`](cluster/README.md) for per-role commands and the port map.

If you flash an arm by hand, remember the vendor database is a separate partition:

```text
idf.py -p PORT flash                         # app only
esptool.py -p PORT write_flash 0x310000 data/eui.bin
```

Without that database an arm reports every device as unknown vendor and class.

---

## First boot and wiring

1. Wire the boards on one shared I2C bus (SDA, SCL, GND common). The brain is the
   master; the arms and the S3 node are slaves at fixed addresses (S3 node `0x13`,
   arms `0x11`/`0x12`).
2. Power all boards. The brain brings up its Wi-Fi access point and starts polling
   the arms; the S3 node mounts its microSD card.
3. On the brain's LCD you'll see it come up as the host and report how many arms
   have linked.

---

## Using it from your phone

1. Join the brain's Wi-Fi access point from your phone.
2. Open the web app at `http://192.168.4.1/`.
3. Results stream in as the arms scan. Each device shows an icon for its type
   (Wi-Fi AP, BLE device, tracker, drone), a name/vendor where one can be resolved,
   signal strength, and the local time it was last seen.

The web app collects the results in your browser as you go, so a long session keeps
climbing even past what the brain's memory holds. **Refresh** pulls the latest and,
while it runs, pauses and dims the live cards so it doesn't fight the brain for the
board's few network sockets, then re-enables them.

### Controls

- **Adv rescan** — runs a deeper Wi-Fi + BLE audit on every arm once.
- **Start walk / Stop walk** — puts the arms into a continuous coordinated sweep for
  wardriving-style coverage as you move.
- **Flag** — from any live result, add a device to the sentinel watchlist.

### Sentinel watchlist

The sentinel (owned by the S3 node) watches for the devices and signatures you flag
and records hits with a timestamp. Arm or disarm it from the web app, add devices by
MAC or name, and review the flagged-detection history.

### Environments

The brain learns places from the Wi-Fi landmarks around it. The Environments view
shows whether you're somewhere new or somewhere it recognizes, and lets you name a
place so it's remembered on the next visit.

### ePup

Everything in the project is dog-centered. The ePup is a learning mascot that
reflects the cluster's activity and place familiarity. It's mostly cosmetic for now.

---

## The microSD record store

The full record history lives on the S3 node's microSD card, independent of what the
browser or the brain's memory is holding. That card is the durable log of a session;
the brain's memory and the browser are the live/working views.

---

## Current limits and honesty notes

- **Listen-only.** Dog Park only observes RF that nearby devices already broadcast or
  leak. It never forces a response, connects, or attacks.
- **The bus is local.** The arms, brain, and S3 node coordinate over a wired I2C bus,
  not over the air; this is a local rig, not a mesh.
- **Standalone SniffCheck is separate.** The single-dongle `SniffCheck` firmware is
  its own thing; a Dog Park board runs a cluster role instead.
- **Identity is a best guess.** Vendor, device type, and place recognition are
  confidence-based estimates from observed fields, not proof.

---

## Troubleshooting

**An arm doesn't link.** Check the shared I2C wiring (SDA/SCL/GND common) and that
the arm is powered and running the arm firmware. The brain's LCD shows the linked
arm count.

**Devices all read "unknown" vendor/class.** The arm's vendor database partition is
blank — flash `data/eui.bin` to `0x310000` on that arm (the web flasher's arm image
already includes it; `flash_all.sh` writes it automatically).

**The web app won't load.** Confirm your phone is joined to the brain's access point
and open `http://192.168.4.1/`. Refresh if a control feels stuck.

**Web Serial won't flash.** Use Chrome or Edge on a desktop; Firefox, Safari, and
phones don't have the Web Serial API.

---

## Safety / privacy posture

Dog Park is passive.

It only observes RF data that nearby devices already broadcast or leak. It does not
force devices to respond. It does not connect to them. It does not identify a person
with certainty.

Use the outputs as:

```text
signals
hints
confidence-based estimates
```

not as proof.
