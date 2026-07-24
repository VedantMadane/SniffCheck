# Dog Park — User Guide

Dog Park is the multi-board (cluster) way to run SniffCheck. A **brain** board hosts
a web app and merges results; one or more **arm** boards do the scanning; an optional
**S3 node** keeps the full history on microSD and runs the sentinel watchlist. You
control everything from a browser — no app store, no account, no router. The scan
data never leaves the cluster.

Like the rest of SniffCheck, Dog Park only listens. It does not deauth, jam, connect
to, pair with, or attack anything nearby.

This page is the short overview. For the full walkthrough see
[`DogParkUserGuide.md`](DogParkUserGuide.md); for the architecture and build see
[`DogParkClusterS3.md`](DogParkClusterS3.md) and [`cluster/README.md`](cluster/README.md).

---

## What you need

- **1 brain** board (ESP32-C5) running the Dog Park **brain** firmware — the I2C host
  and web-app server.
- **1 or more arm** boards (ESP32-C5) running the Dog Park **arm** firmware — the
  headless scanners.
- **Optional: 1 S3 node** (ESP32-S3, e.g. LilyGO T-Dongle-S3) running the Dog Park
  **S3 node** firmware — the microSD record store, sentinel, and status LCD.
- **A phone or laptop** with a browser to open the web app.

You do **not** need a router or any internet. The brain runs its own Wi-Fi access
point, and the whole web app is served from the brain itself.

---

## How it fits together

```text
[ arm C5 ] --\
              >-- I2C bus --> [ brain C5 ] --Wi-Fi AP--> [ your phone ]
[ arm C5 ] --/                 192.168.4.1                web app in browser
                                   |
                              [ S3 node ] -- microSD history + sentinel
```

- The arms scan and hand their results to the brain over the shared I2C bus.
- The brain aggregates them, runs its own access point, and serves the web app at
  `http://192.168.4.1/`.
- Your phone joins the brain's access point and opens that address. Nothing about
  your scans leaves the cluster.

---

## Everyday use

1. **Power on** the brain, the arms, and (if used) the S3 node on the shared bus.
2. On your phone, **join the brain's Wi-Fi access point**.
3. Open **`http://192.168.4.1/`**.
4. Results stream in as the arms scan. Use the controls to **rescan**, start a
   **walk**, flag devices into the **sentinel** watchlist, and review **environments**
   the brain recognizes. The full record history lives on the S3 node's microSD card.

Analysis (Wi-Fi / BLE / tracker / drone breakdowns, clusters, watchlist, exports) is
the same viewer as standalone SniffCheck, served on-device.

---

## Privacy

- **Scan data stays on the cluster.** The browser talks straight to the brain over its
  own access point; there is no router and nothing goes to the internet.
- **No hard-coded Wi-Fi credentials.** The brain hosts its own access point; you never
  hand it router details.
- **Location never leaves the device** until you explicitly tap an "open in maps" link.

---

## Troubleshooting

- **App won't load.** Confirm your phone is joined to the brain's access point, then
  open `http://192.168.4.1/`.
- **An arm doesn't link.** Check the shared I2C wiring (SDA/SCL/GND common) and that the
  arm is powered and running the arm firmware.
- **Devices all read "unknown" vendor/class.** The arm's vendor database is missing —
  the web flasher's arm image includes it, and `flash_all.sh` writes it automatically.
- **Can't flash a board.** Flashing needs desktop Chrome or Edge over USB; phones and
  Firefox/Safari lack Web Serial.
