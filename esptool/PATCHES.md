# Local patches to the vendored WebSerial ESPTool bundle

`index.js` is a vendored build of the Adafruit/CodeHedge WebSerial ESPTool
(with ESP32-C5 support added upstream). It carries local fixes. Re-vendoring
the bundle drops them — re-apply before shipping.

## ESP32-S3 flasher stub (2026-08-09)

The bundle's ESP32-S3 stub slot held a byte-for-byte copy of the **ESP32-S2**
stub: same base64 text and data, `entry` 0x400287f0, `text_start` 0x40028000,
`data_start` 0x3ffe2bfc — all S2 address space. Uploading that to an S3 puts
code in RAM the S3 does not have, and `MEM_END` jumps into it, so the ROM
loader panics. The browser then reads the ROM's `Guru Meditation…` text as a
SLIP frame and reports:

    Invalid head of packet (0x47)      # 0x47 = 'G'

Flashing the Dog Park S3 node failed here every time; holding BOOT does not
help, because the board *was* already in download mode.

Fixed by swapping in the genuine S3 stub from esptool 4.7.0
(`esptool/targets/stub_flasher/stub_flasher_32s3.json`):

| field        | was (S2 stub) | now (S3 stub) |
| ------------ | ------------- | ------------- |
| `entry`      | 0x400287f0    | 0x40378a50    |
| `text_start` | 0x40028000    | 0x40378000    |
| `data_start` | 0x3ffe2bfc    | 0x3fcb2bf8    |
| text bytes   | 4336          | 5244          |
| data bytes   | 160           | 252           |

The C5/C6/H2/C3/C2/S2/ESP32/8266 slots were checked and are distinct and
correct; only S3 was wrong.
