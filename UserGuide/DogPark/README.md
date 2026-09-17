# DogPark user guide

DogPark is the SniffCheck firmware family for on-device packet inspection demos.

## Firmware family

- Board firmware lives under the DogPark-related directories in this repository.
- Use the DogPark board profile so pin maps and radio settings match the kit.

## Build

1. Install the ESP-IDF or PlatformIO toolchain described in the root README.
2. Select the DogPark board target.
3. Build with the project make or PlatformIO target for that board.
4. Confirm the build produces a flashable image without pin-map errors.

## Install

1. Put the board in flash mode if your kit requires the boot button.
2. Flash the image with the same tool path used for other SniffCheck firmwares.
3. Power-cycle the board after a successful flash.

## Use

1. Open a serial console at the baud rate listed for DogPark in the board notes.
2. Confirm the status LED pattern matches a healthy boot.
3. Start a sniff session with the serial command set.
4. Apply protocol filters when your build includes filter commands.
5. Stop capture before unplugging power.

## Troubleshoot

| Symptom | What to try |
|---------|-------------|
| No serial output | Check cable baud rate and board selection |
| Build fails on pins | Use the DogPark board profile not a generic ESP target |
| No packets seen | Confirm antenna power and that sniff mode is started |
| Flash rejected | Hold boot as required by the board and retry |

## More help

Shared toolchain install steps and issue templates are in the repository root README.
