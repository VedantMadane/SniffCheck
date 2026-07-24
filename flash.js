// SniffCheck web flasher glue.
//
// Drives the vendored Adafruit/CodeHedge WebSerial ESPTool engine
// (esptool/index.js), which flashes the ESP32 board without the
// esptool-js stub path that times out in esp-web-tools 10.2.1
// (see esphome/esp-web-tools#687).
//
// Each firmware is one merged image (bootloader + partition table + app + data)
// flashed at offset 0x0. The picker cascades brand -> device -> firmware family
// -> firmware; the leaf firmware is chip-checked before the flash begins.

import { connect } from "./esptool/index.js";

// Every flashable image, tagged for the cascade. brand/device/family drive the
// three filter steps; role disambiguates the several cluster images on one chip.
const FIRMWARES = [
  {
    id: "standalone-c5", brand: "lilygo", device: "c5", family: "standalone",
    role: "SniffCheck",
    label: "SniffCheck — T-Dongle C5 (ESP32-C5)",
    url: "firmware/sniffcheck-merged.bin",
    chip: /c5/i, chipName: "ESP32-C5", imageChipId: 23,
    bootloaderOffset: 0x2000, appOffset: 0x10000, offset: 0x0,
  },
  {
    id: "cluster-brain", brand: "lilygo", device: "c5", family: "cluster",
    role: "Brain",
    label: "Dog Park cluster — brain (ESP32-C5)",
    url: "firmware/sniffcheck-cluster-brain-merged.bin",
    chip: /c5/i, chipName: "ESP32-C5", imageChipId: 23,
    bootloaderOffset: 0x2000, appOffset: 0x10000, offset: 0x0,
  },
  {
    id: "cluster-arm", brand: "lilygo", device: "c5", family: "cluster",
    role: "Arm",
    label: "Dog Park cluster — arm (ESP32-C5)",
    url: "firmware/sniffcheck-cluster-arm-merged.bin",
    chip: /c5/i, chipName: "ESP32-C5", imageChipId: 23,
    bootloaderOffset: 0x2000, appOffset: 0x10000, offset: 0x0,
  },
  {
    id: "cluster-s3node", brand: "lilygo", device: "s3", family: "cluster",
    role: "S3 node",
    label: "Dog Park cluster — S3 node (ESP32-S3)",
    url: "firmware/sniffcheck-cluster-s3node-merged.bin",
    chip: /s3/i, chipName: "ESP32-S3", imageChipId: 9,
    bootloaderOffset: 0x0, appOffset: 0x10000, offset: 0x0,
  },
];

// Brands shown in step 1. `soon` brands have no firmware yet but keep their slot.
const BRANDS = [
  { id: "lilygo", label: "LilyGo" },
  { id: "xiao", label: "Xiao (Seeed)", soon: true },
];
const DEVICE_LABELS = { c5: "ESP32-C5", s3: "ESP32-S3" };
const FAMILY_LABELS = { standalone: "Standalone", cluster: "Dog Park cluster" };

const installBtn = document.getElementById("install");
const brandSel = document.getElementById("brand");
const deviceSel = document.getElementById("device");
const familySel = document.getElementById("family");
const targetSel = document.getElementById("target");
const noteEl = document.getElementById("picknote");
const logEl = document.getElementById("log");
const barEl = document.getElementById("bar");
const barFill = document.getElementById("barfill");
const SELS = [brandSel, deviceSel, familySel, targetSel];

function log(line) {
  logEl.style.display = "block";
  logEl.textContent += line + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}

function setProgress(done, total) {
  barEl.style.display = "block";
  const pct = total ? Math.min((done / total) * 100, 100) : 0;
  barFill.style.width = pct.toFixed(1) + "%";
}

function formatMac(mac) {
  return mac.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(":");
}

// --- cascade -------------------------------------------------------------
// Each step fills the next select from FIRMWARES filtered by the choices so
// far, then either advances or, at a dead end, notes why and disables Install.

const serialOK = "serial" in navigator;

function fill(sel, items, valueOf, labelOf) {
  sel.innerHTML = "";
  for (const it of items) {
    const o = document.createElement("option");
    o.value = valueOf(it);
    o.textContent = labelOf(it);
    sel.appendChild(o);
  }
  sel.disabled = items.length === 0;
}

function uniq(arr) { return [...new Set(arr)]; }

function setNote(msg) { noteEl.textContent = msg || ""; }

function firmwareReady(ok) {
  installBtn.disabled = !(ok && serialOK);
}

function onBrand() {
  const brand = brandSel.value;
  const meta = BRANDS.find((b) => b.id === brand);
  const devices = uniq(FIRMWARES.filter((f) => f.brand === brand).map((f) => f.device));
  if ((meta && meta.soon) || devices.length === 0) {
    fill(deviceSel, [], (d) => d, (d) => d);
    fill(familySel, [], (f) => f, (f) => f);
    fill(targetSel, [], (t) => t, (t) => t);
    setNote(`No ${meta ? meta.label : brand} firmware yet — coming soon.`);
    firmwareReady(false);
    return;
  }
  fill(deviceSel, devices, (d) => d, (d) => DEVICE_LABELS[d] || d);
  onDevice();
}

function onDevice() {
  const brand = brandSel.value, device = deviceSel.value;
  const families = uniq(
    FIRMWARES.filter((f) => f.brand === brand && f.device === device).map((f) => f.family)
  );
  fill(familySel, families, (f) => f, (f) => FAMILY_LABELS[f] || f);
  onFamily();
}

function onFamily() {
  const brand = brandSel.value, device = deviceSel.value, family = familySel.value;
  const matches = FIRMWARES.filter(
    (f) => f.brand === brand && f.device === device && f.family === family
  );
  fill(targetSel, matches, (f) => f.id, (f) => f.role || f.label);
  if (matches.length === 0) {
    setNote("No firmware for this combination yet.");
    firmwareReady(false);
  } else {
    setNote("");
    firmwareReady(true);
  }
}

function currentTarget() {
  return FIRMWARES.find((f) => f.id === (targetSel && targetSel.value)) || null;
}

fill(brandSel, BRANDS, (b) => b.id, (b) => (b.soon ? `${b.label} (coming soon)` : b.label));
brandSel.addEventListener("change", onBrand);
deviceSel.addEventListener("change", onDevice);
familySel.addEventListener("change", onFamily);
targetSel.addEventListener("change", () => firmwareReady(!!currentTarget()));
onBrand();

function validateImageHeader(firmware, offset, expectedChipId, description) {
  const headerLength = 24;
  if (firmware.length < offset + headerLength) {
    throw new Error(`Downloaded firmware is truncated before the ${description} header.`);
  }

  if (firmware[offset] !== 0xE9) {
    throw new Error(
      `Downloaded firmware does not contain a valid ESP image at 0x${offset.toString(16)}.`
    );
  }

  const segmentCount = firmware[offset + 1];
  if (segmentCount < 1 || segmentCount > 16) {
    throw new Error(`Downloaded firmware has an invalid ${description} segment count.`);
  }

  const imageChipId = firmware[offset + 12] | (firmware[offset + 13] << 8);
  if (imageChipId !== expectedChipId) {
    throw new Error(
      `Downloaded firmware is for chip ID ${imageChipId}, expected ${expectedChipId}.`
    );
  }
}

function validateFirmware(buf, target) {
  const firmware = new Uint8Array(buf);

  validateImageHeader(
    firmware,
    target.bootloaderOffset,
    target.imageChipId,
    "bootloader"
  );

  const partitionOffset = 0x8000;
  if (
    firmware.length < partitionOffset + 2 ||
    firmware[partitionOffset] !== 0xAA ||
    firmware[partitionOffset + 1] !== 0x50
  ) {
    throw new Error("Downloaded firmware does not contain a valid partition table at 0x8000.");
  }

  validateImageHeader(
    firmware,
    target.appOffset,
    target.imageChipId,
    "application"
  );
}

// Web Serial gate.
if (!serialOK) {
  installBtn.disabled = true;
  const u = document.getElementById("unsupported");
  if (u) u.style.display = "block";
}

let busy = false;

installBtn.addEventListener("click", async () => {
  if (busy) return;
  const target = currentTarget();
  if (!target) return;
  busy = true;
  installBtn.disabled = true;
  SELS.forEach((s) => { if (s) s.disabled = true; });
  logEl.textContent = "";
  barFill.style.width = "0";

  let esploader;
  let stub;
  try {
    esploader = await connect({ log, debug: () => {}, error: log });
    await esploader.initialize();
    log(`Selected firmware: ${target.label}`);
    log(`Connected to ${esploader.chipName}`);
    log(`MAC: ${formatMac(esploader.macAddr())}`);

    if (esploader.chipName && !target.chip.test(esploader.chipName)) {
      log(`WARNING: this firmware needs an ${target.chipName}, got ${esploader.chipName}. Aborting.`);
      throw new Error(`Wrong chip — "${target.label}" is for the ${target.chipName}.`);
    }

    log("Downloading firmware…");
    const response = await fetch(target.url);
    if (!response.ok) {
      throw new Error(`firmware fetch failed: ${response.status}`);
    }

    const buf = await response.arrayBuffer();
    validateFirmware(buf, target);
    log("Firmware image structure validated.");

    stub = await esploader.runStub();

    log("Erasing flash…");
    await stub.eraseFlash();

    log(`Writing ${(buf.byteLength / 1048576).toFixed(2)} MB at 0x0…`);

    await stub.flashData(buf, (written) => setProgress(written, buf.byteLength), target.offset);
    setProgress(1, 1);

    log("Done. Unplug and replug the board to start it.");
  } catch (err) {
    log(`ERROR: ${err.message || err}`);
    log("Try: unplug, hold BOOT, replug while holding, release, then Install again.");
  } finally {
    // Release the port so a retry can reopen it cleanly.
    try {
      if (stub) {
        await stub.disconnect();
        await stub.port.close();
      } else if (esploader) {
        await esploader.disconnect();
      }
    } catch (_) { /* ignore close races */ }
    SELS.forEach((s) => { if (s) s.disabled = false; });
    firmwareReady(!!currentTarget());
    busy = false;
  }
});
