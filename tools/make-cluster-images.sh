#!/usr/bin/env bash
# Build every merged image the web flasher offers, from the build caches, and
# check each one against the exact rules docs/webflasher/flash.js enforces
# before it will flash: magic 0xE9 and the right chip id at the bootloader and
# app offsets, and a 0xAA50 partition table at 0x8000.
#
#   tools/make-cluster-images.sh            # all four
#   tools/make-cluster-images.sh brain      # one
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/webflasher/firmware"
EUI="$ROOT/data/eui.bin"
EUI_OFFSET=0x310000

command -v esptool.py >/dev/null \
  || { echo "error: esptool.py not on PATH — run '. \$HOME/esp/esp-idf/export.sh'" >&2; exit 1; }
[ -f "$EUI" ] || { echo "error: no $EUI" >&2; exit 1; }
mkdir -p "$OUT"

# name | build cache | out basename | app bin | with eui | chip id
TARGETS=(
  "standalone|sniffcheck-build|sniffcheck-merged|sniffcheck_c5.bin|yes|23"
  "brain|sc-brain-build|sniffcheck-cluster-brain-merged|sniffcheck_cluster_brain.bin|no|23"
  "arm|sc-cluster-arm-build|sniffcheck-cluster-arm-merged|sniffcheck_cluster_arm.bin|yes|23"
  "s3node|sc-s3-build|sniffcheck-cluster-s3node-merged|sniffcheck_cluster_head.bin|no|9"
)

merge_one() {
  local name="$1" cache="$2" base="$3" app="$4" with_eui="$5" chipid="$6"
  local build="$HOME/.cache/$cache"
  local args="$build/flasher_args.json"
  [ -f "$args" ] || { echo "error: no $args — build $name first" >&2; return 1; }

  read -r CHIP MODE SIZE FREQ < <(python3 - "$args" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
wf = d.get("write_flash_args", [])
def opt(n, dflt): return wf[wf.index(n) + 1] if n in wf else dflt
print(d.get("extra_esptool_args", {}).get("chip", "esp32c5"),
      opt("--flash_mode", "dio"), opt("--flash_size", "16MB"), opt("--flash_freq", "80m"))
PY
)

  mapfile -t PARTS < <(python3 - "$args" "$build" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1])); build = sys.argv[2]
for off, f in sorted(d["flash_files"].items(), key=lambda kv: int(kv[0], 16)):
    print(off); print(os.path.join(build, f))
PY
)

  local merged="$OUT/$base.bin"
  local extra=()
  [ "$with_eui" = yes ] && extra=("$EUI_OFFSET" "$EUI")

  echo "== $name: chip=$CHIP mode=$MODE size=$SIZE freq=$FREQ$([ "$with_eui" = yes ] && echo ' +eui')"
  esptool.py --chip "$CHIP" merge_bin --flash_mode "$MODE" --flash_size "$SIZE" \
    --flash_freq "$FREQ" -o "$merged" "${PARTS[@]}" "${extra[@]}" >/dev/null

  cp "$build/$app" "$OUT/${base%-merged}-app.bin"

  python3 - "$merged" "$chipid" "$CHIP" <<'PY'
import sys
p, want, chip = sys.argv[1], int(sys.argv[2]), sys.argv[3]
b = open(p, "rb").read()
bl = 0x0 if chip == "esp32s3" else 0x2000
def hdr(off, what):
    if len(b) < off + 24:            raise SystemExit(f"FAIL {p}: truncated before {what}")
    if b[off] != 0xE9:               raise SystemExit(f"FAIL {p}: {what} magic 0x{b[off]:02x} != 0xE9")
    n = b[off + 1]
    if not 1 <= n <= 16:             raise SystemExit(f"FAIL {p}: {what} segment count {n}")
    cid = b[off + 12] | (b[off + 13] << 8)
    if cid != want:                  raise SystemExit(f"FAIL {p}: {what} chip id {cid} != {want}")
    print(f"   ok {what} @0x{off:x}  segs={n} chip_id={cid}")
hdr(bl, "bootloader")
if b[0x8000] != 0xAA or b[0x8001] != 0x50:
    raise SystemExit(f"FAIL {p}: no 0xAA50 partition table at 0x8000")
print("   ok partition table @0x8000")
hdr(0x10000, "app")
print(f"   ok size {len(b)/1048576:.2f} MB")
PY
}

if [ $# -gt 0 ]; then
  for want in "$@"; do
    for t in "${TARGETS[@]}"; do
      IFS='|' read -r n c b a e i <<<"$t"
      [ "$n" = "$want" ] && merge_one "$n" "$c" "$b" "$a" "$e" "$i"
    done
  done
else
  for t in "${TARGETS[@]}"; do
    IFS='|' read -r n c b a e i <<<"$t"
    merge_one "$n" "$c" "$b" "$a" "$e" "$i"
  done
fi

echo
echo "images in $OUT"
