#!/usr/bin/env bash
set -u
IDF_HOME="${IDF_HOME:-$HOME/esp/esp-idf}"
# This script lives in cluster/master/ for historical reasons; the projects it
# builds are siblings of that directory, so resolve against cluster/, not itself.
CLUSTER_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_DIR="$(cd "$CLUSTER_DIR/.." && pwd)"
CACHE="$HOME/.cache"; LOG_DIR="$CACHE/cluster-logs"; STAMP="$(date +%Y%m%d-%H%M%S)"
# A pack is a brain, one or more arms, and the S3 node. cluster/master/ is the
# pre-Phase-115 head and is no longer flashed to anything: the brain is the I2C
# master and WebAP host now, and it compiles the parts of master/main it still
# needs (cluster_web.c, master_shim.c) straight into its own build.
PORT_BRAIN="${PORT_BRAIN:-/dev/ttyACM0}"
PORT_ARM1="${PORT_ARM1:-/dev/ttyACM1}"
PORT_ARM2="${PORT_ARM2:-/dev/ttyACM2}"
PORT_S3="${PORT_S3:-/dev/ttyACM3}"

# Build caches match the ones tools/make-cluster-images.sh merges from, so a
# board flashed here and an image published there come from the same build.
# arm1 and arm2 are the same firmware on two ports: arms are interchangeable and
# sort out their own I2C slots at boot, so there is one arm build for the pack.
proj()  { case "$1" in brain) echo brain;; arm1|arm2) echo arm;; s3) echo head-s3;; esac; }
bdir()  { case "$1" in brain) echo "$CACHE/sc-brain-build";;
                       arm1|arm2) echo "$CACHE/sc-cluster-arm-build";;
                       s3)    echo "$CACHE/sc-s3-build";; esac; }
port()  { case "$1" in brain) echo "$PORT_BRAIN";; arm1) echo "$PORT_ARM1";; arm2) echo "$PORT_ARM2";; s3) echo "$PORT_S3";; esac; }
chip()  { case "$1" in s3) echo esp32s3;; *) echo esp32c5;; esac; }

# Which boards to touch. Drop arm2 (ARMS="brain arm1 s3") for a one-arm pack —
# the brain plans whatever answers, so a single arm just sweeps the whole
# spectrum. Add more arms by giving them ports and listing them here.
ROLES=(${ARMS:-brain arm1 arm2 s3})

MODE="${1:-all}"
if ! command -v idf.py >/dev/null 2>&1; then
    mkdir -p "$LOG_DIR"
    # shellcheck disable=SC1091
    source "$IDF_HOME/export.sh" >"$LOG_DIR/$STAMP-idf-export.log" 2>&1 \
        || { echo "FAIL: could not source $IDF_HOME/export.sh"; exit 1; }
fi
mkdir -p "$LOG_DIR"

if [ "$MODE" = "clean" ]; then
    for r in "${ROLES[@]}"; do rm -rf "$(bdir "$r")" && echo "removed $(bdir "$r")"; done; exit 0
fi
if [ "$MODE" = "monitor" ]; then
    R="${2:-brain}"; exec idf.py -B "$(bdir "$R")" -p "$(port "$R")" monitor
fi

run() {
    local label="$1" slug="$2"; shift 2
    local log="$LOG_DIR/$STAMP-$slug.log"; printf '  %-22s ' "$label"
    local t0 t1 rc; t0=$(date +%s); "$@" >"$log" 2>&1; rc=$?; t1=$(date +%s)
    if [ $rc -eq 0 ]; then echo "OK   ($((t1-t0))s)"
    else echo "FAIL ($((t1-t0))s, exit $rc)"; echo "  -- tail $log --"; tail -n 25 "$log"; exit $rc; fi
}

for r in "${ROLES[@]}"; do
    P="$CLUSTER_DIR/$(proj "$r")"
    echo "[$r]  proj $(proj "$r")  build $(bdir "$r")  port $(port "$r")"
    cd "$P" || { echo "FAIL: no project at $P"; exit 1; }
    BD="$(bdir "$r")"
    if [ ! -f "$BD/sdkconfig" ]; then
        run "set-target $(chip "$r")" "$r-settarget" idf.py -B "$BD" --preview set-target "$(chip "$r")"
    fi
    run "build" "$r-build" idf.py -B "$BD" build
    [ "$MODE" = "build" ] && continue
    run "flash ($(port "$r"))" "$r-flash" idf.py -B "$BD" -p "$(port "$r")" flash
    # Arms do the wifi/BLE scanning + vendor/device_class resolution, so they need the
    # euidb partition (0x310000) populated with data/eui.bin. idf.py flash never writes it;
    # without it eui_db_init() fails and every device resolves as unknown vendor/class.
    # parttool hangs on the C5 + IDF 5.5 combo, so esptool direct write (matches root README).
    case "$r" in arm1|arm2)
        run "euidb ($(port "$r"))" "$r-euidb" \
            python -m esptool --chip esp32c5 --port "$(port "$r")" --baud 460800 \
            write_flash --flash_size 16MB 0x310000 "$REPO_DIR/data/eui.bin"
        ;;
    esac
done
echo "$([ "$MODE" = build ] && echo built || echo flashed) ${ROLES[*]}. monitor: ./flash_all.sh monitor <role>"
