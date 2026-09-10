#!/usr/bin/env bash
# Reproduce the validated Dali build:
# Neutron clang 24 + old KMI CRC wrapper + ThinLTO + Google AutoFDO,
# global O3 with a narrow O2 whitelist for boot-critical crypto/verity paths.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

TOOLCHAIN="${TOOLCHAIN:-/root/neutron-clang-06092026-kmi-old}"
PROFILE="${CLANG_AUTOFDO_PROFILE:-/root/flash-dali-r510928/google-autofdo-android15-6.6-20260909/kernel.afdo}"
CONFIG="${DALI_BUILD_CONFIG:-/root/flash-dali-r510928/neutron-thinlto-google-afdo-20260910.config}"
OUT_DIR="${OUT_DIR:-${SOURCE_DIR}/out/dali-neutron-global-o3-whitelist-o2}"
DEVICE_MODULES_DIR="${DEVICE_MODULES_DIR:-${SOURCE_DIR}/kernel_device_modules-6.6}"
JOBS="${JOBS:-8}"
DRY_RUN="${DALI_DRY_RUN:-0}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ -x "${TOOLCHAIN}/bin/clang" ]] || die "clang not found under ${TOOLCHAIN}/bin; set TOOLCHAIN"
[[ -f "$PROFILE" ]] || die "AutoFDO profile not found: $PROFILE; set CLANG_AUTOFDO_PROFILE"
[[ -f "$CONFIG" ]] || die "complete kernel config not found: $CONFIG; set DALI_BUILD_CONFIG"
[[ -d "$DEVICE_MODULES_DIR" ]] || die "device-module tree not found: $DEVICE_MODULES_DIR; set DEVICE_MODULES_DIR"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "JOBS must be a positive integer"
[[ "$DRY_RUN" == 0 || "$DRY_RUN" == 1 ]] || die "DALI_DRY_RUN must be 0 or 1"

export CLANG_AUTOFDO_PROFILE="$PROFILE"

make_arg=(
  --make-arg 'KCFLAGS=-O3 -mtune=cortex-x925'
  --make-arg 'DALI_SCHED_OMIT_FRAME_POINTER=y'
  --make-arg 'PAHOLE_FLAGS=--skip_encoding_btf_vars'
)

# Keep the objects that participate in boot-critical dm-verity and crypto
# paths at O2. The final compiler option wins over the global KCFLAGS=-O3.
o2_whitelist=(
  'CFLAGS_dm.o=-O2'
  'CFLAGS_dm-table.o=-O2'
  'CFLAGS_dm-linear.o=-O2'
  'CFLAGS_dm-stripe.o=-O2'
  'CFLAGS_dm-io.o=-O2'
  'CFLAGS_dm-kcopyd.o=-O2'
  'CFLAGS_dm-rq.o=-O2'
  'CFLAGS_dm-bufio.o=-O2'
  'CFLAGS_dm-verity-target.o=-O2'
  'CFLAGS_dm-verity-fec.o=-O2'
  'CFLAGS_ahash.o=-O2'
  'CFLAGS_shash.o=-O2'
  'CFLAGS_hash_info.o=-O2'
  'CFLAGS_sha256_generic.o=-O2'
  'CFLAGS_sha256.o=-O2'
  'CFLAGS_sha256-glue.o=-O2'
  'CFLAGS_sha2-ce-glue.o=-O2'
  'CFLAGS_coresight-etm4x-core.o=-O2'
)

for arg in "${o2_whitelist[@]}"; do
  make_arg+=(--make-arg "$arg")
done

extra_arg=()
if [[ "$DRY_RUN" == 1 ]]; then
  extra_arg+=(--dry-run)
fi

exec "$SOURCE_DIR/tools/build_kernel.sh" \
  --source "$SOURCE_DIR" \
  --toolchain "$TOOLCHAIN" \
  --out "$OUT_DIR" \
  --config "$CONFIG" \
  --with-modules \
  --device-modules-dir "$DEVICE_MODULES_DIR" \
  --jobs "$JOBS" \
  "${extra_arg[@]}" \
  "${make_arg[@]}"
