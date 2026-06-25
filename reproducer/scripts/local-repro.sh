#!/usr/bin/env bash
#
# Standalone local reproducer for the nydus FUSE page-cache cgroup accounting
# issue.  Does NOT require kubernetes or kind — it runs nydusd directly and uses
# cgroup v2 to show exactly which cgroup is charged for the page cache of files
# read through a nydus FUSE mount.
#
# Verified on: Linux 6.8 aarch64, cgroup v2, nydus v2.3.0.  Each stage below was
# validated and produced: BUG pod1=65MiB / pod2=0MiB; FIX warm=65MiB / ctr=0MiB
# with big.dat=0 resident and blob cache=66M; ANTI-PATTERN whole=165MiB, cache=166M.
#
# Prerequisites: nydusd, nydus-image, go, fincore (util-linux), python3, root.
# Run this in a real terminal (it uses job control to background nydusd).
# Usage: sudo ./local-repro.sh   (or run as a user with passwordless sudo)

set -euo pipefail

WORK=/tmp/nydus-repro
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OWNER_SH="${SCRIPTS_DIR}/page-cgroup-owner.sh"
CG=/sys/fs/cgroup/nydus_repro

# Save the terminal mode so we can restore it on exit. Backgrounding nydusd (via
# sudo + FUSE) can leave the controlling TTY in raw mode, which makes subsequent
# output staircase (LF without CR). Restoring on exit keeps the terminal sane.
STTY_SAVE="$(stty -g 2>/dev/null || true)"

PAYLOAD_MB="${PAYLOAD_MB:-60}"    # embedded payload size → fat binary
UNUSED_MB="${UNUSED_MB:-100}"     # large file the container never reads

hr() { printf '%.0s=' {1..72}; echo; }
mib() { echo "$(( ${1:-0} / 1048576 )) MiB"; }

cleanup() {
    sudo umount "${WORK}/mnt" 2>/dev/null || true
    sudo pkill -f "nydusd.*nydus-repro" 2>/dev/null || true
    sudo rmdir "${CG}"/* 2>/dev/null || true
    sudo rmdir "${CG}" 2>/dev/null || true
    [ -n "${STTY_SAVE}" ] && stty "${STTY_SAVE}" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Build a fat Go binary + a large unused file, then a nydus RAFS v6 image
# ---------------------------------------------------------------------------
hr; echo "1. Building fat binary (${PAYLOAD_MB}MiB embed) + ${UNUSED_MB}MiB unused file"; hr
rm -rf "${WORK}"; mkdir -p "${WORK}"/{src,rootfs/unused,blobs,cache,mnt}
dd if=/dev/urandom of="${WORK}/src/payload.bin" bs=1M count="${PAYLOAD_MB}" status=none
cp "${SCRIPTS_DIR}/../app/main.go" "${WORK}/src/main.go"
( cd "${WORK}/src" && go mod init nydus-reproducer >/dev/null 2>&1 && \
  CGO_ENABLED=0 go build -ldflags="-s" -o "${WORK}/rootfs/app" . )
dd if=/dev/urandom of="${WORK}/rootfs/unused/big.dat" bs=1M count="${UNUSED_MB}" status=none
echo "binary: $(stat -c %s "${WORK}/rootfs/app") bytes"

# Prefetch hint lists only /app — the startup working set.
echo "/app" | nydus-image create --type dir-rafs --fs-version 6 \
    --bootstrap "${WORK}/bootstrap" --blob-dir "${WORK}/blobs" \
    --prefetch-policy fs "${WORK}/rootfs" >/dev/null 2>&1
echo "nydus image built."

# ---------------------------------------------------------------------------
# 2. Launch nydusd (fusedev), prefetch DISABLED so reads are purely on-demand
# ---------------------------------------------------------------------------
hr; echo "2. Mounting nydus image via FUSE (fs_prefetch disabled)"; hr
cat > "${WORK}/nydusd.json" <<EOF
{
  "device": {
    "backend": { "type": "localfs", "config": { "dir": "${WORK}/blobs" } },
    "cache":   { "type": "blobcache", "config": { "work_dir": "${WORK}/cache" } }
  },
  "mode": "direct", "digest_validate": false, "enable_xattr": true,
  "fs_prefetch": { "enable": false }
}
EOF
sudo nydusd --config "${WORK}/nydusd.json" --mountpoint "${WORK}/mnt" \
    --bootstrap "${WORK}/bootstrap" --log-level error \
    --apisock "${WORK}/api.sock" >"${WORK}/nydusd.log" 2>&1 </dev/null &
sleep 3
# nydusd (via sudo) leaves the controlling TTY in raw mode; restore it now so
# the rest of the script's output prints with proper CR/LF instead of staircasing.
[ -n "${STTY_SAVE}" ] && stty "${STTY_SAVE}" 2>/dev/null || true
mount | grep -q "${WORK}/mnt" || { echo "FAIL: mount not up"; cat "${WORK}/nydusd.log"; exit 1; }
echo "mounted: $(ls "${WORK}/mnt")"

# ---------------------------------------------------------------------------
# 3. cgroup setup
# ---------------------------------------------------------------------------
sudo mkdir -p "${CG}"
echo "+memory" | sudo tee "${CG}/cgroup.subtree_control" >/dev/null 2>&1 || true
read_in_cgroup() {   # $1 = cgroup name, $2 = path to read
    sudo mkdir -p "${CG}/$1"
    sudo sh -c "echo \$\$ > ${CG}/$1/cgroup.procs; exec cat '$2' > /dev/null"
}
mem() { cat "${CG}/$1/memory.current"; }

drop() { sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null; sleep 1; }

# ---------------------------------------------------------------------------
# 4. THE BUG: first container reader pays; second is free
# ---------------------------------------------------------------------------
hr; echo "4. THE BUG — first reader through FUSE pays the page-cache cost"; hr
drop
read_in_cgroup pod1 "${WORK}/mnt/app"
read_in_cgroup pod2 "${WORK}/mnt/app"
echo "  pod1 (reads 1st): $(mib "$(mem pod1)")     <-- charged the full binary"
echo "  pod2 (reads 2nd): $(mib "$(mem pod2)")     <-- pays nothing (cache already warm)"
echo "  page owner:"; sudo bash "${OWNER_SH}" "${WORK}/mnt/app" 2>&1 | sed -n '/Charged to/,/->/p' | sed 's/^/    /'

hr; echo "DONE."; hr
