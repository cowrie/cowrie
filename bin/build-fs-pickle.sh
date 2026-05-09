#!/bin/sh

# SPDX-FileCopyrightText: 2026 Stefan Grosser
#
# SPDX-License-Identifier: BSD-3-Clause

# Rebuild a cowrie fs.pickle from a real container so the emulated
# filesystem layout matches a target OS.
#
# Run from the repo root:
#     bin/build-fs-pickle.sh                # default: Debian 12, writes
#                                           # src/cowrie/data/fs.pickle.new
#     make build-fs-pickle                  # same as above
#
# Customize via env vars. Common cases:
#
#   # Debian/Ubuntu (default family):
#   FAMILY=apt PACKAGES="openssh-server vim curl" bin/build-fs-pickle.sh
#
#   # OpenWrt:
#   FAMILY=opkg \
#       IMAGE=openwrt/rootfs:x86-64-23.05.5 \
#       OUT=/path/to/personas/openwrt/fs.pickle.new \
#       bin/build-fs-pickle.sh
#
#   # BusyBox-like rootfs (the image must already contain python3, since
#   # FAMILY=none performs no install step. python:3-alpine is a busybox
#   # userland with python3 layered on, close enough for cowrie):
#   FAMILY=none \
#       IMAGE=python:3-alpine \
#       OUT=/path/to/personas/busybox/fs.pickle.new \
#       bin/build-fs-pickle.sh
#
# FAMILY values:
#   apt   - Debian/Ubuntu base. Installs python3 + $PACKAGES via apt-get.
#   opkg  - OpenWrt rootfs. Installs python3-light + $PACKAGES via opkg.
#   none  - No install step. IMAGE must already contain python3.
#
# Output is written to $OUT (default src/cowrie/data/fs.pickle.new). Diff
# it against the existing pickle, then mv it into place when happy.

set -eu

DOCKER="${DOCKER:-docker}"
FAMILY="${FAMILY:-apt}"
OUT="${OUT:-src/cowrie/data/fs.pickle.new}"

case "$FAMILY" in
    apt)
        : "${IMAGE:=debian:12}"
        : "${PACKAGES:=openssh-server sudo vim-tiny curl wget net-tools iproute2 procps htop ca-certificates gnupg cron rsyslog systemd less man-db bash-completion}"
        ;;
    opkg)
        : "${IMAGE:?FAMILY=opkg requires IMAGE (e.g. openwrt/rootfs:x86-64-23.05.5)}"
        : "${PACKAGES:=dropbear curl wget}"
        ;;
    none)
        : "${IMAGE:?FAMILY=none requires IMAGE (the image must already contain python3)}"
        : "${PACKAGES:=}"
        ;;
    *)
        echo "error: unknown FAMILY=$FAMILY (want apt|opkg|none)" >&2
        exit 1
        ;;
esac

if [ ! -f src/cowrie/scripts/createfs.py ]; then
    echo "error: run from the cowrie repo root" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT")"
OUTDIR="$(cd "$(dirname "$OUT")" && pwd)"

# Mount points are named with 'cowrie' in the path so createfs's built-in
# blacklist (*cowrie*) skips them when walking /.
"$DOCKER" run --rm \
    -v "$(pwd)/src/cowrie/scripts/createfs.py:/cowrie-build/createfs.py:ro" \
    -v "$OUTDIR:/cowrie-out" \
    -e OUTNAME="$(basename "$OUT")" \
    -e FAMILY="$FAMILY" \
    -e PACKAGES="$PACKAGES" \
    "$IMAGE" \
    sh -eu -c '
        case "$FAMILY" in
            apt)
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq
                # shellcheck disable=SC2086
                apt-get install -y -qq --no-install-recommends python3 $PACKAGES
                apt-get clean
                ;;
            opkg)
                opkg update
                # shellcheck disable=SC2086
                opkg install python3-light $PACKAGES
                ;;
            none)
                ;;
        esac
        python3 /cowrie-build/createfs.py -l / -o /cowrie-out/"$OUTNAME"
        chmod 0644 /cowrie-out/"$OUTNAME"
    '

echo
echo "Wrote $OUT (image: $IMAGE, family: $FAMILY)"
echo "Review, then install with:"
echo "    mv $OUT src/cowrie/data/fs.pickle"
