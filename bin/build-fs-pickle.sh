#!/bin/sh
# Rebuild src/cowrie/data/fs.pickle from a real Debian container so the
# emulated filesystem layout matches a current Debian release.
#
# Run from the repo root:    bin/build-fs-pickle.sh
# or:                        make build-fs-pickle
#
# Override defaults with env vars, e.g.:
#   IMAGE=debian:12.5 PACKAGES="openssh-server vim curl" bin/build-fs-pickle.sh
#
# Output is written to src/cowrie/data/fs.pickle.new. Diff it against the
# committed pickle, then `mv` it into place when you're happy.

set -eu

DOCKER="${DOCKER:-docker}"
IMAGE="${IMAGE:-debian:12}"
OUT="${OUT:-src/cowrie/data/fs.pickle.new}"

# Package set to install in the container before pickling. This shapes the
# OS surface that attackers see (binaries under /usr/bin, libs, /etc/*, etc).
# Tweak to match the persona you're emulating.
PACKAGES="${PACKAGES:-openssh-server sudo vim-tiny curl wget net-tools iproute2 procps htop ca-certificates gnupg cron rsyslog systemd less man-db bash-completion}"

if [ ! -f src/cowrie/scripts/createfs.py ]; then
    echo "error: run from the cowrie repo root" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT")"

# Mount points are named with 'cowrie' in the path so createfs's built-in
# blacklist (*cowrie*) skips them when walking /.
"$DOCKER" run --rm \
    -v "$(pwd)/src/cowrie/scripts/createfs.py:/cowrie-build/createfs.py:ro" \
    -v "$(pwd)/$(dirname "$OUT"):/cowrie-out" \
    -e PACKAGES="$PACKAGES" \
    -e OUTNAME="$(basename "$OUT")" \
    "$IMAGE" \
    sh -eu -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        # shellcheck disable=SC2086
        apt-get install -y -qq --no-install-recommends python3 $PACKAGES
        apt-get clean
        python3 /cowrie-build/createfs.py -l / -o /cowrie-out/"$OUTNAME"
        chmod 0644 /cowrie-out/"$OUTNAME"
    '

echo
echo "Wrote $OUT (image: $IMAGE)"
echo "Review, then install with:"
echo "    mv $OUT src/cowrie/data/fs.pickle"
