# Container flavors

Bake-time OS-fingerprint variants. Each flavor directory contains an optional
`cowrie.cfg` (overrides on top of `etc/cowrie.cfg.dist`) and an optional
`honeyfs/` tree (overlaid on top of the repo's base `honeyfs/`).

The Dockerfile takes a `FLAVOR` build-arg. When set, it copies the flavor's
`cowrie.cfg` to `etc/cowrie.cfg` and overlays the flavor's `honeyfs/` files
onto the base honeyfs/ inside the image.

```
docker buildx build --build-arg FLAVOR=debian-12-bookworm \
    -t cowrie:debian-12-bookworm -f docker/Dockerfile .
```

Or via Make:

```
make docker-build-debian-12
make docker-build-openwrt
make docker-build-legacy
```

Available flavors:

- `legacy-debian-7` — current default; Debian 7 wheezy, kernel 3.2 (2014).
  Empty by design; the base honeyfs/ already represents this.
- `debian-12-bookworm` — Debian 12 bookworm, kernel 6.1 LTS. Believable for
  an unpatched 2026 server.
- `openwrt` — OpenWrt 23.05.5 on MediaTek MT7621 (mipsel_24kc). IoT/SOHO
  router surface; targets Mirai-class scanners.

Adding a new flavor: create `docker/flavors/<name>/`, drop in a partial
`cowrie.cfg` with the keys you want to override, plus any `honeyfs/`
files that should land on top of the base. The Dockerfile picks them up
when built with `--build-arg FLAVOR=<name>`.
