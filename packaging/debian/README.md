# Debian package — kochab-agent

Build minimal `.deb` for distribution to Debian/Ubuntu hosts.

## Layout

```
debian/
  DEBIAN/
    control           # Package metadata
    postinst          # daemon-reload + enable (does NOT start — needs enrollment)
    prerm             # stop + disable
    postrm            # purge → rm -rf /etc/kochab
  etc/systemd/system/
    kochab-agent.service  # Copied from packaging/kochab-agent.service
  usr/local/bin/
    kochab-agent      # Built binary (drop here before dpkg-deb)
```

## Build

```bash
# 1. Build static binary (or cross-compile for amd64)
GOOS=linux GOARCH=amd64 go build -o packaging/debian/usr/local/bin/kochab-agent ./cmd/kochab-agent

# 2. Set version in DEBIAN/control if needed (default 0.1.0)

# 3. Ensure maintainer scripts are executable (dpkg-deb refuses 644 perms)
chmod 755 packaging/debian/DEBIAN/postinst packaging/debian/DEBIAN/prerm packaging/debian/DEBIAN/postrm

# 4. Build the package
dpkg-deb --build packaging/debian kochab-agent_0.1.0_amd64.deb
```

## Install / Uninstall on host

```bash
sudo dpkg -i kochab-agent_0.1.0_amd64.deb     # install
sudo KOCHAB_ENROLL_TOKEN=... kochab-agent --enroll
sudo systemctl start kochab-agent

sudo apt purge kochab-agent                   # full removal incl. /etc/kochab
# OR
sudo kochab-agent --uninstall                 # in-binary equivalent
```
