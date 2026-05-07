# kochab-agent

Thin agent daemon per Kochab — heartbeat, audit, task runner.

Daemon leggero outbound-only che gira su ogni server gestito. Raccoglie dati, esegue task firmati dalla piattaforma, reporta stato.

## Requisiti

- Go 1.26+
- Linux (target deployment), macOS (sviluppo)

## Build

```bash
make build                       # Build per piattaforma locale
make cross-compile               # Cross-compile linux amd64 + arm64 + sha256
make deb VERSION=0.2.0           # Build .deb amd64 (richiede dpkg-deb)
make release VERSION=0.2.0       # Full release (cross-compile + deb)
make test                        # Esegui test
make lint                        # Lint con golangci-lint
```

## Install via curl (one-liner)

Sysadmin con token enrollment generato via `app.kochab.ai`:

```bash
curl -fsSL https://get.kochab.ai/enroll/$TOKEN | sudo bash
```

Lo script:

1. Scarica binary linux dal GitHub Release più recente (`https://github.com/vcnngr/kochab-agent/releases/latest/download/kochab-agent`).
2. Verifica SHA256 sibling — hard-fail se mancante o mismatch (no skip-on-error).
3. Installa in `/usr/local/bin/kochab-agent`, systemd unit in `/etc/systemd/system/kochab-agent.service`.
4. Esegue enrollment con il token (POST `/v1/agents/enroll`).
5. `systemctl enable --now kochab-agent`.

Per ispezione manuale prima di eseguire:

```bash
curl -fsSL https://get.kochab.ai/enroll/$TOKEN | tee install.sh
less install.sh
sudo bash install.sh
```

## Install via .deb

Download dalla [GitHub Release](https://github.com/vcnngr/kochab-agent/releases/latest):

```bash
TAG=v0.2.0
wget https://github.com/vcnngr/kochab-agent/releases/download/$TAG/kochab-agent_${TAG#v}_amd64.deb
wget https://github.com/vcnngr/kochab-agent/releases/download/$TAG/kochab-agent_${TAG#v}_amd64.deb.sha256
sha256sum -c kochab-agent_${TAG#v}_amd64.deb.sha256
sudo dpkg -i kochab-agent_${TAG#v}_amd64.deb
# Enrollment via env var (NO token su CLI — process args leggibili da altri user)
sudo KOCHAB_ENROLL_TOKEN="<TOKEN>" /usr/local/bin/kochab-agent --enroll --platform-url https://api.kochab.ai
sudo systemctl enable --now kochab-agent
```

## Release process

Tag-driven (push `v<MAJOR>.<MINOR>.<PATCH>`):

1. `git tag v0.2.0 && git push origin v0.2.0` (solo maintainer admin — protected tag rule).
2. `.github/workflows/release.yml` cross-compile + .deb + Docker buildx multi-arch.
3. GitHub Release pubblica creata con 6 artefatti: `kochab-agent`, `kochab-agent.sha256`, `kochab-agent-arm64`, `kochab-agent-arm64.sha256`, `kochab-agent_<v>_amd64.deb`, `.deb.sha256`.
4. Docker Hub `vcnngr/kochab-agent:<tag>` + `:latest` aggiornati (multi-arch).

Pipeline FALLISCE se uno qualsiasi degli step fallisce (no parziale).

## Licenza

Apache License 2.0 — vedi [LICENSE](LICENSE).
