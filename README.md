# kochab-agent

Thin agent daemon per Kochab — heartbeat, audit, task runner.

Daemon leggero outbound-only che gira su ogni server gestito. Raccoglie dati, esegue task firmati dalla piattaforma, reporta stato.

## Requisiti

- Go 1.26+
- Linux (target deployment), macOS (sviluppo)

## Build

```bash
make build        # Build per piattaforma locale
make cross        # Cross-compile linux/amd64
make test         # Esegui test
make lint         # Lint con golangci-lint
```

## Licenza

Apache License 2.0 — vedi [LICENSE](LICENSE).
