# Optional daily discovery schedule

Purpose: run `proxywatch discover` once a day on a Linux server with systemd. Nothing here is installed automatically.

```bash
sudo mkdir -p /opt/proxywatch && sudo cp -r . /opt/proxywatch && cd /opt/proxywatch
sudo scripts/init-secrets.sh            # then add optional keys: docs/API-KEYS.md
sudo mkdir -p data output/blocklist && sudo chown -R 10001:10001 data output secrets
docker compose build
docker compose run --rm proxywatch doctor
docker compose run --rm proxywatch discover

sudo install -m 644 deploy/proxywatch.service deploy/proxywatch.timer /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/proxywatch.service /etc/systemd/system/proxywatch.timer
sudo systemctl daemon-reload
sudo systemctl enable --now proxywatch.timer
```

The unit assumes `/usr/bin/docker` and `/opt/proxywatch`; adjust `ExecStart` if yours differ. Docker socket access is administrative access.

- The timer runs once a day between 03:00 and 04:00 UTC, with a randomized delay. `Persistent=true` catches up on a missed run.
- A running service is never started twice. Avoid manual `discover` runs while it is active.
- Regenerate lists after a run with `docker compose run --rm proxywatch blocklist --out-dir /output/blocklist`. You can also add an `ExecStartPost=` override for this.

Inspect or disable the schedule:

```bash
systemctl status proxywatch.timer proxywatch.service
journalctl -u proxywatch.service --since today
sudo systemctl disable --now proxywatch.timer
```

A partial run, such as one with a missing key or a quota hit, still exits successfully. Check `docker compose run --rm proxywatch sources` for per-source errors. Treat `data/` and the journal as private.
