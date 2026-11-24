# VPS stack

---

## systemd

| Service                                 | Listening Port(s)                    | Purpose                                                    |
| :-------------------------------------- | :----------------------------------- | :--------------------------------------------------------- |
| `eepy-page-backend.service`             | `127.0.0.1:8000` (`uvicorn`)         | eepy.page backend                                          |
| `caddy.service`                         | `*:80`, `*:443` (TCP + UDP)          | Publicly exposing services (backend, admin panel, weblate) |
| `pdns.service`                          | `*:53` (TCP + UDP), `127.0.0.1:8081` | PowerDNS authoritative nameserver                          |
| `fail2ban.service`                      | -                                    | Stops suspicious login attempts and reports to AbuseIPDB   |
| `ssh.service`                           | `*:22` (TCP)                         | OpenSSH server                                             |
| `docker.service` + `containerd.service` | -                                    | Docker runtime                                             |
| `php8.4-fpm.service`                    | -                                    | PHP runtime for admin panel (running via Caddy)            |

---

## Docker Compose

| Name                          | Containers                                                                                | Host Port(s)                                                 | Volumes                                                                                                                    |
| :---------------------------- | :---------------------------------------------------------------------------------------- | :----------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------- |
| Redis (backend rate limiting) | `redis` (`redis:8.10-alpine`)                                                             | `127.0.0.1:6379`                                             | `redis_redis-data`                                                                                                         |
| Weblate                       | `weblate` (`weblate:latest`), `database` (`postgres:18-alpine`), `cache` (`valkey:9.1.3`) | `127.0.0.1:8010 -> 8080`                                     | `weblate-docker_postgres-data`, `weblate-docker_redis-data`, `weblate-docker_weblate-cache`, `weblate-docker_weblate-data` |
| PowerDNS-Admin                | `powerdns_admin` (`pda-legacy:latest`), `powerdns_admin_db` (`mariadb:11`)                | `127.0.0.1:9191` (`gunicorn`), `127.0.0.1:3307` (`mariadbd`) | `powerdns-admin_pda_db`                                                                                                    |

---

## Caddy

| Domain                 | Target info                |
| :--------------------- | :------------------------- |
| `CADDY_DOMAIN`         | Reverse proxy for backend  |
| `CADDY_PANEL_DOMAIN`   | PHP server for admin panel |
| `CADDY_WEBLATE_DOMAIN` | Reverse proxy for Weblate  |

---

## Networking

**Public:** `22/tcp` (SSH), `53/tcp+udp` (PowerDNS), `80/tcp` + `443/tcp` (Caddy)
**Localhost-only:**

- `3307/tcp`: `powerdns_admin_db` (MariaDB)
- `6379/tcp`: `redis`
- `8000/tcp`: `eepy-page-backend` (`uvicorn`)
- `8010/tcp`: `weblate`
- `8081/tcp`: `pdns_server` HTTP API
- `9191/tcp`: `powerdns_admin` (`gunicorn`)
