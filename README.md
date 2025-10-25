# FIDO2
Semester project for Óbuda University

## Development setup

1. Copy `.env` (already committed for local dev) and tweak values if needed.  
   - `FRONTEND_UPSTREAM` defaults to `http://host.docker.internal:5173` so Caddy inside Docker can reach the host-only Flutter dev server.  
   - `ALLOWED_ORIGINS` already lists both the reverse-proxied origin (`http://localhost:8080`) and the direct dev server (`http://localhost:5173`).
2. Start the backend stack (Postgres, Redis, FastAPI backend, Caddy gateway):

   ```bash
   docker compose up --build
   ```

   Caddy listens on `http://localhost:8080` and proxies `/api` calls to the backend container.
3. Run the Flutter web frontend on the host (outside Docker) so that hot reload keeps working:

   ```bash
   cd frontend
   flutter run -d chrome --web-hostname 0.0.0.0 --web-port 5173
   ```

   The dev server stays on `http://localhost:5173`, while Caddy proxies it at `http://localhost:8080` for an end-to-end experience with the backend.

## Notes

- On Linux, `host.docker.internal` is provided to the Caddy container via `extra_hosts`. If you need to expose a different host/port for the frontend, change `FRONTEND_UPSTREAM` in `.env` (e.g. `http://host.docker.internal:4173`).  
- Any VS Code launch configuration (see `.vscode/launch.json`) expects the commands above and will start the Flutter web server with the same port arguments so that Caddy can keep proxying traffic.
