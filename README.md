# project-sdn-core

# sdn-core

Base scaffold for the SDN core service using FastAPI and a modular monolith layout.

This repository implements the core service in `FastAPI`, even if earlier design material may mention `Flask`.

## Backend Convention

All backend functionality in `sdn-core` should be implemented with `FastAPI`.

Project rules:

- The main application instance lives in `app/main.py`.
- Each functional module exposes endpoints through `APIRouter`.
- Routers are registered in the main app with `include_router(...)`.
- The standard execution entrypoint is `uvicorn app.main:app`.

## Architecture Notes

- `M1` integrates with `FreeRADIUS` and a captive portal flow for authentication and role resolution.
- The real credential source is `PostgreSQL`.
- Visitors also pass through the captive portal and are classified there as `visitante`.
- `M2` preloads proactive `T2` rules at system startup.
- `M6` is the only module allowed to talk to `ONOS`; it usually installs/removes rules and may occasionally query ONOS state for reconciliation.
- `M5` is implemented only with `PostgreSQL`.

## Structure

- `app/`: FastAPI application, modules, shared code, templates.
- `docker/`: Container build and local compose files.
- `dhcp/`: External DHCP configuration samples.
- `scripts/`: Startup scripts.
- `docs/`: Markdown documentation for agents and internal guides.

## Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```
