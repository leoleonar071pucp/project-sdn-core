# project-sdn-core

# sdn-core

Base scaffold for the SDN core service using FastAPI and a modular monolith layout.

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
