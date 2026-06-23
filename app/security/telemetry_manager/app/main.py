from fastapi import Depends, FastAPI, Header, HTTPException

from .config import Settings
from .inventory import Inventory
from .models import MirrorRequest
from .repository import MemoryMirrorRepository, MySQLMirrorRepository
from .service import MirrorService


settings = Settings()
repository = (
    MySQLMirrorRepository(settings)
    if settings.mysql_persistence_enabled
    else MemoryMirrorRepository()
)
inventory = Inventory(settings.inventory_path)
service = MirrorService(repository, inventory, settings.ovsdb_actions_enabled)
app = FastAPI(title="Telemetry Manager", version="0.1.0")


def authorize(x_security_token: str | None = Header(default=None)):
    if x_security_token != settings.security_token:
        raise HTTPException(status_code=401, detail="invalid security token")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "ovsdb_actions_enabled": settings.ovsdb_actions_enabled,
        "unresolved_inventory": inventory.unresolved_assets(),
    }


@app.post("/mirrors", dependencies=[Depends(authorize)])
def create_mirror(request: MirrorRequest):
    try:
        return service.create(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/mirrors", dependencies=[Depends(authorize)])
def list_mirrors():
    return repository.list()


@app.get("/mirrors/{incident_id}", dependencies=[Depends(authorize)])
def get_mirror(incident_id: str):
    record = repository.get(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="mirror not found")
    return record


@app.delete("/mirrors/{incident_id}", dependencies=[Depends(authorize)])
def delete_mirror(incident_id: str):
    record = service.remove(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="mirror not found")
    return record


@app.post("/mirrors/reconcile", dependencies=[Depends(authorize)])
def reconcile():
    return {"changed": service.reconcile()}
