from datetime import datetime, timezone

from .inventory import Inventory
from .models import MirrorRecord, MirrorRequest, MirrorStatus
from .ovsdb import OVSDBOperationBuilder


class MirrorService:
    def __init__(self, repository, inventory: Inventory, ovsdb_enabled: bool = False):
        self.repository = repository
        self.inventory = inventory
        self.ovsdb_enabled = ovsdb_enabled

    def create(self, request: MirrorRequest) -> MirrorRecord:
        existing = self.repository.get(request.incident_id)
        if existing and existing.status not in {
            MirrorStatus.REMOVED,
            MirrorStatus.EXPIRED,
            MirrorStatus.FAILED,
        }:
            return existing
        resolved = self.inventory.resolve(
            request.asset_id,
            {
                "bridge": request.bridge,
                "source_port": request.source_port,
                "output_tunnel_port": request.output_tunnel_port,
            },
        )
        record = MirrorRecord.from_request(request, **resolved)
        record.create_operation = OVSDBOperationBuilder.create(record)
        record.delete_operation = OVSDBOperationBuilder.delete(record)
        # Execution is deliberately unavailable in the offline phase.
        record.status = (
            MirrorStatus.FAILED if self.ovsdb_enabled else MirrorStatus.SIMULATED
        )
        self.repository.save(record)
        return record

    def remove(self, incident_id: str) -> MirrorRecord | None:
        record = self.repository.get(incident_id)
        if not record:
            return None
        record.status = (
            MirrorStatus.FAILED if self.ovsdb_enabled else MirrorStatus.REMOVED
        )
        record.updated_at = datetime.now(timezone.utc)
        self.repository.save(record)
        return record

    def reconcile(self, now: datetime | None = None) -> list[MirrorRecord]:
        now = now or datetime.now(timezone.utc)
        changed = []
        for record in self.repository.list():
            if (
                not record.permanent
                and record.expires_at
                and record.expires_at <= now
                and record.status in {MirrorStatus.SIMULATED, MirrorStatus.ACTIVE}
            ):
                record.status = MirrorStatus.EXPIRED
                record.updated_at = now
                self.repository.save(record)
                changed.append(record)
        return changed
