from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.inventory import Inventory
from app.models import MirrorRequest, MirrorStatus
from app.repository import MemoryMirrorRepository
from app.service import MirrorService


INVENTORY = Path(__file__).parents[1] / "inventory" / "critical-assets.yaml"


def service():
    return MirrorService(MemoryMirrorRepository(), Inventory(INVENTORY), False)


def request(**updates):
    data = {
        "incident_id": "inc-1",
        "switch_dpid": "of:1",
        "bridge": "br-test",
        "source_port": "host-port",
        "output_tunnel_port": "gre-security",
        "ttl_seconds": 60,
    }
    data.update(updates)
    return MirrorRequest(**data)


def test_creates_idempotent_simulated_mirror():
    manager = service()
    first = manager.create(request())
    second = manager.create(request())
    assert first.mirror_id == second.mirror_id
    assert first.status == MirrorStatus.SIMULATED
    assert first.create_operation[0] == "ovs-vsctl"
    assert "clear" not in first.create_operation


def test_placeholder_inventory_is_rejected():
    manager = service()
    try:
        manager.create(
            MirrorRequest(
                incident_id="inc-placeholder",
                switch_dpid="of:1",
                asset_id="portal",
            )
        )
    except ValueError as exc:
        assert "unresolved" in str(exc)
    else:
        raise AssertionError("placeholder inventory must be rejected")


def test_reconcile_expires_temporary_mirror():
    manager = service()
    mirror = manager.create(request())
    changed = manager.reconcile(
        mirror.expires_at + timedelta(seconds=1)
    )
    assert changed[0].status == MirrorStatus.EXPIRED


def test_permanent_mirror_does_not_expire():
    manager = service()
    mirror = manager.create(request(incident_id="permanent", permanent=True))
    assert manager.reconcile(datetime.now(timezone.utc) + timedelta(days=1)) == []
