from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.dependencies import get_onos_client
from app.modules.m6_translator.onos_client import ONOSClient
from app.modules.m6_translator.service import install_macro_flow, block_mac, install_temporal_flow, remove_flow

router = APIRouter(prefix="/flows", tags=["flows"])


class MacroFlowRequest(BaseModel):
    device_id: str
    cidr_src: str
    ip_dst: str
    port: int
    protocol: int = 6


class BlockMacRequest(BaseModel):
    device_id: str
    mac_address: str


class TemporalFlowRequest(BaseModel):
    device_id: str
    ip_src: str
    ip_dst: str
    port: int
    timeout_sec: int
    protocol: int = 6


@router.post("/macro")
def install_macro_flow_endpoint(
    payload: MacroFlowRequest,
    client: ONOSClient = Depends(get_onos_client),
) -> dict:
    return install_macro_flow(client, payload.device_id, payload.cidr_src, payload.ip_dst, payload.port, payload.protocol)


@router.post("/block")
def block_mac_endpoint(
    payload: BlockMacRequest,
    client: ONOSClient = Depends(get_onos_client),
) -> dict:
    return block_mac(client, payload.device_id, payload.mac_address)


@router.post("/temporal")
def install_temporal_flow_endpoint(
    payload: TemporalFlowRequest,
    client: ONOSClient = Depends(get_onos_client),
) -> dict:
    return install_temporal_flow(client, payload.device_id, payload.ip_src, payload.ip_dst, payload.port, payload.timeout_sec, payload.protocol)


@router.delete("/{device_id}/{flow_id}")
def remove_flow_endpoint(
    device_id: str,
    flow_id: str,
    client: ONOSClient = Depends(get_onos_client),
) -> dict:
    return remove_flow(client, device_id, flow_id)
