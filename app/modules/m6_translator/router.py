from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.dependencies import get_onos_client
from app.modules.m6_translator.onos_client import ONOSClient
from app.modules.m6_translator.service import install_flow, remove_flow

router = APIRouter(prefix="/flows", tags=["flows"])


class InstallFlowRequest(BaseModel):
    device_id: str
    flow: dict


class RemoveFlowRequest(BaseModel):
    device_id: str
    flow_id: str


@router.post("/install")
def install_flow_endpoint(
    payload: InstallFlowRequest,
    client: ONOSClient = Depends(get_onos_client),
) -> dict:
    return install_flow(client=client, device_id=payload.device_id, flow=payload.flow)


@router.post("/remove")
def remove_flow_endpoint(
    payload: RemoveFlowRequest,
    client: ONOSClient = Depends(get_onos_client),
) -> dict:
    return remove_flow(client=client, device_id=payload.device_id, flow_id=payload.flow_id)
