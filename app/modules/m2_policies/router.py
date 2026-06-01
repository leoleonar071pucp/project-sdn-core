from fastapi import APIRouter

from app.modules.m2_policies.models import (
    PolicyCheckRequest,
    PolicyCheckResponse,
    PolicyRule,
)
from app.modules.m2_policies.service import check_policy, list_rules

router = APIRouter(prefix="/policies", tags=["policies"])


@router.post("/check", response_model=PolicyCheckResponse)
def check_policy_endpoint(payload: PolicyCheckRequest) -> PolicyCheckResponse:
    return check_policy(payload)


@router.get("/rules", response_model=list[PolicyRule])
def list_rules_endpoint() -> list[PolicyRule]:
    return list_rules()
