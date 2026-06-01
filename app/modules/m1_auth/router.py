from fastapi import APIRouter

from app.modules.m1_auth.models import LoginRequest, LoginResponse, LogoutResponse
from app.modules.m1_auth.service import login, logout

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login_endpoint(payload: LoginRequest) -> LoginResponse:
    return login(payload)


@router.post("/logout", response_model=LogoutResponse)
def logout_endpoint() -> LogoutResponse:
    return logout()
