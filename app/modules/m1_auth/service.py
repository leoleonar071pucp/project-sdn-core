from app.modules.m1_auth.models import LoginRequest, LoginResponse, LogoutResponse


def login(payload: LoginRequest) -> LoginResponse:
    token = f"token-for-{payload.username}"
    return LoginResponse(access_token=token)


def logout() -> LogoutResponse:
    return LogoutResponse(message="Session closed")
