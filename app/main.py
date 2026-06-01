from fastapi import FastAPI

from app.modules.m1_auth.router import router as auth_router
from app.modules.m2_policies.router import router as policies_router
from app.modules.m6_translator.router import router as translator_router


def create_app() -> FastAPI:
    app = FastAPI(title="SDN Core API", version="0.1.0")

    app.include_router(auth_router)
    app.include_router(policies_router)
    app.include_router(translator_router)

    @app.get("/health", tags=["health"])
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
