import httpx

from ..config import Settings


class M2Client:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def check_access(self, payload: dict) -> dict:
        if not self.settings.network_actions_enabled:
            return {"allow": False, "reason": "simulated", "simulated": True}
        async with httpx.AsyncClient(
            timeout=self.settings.http_timeout_seconds
        ) as client:
            response = await client.post(
                f"{self.settings.m2_base_url}/v1/data/policy/allow_resource",
                json={"input": payload},
            )
            response.raise_for_status()
            return response.json().get("result", {})
