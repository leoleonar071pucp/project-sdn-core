from pydantic import BaseModel


class PolicyCheckRequest(BaseModel):
    subject: str
    action: str
    resource: str


class PolicyCheckResponse(BaseModel):
    allowed: bool
    reason: str


class PolicyRule(BaseModel):
    name: str
    effect: str
    resource: str
