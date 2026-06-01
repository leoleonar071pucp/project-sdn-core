from app.modules.m2_policies.models import (
    PolicyCheckRequest,
    PolicyCheckResponse,
    PolicyRule,
)


def check_policy(payload: PolicyCheckRequest) -> PolicyCheckResponse:
    allowed = payload.action.lower() != "deny"
    reason = "Allowed by default policy" if allowed else "Denied by policy rule"
    return PolicyCheckResponse(allowed=allowed, reason=reason)


def list_rules() -> list[PolicyRule]:
    return [
        PolicyRule(name="default-allow", effect="allow", resource="network:*"),
        PolicyRule(name="block-deny-action", effect="deny", resource="network:restricted"),
    ]
