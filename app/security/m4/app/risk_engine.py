from .models import (
    CorrelatedEvidence,
    EventSource,
    RiskDecision,
    SecurityAction,
)


BASE_SCORES = {
    "policy_denial": 2,
    "policy_denial_burst": 30,
    "port_scan": 45,
    "invalid_ip_mac_binding": 80,
    "traffic_spike": 30,
    "possible_ddos": 60,
    "possible_exfiltration": 50,
    "suricata_low": 15,
    "suricata_medium": 35,
    "suricata_high": 70,
    "suricata_critical": 100,
    "web_attack": 60,
    "suricata_anomaly": 40,
    "suricata_http": 15,
    "suricata_tls": 10,
    "suricata_flow": 5,
    "fan_out": 45,
}


class RiskEngine:
    def evaluate(self, evidence: CorrelatedEvidence) -> RiskDecision:
        score = 0
        reasons: list[str] = []
        types = [event.event_type for event in evidence.events]

        for event in evidence.events:
            event_score = max(BASE_SCORES.get(event.event_type, 0), event.severity)
            denials = int(event.metadata.get("denials", 0))
            unique_ports = int(event.metadata.get("unique_ports", 0))
            unique_destinations = int(event.metadata.get("unique_destinations", 0))

            if event.event_type == "policy_denial" and denials >= 50:
                event_score = max(event_score, 40)
            if unique_ports >= 20:
                event_score = max(event_score, 35)
            if unique_destinations >= 10:
                event_score = max(event_score, 25)

            score += event_score
            if event_score:
                reasons.append(f"{event.event_type} (+{event_score})")

        if len(evidence.sources) >= 2:
            score += 20
            reasons.append("coincidencia entre fuentes (+20)")

        score = min(score, 100)
        action = self._select_action(score, set(types))
        threat_type = self._threat_type(types)
        confidence = "high" if score >= 80 else "medium" if score >= 30 else "low"

        return RiskDecision(
            score=score,
            confidence=confidence,
            threat_type=threat_type,
            recommended_action=action,
            reasons=reasons,
        )

    @staticmethod
    def _select_action(score: int, event_types: set[str]) -> SecurityAction:
        if "suricata_critical" in event_types:
            return SecurityAction.BLOCK
        if "invalid_ip_mac_binding" in event_types:
            return SecurityAction.TEMP_BLOCK
        if score >= 80:
            return SecurityAction.BLOCK
        if score >= 50:
            return SecurityAction.TEMP_BLOCK
        if score >= 30:
            return SecurityAction.MIRROR
        if score >= 15:
            return SecurityAction.WATCH
        return SecurityAction.LOG

    @staticmethod
    def _threat_type(event_types: list[str]) -> str:
        priority = (
            "invalid_ip_mac_binding",
            "suricata_critical",
            "web_attack",
            "possible_ddos",
            "possible_exfiltration",
            "port_scan",
            "policy_denial_burst",
            "policy_denial",
        )
        return next((item for item in priority if item in event_types), "unknown")
