from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EventDefinition:
    """
    Standard observability event definition.
    """

    name: str
    domain: str
    severity: str
    message: str

class Severity(str):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"

class Events:
    # ==================================================================
    # Identity (M1)
    # ==================================================================

    AUTH_LOGIN_STARTED = EventDefinition(
        name="auth.login.started",
        domain="identity",
        severity="INFO",
        message="User authentication started.",
    )

    AUTH_SUCCESS = EventDefinition(
        name="auth.success",
        domain="identity",
        severity="INFO",
        message="User authenticated successfully.",
    )

    AUTH_LOGIN_FAILED = EventDefinition(
        name="auth.login.failed",
        domain="identity",
        severity="WARN",
        message="User authentication failed.",
    )

    AUTH_ACCOUNT_LOCKED = EventDefinition(
        name="auth.account.locked",
        domain="identity",
        severity="WARN",
        message="User account locked after multiple failed authentication attempts.",
    )

    AUTH_LOGOUT = EventDefinition(
        name="auth.logout",
        domain="identity",
        severity="INFO",
        message="User logged out.",
    )

    AUTH_SESSION_STARTED = EventDefinition(
        name="auth.session.started",
        domain="identity",
        severity="INFO",
        message="User session started.",
    )

    AUTH_SESSION_ENDED = EventDefinition(
        name="auth.session.ended",
        domain="identity",
        severity="INFO",
        message="User session ended.",
    )

    AUTH_REGISTER_FAILED = EventDefinition(
        name="auth.register.failed",
        domain="identity",
        severity="WARN",
        message="Guest user registration failed.",
    )

    AUTH_RADIUS_TIMEOUT = EventDefinition(
        name="auth.radius.timeout",
        domain="identity",
        severity="ERROR",
        message="RADIUS server did not respond within the configured timeout.",
    )

    AUTH_RADIUS_ERROR = EventDefinition(
        name="auth.radius.error",
        domain="identity",
        severity="ERROR",
        message="RADIUS authentication failed due to a server error.",
    )

    AUTH_DATABASE_ERROR = EventDefinition(
        name="auth.database.error",
        domain="identity",
        severity="ERROR",
        message="Authentication database operation failed.",
    )

    # ==================================================================
    # Policy Engine (M2)
    # ==================================================================

    POLICY_QUERY = EventDefinition(
        name="policy.query",
        domain="policy",
        severity="INFO",
        message="Policy evaluation requested.",
    )

    POLICY_ALLOWED = EventDefinition(
        name="policy.allowed",
        domain="policy",
        severity="INFO",
        message="Access authorized by policy.",
    )

    POLICY_DENIED = EventDefinition(
        name="policy.denied",
        domain="policy",
        severity="WARN",
        message="Access denied by policy.",
    )

    POLICY_UPDATED = EventDefinition(
        name="policy.updated",
        domain="policy",
        severity="INFO",
        message="Policy updated successfully.",
    )

    POLICY_SYNC_STARTED = EventDefinition(
        name="policy.sync.started",
        domain="policy",
        severity="INFO",
        message="Policy synchronization started.",
    )

    POLICY_SYNC_COMPLETED = EventDefinition(
        name="policy.sync.completed",
        domain="policy",
        severity="INFO",
        message="Policy synchronization completed successfully.",
    )

    POLICY_SYNC_FAILED = EventDefinition(
        name="policy.sync.failed",
        domain="policy",
        severity="ERROR",
        message="Policy synchronization failed.",
    )

    # ==================================================================
    # SDN / OpenFlow (M6)
    # ==================================================================

    FLOW_INSTALL_REQUESTED = EventDefinition(
        name="flow.install.requested",
        domain="network",
        severity="INFO",
        message="Flow installation requested.",
    )

    FLOW_INSTALLED = EventDefinition(
        name="flow.installed",
        domain="network",
        severity="INFO",
        message="Flow installed successfully.",
    )

    FLOW_INSTALL_FAILED = EventDefinition(
        name="flow.install.failed",
        domain="network",
        severity="ERROR",
        message="Flow installation failed.",
    )

    FLOW_REMOVED = EventDefinition(
        name="flow.removed",
        domain="network",
        severity="INFO",
        message="Flow removed successfully.",
    )

    # ==================================================================
    # Security (M3 / M4)
    # ==================================================================

    IDS_ALERT = EventDefinition(
        name="ids.alert",
        domain="security",
        severity="WARN",
        message="Intrusion detection alert generated.",
    )

    IDS_FLOW_DETECTED = EventDefinition(
        name="ids.flow.detected",
        domain="security",
        severity="INFO",
        message="Network flow detected by the IDS.",
    )

    IDS_HOST_SCAN = EventDefinition(
        name="ids.host.scan",
        domain="security",
        severity="WARN",
        message="Host scanning activity detected.",
    )

    IDS_DOS = EventDefinition(
        name="ids.dos",
        domain="security",
        severity="ERROR",
        message="Denial-of-Service attack detected.",
    )

    IDS_MALWARE = EventDefinition(
        name="ids.malware",
        domain="security",
        severity="ERROR",
        message="Malware-related activity detected.",
    )

    MITIGATION_STARTED = EventDefinition(
        name="mitigation.started",
        domain="security",
        severity="INFO",
        message="Threat mitigation started.",
    )

    MITIGATION_COMPLETED = EventDefinition(
        name="mitigation.completed",
        domain="security",
        severity="INFO",
        message="Threat mitigation completed successfully.",
    )

    MITIGATION_FAILED = EventDefinition(
        name="mitigation.failed",
        domain="security",
        severity="ERROR",
        message="Threat mitigation failed.",
    )

    # ==================================================================
    # Monitoring (M5)
    # ==================================================================

    MONITORING_STARTED = EventDefinition(
        name="monitoring.started",
        domain="monitoring",
        severity="INFO",
        message="Monitoring service started.",
    )

    MONITORING_STOPPED = EventDefinition(
        name="monitoring.stopped",
        domain="monitoring",
        severity="INFO",
        message="Monitoring service stopped.",
    )

    MONITORING_FAILED = EventDefinition(
        name="monitoring.failed",
        domain="monitoring",
        severity="ERROR",
        message="Monitoring service failed.",
    )

    SWITCH_CONNECTED = EventDefinition(
        name="switch.connected",
        domain="network",
        severity="INFO",
        message="Switch connected to the SDN controller.",
    )

    SWITCH_DISCONNECTED = EventDefinition(
        name="switch.disconnected",
        domain="network",
        severity="WARN",
        message="Switch disconnected from the SDN controller.",
    )

    SWITCH_DOWN = EventDefinition(
        name="switch.down",
        domain="network",
        severity="WARN",
        message="Switch is down or unavailable.",
    )

    LINK_UP = EventDefinition(
        name="link.up",
        domain="network",
        severity="INFO",
        message="Link is up.",
    )

    LINK_DOWN = EventDefinition(
        name="link.down",
        domain="network",
        severity="WARN",
        message="Link is down.",
    )

    PORT_ERROR_THRESHOLD_EXCEEDED = EventDefinition(
        name="port.error.threshold.exceeded",
        domain="network",
        severity="WARN",
        message="Port error threshold exceeded.",
    )

    PORT_DROP_THRESHOLD_EXCEEDED = EventDefinition(
        name="port.drop.threshold.exceeded",
        domain="network",
        severity="WARN",
        message="Port drop threshold exceeded.",
    )

    FLOW_THRESHOLD_EXCEEDED = EventDefinition(
        name="flow.threshold.exceeded",
        domain="network",
        severity="WARN",
        message="Flow threshold exceeded.",
    )

    FLOW_INSTALLATION_SPIKE = EventDefinition(
        name="flow.installation.spike",
        domain="network",
        severity="WARN",
        message="Sudden spike in flow installations detected.",
    )