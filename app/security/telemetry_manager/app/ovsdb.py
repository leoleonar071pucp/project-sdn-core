from .models import MirrorRecord


class OVSDBOperationBuilder:
    """Builds argv arrays only. It never invokes a shell or subprocess."""

    @staticmethod
    def create(record: MirrorRecord) -> list[str]:
        name = record.mirror_id.replace("-", "_")
        return [
            "ovs-vsctl",
            "--",
            "--id=@src",
            "get",
            "Port",
            record.source_port,
            "--",
            "--id=@out",
            "get",
            "Port",
            record.output_tunnel_port,
            "--",
            "--id=@mirror",
            "create",
            "Mirror",
            f"name={name}",
            "select-src-port=@src",
            "select-dst-port=@src",
            "output-port=@out",
            "--",
            "add",
            "Bridge",
            record.bridge,
            "mirrors",
            "@mirror",
        ]

    @staticmethod
    def delete(record: MirrorRecord) -> list[str]:
        name = record.mirror_id.replace("-", "_")
        return [
            "ovs-vsctl",
            "--",
            "--id=@mirror",
            "get",
            "Mirror",
            name,
            "--",
            "remove",
            "Bridge",
            record.bridge,
            "mirrors",
            "@mirror",
            "--",
            "destroy",
            "Mirror",
            name,
        ]
