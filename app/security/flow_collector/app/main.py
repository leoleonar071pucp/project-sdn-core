import argparse
import json
from pathlib import Path

from .collector import FlowCollector
from .config import Settings
from .detector import FlowDetector


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("protocol", choices=["sflow", "netflow"])
    parser.add_argument("--file", type=Path)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    settings = Settings()
    collector = FlowCollector(
        FlowDetector(),
        dry_run=settings.dry_run,
        output_path=settings.output_path,
        m4_url=settings.m4_url,
        token=settings.security_token,
        max_datagram_size=settings.max_datagram_size,
    )
    if args.file:
        print(json.dumps(collector.process_datagram(args.protocol, args.file.read_bytes(), "fixture")))
    else:
        collector.serve_udp(
            args.protocol,
            args.host,
            args.port
            or (
                settings.sflow_port
                if args.protocol == "sflow"
                else settings.netflow_port
            ),
        )


if __name__ == "__main__":
    main()
