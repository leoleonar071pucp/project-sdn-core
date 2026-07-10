import argparse
import json
from pathlib import Path

from .config import Settings
from .forwarder import EveForwarder


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path)
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--retry-queue", action="store_true")
    args = parser.parse_args()
    forwarder = EveForwarder(Settings())
    result = (
        {"retried": forwarder.retry_queue()}
        if args.retry_queue
        else forwarder.process_file(args.file, resume=not args.no_resume)
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
