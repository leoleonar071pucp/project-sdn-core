import json
from pathlib import Path

from app.config import Settings
from app.forwarder import EveForwarder


FIXTURES = Path(__file__).parents[2] / "suricata" / "fixtures"


def settings(tmp_path):
    return Settings(
        eve_path=tmp_path / "eve.json",
        state_path=tmp_path / "offset.json",
        queue_path=tmp_path / "queue.jsonl",
        dry_run_output=tmp_path / "out.jsonl",
        dry_run=True,
    )


def test_processes_valid_fixture_and_filters_tls_as_supported(tmp_path):
    sent = []
    forwarder = EveForwarder(settings(tmp_path), sender=sent.append)
    result = forwarder.process_file(FIXTURES / "eve-valid.json", resume=False)

    assert result["forwarded"] == 2
    assert {item["event_type"] for item in sent} == {"alert", "tls"}


def test_deduplicates_fixture(tmp_path):
    sent = []
    result = EveForwarder(settings(tmp_path), sender=sent.append).process_file(
        FIXTURES / "eve-duplicate.json", resume=False
    )
    assert result["forwarded"] == 1
    assert result["duplicates_or_filtered"] == 1


def test_persists_offset_and_only_reads_new_lines(tmp_path):
    cfg = settings(tmp_path)
    cfg.eve_path.write_text(
        (FIXTURES / "eve-critical.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    sent = []
    forwarder = EveForwarder(cfg, sender=sent.append)
    first = forwarder.process_file()
    second = forwarder.process_file()

    assert first["forwarded"] == 1
    assert second["processed"] == 0


def test_failed_send_is_queued(tmp_path):
    cfg = settings(tmp_path)

    def fail(_):
        raise RuntimeError("offline")

    forwarder = EveForwarder(cfg, sender=fail)
    result = forwarder.process_file(FIXTURES / "eve-critical.json", resume=False)

    assert result["forwarded"] == 0
    queued = [json.loads(line) for line in cfg.queue_path.read_text().splitlines()]
    assert len(queued) == 1


def test_retry_queue_delivers_pending_event(tmp_path):
    cfg = settings(tmp_path)
    cfg.queue_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.queue_path.write_text(
        json.dumps({"event_id": "queued", "event_type": "alert"}) + "\n",
        encoding="utf-8",
    )
    sent = []
    count = EveForwarder(cfg, sender=sent.append).retry_queue()
    assert count == 1
    assert sent[0]["event_id"] == "queued"
    assert cfg.queue_path.read_text(encoding="utf-8") == ""


def test_invalid_lines_do_not_stop_processing(tmp_path):
    result = EveForwarder(settings(tmp_path), sender=lambda event: None).process_file(
        FIXTURES / "eve-invalid.json", resume=False
    )
    assert result["invalid"] == 1
    assert result["duplicates_or_filtered"] == 1


def test_default_dry_run_never_calls_http(tmp_path, monkeypatch):
    cfg = settings(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("HTTP is forbidden in dry-run")

    monkeypatch.setattr("app.forwarder.httpx.post", forbidden)
    result = EveForwarder(cfg).process_file(
        FIXTURES / "eve-critical.json", resume=False
    )
    assert result["forwarded"] == 1
    assert cfg.dry_run_output.exists()


def test_marks_critical_destination_as_permanent_mirror(tmp_path):
    cfg = settings(tmp_path)
    cfg.critical_assets_path = FIXTURES.parents[0] / "critical-assets.yaml"
    sent = []
    EveForwarder(cfg, sender=sent.append).process_file(
        FIXTURES / "eve-critical.json", resume=False
    )
    assert sent[0]["mirror_scope"] == "permanent"
    assert sent[0]["asset_id"] == "grades"
