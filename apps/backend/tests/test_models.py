from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.models import (
    Capture, CaptureFormat, CaptureStatus, Flow, Host,
    Investigation, InvestigationStatus, TimelineEvent,
)


def make_capture(**overrides):
    values = dict(
        original_filename="sample.pcap",
        file_path="data/captures/sample.pcap",
        file_size_bytes=1024,
        sha256="a" * 64,
        file_format=CaptureFormat.PCAP,
    )
    values.update(overrides)
    return Capture(**values)


def make_two_hosts(db, capture):
    a = Host(capture_id=capture.id, ip_address="10.0.0.1")
    b = Host(capture_id=capture.id, ip_address="10.0.0.2")
    db.add_all([a, b])
    db.flush()
    return a, b


def test_ids_are_uuids_and_times_are_utc(db_session):
    capture = make_capture()
    db_session.add(capture)
    db_session.commit()
    db_session.expire_all()

    saved = db_session.scalars(select(Capture)).one()
    assert len(saved.id) == 36 and saved.id.count("-") == 4
    assert saved.created_at.tzinfo is not None
    assert saved.created_at.utcoffset() == timedelta(0)
    assert saved.status == CaptureStatus.IMPORTED
    assert saved.packet_count is None  # nothing fabricated: stays empty until a parser fills it


def test_naive_datetime_is_rejected(db_session):
    db_session.add(make_capture(first_packet_at=datetime(2026, 1, 1)))
    with pytest.raises(Exception, match="timezone"):
        db_session.commit()


def test_other_timezones_are_stored_as_utc(db_session):
    ist = timezone(timedelta(hours=5, minutes=30))
    db_session.add(make_capture(first_packet_at=datetime(2026, 1, 1, 12, 0, tzinfo=ist)))
    db_session.commit()
    db_session.expire_all()
    saved = db_session.scalars(select(Capture)).one()
    assert saved.first_packet_at == datetime(2026, 1, 1, 6, 30, tzinfo=timezone.utc)


def test_foreign_keys_are_enforced(db_session):
    db_session.add(Host(capture_id="does-not-exist", ip_address="10.0.0.1"))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_same_ip_only_once_per_capture(db_session):
    capture = make_capture()
    db_session.add(capture)
    db_session.flush()
    db_session.add_all([
        Host(capture_id=capture.id, ip_address="10.0.0.1"),
        Host(capture_id=capture.id, ip_address="10.0.0.1"),
    ])
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_same_ip_allowed_in_different_captures(db_session):
    c1, c2 = make_capture(), make_capture(sha256="b" * 64)
    db_session.add_all([c1, c2])
    db_session.flush()
    db_session.add_all([
        Host(capture_id=c1.id, ip_address="10.0.0.1"),
        Host(capture_id=c2.id, ip_address="10.0.0.1"),
    ])
    db_session.commit()


def test_deleting_capture_removes_its_data_but_keeps_investigation(db_session):
    capture = make_capture()
    db_session.add(capture)
    db_session.flush()
    a, b = make_two_hosts(db_session, capture)
    flow = Flow(capture_id=capture.id, src_host_id=a.id, dst_host_id=b.id, protocol="TCP")
    case = Investigation(title="Suspicious beaconing")
    case.captures.append(capture)
    case.flows.append(flow)
    db_session.add_all([flow, case])
    db_session.flush()
    db_session.add(TimelineEvent(
        capture_id=capture.id, investigation_id=case.id, flow_id=flow.id,
        event_time=datetime(2026, 1, 1, tzinfo=timezone.utc), event_type="note", title="First contact",
    ))
    db_session.commit()

    db_session.delete(capture)
    db_session.commit()

    for table in ("hosts", "flows", "timeline_events", "investigation_captures", "investigation_flows"):
        assert db_session.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar() == 0, table
    assert db_session.scalars(select(Investigation)).one().title == "Suspicious beaconing"
    assert db_session.scalars(select(Investigation)).one().status == InvestigationStatus.OPEN


def test_deleting_investigation_keeps_timeline_events(db_session):
    capture = make_capture()
    case = Investigation(title="Case")
    db_session.add_all([capture, case])
    db_session.flush()
    event = TimelineEvent(
        capture_id=capture.id, investigation_id=case.id,
        event_time=datetime(2026, 1, 1, tzinfo=timezone.utc), event_type="note", title="Something",
    )
    db_session.add(event)
    db_session.commit()

    db_session.delete(case)
    db_session.commit()
    db_session.expire_all()
    assert db_session.scalars(select(TimelineEvent)).one().investigation_id is None
