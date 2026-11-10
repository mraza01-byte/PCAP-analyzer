from app.models import Capture, CaptureStatus, Flow, Host, TimelineEvent


def persist_analysis(db, capture: Capture, analysis: dict) -> None:
    hosts_by_ip = {}
    for data in analysis["hosts"]:
        host = Host(
            capture_id=capture.id,
            ip_address=data["ip_address"],
            mac_address=data["mac_address"],
            first_seen_at=data["first_seen_at"],
            last_seen_at=data["last_seen_at"],
            packet_count=data["packet_count"],
            bytes_sent=data["bytes_sent"],
            bytes_received=data["bytes_received"],
            open_ports=data["open_ports"],
        )
        db.add(host)
        hosts_by_ip[data["ip_address"]] = host
    db.flush()

    flows_by_key = {}
    for data in analysis["flows"]:
        flow = Flow(
            capture_id=capture.id,
            src_host_id=hosts_by_ip[data["src_ip"]].id,
            dst_host_id=hosts_by_ip[data["dst_ip"]].id,
            src_port=data["src_port"],
            dst_port=data["dst_port"],
            protocol=data["protocol"],
            start_time=data["start_time"],
            end_time=data["end_time"],
            packet_count=data["packet_count"],
            byte_count=data["bytes_total"],
            bytes_forward=data["bytes_forward"],
            bytes_reverse=data["bytes_reverse"],
            application=data["application"],
            tcp_flags=data["tcp_flags"],
        )
        db.add(flow)
        flows_by_key[data["flow_key"]] = flow
    db.flush()

    for data in analysis["timeline_events"]:
        db.add(TimelineEvent(
            capture_id=capture.id,
            flow_id=flows_by_key[data["flow_key"]].id,
            event_time=data["event_time"],
            event_type=data["event_type"],
            title=data["title"],
            description=data["description"],
        ))

    capture.packet_count = analysis["packet_count"]
    capture.first_packet_at = analysis["first_packet_at"]
    capture.last_packet_at = analysis["last_packet_at"]
    capture.error_message = None
    capture.status = CaptureStatus.COMPLETED
    db.commit()