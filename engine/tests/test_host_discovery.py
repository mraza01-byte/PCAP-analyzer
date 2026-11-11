import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from services.host_discovery import discover_hosts

pcap_file = Path(__file__).resolve().parent.parent / "evidence" / "eg.pcapng"

print(discover_hosts(str(pcap_file)))