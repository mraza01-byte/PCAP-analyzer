from pydantic import BaseModel


class PlatformSettings(BaseModel):
    app_name: str
    app_version: str
    environment: str
    host: str
    port: int
    database_path: str
    database_size_bytes: int
    python_version: str
    os_platform: str
    cpu_count: int
    # Phase 1 has no TShark and no evidence storage, so these are reported honestly as "none".
    tshark_detected: bool
    tshark_binary_path: str
    evidence_directory: str
