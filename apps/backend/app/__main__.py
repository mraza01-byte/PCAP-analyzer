import argparse

import uvicorn

from app.core.config import get_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the PCAP-MAN backend.")
    parser.add_argument("--reload", action="store_true", help="Reload the server when source files change.")
    args = parser.parse_args()
    settings = get_settings()
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=args.reload)


if __name__ == "__main__":
    main()
