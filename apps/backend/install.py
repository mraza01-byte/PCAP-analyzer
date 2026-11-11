import subprocess
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent


def main() -> None:
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(BACKEND_DIR / "requirements-dev.txt")],
        cwd=BACKEND_DIR,
        check=True,
    )


if __name__ == "__main__":
    main()
