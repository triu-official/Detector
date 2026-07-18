"""
Detector - One-Click Launcher
Handles venv setup, dependency installation, browser opening, and server startup.
Works both as a .py script and as a PyInstaller .exe bundle.
"""
from __future__ import annotations

import os
import sys
import subprocess
import threading
import time
import webbrowser

APP_NAME = "Detector - Phishing URL Analyzer"
APP_URL = "http://127.0.0.1:5000"
PORT = 5000


def get_project_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_python(project_dir: str) -> str:
    venv_python = os.path.join(project_dir, "venv", "Scripts", "python.exe")
    if os.path.isfile(venv_python):
        return venv_python
    return sys.executable


def ensure_venv(project_dir: str) -> str:
    venv_dir = os.path.join(project_dir, "venv")
    venv_python = os.path.join(venv_dir, "Scripts", "python.exe")

    if not os.path.isfile(venv_python):
        print(f"[{APP_NAME}]")
        print(f"  First-time setup: creating Python environment...")
        subprocess.run(
            [sys.executable, "-m", "venv", venv_dir],
            cwd=project_dir,
            check=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        print(f"  Python environment created.")

    return venv_python


def install_deps(python_path: str, project_dir: str) -> None:
    req_file = os.path.join(project_dir, "requirements.txt")
    if not os.path.isfile(req_file):
        return

    print(f"  Checking dependencies...")
    result = subprocess.run(
        [python_path, "-m", "pip", "install", "-r", req_file, "-q"],
        cwd=project_dir,
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        print(f"  Warning: Some dependencies may not have installed correctly.")
        if result.stderr:
            print(f"  {result.stderr[:200]}")
    else:
        print(f"  Dependencies OK.")


def ensure_dirs(project_dir: str) -> None:
    for d in ("results", "instance"):
        path = os.path.join(project_dir, d)
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)


def open_browser_delayed() -> None:
    time.sleep(3)
    webbrowser.open(APP_URL)


def run_server(python_path: str, project_dir: str) -> None:
    print(f"  Starting server...")
    print(f"")
    print(f"  ========================================")
    print(f"  Open your browser and go to:")
    print(f"  {APP_URL}")
    print(f"  ========================================")
    print(f"")
    print(f"  Press Ctrl+C to stop the server.")
    print(f"")

    subprocess.run(
        [python_path, "run.py"],
        cwd=project_dir,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def main() -> None:
    project_dir = get_project_dir()
    os.chdir(project_dir)

    print(f"")
    print(f"  ========================================")
    print(f"    {APP_NAME}")
    print(f"  ========================================")
    print(f"")

    python_path = ensure_venv(project_dir)
    install_deps(python_path, project_dir)
    ensure_dirs(project_dir)

    print(f"  Launching browser...")
    browser_thread = threading.Thread(target=open_browser_delayed, daemon=True)
    browser_thread.start()

    try:
        run_server(python_path, project_dir)
    except KeyboardInterrupt:
        print(f"\n  Server stopped.")
    except Exception as e:
        print(f"\n  Error: {e}")
        input("\n  Press Enter to exit...")


if __name__ == "__main__":
    main()
