#!/usr/bin/env python3
#
# run.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
#

from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------
# Load environment early (before config is read)
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

if ENV_FILE.exists():
	load_dotenv(ENV_FILE)

# ---------------------------------------------------------
# Deliberately imported after load_dotenv() above so app.utils.config and any
# module it pulls in observe .env values at import time, not just at
# load_config() call time. The server logic lives in app.server so the Docker
# image, which does not ship this file, can start it too.
from app.server import main  # noqa: E402

if __name__ == "__main__":
	main()
