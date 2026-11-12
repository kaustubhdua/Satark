#!/usr/bin/python3
"""Persistent TTL watchdog for SATARK Wazuh firewall responses."""
from __future__ import annotations

import logging
import signal
import time

from satark_response_state import ResponseStateError, expire_due

logging.basicConfig(level=logging.INFO, format="%(asctime)s satark-response-watchdog %(levelname)s %(message)s")
running = True


def stop(_signum, _frame):
    global running
    running = False


def main() -> int:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        try:
            for ip in expire_due():
                logging.info("expired SATARK firewall block for %s", ip)
        except (ResponseStateError, OSError) as error:
            logging.error("watchdog pass failed: %s", error)
        time.sleep(5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
