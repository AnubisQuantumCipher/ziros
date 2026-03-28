#!/usr/bin/env python3
"""Compatibility shim for the legacy ANE scheduler trainer."""

from __future__ import annotations

from train_scheduler_model import main


if __name__ == "__main__":
    raise SystemExit(main())
