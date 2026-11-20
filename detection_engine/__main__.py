"""Allow running the detection lab via `python -m detection_engine`."""

from detection_engine.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
