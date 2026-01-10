"""Module entrypoint so `python -m protoscan` works."""

from .cli import main


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
