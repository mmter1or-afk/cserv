"""Backward-compatible application entrypoint."""

from app import app

if __name__ == "__main__":
    app.run()
