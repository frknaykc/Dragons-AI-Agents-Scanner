"""Entrypoint for the build-only PyInstaller bundle; CLI policy stays in dragonscan.cli."""

from dragonscan.cli import main

if __name__ == "__main__":
    main()
