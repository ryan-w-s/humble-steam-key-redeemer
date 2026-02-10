@echo off
echo Installing dependencies...
uv sync
echo Running
uv run humblesteamkeysredeemer.py %*
set /p=Press ENTER to close terminal
