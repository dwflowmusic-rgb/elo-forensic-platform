@echo off
set "PYTHONPATH=/app/applet/src;%PYTHONPATH%"
set "PYTHONHASHSEED=42"
"/usr/bin/python3" -m edrm.interfaces.cli %*
