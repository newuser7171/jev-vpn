@echo off
title Jev-VPN Console Daemon
cd /d "C:\Users\newuser\.gemini\antigravity\scratch\jev-vpn"
python cli.py start --port 8998
if errorlevel 1 pause
