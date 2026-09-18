# ProxyMe

Share your Android internet via HTTP / HTTPS / SOCKS5 proxy — built for Termux.

Single file. No dependencies. Pure Python stdlib.

## Features

- HTTP, HTTPS (CONNECT), SOCKS4, and SOCKS5 proxy on **one port** (default `10001`)
- Auto-detects HTTP vs SOCKS from the first byte — no separate ports needed
- Live terminal UI showing connections, speed, uptime, and active clients
- Port forwarding (`local_port -> host:port`) on the fly
- VPN-aware (binds to `tun0` when available)
- Remote DNS resolution for SOCKS5
- Logs every session to a timestamped file

## Requirements

- Termux (or any Linux with Python 3.7+)
- Python 3 (usually preinstalled)

```bash
pkg update && pkg upgrade -y
pkg install git python -y
git clone https://github.com/Mas70ud/proxyme.git
cd proxyme
python proxyme.py
