#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TermuxProxy v1.0
Share Android internet via HTTP / HTTPS / SOCKS5 proxy
Single-file, stdlib-only, designed for Termux
"""

import socket
import select
import threading
import sys
import os
import time
import signal
import struct
import datetime
import re
import platform
import ipaddress
from urllib.parse import urlparse

# ─── Config ────────────────────────────────────────────────
PROXY_PORT = 10001     # Single port for both HTTP & SOCKS
BIND_ADDR = '0.0.0.0'  # Listen on all interfaces
BUFFER_SIZE = 8192      # Buffer size
TIMEOUT = 60            # Connection timeout (seconds)
USE_VPN_BIND = False    # Try to bind outgoing conns to tun0 (needs root)
REMOTE_DNS = True       # Resolve DNS on proxy side (SOCKS5)

# ─── Stats ─────────────────────────────────────────────────
stats = {
    'total_conn': 0, 'active_conn': 0,
    'http_conn': 0, 'https_conn': 0, 'socks_conn': 0,
    'bytes_up': 0, 'bytes_down': 0, 'start': None,
}
clients = []   # [(ip, port, type, time, up, down), ...]
clients_lock = threading.Lock()
server_running = True

# ─── Utilities ─────────────────────────────────────────────
def now():
    return datetime.datetime.now().strftime('%H:%M:%S')

def bytes_fmt(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024: return f'{n:.1f}{unit}'
        n /= 1024
    return f'{n:.1f}TB'

LOG_FILE = None  # set in main() with timestamp

def log(typ, msg):
    ts = now()
    line = f'[{ts}] {typ} {msg}'
    if LOG_FILE:
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(line + '\n')
        except:
            pass

def local_ips():
    """Return list of (ip, interface_name) — hotspot (10.x.x.x) first"""
    ips = []
    seen = set()
    try:
        import subprocess
        out = subprocess.check_output(['ip', '-o', 'addr', 'show']).decode()
        for m in re.finditer(r'\d+:\s+(\S+).*?inet (\d+\.\d+\.\d+\.\d+)', out):
            iface, ip = m.group(1), m.group(2)
            if iface.endswith('@'): iface = iface[:-1]
            if not ip.startswith('127.') and ip not in seen:
                ips.append((ip, iface))
                seen.add(ip)
    except:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        if ip not in seen and not ip.startswith('127.'):
            ips.append((ip, 'default'))
            seen.add(ip)
        s.close()
    except:
        pass
    # Sort: 10.x.x.x (hotspot) first, then 172.x.x.x, then 192.168.x.x, then others
    def sort_key(item):
        ip = item[0]
        if ip.startswith('10.'): return 0
        if ip.startswith('172.'): return 1
        if ip.startswith('192.168.'): return 2
        return 3
    ips.sort(key=sort_key)
    return ips or [('127.0.0.1', 'lo')]


_host_cache = {}

def resolve_hostname(ip):
    """Reverse DNS lookup with cache and short timeout"""
    if ip in _host_cache:
        return _host_cache[ip]
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2)
        host = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old_timeout)
        _host_cache[ip] = host
        return host
    except:
        _host_cache[ip] = None
        return None


def vpn_active():
    """Return whether a VPN interface (tun0 / ip_vpn*) is up"""
    try:
        import subprocess
        out = subprocess.check_output(['ip', 'link', 'show', 'up']).decode().lower()
        for name in ('tun', 'tap', 'ip_vpn', 'wg', 'vpn'):
            if name in out:
                return True
    except:
        pass
    return False


def create_remote():
    """Create an outgoing socket with VPN-aware settings"""
    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote.settimeout(TIMEOUT)
    remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if USE_VPN_BIND and vpn_active():
        try:
            remote.setsockopt(socket.SOL_SOCKET, 25, b'tun0')  # SO_BINDTODEVICE
        except:
            pass
    return remote


def resolve_target(host, port):
    """Resolve host to IP when needed — bypasses broken system DNS on VPN"""
    try:
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        return addr[0][4][0], port
    except:
        return host, port


# ═══════════════════════════════════════════════════════════
#  SOCKS5
# ═══════════════════════════════════════════════════════════

SOCKS5_NO_AUTH = 0x00
SOCKS5_AUTH_USERPASS = 0x02
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04

SOCKS5_REPLIES = {
    0x00: 'Granted',
    0x01: 'General failure',
    0x02: 'Connection not allowed',
    0x03: 'Network unreachable',
    0x04: 'Host unreachable',
    0x05: 'Connection refused',
    0x06: 'TTL expired',
    0x07: 'Command not supported',
    0x08: 'Address type not supported',
}

def socks5_auth(client):
    """SOCKS5 auth negotiation — no password required (version already read)"""
    data = client.recv(1)  # nmethods only — version was already consumed
    if len(data) < 1: return False
    nmethods = data[0]
    methods = client.recv(nmethods) if nmethods > 0 else b''
    client.send(bytes([0x05, SOCKS5_NO_AUTH]))
    return True

def socks5_read_addr(client, atyp):
    """Read SOCKS5 destination address — atyp already parsed from request header"""
    if atyp == SOCKS5_ATYP_IPV4:
        addr = socket.inet_ntoa(client.recv(4))
    elif atyp == SOCKS5_ATYP_DOMAIN:
        dlen_byte = client.recv(1)
        if len(dlen_byte) < 1:
            raise ValueError('Connection closed before domain length')
        dlen = dlen_byte[0]
        addr = client.recv(dlen).decode()
    elif atyp == SOCKS5_ATYP_IPV6:
        addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
    else:
        raise ValueError(f'Unknown ATYP: {atyp}')
    port = struct.unpack('>H', client.recv(2))[0]
    return addr, port

def socks5_request(client):
    """Process SOCKS5 request"""
    data = client.recv(4)
    if len(data) < 4: return None, None
    ver, cmd, rsv, atyp = data
    if cmd != SOCKS5_CMD_CONNECT:
        client.send(bytes([0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]))
        log('!', f'SOCKS5 non-CONNECT cmd={cmd}, raw: {data.hex()}')
        return None, None
    try:
        addr, port = socks5_read_addr(client, atyp)
        return addr, port
    except ValueError as e:
        raise ValueError(f'Bad request: ver={ver}, cmd={cmd}, rsv={rsv}, atyp={atyp}, raw_header={data.hex()}, context: {e}')

def socks5_reply(client, code, bind_addr='0.0.0.0', bind_port=0):
    """Send SOCKS5 reply"""
    reply = struct.pack('!BBBB', 0x05, code, 0x00, SOCKS5_ATYP_IPV4)
    reply += socket.inet_aton(bind_addr)
    reply += struct.pack('>H', bind_port)
    client.send(reply)


def socks4_handle(client, addr, first_byte):
    """Handle SOCKS4 / SOCKS4a connection — first_byte is 0x04"""
    with clients_lock:
        stats['socks_conn'] += 1
        stats['total_conn'] += 1
        stats['active_conn'] += 1
    try:
        data = first_byte + client.recv(7)  # CMD + PORT(2) + IP(4)
        if len(data) < 8:
            return
        ver, cmd, port_hi, port_lo = data[0], data[1], data[2], data[3]
        dst_ip = f'{data[4]}.{data[5]}.{data[6]}.{data[7]}'
        port = (port_hi << 8) | port_lo

        if cmd != 1:  # SOCKS4 CONNECT
            client.send(bytes([0x00, 0x5B, 0,0,0,0,0,0]))
            return

        # Read USERID (null-terminated)
        while True:
            b = client.recv(1)
            if not b or b == b'\x00':
                break

        target_host = dst_ip
        # SOCKS4a: if IP is 0.0.0.x (x != 0), read domain after USERID
        if dst_ip.startswith('0.0.0.') and dst_ip != '0.0.0.0':
            domain = b''
            while True:
                b = client.recv(1)
                if not b or b == b'\x00':
                    break
                domain += b
            target_host = domain.decode() if domain else dst_ip

        log('4', f'SOCKS4 {target_host}:{port} from {addr[0]}:{addr[1]}')
        if REMOTE_DNS:
            target_host, _ = resolve_target(target_host, port)

        remote = create_remote()
        try:
            remote.connect((target_host, port))
            # SOCKS4 reply: [0x00, 0x5A, PORT_HI, PORT_LO, IP1..4]
            reply = bytes([0x00, 0x5A, port_hi, port_lo, data[4], data[5], data[6], data[7]])
            client.send(reply)
            log('+', f'SOCKS4 relay: {addr[0]} -> {target_host}:{port}')
            tunnel_relay(client, remote, addr[0], addr[1], 'SOCKS5')
        except Exception as e:
            code = 0x5B  # Request rejected or failed
            err = str(e).lower()
            if 'refused' in err: code = 0x5C
            elif 'unreach' in err or 'network' in err: code = 0x5B
            else: code = 0x5B
            reply = bytes([0x00, code, 0,0,0,0,0,0])
            client.send(reply)
            remote.close()
            client.close()
            log('x', f'SOCKS4 failed: {target_host}:{port} - {e}')
    except Exception as e:
        log('!', f'SOCKS4 error: {e}')
    finally:
        with clients_lock:
            stats['active_conn'] -= 1
        try:
            client.close()
        except:
            pass


def handle_socks5(client, addr, first_byte=None):
    """Detect SOCKS4 vs SOCKS5 and dispatch"""
    try:
        if first_byte is None:
            first = client.recv(1)
        else:
            first = first_byte
        if not first:
            try: client.close()
            except: pass
            return
        if first[0] == 0x04:
            # SOCKS4 — manages its own stats
            socks4_handle(client, addr, first)
            return
        elif first[0] != 0x05:
            try: client.close()
            except: pass
            return
    except:
        try: client.close()
        except: pass
        return

    # SOCKS5 — from here on
    with clients_lock:
        stats['socks_conn'] += 1
        stats['total_conn'] += 1
        stats['active_conn'] += 1
    log('5', f'SOCKS5 from {addr[0]}:{addr[1]}')

    try:
        if not socks5_auth(client):
            return

        target_host, target_port = socks5_request(client)
        if not target_host:
            return

        # Connect to destination
        if REMOTE_DNS:
            target_host, _ = resolve_target(target_host, target_port)
        remote = create_remote()
        try:
            remote.connect((target_host, target_port))
            socks5_reply(client, 0x00, BIND_ADDR, 0)
        except Exception as e:
            err = str(e).lower()
            if 'refused' in err: code = 0x05
            elif 'unreach' in err or 'network' in err: code = 0x03
            elif 'host' in err: code = 0x04
            else: code = 0x01
            socks5_reply(client, code)
            remote.close()
            log('x', f'SOCKS5 connection failed: {target_host}:{target_port} - {e}')
            return

        log('+', f'SOCKS5 relay: {addr[0]} -> {target_host}:{target_port}')
        tunnel_relay(client, remote, addr[0], addr[1], 'SOCKS5')

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as e:
        log('!', f'SOCKS5 error: {e}')
    finally:
        with clients_lock:
            stats['active_conn'] -= 1
        try:
            client.close()
        except:
            pass


# ═══════════════════════════════════════════════════════════
#  HTTP / HTTPS Proxy
# ═══════════════════════════════════════════════════════════

def parse_http_request(data):
    """Parse HTTP request and extract host + port"""
    first_line = data.split(b'\r\n')[0].decode('utf-8', errors='replace')
    parts = first_line.split(' ')
    if len(parts) < 3:
        return None, None, None

    method = parts[0].upper()
    url = parts[1]

    if method == 'CONNECT':
        # CONNECT server.com:443 HTTP/1.1
        try:
            host, port_str = url.split(':')
            return method, host, int(port_str)
        except:
            return None, None, None
    else:
        # GET http://server.com/path HTTP/1.1
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        return method, host, port


def handle_http(client, addr, initial_data=b''):
    buff = initial_data
    remote = None
    try:
        while b'\r\n\r\n' not in buff:
            chunk = client.recv(BUFFER_SIZE)
            if not chunk:
                return
            buff += chunk
            if len(buff) > 65536:
                return

        method, host, port = parse_http_request(buff)
        if not host:
            client.send(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            return

        if method == 'CONNECT':
            with clients_lock:
                stats['https_conn'] += 1
                stats['total_conn'] += 1
            log('T', f'HTTPS CONNECT {host}:{port} from {addr[0]}:{addr[1]}')

            remote = create_remote()
            try:
                remote.connect((host, port))
                client.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                log('+', f'HTTPS tunnel: {addr[0]} -> {host}:{port}')
                tunnel_relay(client, remote, addr[0], addr[1], 'HTTPS')
            except Exception as e:
                client.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                log('x', f'HTTPS CONNECT failed: {host}:{port} - {e}')
                remote.close() if remote else None
            return

        # HTTP request (non-CONNECT)
        with clients_lock:
            stats['http_conn'] += 1
            stats['total_conn'] += 1
        log('G', f'HTTP {method} {host}:{port} from {addr[0]}:{addr[1]}')

        # Rewrite request — remove absolute URL
        lines = buff.split(b'\r\n')
        first = lines[0].decode('utf-8', errors='replace')
        parts = first.split(' ')
        parsed = urlparse(parts[1])
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        lines[0] = f'{parts[0]} {path} HTTP/1.1'.encode()
        # Strip Proxy-* headers
        lines = [l for l in lines if not l.lower().startswith(b'proxy-')]
        buff = b'\r\n'.join(lines)

        remote = create_remote()
        remote.connect((host, port))
        remote.sendall(buff)

        # All methods: bidirectional relay (reliable, no buffering)
        with clients_lock:
            stats['bytes_up'] += len(buff)
        tunnel_relay(client, remote, addr[0], addr[1], 'HTTP')

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as e:
        log('!', f'HTTP error: {e}')
    finally:
        try:
            client.close()
        except:
            pass
        if remote:
            try:
                remote.close()
            except:
                pass


# ═══════════════════════════════════════════════════════════
#  Bidirectional Tunnel (Relay)
# ═══════════════════════════════════════════════════════════

def tunnel_relay(src, dst, src_ip, src_port, proxy_type):
    """Forward data between two sockets bidirectionally"""
    up_bytes = 0
    down_bytes = 0
    with clients_lock:
        stats['active_conn'] += 1

    client_info = (src_ip, src_port, proxy_type, time.time(), 0, 0)
    with clients_lock:
        clients.append(client_info)

    sockets = [src, dst]
    try:
        while server_running:
            r, _, x = select.select(sockets, [], sockets, 30)
            if x:
                break
            if not r:
                continue

            for s in r:
                try:
                    data = s.recv(BUFFER_SIZE)
                    if not data:
                        return
                    if s is src:
                        dst.sendall(data)
                        up_bytes += len(data)
                    elif s is dst:
                        src.sendall(data)
                        down_bytes += len(data)
                except:
                    return

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        with clients_lock:
            stats['bytes_up'] += up_bytes
            stats['bytes_down'] += down_bytes
            stats['active_conn'] -= 1
            for i, c in enumerate(clients):
                if c[0] == src_ip and c[1] == src_port and c[2] == proxy_type:
                    clients[i] = (src_ip, src_port, proxy_type, c[3], up_bytes, down_bytes)
                    break
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass


# ═══════════════════════════════════════════════════════════
#  Port Forwarding
# ═══════════════════════════════════════════════════════════

port_forwards = []  # [(listen_port, target_host, target_port, running)]
pf_lock = threading.Lock()

def pf_thread(listen_port, target_host, target_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((BIND_ADDR, listen_port))
        server.listen(20)
        server.settimeout(2)
        log('F', f'Port forward: {listen_port} -> {target_host}:{target_port}')
    except Exception as e:
        log('x', f'Port forward bind failed on {listen_port}: {e}')
        with pf_lock:
            port_forwards[:] = [p for p in port_forwards if p[0] != listen_port]
        return

    while server_running:
        try:
            client, addr = server.accept()
            log('+', f'Forward from {addr[0]}:{addr[1]} -> {target_host}:{target_port}')
            threading.Thread(target=pf_handle, args=(client, target_host, target_port, addr), daemon=True).start()
        except socket.timeout:
            continue
        except:
            break
    server.close()

def pf_handle(client, host, port, addr):
    remote = None
    try:
        remote = create_remote()
        remote.connect((host, port))
        tunnel_relay(client, remote, addr[0], addr[1], 'FORWARD')
    except Exception as e:
        log('x', f'Forward connect failed: {host}:{port} - {e}')
    finally:
        try:
            client.close()
        except:
            pass
        if remote:
            try:
                remote.close()
            except:
                pass


def handle_client(client, addr):
    """Detect HTTP vs SOCKS from the first byte and dispatch"""
    try:
        first = client.recv(1)
        if not first:
            try: client.close()
            except: pass
            return
        # SOCKS: first byte is 0x04 (SOCKS4) or 0x05 (SOCKS5)
        if first[0] in (0x04, 0x05):
            handle_socks5(client, addr, first)
        else:
            # Anything else = HTTP (GET/POST/CONNECT/...)
            handle_http(client, addr, first)
    except:
        try: client.close()
        except: pass


# ═══════════════════════════════════════════════════════════
#  Servers
# ═══════════════════════════════════════════════════════════

def start_proxy():
    """Start combined HTTP + SOCKS proxy on one port"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((BIND_ADDR, PROXY_PORT))
        server.listen(200)
        server.settimeout(2)
        log('*', f'Proxy on port {PROXY_PORT} (HTTP+SOCKS)')
    except Exception as e:
        log('x', f'Cannot bind port {PROXY_PORT}: {e}')
        return

    while server_running:
        try:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
        except socket.timeout:
            continue
        except:
            break
    server.close()


# ═══════════════════════════════════════════════════════════
#  Terminal TUI  (ASCII only — no emoji, no wide chars)
# ═══════════════════════════════════════════════════════════

BOX_W = 46  # total width of one box line (including borders)

def tui():
    """Real-time terminal status display — pure ASCII"""
    if not sys.stdout.isatty():
        return

    sys.stdout.write('\033[?25l')

    try:
        while server_running:
            uptime = str(datetime.timedelta(seconds=int(time.time() - (stats['start'] or time.time()))))
            ips = local_ips()

            def b(text):
                """Pad text to exactly BOX_W-2 = 44 chars, wrap in borders"""
                return f'|{text:<44}|'

            sep = '+' + '-' * 44 + '+'
            lines = []
            lines.append('\033[H\033[J')
            lines.append(sep)
            lines.append(b('                  ProxyMe'))
            lines.append(sep)
            flag = ' +VPN' if vpn_active() else ''
            lines.append(b(f'  Status: Running{flag}'))
            lines.append(sep)
            lines.append(b('  Available interfaces:'))
            for ip, iface in ips:
                lines.append(b(f'    {ip}  ({iface})'))
            lines.append(sep)
            lines.append(b(f'  Proxy: {PROXY_PORT} (HTTP+SOCKS)'))
            lines.append(b(f'  Uptime: {uptime}'))
            lines.append(sep)
            lines.append(b('  Connections:'))
            lines.append(b(f'    Total {stats["total_conn"]}    HTTP {stats["http_conn"]}    HTTPS {stats["https_conn"]}'))
            lines.append(b(f'    Active {stats["active_conn"]}    SOCKS {stats["socks_conn"]}'))
            lines.append(sep)
            lines.append(b(f'  Up: {bytes_fmt(stats["bytes_up"])}  Down: {bytes_fmt(stats["bytes_down"])}'))
            lines.append(sep)
            lines.append(b('  Active sessions:'))
            if clients:
                with clients_lock:
                    recent = [c for c in clients if c[3] > time.time() - 60]
                    if recent:
                        seen = {}
                        for c in recent:
                            ip, ptype = c[0], c[2]
                            if ip not in seen:
                                seen[ip] = set()
                            seen[ip].add(ptype)
                        for ip, types in seen.items():
                            h = resolve_hostname(ip)
                            src = h.split('.')[0][:20] if h else ip
                            if len(src) > 20:
                                src = src[:18] + '..'
                            types_str = '/'.join(sorted(types))
                            lines.append(b(f'    {src}  {types_str}'))
                    else:
                        lines.append(b('    (none)'))
            else:
                lines.append(b('    (none)'))
            lines.append(sep)
            lines.append(b('  Port forwards:'))
            with pf_lock:
                if port_forwards:
                    for pf in port_forwards:
                        lines.append(b(f'    {pf[0]} -> {pf[1]}:{pf[2]}'))
                else:
                    lines.append(b('    (none)'))
            lines.append(sep)
            lines.append(b('  Commands: q=quit  p=fwd  c=clear'))
            lines.append('+' + '-' * 44 + '+')  # bottom

            sys.stdout.write('\n'.join(lines))
            sys.stdout.flush()
            time.sleep(2)

    finally:
        sys.stdout.write('\033[?25h')


# ═══════════════════════════════════════════════════════════
#  User Input Handler
# ═══════════════════════════════════════════════════════════

def input_handler():
    """Handle user commands"""
    global server_running
    while server_running:
        try:
            cmd = sys.stdin.readline().strip().lower()
            if not cmd:
                time.sleep(0.1)
                continue
            if cmd == 'q':
                log('q', 'Closing server...')
                server_running = False
                break
            elif cmd == 'p':
                sys.stdout.write('\r[?] Port forward: local_port>host:port  (e.g. 3333>google.com:80)\n')
                sys.stdout.flush()
                spec = sys.stdin.readline().strip()
                m = re.match(r'(\d+)>(.+):(\d+)', spec)
                if m:
                    lport, thost, tport = int(m.group(1)), m.group(2), int(m.group(3))
                    with pf_lock:
                        if any(p[0] == lport for p in port_forwards):
                            log('!', f'Port {lport} already forwarded')
                        else:
                            pf = (lport, thost, tport, True)
                            port_forwards.append(pf)
                            threading.Thread(target=pf_thread, args=(lport, thost, tport), daemon=True).start()
                else:
                    log('!', 'Invalid format. Use: port>host:port')
            elif cmd == 'c':
                with clients_lock:
                    clients.clear()
                    log('C', 'Client list cleared')
            elif cmd == 'v':
                global USE_VPN_BIND
                USE_VPN_BIND = not USE_VPN_BIND
                log('V', f'VPN bind {"ENABLED" if USE_VPN_BIND else "DISABLED"}')
        except:
            break


# ═══════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════

def main():
    global server_running, stats, LOG_FILE
    stats['start'] = time.time()

    log_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else os.getcwd()
    log_stamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    LOG_FILE = os.path.join(log_dir, f'proxy-{log_stamp}.log')

    # Check Termux environment
    is_termux = 'com.termux' in os.environ.get('HOME', '') or 'termux' in platform.release().lower()

    print()
    print('+' + '-' * 44 + '+')
    print('|                  ProxyMe                  |')
    print('|   Share phone internet via HTTP / SOCKS5   |')
    print('|   Pure Python stdlib - zero deps           |')
    print('+' + '-' * 44 + '+')
    if is_termux:
        print('   [v] Termux detected')
    if vpn_active():
        print('   [v] VPN interface detected -- traffic goes through VPN')
    else:
        print('   [!] No VPN detected')
    print('   [*] Proxy    : port %d (HTTP+SOCKS)' % PROXY_PORT)
    print('   [*] Bind     : %s' % BIND_ADDR)
    print()
    print('   --- Available Interfaces ---')
    for ip, iface in local_ips():
        print('   %-15s (%s)' % (ip, iface))
    print()
    print('   q=quit  p=fwd  c=clear')
    print('   Log: %s' % LOG_FILE)
    print()

    # Signal handlers
    signal.signal(signal.SIGINT, lambda s, f: exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: exit(0))

    # Start server
    t = threading.Thread(target=start_proxy, daemon=True)
    t.start()

    # TUI
    tui_thread = threading.Thread(target=tui, daemon=True)
    tui_thread.start()

    # User input
    input_handler()

    # Clean shutdown
    server_running = False
    log('q', 'Bye! Proxy servers stopped.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        log('q', 'Bye!')