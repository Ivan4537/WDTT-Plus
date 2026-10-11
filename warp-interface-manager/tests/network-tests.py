#!/usr/bin/env python3
"""Real WireGuard/routing regression checks in an offline disposable container."""
from contextlib import ExitStack
import hashlib
import difflib
import http.server
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
from tempfile import TemporaryDirectory
import threading
import time


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f'Command failed: {args[0]}: {result.stderr.strip()}')
    return result.stdout.strip()


assert Path('/.dockerenv').exists() and os.geteuid() == 0, 'Use the documented offline test container.'
assert not run('ip', '-4', 'route', 'show', 'default'), 'Refusing a container with an external default route.'
# This mount is private to the disposable container; all sysctls below are per-netns.
run('mount', '-o', 'remount,rw', '/proc/sys')
run('ip', 'link', 'set', 'lo', 'up')


Path('/etc/wireguard').mkdir(mode=0o700, exist_ok=True)
# Keep keys in WireGuard's standard protected tree, including on hosts whose
# security policy restricts wg's file access to /etc/wireguard.
with ExitStack() as cleanup, TemporaryDirectory(prefix='wim-network-', dir='/etc/wireguard') as temp:
    root = Path(temp)
    peers = {}
    for peer in ('wan', 'one', 'two', 'other'):
        process = subprocess.Popen(['unshare', '--net', 'sleep', '3600'])
        cleanup.callback(process.wait)
        cleanup.callback(process.terminate)
        for _ in range(100):
            if os.readlink(f'/proc/{process.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                break
            time.sleep(.01)
        else:
            raise RuntimeError('Peer network namespace did not start.')
        peers[peer] = process.pid

    def peer(name, *args):
        return run('nsenter', '-t', str(peers[name]), '-n', *args)

    for name, iface, subnet in (('wan', 'eth0', '192.0.2'), ('one', 'csqtt1', '10.70.0'), ('two', 'csqtt2', '10.71.0'), ('other', 'spare0', '10.72.0')):
        remote = iface + '-peer'
        run('ip', 'link', 'add', iface, 'type', 'veth', 'peer', 'name', remote)
        run('ip', 'link', 'set', remote, 'netns', str(peers[name]))
        run('ip', 'addr', 'add', subnet + '.1/24', 'dev', iface)
        run('ip', 'link', 'set', iface, 'up')
        peer(name, 'ip', 'link', 'set', 'lo', 'up')
        peer(name, 'ip', 'addr', 'add', subnet + '.2/24', 'dev', remote)
        peer(name, 'ip', 'link', 'set', remote, 'up')
        if name != 'wan':
            peer(name, 'ip', 'route', 'add', 'default', 'via', subnet + '.1')
    run('ip', 'route', 'add', 'default', 'via', '192.0.2.2')
    peer('wan', 'ip', 'addr', 'add', '203.0.113.10/32', 'dev', 'lo')

    def private_file(name):
        path = root / name
        path.write_text(run('wg', 'genkey') + '\n')
        path.chmod(0o600)
        return path

    server_key = private_file('server.key')
    peer_key = private_file('peer.key')
    server_public = run('wg', 'pubkey', input=server_key.read_text())
    peer_public = run('wg', 'pubkey', input=peer_key.read_text())
    peer('wan', 'ip', 'link', 'add', 'wg-peer', 'type', 'wireguard')
    peer('wan', 'ip', 'addr', 'add', '172.16.0.1/24', 'dev', 'wg-peer')
    peer('wan', 'wg', 'set', 'wg-peer', 'listen-port', '51820', 'private-key', str(peer_key), 'peer', server_public, 'allowed-ips', '172.16.0.2/32')
    peer('wan', 'ip', 'link', 'set', 'wg-peer', 'up')
    config = root / 'config'
    config.mkdir(mode=0o700)
    (config / 'owner').write_text('warp-interface-manager-v1\n')
    profile = root / 'warp-selective.conf'
    profile.write_text(f'''# Managed by warp-interface-manager. Do not edit while active.
[Interface]
PrivateKey = {server_key.read_text().strip()}
Address = 172.16.0.2/32
Table = off
MTU = 1280
[Peer]
PublicKey = {peer_public}
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.2:51820
PersistentKeepalive = 25
''')
    profile.chmod(0o600)
    original_profile = hashlib.sha256(profile.read_bytes()).hexdigest()

    # Simulate an existing unrelated VPN's firewall, including a restrictive policy.
    run('iptables', '-P', 'FORWARD', 'DROP')
    run('iptables', '-A', 'FORWARD', '-i', 'spare0', '-o', 'eth0', '-j', 'ACCEPT')
    run('iptables', '-A', 'FORWARD', '-i', 'eth0', '-o', 'spare0', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT')
    run('iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE')
    run('iptables', '-t', 'mangle', '-A', 'OUTPUT', '-m', 'comment', '--comment', 'UNRELATED_TEST_RULE', '-j', 'ACCEPT')
    def firewall_snapshot():
        return re.sub(r'\[\d+:\d+\]', '[0:0]', '\n'.join(line for line in run('iptables-save').splitlines() if not line.startswith('#')))
    original_filter = firewall_snapshot()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.client_address[0].encode())

        def log_message(self, *args):
            pass

    inbound = http.server.ThreadingHTTPServer(('192.0.2.1', 18080), Handler)
    cleanup.callback(inbound.server_close)
    cleanup.callback(inbound.shutdown)
    threading.Thread(target=inbound.serve_forever, daemon=True).start()

    def udp_echo():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('192.0.2.1', 18081))
        cleanup.callback(sock.close)
        def loop():
            while True:
                try:
                    data, address = sock.recvfrom(1024)
                    sock.sendto(data, address)
                except OSError:
                    return
        threading.Thread(target=loop, daemon=True).start()
    udp_echo()

    # WAN HTTP and UDP/53 servers run in the isolated peer namespace.
    peer_script = root / 'peer-server.py'
    peer_script.write_text('''import http.server,socket,threading
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200); self.end_headers(); self.wfile.write(self.client_address[0].encode())
 def log_message(self,*args): pass
def dns():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('203.0.113.10',53))
 while True:
  d,a=s.recvfrom(1024); s.sendto(a[0].encode()+b'|'+d,a)
threading.Thread(target=dns,daemon=True).start()
http.server.ThreadingHTTPServer(('203.0.113.10',18082),H).serve_forever()
''')
    process = subprocess.Popen(['nsenter', '-t', str(peers['wan']), '-n', 'python3', str(peer_script)])
    cleanup.callback(process.wait)
    cleanup.callback(process.terminate)
    for _ in range(100):
        try:
            run('curl', '-fsS', '--max-time', '1', 'http://203.0.113.10:18082/')
            break
        except RuntimeError:
            time.sleep(.02)
    else:
        raise RuntimeError('Isolated WAN server did not start.')

    prefix = f'''
set -euo pipefail
export WIM_TEST_MODE=1 WIM_SOURCE_ONLY=1
source /project/warp-interface-manager.sh
CONFIG_DIR={shlex.quote(str(config))}
OWNER_FILE="$CONFIG_DIR/owner"; STATE_FILE="$CONFIG_DIR/state.env"
WG_CONFIG={shlex.quote(str(profile))}
DATA_DIR={shlex.quote(str(root / 'data'))}; HEALTH_FILE="$DATA_DIR/health.env"
RUNTIME_DIR={shlex.quote(str(root / 'runtime'))}; RUNTIME_FILE="$RUNTIME_DIR/runtime.env"
LOG_DIR={shlex.quote(str(root / 'logs'))}; EVENT_LOG="$LOG_DIR/events.log"; INSTALL_LOG="$LOG_DIR/install.log"
detect_ssh_ports() {{ printf '2222'; }}
perform_warp_test() {{
    [[ "$(curl -fsS --interface "$(profile_ipv4)" --max-time 3 http://203.0.113.10:18082/)" == 172.16.0.2 ]] || return 1
    [[ "$(wg show warp-selective latest-handshakes | awk '{{print $2}}')" -gt 0 ]] || return 1
    WARP_EXIT_IP=203.0.113.10
}}
perform_full_host_test() {{ [[ "$(curl -fsS --max-time 3 http://203.0.113.10:18082/)" == 172.16.0.2 ]]; }}
'''

    def manager(command):
        return run('bash', '-c', prefix + '\n' + command)

    def outbound(name=None):
        args = ('curl', '-fsS', '--max-time', '3', 'http://203.0.113.10:18082/')
        return peer(name, *args) if name else run(*args)

    def dns(name=None, native=False):
        code = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        if native:
            code += "s.bind(('192.0.2.1',0));"
        code += "s.settimeout(3);s.sendto(b'dns-probe',('203.0.113.10',53));print(s.recv(1024).decode())"
        return peer(name, 'python3', '-c', code) if name else run('python3', '-c', code)

    def incoming():
        assert peer('wan', 'curl', '-fsS', '--max-time', '3', '--interface', '203.0.113.10', 'http://192.0.2.1:18080/') == '203.0.113.10'
        code = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('203.0.113.10',0));s.settimeout(3);s.sendto(b'reply-probe',('192.0.2.1',18081));assert s.recv(1024)==b'reply-probe'"
        peer('wan', 'python3', '-c', code)

    def stopped():
        manager('runtime_down')
        assert 'WARP_INTERFACE_MANAGER' not in run('iptables-save')
        current_filter = firewall_snapshot()
        assert current_filter == original_filter, 'Unrelated firewall changed:\n' + '\n'.join(difflib.unified_diff(original_filter.splitlines(), current_filter.splitlines()))
        assert '51880' not in run('ip', '-4', 'rule', 'show')
        assert not Path('/sys/class/net/warp-selective').exists(), 'WireGuard interface remained.'
        assert hashlib.sha256(profile.read_bytes()).hexdigest() == original_profile
        assert run('sysctl', '-n', 'net.ipv4.conf.all.rp_filter') == '1', 'Global rp_filter changed.'

    run('sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
    run('sysctl', '-q', '-w', 'net.ipv4.conf.all.rp_filter=1')
    run('sysctl', '-q', '-w', 'net.ipv4.conf.default.rp_filter=1')
    manager('write_state csqtt1,csqtt2 51880 18000 1700000000 0 0 interface ""; service_up')
    assert run('sysctl', '-n', 'net.ipv4.conf.all.rp_filter') == '1'
    assert outbound('one') == outbound('two') == '172.16.0.2'
    assert outbound('other') == outbound() == '192.0.2.1'
    assert dns('one') == dns('two') == '172.16.0.2|dns-probe'
    incoming()
    print('OK: two ingress interfaces share WARP; unrelated ingress and host keep their route.')
    manager('load_state; rm -f "$RUNTIME_FILE"; service_up')
    assert outbound('two') == '172.16.0.2'
    print('OK: stale tunnel recovered using the saved profile without re-registration.')
    stopped()

    # An inbound server connection may already exist when host routing changes.
    # Its first subsequent packet can be server push, without a new inbound packet.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cleanup.callback(listener.close)
    listener.bind(('192.0.2.1', 18084))
    listener.listen(1)
    listener.settimeout(3)
    push_code = "import socket,sys;s=socket.socket();s.bind(('203.0.113.10',0));s.connect(('192.0.2.1',18084));print('ready',flush=True);sys.stdin.readline();s.settimeout(3);print(s.recv(4).decode(),flush=True)"
    push_client = subprocess.Popen(['nsenter', '-t', str(peers['wan']), '-n', 'python3', '-u', '-c', push_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    cleanup.callback(push_client.wait)
    cleanup.callback(push_client.terminate)
    push_connection, _ = listener.accept()
    cleanup.callback(push_connection.close)
    assert push_client.stdout.readline().strip() == 'ready'
    manager('write_state - 51880 18000 1700000000 0 0 host 2222; service_up')
    push_connection.sendall(b'live')
    push_client.stdin.write('receive\n')
    push_client.stdin.flush()
    assert push_client.stdout.readline().strip() == 'live', 'Existing inbound server-push connection lost its reply route.'
    assert outbound() == '172.16.0.2'
    assert dns() == '172.16.0.2|dns-probe'
    assert run('curl', '-fsS', '--max-time', '3', '--interface', '192.0.2.1', 'http://203.0.113.10:18082/') == '172.16.0.2'
    assert dns(native=True) == '172.16.0.2|dns-probe'
    assert outbound('other') == '192.0.2.1'
    assert 'eth0' in run('ip', '-4', 'route', 'get', '203.0.113.10', 'from', '10.70.0.2', 'iif', 'csqtt1')
    incoming()
    print('OK: host HTTP/DNS and bound native addresses use WARP; new/existing inbound replies and unselected transit use main.')
    stopped()

    run('sysctl', '-q', '-w', 'net.ipv4.conf.csqtt1.rp_filter=1')
    run('sysctl', '-q', '-w', 'net.ipv4.conf.csqtt2.rp_filter=2')
    manager('write_state csqtt1,csqtt2 51880 18000 1700000000 0 0 host 2222; service_up')
    assert outbound() == outbound('one') == outbound('two') == '172.16.0.2'
    assert outbound('other') == '192.0.2.1'
    incoming()
    print('OK: combined host + two-interface mode works with restrictive FORWARD policy.')
    stopped()
    assert run('sysctl', '-n', 'net.ipv4.conf.csqtt1.rp_filter') == '1'
    assert run('sysctl', '-n', 'net.ipv4.conf.csqtt2.rp_filter') == '2'
print('OK: real offline Linux/WireGuard network checks passed.')
