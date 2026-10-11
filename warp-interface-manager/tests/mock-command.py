#!/usr/bin/env python3
"""Stateful kernel/tool model, confined to the test's temporary directory."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys

root = Path(os.environ['WIM_MOCK_ROOT'])
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / 'calls.log').open('a') as log:
    log.write(name + ' ' + ' '.join(args) + '\n')
state_path = root / 'kernel.json'
state = json.loads(state_path.read_text()) if state_path.exists() else {'rules': [], 'routes': [], 'firewall': [], 'forward': 0}

def save():
    state_path.write_text(json.dumps(state))

def fault(key):
    return os.environ.get('WIM_MOCK_' + key, '0') == '1'

def key(value):
    return base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()

def option(values, flag, default=''):
    return values[values.index(flag) + 1] if flag in values else default

def live():
    return (root / 'warp-up').exists()

def down():
    for p in (root / 'warp-up', root / 'sys/warp-selective/ifindex'):
        p.unlink(missing_ok=True)

def rule_matches(rule, query):
    for flag in ('iif', 'from', 'to', 'fwmark', 'ipproto', 'sport', 'table', 'priority', 'suppress_prefixlength'):
        actual, expected = option(rule, flag), option(query, flag)
        if flag in ('from', 'to'):
            actual, expected = actual.removesuffix('/32'), expected.removesuffix('/32')
        if flag in query and actual != expected:
            return False
    return True

if name == 'ip':
    if args[:3] == ['-4', 'rule', 'show']:
        if fault('FAIL_RULE_SHOW'): sys.exit(1)
        print('0: from all lookup local')
        for rule in sorted(state['rules'], key=lambda r: int(option(r, 'priority'))):
            if fault('MISSING_IIF') and option(rule, 'iif') == 'tun-test': continue
            if fault('MISSING_SECOND_IIF') and option(rule, 'iif') == 'tun-second': continue
            if fault('MISSING_SSH_RULE') and 'sport' in rule: continue
            if fault('MISSING_ENDPOINT_RULE') and 'to' in rule: continue
            if fault('MISSING_REPLY_RULE') and 'fwmark' in rule: continue
            selectors = []
            for flag in ('from', 'to', 'iif', 'fwmark', 'ipproto', 'sport', 'suppress_prefixlength'):
                if flag in rule:
                    selectors.extend([flag, option(rule, flag)])
            if 'from' not in rule: selectors = ['from', 'all'] + selectors
            if fault('WRONG_LOCAL_RULE') and option(rule, 'iif') == 'lo' and option(rule, 'table') != 'main': selectors = ['from', 'all']
            print(option(rule, 'priority') + ': ' + ' '.join(selectors) + ' lookup ' + option(rule, 'table'))
        if fault('GLOBAL_CONFLICT'): print('12000: from all fwmark 0x1 lookup 52000')
        print('32766: from all lookup main\n32767: from all lookup default')
    elif args[:2] == ['-4', 'rule'] and args[2] in ('add', 'del'):
        rule = args[3:]
        if fault('FAIL_RULE_ADD') and args[2] == 'add': sys.exit(1)
        if fault('FAIL_RULE_DELETE') and args[2] == 'del': sys.exit(1)
        if args[2] == 'add': state['rules'].append(rule)
        else:
            match = next((r for r in state['rules'] if rule_matches(r, rule)), None)
            if match is None: sys.exit(2)
            state['rules'].remove(match)
        save()
    elif args[:2] == ['-4', 'route']:
        op = args[2]
        if op == 'show':
            if fault('FAIL_ROUTE_SHOW'): sys.exit(1)
            if 'dev' in args: sys.exit(0)
            table = option(args, 'table', 'main')
            if table in ('main', 'all'): print('default via 192.0.2.1 dev eth0')
            if not fault('MISSING_TABLE_ROUTE'):
                for route in state['routes']:
                    if table == 'all' or option(route, 'table') == table:
                        print('default dev warp-selective' + (' table ' + option(route, 'table') if table == 'all' else ''))
        elif op in ('add', 'del'):
            route = args[3:]
            if op == 'add': state['routes'].append(route)
            elif route in state['routes']: state['routes'].remove(route)
            else: sys.exit(2)
            save()
        elif op == 'get':
            src = option(args, 'from')
            incoming = option(args, 'iif', 'lo')
            mark = int(option(args, 'mark', '0'), 0)
            dev = 'eth0'
            for rule in sorted(state['rules'], key=lambda r: int(option(r, 'priority'))):
                if 'from' in rule and option(rule, 'from').split('/')[0] != src: continue
                if 'iif' in rule and option(rule, 'iif') != incoming: continue
                if 'to' in rule and option(rule, 'to').split('/')[0] != args[3]: continue
                if 'sport' in rule: continue
                if 'fwmark' in rule:
                    value, mask = option(rule, 'fwmark').split('/')
                    if mark & int(mask, 0) != int(value, 0): continue
                if 'suppress_prefixlength' in rule: continue
                dev = 'eth0' if option(rule, 'table') == 'main' else 'warp-selective'
                break
            print(args[3] + ' dev ' + dev + ' src ' + (src or '172.16.0.2'))
    elif args[:3] == ['link', 'show', 'dev']:
        iface = args[3]
        if iface == 'warp-selective':
            if not live(): sys.exit(1)
        elif not (root / 'sys' / iface).is_dir() or (fault('SECOND_DOWN') and iface == 'tun-second'): sys.exit(1)
        print('10: ' + iface + ': <POINTOPOINT,UP,LOWER_UP> mtu 1280 state UNKNOWN')
    elif args[:4] == ['link', 'delete', 'dev', 'warp-selective']:
        if fault('FAIL_DELETE'): sys.exit(1)
        down()
    elif args[:4] == ['-d', '-o', 'link', 'show']:
        print('10: ' + args[-1] + ': <UP> mtu 1500 ' + ('veth' if 'veth' in args[-1] else 'tun'))
    elif args[:2] == ['rule', 'help']:
        print('ipproto PROTOCOL sport NUMBER')
    elif 'addr' in args:
        print('10: tun-test inet 10.70.0.1/24 scope global tun-test')
elif name == 'iptables':
    table = option(args, '-t', 'filter')
    op = next((x for x in args if x in ('-A', '-I', '-C', '-D')), '')
    offset = args.index(op)
    tail = args[offset + 1:]
    if len(tail) > 1 and tail[1].isdigit(): tail = [tail[0]] + tail[2:]
    entry = [table] + tail
    if op == '-C':
        if fault('MISSING_NAT') and table == 'nat': sys.exit(1)
        if fault('MISSING_REPLY_FIREWALL') and table == 'mangle': sys.exit(1)
        sys.exit(0 if entry in state['firewall'] else 1)
    if fault('FAIL_FIREWALL_ADD') and op in ('-A', '-I'): sys.exit(1)
    if fault('FAIL_OUTPUT_ADD') and table == 'mangle' and tail[0] == 'OUTPUT' and op in ('-A', '-I'): sys.exit(1)
    if fault('FAIL_FIREWALL_DELETE') and op == '-D': sys.exit(1)
    if op in ('-A', '-I'): state['firewall'].append(entry)
    elif entry in state['firewall']: state['firewall'].remove(entry)
    else: sys.exit(1)
    save()
elif name == 'iptables-save':
    if fault('FAIL_IPTABLES_SAVE'): sys.exit(1)
    for entry in state['firewall']: print('-A ' + ' '.join(entry[1:]))
    if fault('FOREIGN_MARK'): print('-A OUTPUT -j MARK --set-xmark 0x1/0xffffffff')
elif name == 'nft':
    if fault('FAIL_NFT'): sys.exit(1)
    if fault('FOREIGN_MARK'): print('meta mark set 0x1')
elif name == 'wg':
    if args == ['pubkey']:
        value = sys.stdin.read().strip()
        if not re.fullmatch(r'[A-Za-z0-9+/]{43}=', value): sys.exit(1)
        print(key(value))
    elif args[:2] == ['show', 'warp-selective']:
        if not live() or fault('NOT_WG'): sys.exit(1)
        if args[2:] == ['public-key']: print((root / 'warp-up').read_text())
        elif args[2:] == ['latest-handshakes']: print('peer 1700000000')
        elif args[2:] == ['endpoints']: print('peer ' + ('162.159.192.99:2408' if fault('ROTATED_ENDPOINT') else '162.159.192.1:2408'))
    else: sys.exit(1)
elif name == 'wg-quick':
    if args[0] == 'up':
        if live() or fault('FAIL_UP'): sys.exit(1)
        private = re.search(r'^PrivateKey\s*=\s*(.*)$', Path(args[1]).read_text(), re.M).group(1)
        (root / 'warp-up').write_text(key(private))
        (root / 'sys/warp-selective').mkdir(exist_ok=True)
        (root / 'sys/warp-selective/ifindex').write_text('42')
    else:
        if fault('SWAP_DURING_DOWN'):
            (root / 'warp-up').write_text(key('foreign'))
            (root / 'sys/warp-selective/ifindex').write_text('43')
        if fault('FAIL_DOWN') or fault('SWAP_DURING_DOWN'): sys.exit(1)
        down()
elif name == 'getent':
    print('162.159.192.1 STREAM engage.cloudflareclient.com')
elif name == 'curl':
    once = root / 'curl-fail-once'
    if once.exists(): once.unlink(); sys.exit(28)
    if fault('FAIL_CURL'): sys.exit(28)
    print('warp=on\nip=203.0.113.8')
elif name == 'sysctl':
    if args[0] == '-n': print('0' if fault('FORWARD_OFF') else state['forward'])
    else:
        state['forward'] = int(args[-1].split('=')[-1])
        save()
else:
    raise RuntimeError('Unexpected mock command: ' + name)
