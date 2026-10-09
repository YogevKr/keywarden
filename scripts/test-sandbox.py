#!/usr/bin/env python3
"""Probe the same-user sandbox using synthetic files and sockets only."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading

repo = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='kw-sandbox-', dir='/tmp') as root:
    root = Path(root).resolve()
    workspace = root / 'workspace'
    workspace.mkdir()
    client = root / 'keywarden'
    shutil.copy2(repo / 'apps/broker-rs/target/debug/keywarden-broker', client)
    secret = root / 'synthetic-private-file'
    secret.write_text('synthetic test value')
    (workspace / 'secret-link').symlink_to(secret)
    broker_socket = root / 'broker.sock'
    admin_socket = root / 'broker.admin.sock'
    sockets = []
    for path in [broker_socket, admin_socket]:
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(path))
        server.listen()
        server.settimeout(10)
        sockets.append(server)
    probe = workspace / 'probe.py'
    probe.write_text('''import json, os, socket, subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
checks = {}
for name, path in [('private_file', root/'synthetic-private-file'), ('symlink', Path('secret-link'))]:
    try: path.read_text(); checks[name] = False
    except PermissionError: checks[name] = True
for name,path in [('broker',root/'broker.sock'),('admin_blocked',root/'broker.admin.sock')]:
    s=socket.socket(socket.AF_UNIX)
    try: s.connect(str(path)); checks[name]=(name=='broker')
    except PermissionError: checks[name]=(name=='admin_blocked')
    finally: s.close()
Path('allowed-output').write_text('ok')
checks['workspace_write'] = Path('allowed-output').read_text()=='ok'
checks['inherited_token_removed'] = 'OP_SERVICE_ACCOUNT_TOKEN' not in os.environ and 'KEYWARDEN_RELAY_TOKEN' not in os.environ
for name, command in [('opgate_blocked',['/opt/homebrew/bin/opgate','--help']),('op_blocked',['/opt/homebrew/bin/op','--version'])]:
    try: result=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); checks[name]=result.returncode!=0
    except PermissionError: checks[name]=True
print(json.dumps(checks))
sys.exit(0 if all(checks.values()) else 1)
''')
    command = [str(client),'run','--workspace',str(workspace),'--','/opt/homebrew/bin/python3',str(probe),str(root)]
    result = subprocess.run(command,env={**os.environ,'KEYWARDEN_SOCKET':str(broker_socket),'OP_SERVICE_ACCOUNT_TOKEN':'synthetic-token','KEYWARDEN_RELAY_TOKEN':'synthetic-token'},capture_output=True,text=True,timeout=30)
    print(result.stdout,end='')
    if result.returncode:
        print(result.stderr,end='')
        raise SystemExit(result.returncode)
    for server in sockets: server.close()
