"""Independent Python RNS/LXMF echo peer, isolated loopback test transport.
Use a new temporary directory for each run; never point at a real identity store.
"""
import argparse
import json
import os
import threading
import time
from pathlib import Path
import RNS
import LXMF

parser = argparse.ArgumentParser()
parser.add_argument('--directory', required=True)
parser.add_argument('--port', type=int, default=14242)
args = parser.parse_args()
root = Path(args.directory)
root.mkdir(parents=True, exist_ok=True)
(root / 'rns').mkdir(exist_ok=True)
(root / 'rns' / 'config').write_text(f'''[reticulum]
enable_transport = yes
share_instance = no
[logging]
loglevel = 0
[interfaces]
  [[Browser test TCP]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {args.port}
''')
rns = RNS.Reticulum(configdir=str(root / 'rns'), loglevel=0)
identity = RNS.Identity()
router = LXMF.LXMRouter(storagepath=str(root / 'lxmf'), autopeer=False)
destination = router.register_delivery_identity(identity, display_name='Independent Python test peer', stamp_cost=None)

def emit(event, **data):
    print(json.dumps({'event': event, **data}), flush=True)

def received(message):
    text = message.content.decode('utf-8', errors='replace')
    valid = bool(message.signature_validated)
    emit('received', source=message.source_hash.hex(), content=text, signature_validated=valid)
    if not valid:
        return
    def reply():
        peer_identity = RNS.Identity.recall(message.source_hash)
        if peer_identity is None:
            emit('error', reason='Sender identity not recalled')
            return
        peer = RNS.Destination(peer_identity, RNS.Destination.OUT, RNS.Destination.SINGLE, 'lxmf', 'delivery')
        outgoing = LXMF.LXMessage(peer, destination, 'Python echo: ' + text, desired_method=LXMF.LXMessage.DIRECT)
        outgoing.register_delivery_callback(lambda m: emit('reply-delivered', destination=m.destination_hash.hex()))
        outgoing.register_failed_callback(lambda m: emit('reply-failed', destination=m.destination_hash.hex()))
        router.handle_outbound(outgoing)
    threading.Thread(target=reply, daemon=True).start()

router.register_delivery_callback(received)
emit('ready', address=destination.hash.hex(), rns_version=RNS.__version__, lxmf_version=LXMF.__version__, tcp_port=args.port)
while True:
    router.announce(destination.hash)
    time.sleep(5)
