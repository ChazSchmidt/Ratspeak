# Reticulum transport and reproducible interoperability tests

## Bridge contract

The browser sends one raw binary Reticulum packet per WebSocket message. The
bridge wraps each packet in Reticulum TCP HDLC framing (`7e` delimiter, `7d`
escape, XOR `20`) and reverses that framing on the return path. Each browser
connection gets its own TCP connection to the configured native Reticulum node.
This is not a plaintext chat server, mock relay, or LXMF implementation.

Run a native Reticulum node with a TCP server interface, for example the official
Python `rnsd` with this added to its configuration:

```ini
[reticulum]
enable_transport = yes

[interfaces]
  [[Browser bridge TCP]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = 4242
```

With dependencies installed in `web/`, start the bridge:

```sh
RNS_TCP_HOST=127.0.0.1 RNS_TCP_PORT=4242 \
ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173 \
node scripts/reticulum-bridge.mjs
```

Connect the local client to `ws://127.0.0.1:8787`. The native node must have other
Reticulum interfaces configured if users on other nodes are to be reachable.
The bridge by itself does not provide Internet Reticulum connectivity.

For remote HTTPS hosting, terminate valid TLS at a reverse proxy supporting
WebSocket upgrades, proxy to the loopback bridge, set `ALLOWED_ORIGINS` to the
exact deployed HTTPS origin, and connect the browser to the proxy's `wss://`
URL. Static hosting alone does not supply a gateway. Do not expose the native
TCP port or an unrestricted bridge as a substitute for a reviewed deployment.
The allowlist is a browser-origin check, not authentication against arbitrary
non-browser clients. Deployers need suitable access/rate limits and abuse controls.

The bridge has no identity keys or message storage and does not parse/decrypt
LXMF. It can observe client IPs, timing, packet sizes, routing headers, public
announces and destinations. It can disrupt, drop or replay traffic. Operators
must not describe gateway use as anonymous. The hosting origin and delivered
JavaScript remain trusted: compromised frontend JavaScript could steal browser
keys or plaintext before encryption. TLS on the gateway does not remove this risk.

## Local reference-implementation test

Create an isolated Python environment with the official PyPI packages:

```sh
python3 -m venv /tmp/ratspeak-interop-venv
/tmp/ratspeak-interop-venv/bin/pip install rns==1.5.7 lxmf==1.2.1
node --test tests/bridge.test.mjs
PYTHON=/tmp/ratspeak-interop-venv/bin/python node tests/transport-interop.mjs
```

The integration script creates fresh temporary identities, starts the Python
Reticulum TCP node and LXMF echo destination, starts the bridge, then runs two
independent JavaScript stacks through the actual `MessagingClient` public
init/connect/send/disconnect/reconnect/close APIs. Incoming JavaScript and Python
messages must also report `verified: true` from the adapter. Everything is local to one process tree; this
also works in environments that isolate loopback between separate commands.
Do not point the test peer at an existing identity/configuration directory.

Verified on 2026-10-20 with `@reticulum/core` and `@reticulum/lxmf` 0.9.13:

- JavaScript A to JavaScript B through a real native Reticulum TCP transport.
- JavaScript to independent Python LXMF, with Python explicitly reporting a
  validated message signature.
- Python encrypted LXMF echo received/decrypted by JavaScript A.
- Replacing a disconnected WebSocket bearer while retaining the identity and
  receiving another message after reconnection.
- The unique test message plaintext absent from all 42 captured raw gateway
  packet frames. This narrow regression check is not a cryptographic audit.
- Unit checks cover HDLC fragmentation/escaping/bounds, origin rejection,
  binary forwarding and rejection of text WebSocket messages.

This fixture uses Node, not browser sessions. It proves a bounded reference-
implementation interoperability case, not full Ratspeak native interoperability,
public-network reliability, general protocol compliance or browser UX readiness.
The browser smoke test must be reported separately. A successful direct send
means data was sent to an encrypted link; the library's small-message send
promise does not itself wait for application delivery or a read receipt.

Primary protocol references:
- https://github.com/markqvist/Reticulum/blob/master/RNS/Interfaces/TCPInterface.py
- https://github.com/markqvist/LXMF
- https://github.com/bergie/reticulum-js
