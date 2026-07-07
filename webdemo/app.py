#!/usr/bin/env python3
"""SiFT web demo — drive a real client/server session from the browser.

This is the "run it live" demo. It starts a genuine SiFT server in-process, and
the web UI acts as a genuine SiFT client against it, so the crypto you see is the
real crypto. Two panels make the protocol observable:

* **Wire panel** — every message the client sends/receives, decoded: header fields,
  nonce, ciphertext (hex), MAC, verification status, sequence number, key
  fingerprint. Fed by the MTP ``tracer`` hook (which redacts key material to a
  fingerprint — no secrets are shown).
* **Security dashboard** — a SIEM-lite live view of the server's ``SecurityMonitor``:
  the event stream, the detection alerts, and event counts. The "attack" buttons
  generate real malicious traffic so you can watch the alerts fire.

    python webdemo/app.py --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import threading

from flask import Flask, jsonify, render_template_string, request, send_file

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Hash import SHA256  # noqa: E402
from Crypto.Protocol.KDF import PBKDF2  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402

from siftprotocols import monitoring  # noqa: E402
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error  # noqa: E402
from siftprotocols.siftlogin import LoginGuard, SiFT_LOGIN, SiFT_LOGIN_Error  # noqa: E402
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error  # noqa: E402
from siftprotocols.siftupl import SiFT_UPL, SiFT_UPL_Error  # noqa: E402
from siftprotocols.siftdnl import SiFT_DNL, SiFT_DNL_Error  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_demo_root") + os.sep

app = Flask(__name__)

# ---- shared server state (embedded SiFT server) --------------------------------
MONITOR = monitoring.SecurityMonitor()
GUARD = LoginGuard(monitor=MONITOR)
SERVER_KEY = RSA.generate(2048)
PUBKEY = SERVER_KEY.publickey()
PUBKEY_FPR = SHA256.new(PUBKEY.export_key(format="DER")).hexdigest()
SERVER_PORT: int = 0
USERS: dict = {}

_client_lock = threading.Lock()


def load_users() -> dict:
    """Load users.txt if present, else fall back to a single demo user."""
    path = os.path.join(REPO, "server", "users.txt")
    users = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                fields = line.split(":")
                users[fields[0]] = {
                    "pwdhash": bytes.fromhex(fields[1]), "icount": int(fields[2]),
                    "salt": bytes.fromhex(fields[3]), "rootdir": fields[4],
                }
    if not users:
        salt = os.urandom(16)
        users["alice"] = {"pwdhash": PBKDF2("aaa", salt, 32, count=100000, hmac_hash_module=SHA256),
                          "icount": 100000, "salt": salt, "rootdir": "alice/"}
    for u in users:
        os.makedirs(os.path.join(DEMO_ROOT, users[u]["rootdir"]), exist_ok=True)
    return users


def _server_handle(conn, addr):
    peer = f"{addr[0]}:{addr[1]}"
    MONITOR.record(monitoring.EVT_SESSION_START, peer=peer)
    mtp = SiFT_MTP(conn, role="server", server_privkey=SERVER_KEY, monitor=MONITOR, peer_name=peer)
    try:
        loginp = SiFT_LOGIN(mtp, guard=GUARD)
        loginp.set_server_users(USERS)
        user, _, _ = loginp.handle_login_server()
        cmdp = SiFT_CMD(mtp)
        cmdp.set_server_rootdir(DEMO_ROOT)
        cmdp.set_user_rootdir(USERS[user]["rootdir"])
        while True:
            cmdp.receive_command()
    except (SiFT_LOGIN_Error, SiFT_CMD_Error, SiFT_MTP_Error, SiFT_UPL_Error, SiFT_DNL_Error):
        pass
    finally:
        MONITOR.record(monitoring.EVT_SESSION_END, peer=peer)
        conn.close()


def start_embedded_server() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def accept_loop():
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=_server_handle, args=(conn, addr), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return port


class BrowserSession:
    """One browser's live SiFT client connection + its captured wire trace."""

    def __init__(self):
        self.wire: list[dict] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(("127.0.0.1", SERVER_PORT))
        self.mtp = SiFT_MTP(self.sock, role="client", server_pubkey=PUBKEY,
                            tracer=self._trace)
        self.cmdp = SiFT_CMD(self.mtp)
        self.user = None

    def _trace(self, event: dict):
        self.wire.append(event)
        del self.wire[:-200]  # keep the last 200 frames

    def login(self, username, password):
        SiFT_LOGIN(self.mtp).handle_login_client(username, password)
        self.user = username

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


SESSION: BrowserSession | None = None


# ---- API -----------------------------------------------------------------------

@app.post("/api/login")
def api_login():
    global SESSION
    data = request.get_json(force=True)
    with _client_lock:
        if SESSION:
            SESSION.close()
        try:
            SESSION = BrowserSession()
            SESSION.login(data["username"], data["password"])
        except (SiFT_LOGIN_Error, SiFT_MTP_Error) as e:
            SESSION = None
            return jsonify(ok=False, error=e.err_msg), 401
    return jsonify(ok=True, user=data["username"], fingerprint=PUBKEY_FPR)


CMD_MAP = {"pwd": "pwd", "ls": "lst", "cd": "chd", "mkd": "mkd", "del": "del"}


@app.post("/api/command")
def api_command():
    data = request.get_json(force=True)
    name, arg = data.get("command"), data.get("arg", "")
    if not SESSION:
        return jsonify(ok=False, error="not logged in"), 401
    if name not in CMD_MAP:
        return jsonify(ok=False, error="unsupported command"), 400
    req = {"command": CMD_MAP[name]}
    if name in ("cd", "mkd", "del"):
        req["param_1"] = arg
    with _client_lock:
        try:
            res = SESSION.cmdp.send_command(req)
        except SiFT_CMD_Error as e:
            return jsonify(ok=False, error=e.err_msg), 400
    return jsonify(ok=True, result=res.get("result_1"), detail=res.get("result_2", ""))


@app.post("/api/upload")
def api_upload():
    if not SESSION:
        return jsonify(ok=False, error="not logged in"), 401
    f = request.files.get("file")
    if not f:
        return jsonify(ok=False, error="no file"), 400
    data = f.read()
    tmp = os.path.join(DEMO_ROOT, "_upload_tmp")
    with open(tmp, "wb") as out:
        out.write(data)
    file_hash = SHA256.new(data).digest()
    req = {"command": "upl", "param_1": os.path.basename(f.filename),
           "param_2": len(data), "param_3": file_hash}
    with _client_lock:
        try:
            res = SESSION.cmdp.send_command(req)
            if res["result_1"] != "accept":
                return jsonify(ok=False, error=res.get("result_2", "rejected")), 400
            SiFT_UPL(SESSION.mtp).handle_upload_client(tmp)
        except (SiFT_CMD_Error, SiFT_UPL_Error) as e:
            return jsonify(ok=False, error=e.err_msg), 400
        finally:
            os.remove(tmp)
    return jsonify(ok=True, name=req["param_1"], size=len(data), hash=file_hash.hex())


@app.get("/api/wire")
def api_wire():
    since = int(request.args.get("since", 0))
    frames = SESSION.wire[since:] if SESSION else []
    return jsonify(count=len(SESSION.wire) if SESSION else 0, frames=frames)


@app.get("/api/monitor")
def api_monitor():
    since = int(request.args.get("since", 0))
    return jsonify(events=MONITOR.events(since_seq=since), alerts=MONITOR.alerts(),
                   summary=MONITOR.summary())


@app.post("/api/attack")
def api_attack():
    """Generate real malicious traffic so the dashboard visibly reacts."""
    kind = request.get_json(force=True).get("kind")
    if kind == "bruteforce":
        # Target a throwaway username so the real demo user is not locked out.
        for _ in range(6):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", SERVER_PORT))
            m = SiFT_MTP(s, role="client", server_pubkey=PUBKEY)
            try:
                SiFT_LOGIN(m).handle_login_client("mallory", "guessing")
            except (SiFT_LOGIN_Error, SiFT_MTP_Error):
                pass
            s.close()
        return jsonify(ok=True, msg="6 bad logins for 'mallory' sent → expect a brute_force_login alert")
    if kind == "traversal":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", SERVER_PORT))
        m = SiFT_MTP(s, role="client", server_pubkey=PUBKEY)
        try:
            SiFT_LOGIN(m).handle_login_client("alice", "aaa")
            c = SiFT_CMD(m)
            for name in ("../escape", "../../etc/passwd"):
                c.send_command({"command": "mkd", "param_1": name})
        except (SiFT_LOGIN_Error, SiFT_CMD_Error, SiFT_MTP_Error):
            pass
        s.close()
        return jsonify(ok=True, msg="path-traversal attempts sent → expect path_traversal alerts")
    if kind == "tamper":
        # Send several tampered frames (each on its own session, since the server
        # closes the connection after a MAC failure) to cross the detection threshold.
        for _ in range(3):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", SERVER_PORT))
            m = SiFT_MTP(s, role="client", server_pubkey=PUBKEY)
            try:
                SiFT_LOGIN(m).handle_login_client("alice", "aaa")
                # Build a real command frame, corrupt one ciphertext byte, send it raw.
                captured = {}
                orig = m.send_bytes
                m.send_bytes = lambda b: captured.__setitem__("f", b)  # type: ignore
                m.send_msg(m.type_command_req, b"pwd")
                m.send_bytes = orig  # type: ignore
                frame = bytearray(captured["f"])
                frame[20] ^= 0x40
                s.sendall(bytes(frame))
                s.settimeout(1)
                try:
                    s.recv(16)
                except OSError:
                    pass
            except (SiFT_LOGIN_Error, SiFT_MTP_Error):
                pass
            s.close()
        return jsonify(ok=True, msg="3 tampered frames sent → expect mac_failure events + a tampering_suspected alert")
    return jsonify(ok=False, error="unknown attack"), 400


@app.get("/")
def index():
    return render_template_string(INDEX_HTML, fingerprint=PUBKEY_FPR)


INDEX_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SiFT — Live Protocol Demo</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3; --muted:#8b949e;
          --accent:#58a6ff; --good:#3fb950; --warn:#d29922; --bad:#f85149; --mono:ui-monospace,SFMono-Regular,Menlo,monospace; }
  * { box-sizing:border-box; } body { margin:0; background:var(--bg); color:var(--fg);
      font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:14px 20px; border-bottom:1px solid var(--border); display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }
  header h1 { font-size:18px; margin:0; } header .fpr { color:var(--muted); font-family:var(--mono); font-size:12px; }
  .wrap { display:grid; grid-template-columns:1fr 1fr; gap:14px; padding:14px; }
  @media (max-width:900px){ .wrap{ grid-template-columns:1fr; } }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px; min-width:0; }
  .panel h2 { font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:0 0 10px; }
  input,button,select { font:inherit; } input { background:#0d1117; border:1px solid var(--border); color:var(--fg); border-radius:6px; padding:6px 8px; }
  button { background:#21262d; border:1px solid var(--border); color:var(--fg); border-radius:6px; padding:6px 10px; cursor:pointer; }
  button:hover { border-color:var(--accent); } button.attack { border-color:#5a2a2a; color:#ffb4ab; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:8px; }
  .out { font-family:var(--mono); font-size:12.5px; white-space:pre-wrap; background:#0d1117; border:1px solid var(--border);
         border-radius:6px; padding:10px; min-height:40px; }
  .frames, .events { max-height:340px; overflow:auto; font-family:var(--mono); font-size:11.5px; }
  .frame { border:1px solid var(--border); border-radius:6px; padding:8px; margin-bottom:8px; }
  .frame .hd { display:flex; justify-content:space-between; color:var(--muted); margin-bottom:4px; }
  .send { border-left:3px solid var(--accent); } .recv { border-left:3px solid var(--good); } .bad { border-left:3px solid var(--bad); }
  .kv { color:var(--muted); } .hex { color:#a5d6ff; word-break:break-all; } .mac-ok{ color:var(--good);} .mac-bad{ color:var(--bad);}
  .evt { padding:4px 6px; border-bottom:1px solid #21262d; } .lvl-alert{ color:var(--bad); font-weight:600;} .lvl-warning{ color:var(--warn);}
  .alerts { margin-bottom:10px; } .alert { background:#2b1416; border:1px solid #5a2a2a; color:#ffb4ab; border-radius:6px; padding:8px; margin-bottom:6px; }
  .pills span { display:inline-block; background:#0d1117; border:1px solid var(--border); border-radius:20px; padding:2px 9px; margin:2px; font-size:11px; color:var(--muted); }
  .muted { color:var(--muted); } .tag{ font-size:10px; padding:1px 6px; border-radius:4px; background:#21262d; color:var(--muted);}
</style></head>
<body>
<header>
  <h1>🔐 SiFT — Live Secure File Transfer</h1>
  <span class="fpr">server key fingerprint (pin this): {{ fingerprint }}</span>
</header>
<div class="wrap">
  <div class="panel">
    <h2>Session</h2>
    <div class="row">
      <input id="user" placeholder="username" value="alice" size="10">
      <input id="pass" type="password" placeholder="password" value="aaa" size="10">
      <button onclick="login()">Log in</button>
      <span id="who" class="muted"></span>
    </div>
    <h2>Commands</h2>
    <div class="row">
      <button onclick="cmd('pwd')">pwd</button>
      <button onclick="cmd('ls')">ls</button>
      <input id="arg" placeholder="dir / file name" size="14">
      <button onclick="cmdArg('cd')">cd</button>
      <button onclick="cmdArg('mkd')">mkd</button>
      <button onclick="cmdArg('del')">del</button>
    </div>
    <div class="row">
      <input type="file" id="file">
      <button onclick="upload()">upl (upload)</button>
    </div>
    <div id="out" class="out">Log in as alice / aaa to begin.</div>

    <h2 style="margin-top:16px">Attacks (watch the dashboard react →)</h2>
    <div class="row">
      <button class="attack" onclick="attack('bruteforce')">Brute-force login</button>
      <button class="attack" onclick="attack('traversal')">Path traversal</button>
      <button class="attack" onclick="attack('tamper')">Tamper a frame</button>
    </div>
    <div id="attackout" class="muted" style="font-size:12px"></div>
  </div>

  <div class="panel">
    <h2>Wire — every message, decoded (ciphertext only; no secrets)</h2>
    <div id="frames" class="frames"><span class="muted">No traffic yet.</span></div>
    <h2 style="margin-top:14px">Security dashboard <span class="tag">SIEM-lite</span></h2>
    <div id="alerts" class="alerts"></div>
    <div id="pills" class="pills"></div>
    <div id="events" class="events"></div>
  </div>
</div>
<script>
let wireSince = 0, evtSince = 0;
const $ = id => document.getElementById(id);
async function post(url, body){ const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})}); return r.json(); }
async function login(){
  const r = await post('/api/login',{username:$('user').value,password:$('pass').value});
  if(r.ok){ $('who').textContent = 'logged in as '+r.user; $('out').textContent='Session established.\nDerived directional AES-256-GCM keys via HKDF.'; wireSince=0; }
  else { $('who').textContent=''; $('out').textContent='Login error: '+r.error; }
}
async function cmd(name){ const r = await post('/api/command',{command:name}); render(r); }
async function cmdArg(name){ const r = await post('/api/command',{command:name, arg:$('arg').value}); render(r); }
function render(r){ $('out').textContent = r.ok ? ((r.result||'')+(r.detail?'\n'+r.detail:'')) : ('Error: '+r.error); }
async function upload(){
  const f=$('file').files[0]; if(!f){ $('out').textContent='pick a file first'; return; }
  const fd=new FormData(); fd.append('file',f);
  const r= await (await fetch('/api/upload',{method:'POST',body:fd})).json();
  $('out').textContent = r.ok ? ('uploaded '+r.name+' ('+r.size+' bytes)\nserver-verified SHA-256: '+r.hash) : ('Error: '+r.error);
}
async function attack(kind){ const r= await post('/api/attack',{kind}); $('attackout').textContent = r.ok? ('▶ '+r.msg) : ('error: '+r.error); }

function esc(s){ return (s||'').toString().replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function trunc(s,n){ s=s||''; return s.length>n ? s.slice(0,n)+'…' : s; }
async function pollWire(){
  try{
    const r = await (await fetch('/api/wire?since='+wireSince)).json();
    if(r.frames && r.frames.length){
      const box=$('frames'); if(wireSince===0) box.innerHTML='';
      for(const f of r.frames){
        const cls = f.direction==='send'?'send':(f.verified?'recv':'bad');
        const mac = f.verified? '<span class="mac-ok">verified</span>':'<span class="mac-bad">MAC FAIL</span>';
        const div=document.createElement('div'); div.className='frame '+cls;
        div.innerHTML = '<div class="hd"><span>'+(f.direction==='send'?'▲ SEND':'▼ RECV')+' · <b>'+esc(f.type)+'</b> · sqn '+f.sqn+'</span><span>'+mac+'</span></div>'+
          '<div><span class="kv">nonce</span> <span class="hex">'+esc(f.nonce)+'</span></div>'+
          '<div><span class="kv">cipher</span> <span class="hex">'+esc(trunc(f.ciphertext,80))+'</span></div>'+
          '<div><span class="kv">mac</span> <span class="hex">'+esc(f.mac)+'</span> · <span class="kv">key</span> '+esc(f.key_fpr)+(f.etk?' · <span class="kv">etk</span> '+esc(trunc(f.etk,24)):'')+'</div>';
        box.appendChild(div);
      }
      wireSince = r.count; $('frames').scrollTop = $('frames').scrollHeight;
    }
  }catch(e){}
}
async function pollMonitor(){
  try{
    const r = await (await fetch('/api/monitor?since='+evtSince)).json();
    const al=$('alerts'); al.innerHTML='';
    for(const a of (r.alerts||[])) al.innerHTML += '<div class="alert">🚨 <b>'+esc(a.rule)+'</b> — '+esc(a.detail||'')+'</div>';
    const pills=$('pills'); pills.innerHTML='';
    for(const k in (r.summary||{})) pills.innerHTML += '<span>'+esc(k)+': '+r.summary[k]+'</span>';
    if(r.events && r.events.length){
      const box=$('events');
      for(const e of r.events){
        const d=document.createElement('div'); d.className='evt lvl-'+e.level;
        d.textContent = '['+e.level+'] '+e.event+(e.username?' user='+e.username:'')+(e.peer?' peer='+e.peer:'')+(e.name?' name='+e.name:'');
        box.appendChild(d); evtSince=e.seq;
      }
      box.scrollTop = box.scrollHeight;
    }
  }catch(e){}
}
setInterval(pollWire, 800); setInterval(pollMonitor, 800);
</script>
</body></html>"""


def main():
    global SERVER_PORT, USERS
    parser = argparse.ArgumentParser(description="SiFT web demo")
    parser.add_argument("--host", default="127.0.0.1", help="web UI bind host")
    parser.add_argument("--port", type=int, default=8000, help="web UI port")
    # Accepted for docker-compose compatibility; the demo embeds its own server.
    parser.add_argument("--sift-host", default=None)
    parser.add_argument("--sift-port", default=None)
    args = parser.parse_args()

    os.makedirs(DEMO_ROOT, exist_ok=True)
    USERS = load_users()
    SERVER_PORT = start_embedded_server()
    print(f"Embedded SiFT server on 127.0.0.1:{SERVER_PORT}")
    print(f"Web demo at http://{args.host}:{args.port}  (login alice / aaa)")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
