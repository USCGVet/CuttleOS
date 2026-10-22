#!/usr/bin/env python3
"""
Cuttle Fleet: one provider managing isolated client farms of Triads
====================================================================

    provider ── client farm (own OS process, master key, client token, state dir, port block)
                 └─ Triads by job: web (wfe) · sql · index · cron  (kernel role profiles)
                      └─ 3 VMs each (2-of-3 vote, WAL, rolling MTD morphs)

Usage:
    python tools/cuttle_fleet.py                 # provider: launch every farm, serve /fleet
    python tools/cuttle_fleet.py farm --client X # one client farm (launched by the provider)
    python tools/cuttle_fleet.py --self-test     # isolation + auth self-test on a 2-client fleet

Plans, jobs and clients come from tools/fleet.toml. State lives under
target/cuttle_images/fleet/<client>/ (gitignored).

Trust boundaries:
  * The provider token sees and manages every client. A client token sees only that client.
  * Farms bind 127.0.0.1 and accept only the per-run secret the provider passes them in the
    environment; browsers never talk to a farm directly.
  * Fleet VMs run with host loopback port forwarding disabled (`forward_node_ports=False`), so
    one client process on the host cannot connect directly to another client's VM `:80`/`:443`.
  * Each client farm derives its node device keys from its own random master key, so no key
    material is shared between clients.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import triad_controller as tc  # noqa: E402

FLEET_CONFIG = tc.ROOT / "tools" / "fleet.toml"
FLEET_DIR = tc.IMAGES_DIR / "fleet"
FARM_SECRET_ENV = "CUTTLE_FARM_SECRET"
FLEET_DIR_ENV = "CUTTLE_FLEET_DIR"
CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
VALID_ROLES = ("wfe", "sql", "shell", "full")
# Service whose request counter is a job's headline KPI.
PRIMARY_SERVICE = {"wfe": "svc-http", "sql": "svc-sql", "shell": "svc-sh", "full": "svc-sh"}
HISTORY_LEN = 60


# --------------------------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------------------------

def load_fleet_config(path: Path = FLEET_CONFIG) -> dict:
    cfg = tomllib.loads(path.read_text(encoding="utf-8"))
    jobs, plans, clients = cfg.get("jobs", {}), cfg.get("plans", {}), cfg.get("clients", [])
    for job_id, job in jobs.items():
        if job.get("role") not in VALID_ROLES:
            raise ValueError(f"job '{job_id}': role must be one of {VALID_ROLES}")
    for plan_id, plan in plans.items():
        for job_id in plan.get("jobs", []):
            if job_id not in jobs:
                raise ValueError(f"plan '{plan_id}' uses unknown job '{job_id}'")
        if not 1 <= len(plan.get("jobs", [])) <= 5:
            raise ValueError(
                f"plan '{plan_id}' must have 1-5 jobs (port block is 100 per client with +50 HTTPS offset)"
            )
    for where, value in [("provider", cfg.get("provider", {}).get("accelerator"))] + [
        (f"plan '{p}'", v.get("accelerator")) for p, v in plans.items()
    ]:
        if value is not None and value not in tc.ACCELERATORS:
            raise ValueError(f"{where}: accelerator must be one of {tc.ACCELERATORS}")
    seen = set()
    for c in clients:
        if not CLIENT_ID_RE.match(c.get("id", "")):
            raise ValueError(f"client id {c.get('id')!r} must match {CLIENT_ID_RE.pattern}")
        if c["id"] in seen:
            raise ValueError(f"duplicate client id '{c['id']}'")
        if c.get("plan") not in plans:
            raise ValueError(f"client '{c['id']}' uses unknown plan '{c.get('plan')}'")
        seen.add(c["id"])

    prov = cfg.get("provider", {})
    port_owners: dict[int, str] = {}

    def claim_port(p: int, label: str):
        if not isinstance(p, int) or isinstance(p, bool) or not (1024 <= p <= 65535):
            raise ValueError(f"{label}: port {p!r} must be an integer in 1024..65535")
        if p in port_owners:
            raise ValueError(f"port collision on {p}: {label} collides with {port_owners[p]}")
        port_owners[p] = label

    if "port" in prov:
        claim_port(prov["port"], "provider.port")
    farm_base = prov.get("farm_port_base", 18900)
    vm_base = prov.get("vm_port_base", 20000)
    for slot, c in enumerate(clients):
        cid = c["id"]
        claim_port(farm_base + slot, f"client '{cid}' farm port")
        plan_jobs = plans[c["plan"]].get("jobs", [])
        for t, job_id in enumerate(plan_jobs):
            base = vm_base + slot * 100 + t * 10
            for nid in (1, 2, 3):
                claim_port(base + nid, f"client '{cid}' job '{job_id}' node {nid} http_port")
                claim_port(base + 50 + nid, f"client '{cid}' job '{job_id}' node {nid} https_port")
    return cfg


def fleet_dir() -> Path:
    override = os.environ.get(FLEET_DIR_ENV)
    return Path(override) if override else FLEET_DIR


def client_slot(cfg: dict, client_id: str) -> int:
    for i, c in enumerate(cfg["clients"]):
        if c["id"] == client_id:
            return i
    raise KeyError(client_id)


def _seed(*parts) -> int:
    digest = hashlib.sha256(":".join(str(p) for p in parts).encode()).digest()
    return 100_000 + int.from_bytes(digest[:4], "little") % 900_000


def triad_specs(cfg: dict, client: dict) -> list:
    """One TriadSpec per job in the client's plan, each with its own ports and state dir."""
    slot = client_slot(cfg, client["id"])
    prov, plan = cfg["provider"], cfg["plans"][client["plan"]]
    cdir = fleet_dir() / client["id"]
    # CUTTLE_ACCEL (set by `--accel` on the provider) overrides the plan, then the fleet default.
    accel = os.environ.get("CUTTLE_ACCEL") or plan.get("accelerator") or prov.get("accelerator", "auto")
    specs = []
    for t, job_id in enumerate(plan["jobs"]):
        job = cfg["jobs"][job_id]
        base = prov["vm_port_base"] + slot * 100 + t * 10
        short = job.get("short", job_id)
        specs.append(
            tc.TriadSpec(
                name=f"{client['id']}-{job_id}",
                job=job_id,
                role=job["role"],
                state_dir=cdir / job_id,
                master_key_path=cdir / "master_key.bin",
                key_context=f"cuttle-farm-node-v1:{client['id']}:{job_id}",
                http_base=base,
                https_base=base + 50,
                smp=int(plan.get("vcpus", 2)),
                memory=str(plan.get("memory", "128M")),
                accel=accel,
                node_names=tuple(f"OS-{i} ({short}-{x})" for i, x in ((1, "A"), (2, "B"), (3, "C"))),
                node_roles=tuple(f"{job.get('label', job_id).upper()} · REPLICA {x}" for x in "ABC"),
                base_seeds=tuple(_seed(client["id"], job_id, i) for i in (1, 2, 3)),
                vote_tables=tuple(job.get("vote_tables", ["kv"])),
                provision_sql=tuple(job.get("provision_sql", [])),
                cron_jobs=tuple((int(a), str(b)) for a, b in job.get("cron", [])),
                log_prefix=f"[{client['id']}/{job_id}] ",
                write_operator_token=False,
                forward_node_ports=False,
            )
        )
    return specs


def load_or_create_secret(path: Path, nbytes: int = 16, binary: bool = False):
    return tc.load_or_create_secret_file(path, nbytes=nbytes, binary=binary)


# --------------------------------------------------------------------------------------------
# farm (one process per client)
# --------------------------------------------------------------------------------------------

def parse_service_status(out: str) -> dict:
    """`service status` -> {'role': .., 'svc': {name: {'state', 'reqs', 'denials'}}}."""
    info = {"role": None, "svc": {}}
    m = re.search(r"role=(\w+)", out)
    if m:
        info["role"] = m.group(1)
    for ln in out.splitlines():
        m = re.match(r"\s*(svc-\w+) .*?state=(\w+).*?reqs=(\d+).*?denials=(\d+)", ln)
        if m:
            info["svc"][m.group(1)] = {"state": m.group(2), "reqs": int(m.group(3)), "denials": int(m.group(4))}
    return info


def _num(pattern: str, text: str):
    m = re.search(pattern, text or "")
    return int(m.group(1)) if m else None


class Farm:
    """One client's Triads, their per-role telemetry and optional synthetic load."""

    def __init__(self, cfg: dict, client: dict):
        self.cfg = cfg
        self.client = client
        self.plan_id = client["plan"]
        self.plan = cfg["plans"][self.plan_id]
        (fleet_dir() / client["id"]).mkdir(parents=True, exist_ok=True)
        load_or_create_secret(fleet_dir() / client["id"] / "master_key.bin", 32, binary=True)
        self.triads: dict = {}
        for spec in triad_specs(cfg, client):
            self.triads[spec.job] = tc.TriadController(show_gui=False, spec=spec)
        self.load_enabled = bool(cfg["provider"].get("synthetic_load", True))
        self.booted = False
        self.boot_error = None
        self.started_at = time.time()
        self.running = True
        self.kpi: dict = {job: {} for job in self.triads}
        self.history: dict = {job: {"reqs_rate": [], "online": []} for job in self.triads}
        self._last_reqs: dict = {}
        self._load_tick = 0

    # ---- lifecycle ----
    def boot(self):
        try:
            for ctrl in self.triads.values():
                ctrl.boot_all_parallel()
            self.booted = True
        except Exception as e:  # surfaced to the provider via /api/farm
            self.boot_error = f"{type(e).__name__}: {e}"
            return
        threading.Thread(target=self._telemetry_loop, daemon=True).start()
        threading.Thread(target=self._load_loop, daemon=True).start()

    def shutdown(self):
        self.running = False
        for ctrl in self.triads.values():
            ctrl.shutdown()

    # ---- telemetry ----
    def _telemetry_loop(self):
        while self.running:
            t0 = time.time()
            for job, ctrl in self.triads.items():
                try:
                    self._sample(job, ctrl)
                except Exception as e:
                    self.kpi[job]["error"] = str(e)
            time.sleep(max(1.0, 5.0 - (time.time() - t0)))

    def _sample(self, job: str, ctrl):
        online = [n for n in ctrl.nodes if n.state == "ONLINE"]
        primary = PRIMARY_SERVICE[ctrl.spec.role]
        reqs = denials = rx = tx = 0
        roles = set()
        for n in online:
            svc = parse_service_status(ctrl.send_shell_cmd(n, "service status", timeout=3.0))
            if svc["role"]:
                roles.add(svc["role"])
            reqs += svc["svc"].get(primary, {}).get("reqs", 0)
            denials += sum(s["denials"] for s in svc["svc"].values())
            st = ctrl.send_shell_cmd(n, "status", timeout=3.0)
            rx += _num(r"net_rx=(\d+)", st) or 0
            tx += _num(r"net_tx=(\d+)", st) or 0
        k = {
            "online": len(online),
            "primary_service": primary,
            "reqs_total": reqs,
            "denials": denials,
            "net_rx": rx,
            "net_tx": tx,
            "roles_seen": sorted(roles),
            "sampled_at": time.time(),
        }
        if ctrl.spec.has_sql and online:
            out = ctrl.send_shell_cmd(online[0], "sql /*triad*/ SELECT * FROM kv", timeout=3.0)
            k["rows"] = max(0, len(out.splitlines()) - 1) if "|" in out else None
            if "idx" in ctrl.spec.vote_tables:
                out = ctrl.send_shell_cmd(online[0], "sql /*triad*/ SELECT * FROM idx", timeout=3.0)
                k["index_rows"] = max(0, len(out.splitlines()) - 1) if "|" in out else None
        if ctrl.spec.role == "full" and online:  # running jobs needs svc-sh, `cron list` needs svc-http
            out = ctrl.send_shell_cmd(online[0], "cron list", timeout=3.0)
            k["cron_active"] = _num(r"active=(\d+)", out)
            k["cron_runs"] = _num(r"total_runs=(\d+)", out)
        prev = self._last_reqs.get(job)
        now = time.time()
        rate = 0.0
        if prev and now > prev[0] and reqs >= prev[1]:
            rate = (reqs - prev[1]) / (now - prev[0])
        self._last_reqs[job] = (now, reqs)
        k["reqs_rate"] = round(rate, 2)
        self.kpi[job] = k
        h = self.history[job]
        h["reqs_rate"].append(k["reqs_rate"])
        h["online"].append(len(online))
        for series in h.values():
            del series[:-HISTORY_LEN]

    # ---- synthetic load (labelled as such in the console) ----
    def _load_loop(self):
        while self.running:
            time.sleep(3.0)
            if not self.load_enabled:
                continue
            self._load_tick += 1
            for job, ctrl in self.triads.items():
                try:
                    self._load_step(job, ctrl)
                except Exception:
                    pass

    def _load_step(self, job: str, ctrl):
        online = [n for n in ctrl.nodes if n.state == "ONLINE"]
        if not online:
            return
        if ctrl.spec.role == "wfe":
            for n in online:
                try:
                    if ctrl.spec.forward_node_ports:
                        urllib.request.urlopen(f"http://127.0.0.1:{n.http_port}/status", timeout=2.0).read()
                    else:
                        # Exercise svc-http via IpcOp::GuardQuery when host port forwarding is disabled.
                        ctrl.send_shell_cmd(n, "guard status", timeout=2.0)
                except Exception:
                    pass
        elif job == "index":
            ctrl.execute_triad_sql("SELECT * FROM idx WHERE term = 'cuttle'")
            if self._load_tick % 10 == 0:
                ctrl.execute_triad_sql(f"UPDATE idx SET rank = {self._load_tick} WHERE term = 'cuttle'")
        elif ctrl.spec.has_sql:
            ctrl.execute_triad_sql("SELECT * FROM kv")
            if self._load_tick % 10 == 0:
                ctrl.execute_triad_sql(f"UPDATE kv SET v = '{self._load_tick}' WHERE k = 'load.counter'")

    # ---- summary served to the provider ----
    def summary(self) -> dict:
        triads = []
        for job, ctrl in self.triads.items():
            jcfg = self.cfg["jobs"][job]
            recent = [e for e in ctrl.events[:40] if e["level"] in ("ALERT", "ERROR", "TAMPER")]
            triads.append(
                {
                    "job": job,
                    "label": jcfg.get("label", job),
                    "role": ctrl.spec.role,
                    "name": ctrl.spec.name,
                    "accel": ctrl.accel,
                    "has_sql": ctrl.spec.has_sql,
                    "forward_node_ports": ctrl.spec.forward_node_ports,
                    "online": sum(1 for n in ctrl.nodes if n.state == "ONLINE"),
                    "nodes": [
                        {
                            "node_id": n.node_id,
                            "name": n.name,
                            "state": n.state,
                            "http_port": n.http_port,
                            "morph_count": n.morph_count,
                            "tx_seq": n.tx_seq,
                            "elf": n.elf_sha256[:12],
                        }
                        for n in ctrl.nodes
                    ],
                    "quorum_status": ctrl.quorum_status,
                    "parity_ok": ctrl.parity_syndrome_ok,
                    "tx_seq": ctrl.triad_tx_seq,
                    "auto_morph": ctrl.auto_morph_enabled,
                    "morphs": sum(n.morph_count for n in ctrl.nodes),
                    "kpi": self.kpi.get(job, {}),
                    "history": self.history.get(job, {}),
                    "alerts": len(recent),
                    "last_event": ctrl.events[0] if ctrl.events else None,
                }
            )
        return {
            "client": self.client["id"],
            "name": self.client.get("name", self.client["id"]),
            "plan": self.plan_id,
            "plan_label": self.plan.get("label", self.plan_id),
            "booted": self.booted,
            "boot_error": self.boot_error,
            "load": self.load_enabled,
            "uptime_s": int(time.time() - self.started_at),
            "triads": triads,
        }


class FarmHandler(tc.TriadHttpHandler):
    """Farm API. Every request needs the provider's per-run farm secret.

    /api/farm                 GET   farm summary (triads, KPIs, history)
    /api/load                 POST  toggle synthetic load
    /api/shutdown             POST  stop every VM and exit
    /api/t/<job>/<triad path> any   the Triad controller API of that job's Triad
    """

    farm: Farm = None
    secret: str = ""

    def _is_authenticated(self) -> bool:
        val = (self.headers.get("X-Cuttle-Farm-Secret") or "").strip()
        return tc.safe_token_eq(val, self.secret)

    def _route_triad(self) -> bool:
        m = re.match(r"^/api/t/([a-z0-9-]+)(/.*)$", self.path)
        ctrl = self.farm.triads.get(m.group(1)) if m else None
        if ctrl is None:
            return False
        self.ctrl = ctrl  # instance attribute: the base handler's routes act on this Triad
        self.path = m.group(2)
        return True

    def do_GET(self):
        if not self._is_authenticated():
            return self._send_json(401, {"ok": False, "error": "unauthorized"})
        if self.path.split("?", 1)[0] == "/api/farm":
            return self._send_json(200, self.farm.summary())
        if not self._route_triad():
            return self._send_json(404, {"error": "unknown endpoint"})
        return tc.TriadHttpHandler.do_GET(self)

    def do_POST(self):
        if not self._is_authenticated():
            return self._send_json(401, {"ok": False, "error": "unauthorized"})
        if self.path in ("/api/load", "/api/shutdown"):
            body = self._read_bounded_body()
            if body is None:
                return None
            if self.path == "/api/load":
                self.farm.load_enabled = not self.farm.load_enabled
                return self._send_json(200, {"ok": True, "load": self.farm.load_enabled})
            self._send_json(200, {"ok": True})
            threading.Thread(target=_farm_exit, args=(self.farm,), daemon=True).start()
            return None
        if not self._route_triad():
            return self._send_json(404, {"error": "unknown endpoint"})
        return tc.TriadHttpHandler.do_POST(self)


def _farm_exit(farm: Farm):
    farm.shutdown()
    time.sleep(0.5)
    os._exit(0)


def run_farm(client_id: str):
    secret = os.environ.pop(FARM_SECRET_ENV, "")
    if len(secret) < 32:
        sys.exit(f"farm: {FARM_SECRET_ENV} must be set by the provider")
    cfg = load_fleet_config(Path(os.environ.get("CUTTLE_FLEET_CONFIG", FLEET_CONFIG)))
    client = next(c for c in cfg["clients"] if c["id"] == client_id)
    farm = Farm(cfg, client)
    FarmHandler.farm = farm
    FarmHandler.secret = secret
    port = cfg["provider"]["farm_port_base"] + client_slot(cfg, client_id)
    server = ThreadingHTTPServer(("127.0.0.1", port), FarmHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # The provider holds our stdin open; EOF means it is gone, so stop the VMs and exit.
    def watch_parent():
        try:
            sys.stdin.read()
        except Exception:
            pass
        _farm_exit(farm)

    threading.Thread(target=watch_parent, daemon=True).start()
    print(f"farm {client_id}: API on 127.0.0.1:{port}, booting {len(farm.triads)} Triads", flush=True)
    farm.boot()
    print(f"farm {client_id}: booted={farm.booted} error={farm.boot_error}", flush=True)
    while True:
        time.sleep(3600)


# --------------------------------------------------------------------------------------------
# provider
# --------------------------------------------------------------------------------------------

class Provider:
    def __init__(self, cfg: dict, config_path: Path = FLEET_CONFIG):
        self.cfg = cfg
        self.config_path = config_path
        self.clients = {c["id"]: c for c in cfg["clients"]}
        # Probe WHPX once here; farms inherit the answer instead of each probing (~2.5 s apiece).
        self.whpx = tc.whpx_available(tc.find_qemu())
        os.environ["CUTTLE_WHPX_AVAILABLE"] = "1" if self.whpx else "0"
        self.accel_setting = os.environ.get("CUTTLE_ACCEL") or cfg["provider"].get("accelerator", "auto")
        fd = fleet_dir()
        fd.mkdir(parents=True, exist_ok=True)
        # Fresh provider token every start; client tokens persist so clients keep their credentials.
        self.provider_token = secrets.token_hex(16)
        tc.write_secret_file(fd / "provider_token.txt", (self.provider_token + "\n").encode("ascii"))
        self.client_tokens: dict[str, str | None] = {}
        self.token_errors: dict[str, str] = {}
        self.status = {}
        for cid in self.clients:
            try:
                self.client_tokens[cid] = load_or_create_secret(fd / cid / "client_token.txt")
                self.status[cid] = "stopped"
            except (OSError, ValueError) as e:
                self.client_tokens[cid] = None
                self.token_errors[cid] = str(e)
                self.status[cid] = "error"
                print(f"[WARN] client '{cid}' disabled due to malformed client_token.txt: {e}", flush=True)
        self.farm_secrets = {cid: secrets.token_hex(24) for cid in self.clients}
        self.procs: dict = {}
        self.cache: dict = {cid: None for cid in self.clients}
        self.lock = threading.Lock()
        self.running = True

    # ---- auth ----
    def scope_for(self, token: str):
        """('provider', None) | ('client', client_id) | (None, None)."""
        if not token:
            return None, None
        if tc.safe_token_eq(token, self.provider_token):
            return "provider", None
        for cid, tok in self.client_tokens.items():
            if tok and tc.safe_token_eq(token, tok):
                return "client", cid
        return None, None

    # ---- farms ----
    def farm_port(self, cid: str) -> int:
        return self.cfg["provider"]["farm_port_base"] + client_slot(self.cfg, cid)

    def start_farm(self, cid: str):
        with self.lock:
            if cid in self.token_errors:
                self.status[cid] = "error"
                return
            p = self.procs.get(cid)
            if p and p.poll() is None:
                return
            log = open(fleet_dir() / cid / "farm.log", "a", encoding="utf-8")
            env = dict(os.environ)
            env[FARM_SECRET_ENV] = self.farm_secrets[cid]
            env[FLEET_DIR_ENV] = str(fleet_dir())
            env["CUTTLE_FLEET_CONFIG"] = str(self.config_path)
            self.procs[cid] = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "farm", "--client", cid],
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
            self.status[cid] = "starting"
            self.cache[cid] = None

    def stop_farm(self, cid: str):
        p = self.procs.get(cid)
        if not p or p.poll() is not None:
            self.status[cid] = "stopped"
            return
        self.status[cid] = "stopping"
        try:
            self.farm_request(cid, "POST", "/api/shutdown", b"", timeout=5.0)
        except Exception:
            pass
        try:
            p.wait(timeout=30.0)
        except subprocess.TimeoutExpired:
            p.kill()
        self.status[cid] = "stopped"
        self.cache[cid] = None

    def farm_request(self, cid: str, method: str, path: str, body: bytes = b"", timeout: float = 30.0):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.farm_port(cid)}{path}",
            data=body if method == "POST" else None,
            method=method,
            headers={"X-Cuttle-Farm-Secret": self.farm_secrets[cid], "Content-Type": "text/plain"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.headers.get("Content-Type", "application/json"), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type", "application/json"), e.read()

    def poll_loop(self):
        while self.running:
            for cid in self.clients:
                p = self.procs.get(cid)
                if not p:
                    continue
                if p.poll() is not None:
                    if self.status[cid] not in ("stopped", "stopping"):
                        self.status[cid] = "error"
                    continue
                try:
                    code, _, raw = self.farm_request(cid, "GET", "/api/farm", timeout=4.0)
                    if code == 200:
                        summary = json.loads(raw)
                        self.cache[cid] = summary
                        if summary.get("boot_error"):
                            self.status[cid] = "error"
                        elif summary.get("booted"):
                            self.status[cid] = "running"
                        else:
                            self.status[cid] = "booting"
                except Exception:
                    if self.status[cid] == "running":
                        self.status[cid] = "unreachable"
            time.sleep(2.0)

    def fleet_view(self, scope: str, cid_scope) -> dict:
        clients = []
        for cid, c in self.clients.items():
            if scope == "client" and cid != cid_scope:
                continue
            plan = self.cfg["plans"][c["plan"]]
            clients.append(
                {
                    "id": cid,
                    "name": c.get("name", cid),
                    "plan": c["plan"],
                    "plan_label": plan.get("label", c["plan"]),
                    "jobs": plan["jobs"],
                    "status": self.status[cid],
                    "token_error": self.token_errors.get(cid),
                    "farm": self.cache[cid],
                }
            )
        jobs = {j: {"label": v.get("label", j), "role": v["role"]} for j, v in self.cfg["jobs"].items()}
        plans = {p: {"label": v.get("label", p), "jobs": v["jobs"]} for p, v in self.cfg["plans"].items()}
        return {"scope": scope, "client": cid_scope, "clients": clients, "jobs": jobs, "plans": plans}

    def shutdown(self):
        self.running = False
        threads = [threading.Thread(target=self.stop_farm, args=(cid,)) for cid in self.clients]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=40.0)


class ProviderHandler(tc.TriadHttpHandler):
    """Provider console + API. Every /api route needs a provider or client token.

    GET  /fleet                                   console page (no data, no tokens embedded)
    POST /api/whoami                              {scope, client}
    GET  /api/fleet                               provider: every client; client: only itself
    POST /api/c/<id>/start | stop | load          provider only
    GET  /api/c/<id>/farm                         that client's farm summary
    *    /api/c/<id>/t/<job>/<triad path>         proxied to the client's farm
    """

    provider: Provider = None

    def _token(self) -> str:
        for hdr in ("X-Cuttle-Session", "X-Session-Token"):
            val = (self.headers.get(hdr) or "").strip()
            if val:
                return val
        auth = (self.headers.get("Authorization") or "").strip()
        return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

    def _scope(self):
        return self.provider.scope_for(self._token())

    def _send_raw(self, code: int, ctype: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self._send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base = self.path.split("?", 1)[0]
        if base in ("/", "/fleet"):
            try:
                page = tc.CONSOLE_HTML.read_text(encoding="utf-8")
            except OSError:
                return self._send_text(404, "text/plain", "console page not found\n")
            return self._send_text(200, "text/html; charset=utf-8", page)
        return self._dispatch("GET", b"")

    def do_POST(self):
        scope, own = self._scope()
        if scope is None:
            return self._send_json(
                401,
                {"ok": False, "error": "unauthorized: provide a provider or client token"},
            )
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except ValueError:
            return self._send_json(400, {"ok": False, "error": "invalid Content-Length"})
        if length < 0:
            return self._send_json(400, {"ok": False, "error": "negative Content-Length"})
        if length > tc.MAX_HTTP_BODY_BYTES:
            return self._send_json(
                413,
                {"ok": False, "error": f"payload exceeds {tc.MAX_HTTP_BODY_BYTES} bytes"},
            )
        body = self.rfile.read(length) if length else b""
        return self._dispatch("POST", body, pre_auth=(scope, own))

    def _dispatch(self, method: str, body: bytes, pre_auth=None):
        scope, own = pre_auth if pre_auth is not None else self._scope()
        if scope is None:
            return self._send_json(401, {"ok": False, "error": "unauthorized: provide a provider or client token"})
        base = self.path.split("?", 1)[0]
        if method == "POST" and base == "/api/whoami":
            c = self.provider.clients.get(own) if own else None
            return self._send_json(200, {"ok": True, "scope": scope, "client": own, "name": c.get("name") if c else None})
        if method == "GET" and base == "/api/fleet":
            return self._send_json(200, self.provider.fleet_view(scope, own))
        m = re.match(r"^/api/c/([a-z0-9-]+)(/.*)$", self.path)
        if not m:
            return self._send_json(404, {"error": "unknown endpoint"})
        cid, rest = m.group(1), m.group(2)
        if scope == "client" and cid != own:
            return self._send_json(403, {"ok": False, "error": "forbidden: this token is scoped to another client"})
        if cid not in self.provider.clients:
            return self._send_json(404, {"error": "unknown endpoint"})
        if method == "POST" and rest in ("/start", "/stop", "/load"):
            if scope != "provider":
                return self._send_json(403, {"ok": False, "error": "forbidden: provider token required"})
            if rest == "/start":
                self.provider.start_farm(cid)
            elif rest == "/stop":
                threading.Thread(target=self.provider.stop_farm, args=(cid,), daemon=True).start()
            else:
                code, ctype, raw = self.provider.farm_request(cid, "POST", "/api/load", b"")
                return self._send_raw(code, ctype, raw)
            return self._send_json(200, {"ok": True, "status": self.provider.status[cid]})
        if method == "GET" and rest == "/farm":
            summary = self.provider.cache.get(cid)
            return self._send_json(200, {"status": self.provider.status[cid], "farm": summary})
        if not rest.startswith("/t/"):
            return self._send_json(404, {"error": "unknown endpoint"})
        if self.provider.status[cid] in ("stopped", "stopping", "error"):
            return self._send_json(503, {"ok": False, "error": f"farm is {self.provider.status[cid]}"})
        try:
            code, ctype, raw = self.provider.farm_request(cid, method, "/api" + rest, body)
        except Exception as e:
            return self._send_json(502, {"ok": False, "error": f"farm unreachable: {e}"})
        return self._send_raw(code, ctype, raw)


def run_provider(config_path: Path = FLEET_CONFIG):
    cfg = load_fleet_config(config_path)
    provider = Provider(cfg, config_path)
    ProviderHandler.provider = provider
    port = cfg["provider"]["port"]
    server = ThreadingHTTPServer(("127.0.0.1", port), ProviderHandler)
    threading.Thread(target=provider.poll_loop, daemon=True).start()
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print("\n============================================================================", flush=True)
    print("  CUTTLE FLEET PROVIDER ONLINE", flush=True)
    print(f"  Console        : http://127.0.0.1:{port}/fleet", flush=True)
    print(f"  Provider token : {provider.provider_token} (saved to {fleet_dir() / 'provider_token.txt'})", flush=True)
    print(f"  Client tokens  : {fleet_dir()}\\<client>\\client_token.txt", flush=True)
    vms = sum(3 * len(cfg["plans"][c["plan"]]["jobs"]) for c in cfg["clients"])
    print(f"  Clients        : {len(cfg['clients'])} farms, {vms} VMs; farm logs in {fleet_dir()}\\<client>\\farm.log", flush=True)
    print(f"  Accelerator    : {provider.accel_setting} (WHPX available: {'yes' if provider.whpx else 'no, using TCG'})", flush=True)
    print("  Press Ctrl+C to stop every farm cleanly.", flush=True)
    print("============================================================================\n", flush=True)

    stagger = float(cfg["provider"].get("boot_stagger_s", 8))
    try:
        for cid in provider.clients:
            provider.start_farm(cid)
            print(f"[{time.strftime('%H:%M:%S')}] launched farm '{cid}' ({provider.clients[cid]['plan']})", flush=True)
            time.sleep(stagger)
        last = None
        while True:
            line = " | ".join(f"{cid}:{provider.status[cid]}" for cid in provider.clients)
            if line != last:
                print(f"[{time.strftime('%H:%M:%S')}] {line}", flush=True)
                last = line
            time.sleep(2.0)
    except KeyboardInterrupt:
        print("\nStopping every client farm...", flush=True)
    finally:
        provider.shutdown()
        server.shutdown()


# --------------------------------------------------------------------------------------------
# self-test: isolation and authorization on a 2-client fleet
# --------------------------------------------------------------------------------------------

SELFTEST_CONFIG = """
[provider]
port = 18899
farm_port_base = 18950
vm_port_base = 21000
boot_stagger_s = 0
synthetic_load = false

[jobs.web]
label = "Web front end"
short = "Web"
role = "wfe"

[jobs.sql]
label = "SQL database"
short = "SQL"
role = "sql"

[jobs.index]
label = "Search index"
short = "Index"
role = "sql"
vote_tables = ["kv", "idx"]
provision_sql = ["CREATE TABLE idx (term TEXT, doc TEXT, rank INT)", "CREATE INDEX idx_term ON idx (term)", "INSERT INTO idx VALUES ('cuttle', 'doc-1', 1)"]

[jobs.cron]
label = "Business jobs (cron)"
short = "Cron"
role = "full"
cron = [[40, "status"]]

[plans.basic]
jobs = ["web", "sql"]
vcpus = 2

[plans.pro]
jobs = ["web", "sql", "index", "cron"]
vcpus = 2

[[clients]]
id = "alpha"
name = "Alpha Test Co"
plan = "pro"

[[clients]]
id = "bravo"
name = "Bravo Test Co"
plan = "basic"
"""


def run_fleet_unit_tests(work: Path):
    """Fast deterministic unit tests for fleet config and secret validation (#15, #23)."""
    # #15a: 6-job plan rejected (would collide HTTP on job 5 with HTTPS on job 0)
    six_jobs_cfg = work / "six_jobs.toml"
    six_jobs_cfg.write_text(
        SELFTEST_CONFIG
        + '\n[jobs.j5]\nrole = "wfe"\n[jobs.j6]\nrole = "wfe"\n[plans.too_many]\njobs = ["web", "sql", "index", "cron", "j5", "j6"]\n',
        encoding="utf-8",
    )
    try:
        load_fleet_config(six_jobs_cfg)
        raise AssertionError("load_fleet_config must reject a 6-job plan")
    except ValueError as e:
        assert "1-5 jobs" in str(e), e

    # #15b: Overlapping provider.port and farm_port_base rejected
    overlap_cfg = work / "overlap.toml"
    overlap_cfg.write_text(
        SELFTEST_CONFIG.replace("farm_port_base = 18950", "farm_port_base = 18899"),
        encoding="utf-8",
    )
    try:
        load_fleet_config(overlap_cfg)
        raise AssertionError("load_fleet_config must reject overlapping provider/farm ports")
    except ValueError as e:
        assert "port collision" in str(e), e

    # #23: Malformed secret file rejected
    bad_sec = work / "bad_master.bin"
    bad_sec.write_bytes(b"short")
    try:
        load_or_create_secret(bad_sec, 32, binary=True)
        raise AssertionError("load_or_create_secret must reject truncated master_key.bin")
    except ValueError:
        pass

    # Round-6 #15: A malformed client_token.txt on one client isolates only that client
    # (`status='error'`), rather than crashing Provider.__init__ for the entire fleet.
    iso_dir = work / "iso_state"
    (iso_dir / "bravo").mkdir(parents=True, exist_ok=True)
    (iso_dir / "bravo" / "client_token.txt").write_text("not-valid-hex\n", encoding="utf-8")
    iso_cfg_path = work / "iso_fleet.toml"
    iso_cfg_path.write_text(SELFTEST_CONFIG, encoding="utf-8")
    old_fleet_env = os.environ.get(FLEET_DIR_ENV)
    old_whpx_env = os.environ.get("CUTTLE_WHPX_AVAILABLE")
    try:
        os.environ[FLEET_DIR_ENV] = str(iso_dir)
        os.environ["CUTTLE_WHPX_AVAILABLE"] = "0"
        iso_cfg = load_fleet_config(iso_cfg_path)
        iso_prov = Provider(iso_cfg, iso_cfg_path)
        assert iso_prov.status["alpha"] == "stopped", iso_prov.status
        assert iso_prov.status["bravo"] == "error", iso_prov.status
        assert iso_prov.client_tokens["alpha"] is not None
        assert iso_prov.client_tokens["bravo"] is None
        assert "bravo" in iso_prov.token_errors
        assert iso_prov.scope_for(iso_prov.client_tokens["alpha"]) == ("client", "alpha")
    finally:
        if old_fleet_env is None:
            os.environ.pop(FLEET_DIR_ENV, None)
        else:
            os.environ[FLEET_DIR_ENV] = old_fleet_env
        if old_whpx_env is None:
            os.environ.pop("CUTTLE_WHPX_AVAILABLE", None)
        else:
            os.environ["CUTTLE_WHPX_AVAILABLE"] = old_whpx_env


def run_self_test() -> int:
    import shutil
    import socket
    import tempfile

    tc.IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="cuttle_fleet_selftest_", dir=str(tc.IMAGES_DIR)))
    run_fleet_unit_tests(work)
    cfg_path = work / "fleet.toml"
    cfg_path.write_text(SELFTEST_CONFIG, encoding="utf-8")
    os.environ[FLEET_DIR_ENV] = str(work / "state")
    cfg = load_fleet_config(cfg_path)
    provider = Provider(cfg, cfg_path)
    ProviderHandler.provider = provider
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=provider.poll_loop, daemon=True).start()

    def call(method, path, token=None, body=b"", headers=None):
        h = dict(headers or {})
        if token:
            h["X-Cuttle-Session"] = token
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body if method == "POST" else None, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=60.0) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw[:1] in (b"{", b"[") else raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw.decode("utf-8", "replace")

    P = provider.provider_token
    A = provider.client_tokens["alpha"]
    B = provider.client_tokens["bravo"]
    ok = False
    try:
        print("=== FLEET SELF-TEST: booting 2 client farms (alpha=pro, bravo=basic) ===", flush=True)
        for cid in provider.clients:
            provider.start_farm(cid)
        deadline = time.time() + 300
        while time.time() < deadline and not all(provider.status[c] == "running" for c in provider.clients):
            if any(provider.status[c] == "error" for c in provider.clients):
                raise AssertionError(f"farm failed to boot: {provider.status}; see {work}/state/<client>/farm.log")
            time.sleep(2.0)
        assert all(provider.status[c] == "running" for c in provider.clients), f"farms not running: {provider.status}"
        print("farms running", flush=True)

        # 1. Authentication (#17, #22): every provider and farm endpoint across every role refuses
        #    {no token, wrong token, non-ASCII token} with 401.
        provider_endpoints = [
            ("GET", "/api/fleet"),
            ("POST", "/api/whoami"),
            ("GET", "/api/c/alpha/farm"),
            ("POST", "/api/c/alpha/start"),
            ("POST", "/api/c/alpha/stop"),
            ("POST", "/api/c/alpha/load"),
        ]
        triad_subpaths = [
            ("GET", "/api/triad"),
            ("GET", "/sql?SELECT+*+FROM+kv"),
            ("POST", "/sql"),
            ("POST", "/api/sql"),
            ("POST", "/api/sh"),
            ("POST", "/api/app"),
            ("POST", "/api/vault"),
            ("POST", "/api/guard"),
            ("POST", "/api/cron"),
            ("POST", "/api/whoami"),
            ("POST", "/api/morph/1"),
            ("POST", "/api/tamper/1"),
            ("POST", "/api/rolling_wave"),
            ("POST", "/api/toggle_auto"),
        ]
        for job in ("web", "sql", "index", "cron"):
            for m_verb, sub in triad_subpaths:
                provider_endpoints.append((m_verb, f"/api/c/alpha/t/{job}{sub}"))

        for method, path in provider_endpoints:
            for bad_tok in (None, "0" * 32, "é" * 32):
                code, _ = call(method, path, token=bad_tok)
                assert code == 401, f"provider {method} {path} (token={bad_tok!r}) must be 401, got {code}"

        farm_endpoints = [
            ("GET", "/api/farm"),
            ("POST", "/api/load"),
            ("POST", "/api/shutdown"),
        ]
        for job in ("web", "sql", "index", "cron"):
            for m_verb, sub in triad_subpaths:
                farm_endpoints.append((m_verb, f"/api/t/{job}{sub}"))

        alpha_farm_port = provider.farm_port("alpha")
        for method, path in farm_endpoints:
            for hdrs in ({}, {"X-Cuttle-Farm-Secret": "0" * 48}, {"X-Cuttle-Farm-Secret": "é" * 48}, {"X-Cuttle-Session": P}):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{alpha_farm_port}{path}",
                    data=b"" if method == "POST" else None,
                    headers=hdrs,
                    method=method,
                )
                try:
                    urllib.request.urlopen(req, timeout=5.0)
                    raise AssertionError(f"farm {method} {path} must refuse headers {list(hdrs)}")
                except urllib.error.HTTPError as e:
                    assert e.code == 401, f"farm {method} {path} expected 401, got {e.code}"

        # #22: Content-Length validation on ProviderHandler
        for bad_cl, expected_code in (("-5", 400), ("notanumber", 400), (str(tc.MAX_HTTP_BODY_BYTES + 1024), 413)):
            with socket.create_connection(("127.0.0.1", port), timeout=5.0) as raw_sock:
                raw_req = (
                    f"POST /api/whoami HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n"
                    f"X-Cuttle-Session: {P}\r\n"
                    f"Content-Length: {bad_cl}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii")
                raw_sock.sendall(raw_req)
                raw_resp = raw_sock.recv(4096).decode("utf-8", errors="replace")
            assert f"HTTP/1.0 {expected_code}" in raw_resp or f"HTTP/1.1 {expected_code}" in raw_resp, (
                f"Expected {expected_code} for Content-Length {bad_cl}, got: {raw_resp[:120]!r}"
            )
        print("auth: all provider & farm endpoints across all 4 roles refused unauthenticated/bad/non-ASCII tokens", flush=True)

        # 2. Scopes: the provider sees both clients; a client sees only itself and nothing provider-only.
        code, me = call("POST", "/api/whoami", P)
        assert code == 200 and me["scope"] == "provider", me
        code, me = call("POST", "/api/whoami", A)
        assert code == 200 and me["scope"] == "client" and me["client"] == "alpha", me
        code, fl = call("GET", "/api/fleet", P)
        assert code == 200 and {c["id"] for c in fl["clients"]} == {"alpha", "bravo"}, fl
        code, fl = call("GET", "/api/fleet", A)
        assert code == 200 and [c["id"] for c in fl["clients"]] == ["alpha"], fl
        for method, path in (("GET", "/api/c/bravo/farm"), ("GET", "/api/c/bravo/t/sql/api/triad"),
                             ("POST", "/api/c/bravo/t/sql/api/sql"), ("POST", "/api/c/bravo/t/sql/api/morph/1")):
            code, _ = call(method, path, A, b"SELECT * FROM kv")
            assert code == 403, f"client alpha -> {path} must be 403, got {code}"
        # #32.5: Client token querying a non-existent client ID gets 403 (cannot enumerate client IDs),
        # while provider token gets 404.
        code, _ = call("GET", "/api/c/nonexistent/farm", A)
        assert code == 403, f"client token querying nonexistent client must get 403, got {code}"
        code, _ = call("GET", "/api/c/nonexistent/farm", P)
        assert code == 404, f"provider token querying nonexistent client must get 404, got {code}"
        for path in ("/api/c/alpha/stop", "/api/c/alpha/start", "/api/c/alpha/load"):
            code, _ = call("POST", path, A)
            assert code == 403, f"client token on provider-only {path} must be 403, got {code}"
        print("scopes: provider sees all; client alpha is confined to its own farm (403 on other/unknown clients)", flush=True)

        # 2b. Network isolation (#16): farm VMs do not forward node HTTP/HTTPS ports on host loopback.
        for vm_port in (21101, 21151, 21001, 21051):
            try:
                with socket.create_connection(("127.0.0.1", vm_port), timeout=1.0):
                    raise AssertionError(f"Fleet VM port {vm_port} must not be forwarded on host loopback")
            except OSError:
                pass
        print("isolation: fleet VM node ports are not forwarded on host loopback", flush=True)

        # 3. Kernel roles are applied per job.
        expect = {("alpha", "web"): "wfe", ("alpha", "sql"): "sql", ("alpha", "index"): "sql",
                  ("alpha", "cron"): "full", ("bravo", "web"): "wfe", ("bravo", "sql"): "sql"}
        for (cid, job), role in expect.items():
            code, r = call("POST", f"/api/c/{cid}/t/{job}/api/sh", P, b"service status")
            assert code == 200, (cid, job, r)
            for name, out in r["per_node"].items():
                assert f"role={role}" in out, f"{cid}/{job} {name}: expected role={role}:\n{out}"
        code, wt = call("GET", "/api/c/alpha/t/web/api/triad", P)
        assert "SERVED CONTENT VERIFIED" in wt["quorum_status"], wt["quorum_status"]
        print("roles: web=wfe, sql=sql, index=sql, cron=full on every node", flush=True)

        # 3b. Every Triad runs on the accelerator the fleet setting resolves to on this host.
        setting = provider.accel_setting
        expected_accel = setting if setting != "auto" else ("whpx" if provider.whpx else "tcg")
        for cid in ("alpha", "bravo"):
            code, fm = call("GET", f"/api/c/{cid}/farm", P)
            accels = {t["job"]: t["accel"] for t in fm["farm"]["triads"]}
            assert set(accels.values()) == {expected_accel}, f"{cid}: expected every Triad on {expected_accel}: {accels}"
        print(f"accelerator: every Triad runs on {expected_accel} (setting {setting})", flush=True)

        # 4. Data isolation: a row written to alpha's SQL Triad never appears in bravo's.
        code, r = call("POST", "/api/c/alpha/t/sql/api/sql", A, b"INSERT INTO kv VALUES ('isolation.probe', 'alpha-only', 1)")
        assert code == 200 and r["ok"], r
        code, ra = call("POST", "/api/c/alpha/t/sql/api/sql", A, b"SELECT * FROM kv")
        code, rb = call("POST", "/api/c/bravo/t/sql/api/sql", B, b"SELECT * FROM kv")
        assert "alpha-only" in ra["output"], ra
        assert "alpha-only" not in rb["output"] and all("alpha-only" not in v for v in rb["per_node"].values()), rb
        print("isolation: alpha's write is invisible to bravo", flush=True)

        # 5. Key isolation (#8): separate master keys, no device key shared across clients or jobs,
        #    and no unused operator_token.txt written in farm Triad directories.
        sd = work / "state"
        assert (sd / "alpha" / "master_key.bin").read_bytes() != (sd / "bravo" / "master_key.bin").read_bytes()
        dev_keys = [p.read_bytes() for p in sd.glob("*/*/node*/device_key_node*.bin")]
        assert len(dev_keys) == 18 and len(set(dev_keys)) == 18, f"expected 18 distinct device keys, got {len(set(dev_keys))}/{len(dev_keys)}"
        assert list(sd.glob("*/*/operator_token.txt")) == [], "farm Triads must not write unused operator_token.txt"
        print("keys: distinct master keys per client, 18 distinct node device keys, no unused operator_token.txt", flush=True)

        # 6. Index Triad provisioned through the WAL on every node, and multi-table heal (#3)
        #    drops and rebuilds both `kv` and `idx` without duplicate rows or a second ALERT.
        code, r = call("POST", "/api/c/alpha/t/index/api/sql", P, b"SELECT * FROM idx")
        assert code == 200 and all("cuttle|doc-1" in v for v in r["per_node"].values()), r
        idx_before_morphs = call("GET", "/api/c/alpha/t/index/api/triad", P)[1]["nodes"][1]["morph_count"]
        code, _ = call("POST", "/api/c/alpha/t/index/api/tamper/2", P)
        assert code == 200
        deadline = time.time() + 90
        while time.time() < deadline:
            t_idx = call("GET", "/api/c/alpha/t/index/api/triad", P)[1]
            if t_idx["nodes"][1]["state"] == "ONLINE" and t_idx["nodes"][1]["morph_count"] > idx_before_morphs:
                break
            time.sleep(1.0)
        code, r_idx = call("POST", "/api/c/alpha/t/index/api/sql", P, b"SELECT * FROM idx")
        assert code == 200 and r_idx["ok"] and "3/3" in r_idx["quorum"], f"index Triad did not converge after heal: {r_idx}"
        idx_outputs = list(r_idx["per_node"].values())
        assert idx_outputs[0] == idx_outputs[1] == idx_outputs[2], f"idx table diverged across nodes after heal: {idx_outputs}"
        assert idx_outputs[1].count("cuttle|doc-1") == 1, f"duplicate row in healed idx table:\n{idx_outputs[1]}"
        print("index: idx table provisioned and healed cleanly across both kv and idx without duplicate rows", flush=True)

        # 7. Cron desired state survives a morph (cron jobs live in node RAM).
        code, r = call("POST", "/api/c/alpha/t/cron/api/cron", P, b"cron add 7 uptime")
        assert code == 200 and r["ok"], r
        ctrl_morphs = lambda: call("GET", "/api/c/alpha/t/cron/api/triad", P)[1]["nodes"][0]["morph_count"]
        before = ctrl_morphs()
        code, _ = call("POST", "/api/c/alpha/t/cron/api/morph/1", P)
        assert code == 200
        deadline = time.time() + 90
        while time.time() < deadline:
            t = call("GET", "/api/c/alpha/t/cron/api/triad", P)[1]
            if t["nodes"][0]["state"] == "ONLINE" and t["nodes"][0]["morph_count"] > before:
                break
            time.sleep(1.0)
        code, r = call("POST", "/api/c/alpha/t/cron/api/sh", P, b"cron list")
        n1 = next(v for k, v in r["per_node"].items() if k.startswith("OS-1"))
        assert 'cmd="uptime"' in n1 and 'cmd="status"' in n1, f"cron jobs not restored after morph:\n{n1}"
        print("cron: desired jobs re-applied after OS-1 morphed", flush=True)

        # 8. The console page is served without credentials, embeds no token, and sets CSP (#18).
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/fleet", timeout=10.0) as resp:
            assert resp.status == 200
            csp = resp.headers.get("Content-Security-Policy", "")
            assert "frame-ancestors 'none'" in csp, f"Missing frame-ancestors in /fleet CSP: {csp}"
            assert resp.headers.get("X-Frame-Options") == "DENY"
            page = resp.read().decode("utf-8")
        assert "Cuttle Triad Console" in page
        assert all(t not in page for t in (P, A, B)), "console page must not embed tokens"
        print("console: /fleet served with CSP headers, no tokens embedded", flush=True)

        print("=== FLEET SELF-TEST PASSED ===", flush=True)
        ok = True
    finally:
        provider.shutdown()
        server.shutdown()
        if ok:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"(state kept for inspection: {work})", flush=True)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Cuttle fleet provider / client farm")
    ap.add_argument("mode", nargs="?", default="provider", choices=("provider", "farm"))
    ap.add_argument("--client", help="client id (farm mode)")
    ap.add_argument("--config", default=str(FLEET_CONFIG), help="fleet config (provider mode)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--accel", choices=tc.ACCELERATORS, help="override every plan's QEMU accelerator")
    args = ap.parse_args()
    if args.accel:
        os.environ["CUTTLE_ACCEL"] = args.accel  # read by triad_specs; inherited by farm processes
    if args.self_test:
        sys.exit(run_self_test())
    if args.mode == "farm":
        if not args.client:
            ap.error("farm mode needs --client")
        run_farm(args.client)
    else:
        run_provider(Path(args.config))


if __name__ == "__main__":
    main()
