#!/usr/bin/env python3
"""
Cuttle 3-as-1 Triad Hypervisor Controller & RAID-SQL Coordinator
=================================================================
Packages 3 independent 4-core Cuttle OS VMs into ONE logical appliance:
  - OS-1 (SQL-Data-A)      : 4x SMP vCPUs, 128 MB RAM, Seed #A, AHCI Disk #1
  - OS-2 (SQL-Data-B)      : 4x SMP vCPUs, 128 MB RAM, Seed #B, AHCI Disk #2
  - OS-3 (SQL-Parity/Check): 4x SMP vCPUs, 128 MB RAM, Seed #C, AHCI Disk #3 + XOR Parity

Features:
  1. Real post-link x86-64 binary diversification (`binmorph.exe`) per VM boot:
     rewrites ~15,350 instructions and permutes registers across 787 functions in ~250ms,
     splicing the morphed ELF directly into each VM's BIOS boot image.
  2. Triple Modular Redundancy (TMR) 2-of-3 Majority Vote + 4 KiB RAID Parity verification
     (D1 ^ D2 = P) across the persistent AHCI SQL partitions (`LBA 1058..1065`, `CTTLSQL1`).
  3. Zero-downtime Rolling MTD Morph: while 1 OS bounces into a freshly scrambled
     kernel binary, the other 2 OSes serve 100% of reads and writes; when the bounced
     OS wakes up (`SHELL resume OK`), it enters `CATCHING_UP` and automatically replays
     all missed SQL writes from the Triad WAL before rejoining `ONLINE`.
  4. Single-Node Tamper Self-Healing: detects unauthorized state divergence on any single
     OS via 2-of-3 majority vote + parity check, heals the corrupted node from its peers,
     and triggers an emergency binary re-morph.
"""

import argparse
import hashlib
import hmac
import json
import os
import queue
import random
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGES_DIR = ROOT / "target" / "cuttle_images"
TRIAD_DIR = IMAGES_DIR / "triad"
BASE_ELF = (
    ROOT
    / "target_enterprise_kernel"
    / "target"
    / "x86_64-unknown-none"
    / "release"
    / "target_enterprise_kernel"
)
BASE_BIOS = IMAGES_DIR / "run_bios.img"
BINMORPH_EXE = ROOT / "target" / "release" / "binmorph.exe"
DEVICE_KEY = ROOT / "device_secret_key.bin"
# Tabbed live operations console served at /console (static page; actions use the operator token).
CONSOLE_HTML = ROOT / "tools" / "triad_console.html"

# AHCI SQL partition layout (LBA 1058..1065 = 8 sectors = 4096 bytes)
SQL_PART_OFFSET = 1058 * 512
SQL_PART_SIZE = 8 * 512


@dataclass
class TriadSpec:
    """
    One Triad's identity, kernel role and placement. The defaults reproduce the standalone
    appliance started by `triad.bat` (role `full`, state in `target/cuttle_images/triad`,
    node HTTP ports 18101-18103). `tools/cuttle_fleet.py` builds one spec per (client, job).
    """

    name: str = "triad"
    job: str = "sql"  # what the Triad serves: web | sql | index | cron
    # Kernel `NodeRole` profile (`service role <role>`), re-applied after every boot because
    # the kernel starts each boot as `full`: wfe (svc-http only), sql (svc-sql only),
    # shell (svc-sh only) or full (all three).
    role: str = "full"
    state_dir: Path = TRIAD_DIR
    master_key_path: Path = DEVICE_KEY
    key_context: str = "cuttle-triad-node-v1"  # domain label for per-node device-key derivation
    http_base: int = 18100  # node N serves HTTP on http_base + N
    https_base: int = 18500
    smp: int = 4
    memory: str = "128M"
    accel: str = "auto"  # QEMU accelerator: auto (WHPX, else TCG) | whpx | tcg
    node_names: tuple = ("OS-1 (SQL-Data-A)", "OS-2 (SQL-Data-B)", "OS-3 (SQL-Parity)")
    node_roles: tuple = ("ACTIVE DATA STRIPE A", "ACTIVE DATA STRIPE B", "RAID PARITY & WITNESS")
    base_seeds: tuple = (100101, 200202, 300303)
    vote_tables: tuple = ("kv",)  # SQL tables compared by the 2-of-3 vote (SQL-capable roles)
    provision_sql: tuple = ()  # statements committed once through the WAL after first boot
    cron_jobs: tuple = ()  # (interval_ticks, command) re-applied after every boot
    log_prefix: str = ""
    write_operator_token: bool = True  # False in fleet farms (which authenticate via farm secret)
    forward_node_ports: bool = True  # False in fleet farms so node ports are not exposed on loopback

    @property
    def has_sql(self) -> bool:
        return self.role in ("sql", "full")

    @property
    def has_shell(self) -> bool:
        return self.role in ("shell", "full")


MAX_HTTP_BODY_BYTES = 64 * 1024
MAX_WAL_ENTRIES = 64


def safe_token_eq(provided: str, expected: str) -> bool:
    """Constant-time ASCII token comparison; returns False (never raises) on non-ASCII input."""
    if not provided or not expected:
        return False
    try:
        b_prov = provided.encode("ascii")
        b_exp = expected.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(b_prov, b_exp)


def restrict_file_permissions(path: Path) -> None:
    """Restrict `path` to mode 0600 on POSIX or an explicit current-user-only ACL on Windows."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        user = os.environ.get("USERNAME")
        domain = os.environ.get("USERDOMAIN")
        principal = f"{domain}\\{user}" if domain and user else user
        if principal:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{principal}:(F)"],
                capture_output=True,
                check=False,
            )


def write_secret_file(path: Path, data: bytes) -> None:
    """Create or replace `path` exclusively with owner-only permissions and fsync."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(str(tmp), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        restrict_file_permissions(tmp)
        tmp.replace(path)
        restrict_file_permissions(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def load_or_create_secret_file(path: Path, nbytes: int = 16, binary: bool = False):
    """
    Load an existing secret file or create a new one exclusively with owner-only permissions.
    Refuses to start (raises ValueError) if an existing file is empty, short, overlong, all-zero,
    or non-hex, rather than silently truncating or replacing a master key or token.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw = path.read_bytes()
        if binary:
            if len(raw) != nbytes:
                raise ValueError(
                    f"malformed secret file {path}: expected exactly {nbytes} bytes, got {len(raw)} bytes"
                )
            if raw == b"\x00" * nbytes:
                raise ValueError(f"malformed secret file {path}: all-zero key rejected")
            restrict_file_permissions(path)
            return raw
        try:
            txt = raw.decode("ascii").strip()
        except UnicodeDecodeError as e:
            raise ValueError(f"malformed token secret file {path}: non-ASCII bytes") from e
        if len(txt) != nbytes * 2 or any(c not in "0123456789abcdefABCDEF" for c in txt):
            raise ValueError(
                f"malformed token secret file {path}: expected {nbytes * 2} hex chars, got {len(txt)}"
            )
        restrict_file_permissions(path)
        return txt
    value = os.urandom(nbytes) if binary else secrets.token_hex(nbytes)
    write_secret_file(path, value if binary else (value + "\n").encode("ascii"))
    return value


def atomic_write_json(path: Path, obj) -> None:
    """Serialize `obj` to JSON, flush + fsync a temporary sibling file, and atomically replace `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    payload = json.dumps(obj, indent=2).encode("utf-8")
    with open(tmp, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def is_printable_ascii_command(s: str) -> bool:
    """Return True iff `s` is non-empty and every character is printable ASCII (0x20..=0x7E)."""
    return bool(s) and all(0x20 <= ord(ch) <= 0x7E for ch in s)


def is_readonly_sql_query(q: str) -> bool:
    """Return True iff `q` is a read-only SQL query (`SELECT`, `.tables`, `SHOW`, `.schema`, `DESCRIBE`)."""
    trimmed = q.strip()
    if trimmed.startswith("/*triad*/"):
        trimmed = trimmed[len("/*triad*/") :].strip()
    if not trimmed:
        return True
    up = trimmed.upper()
    return (
        up.startswith("SELECT")
        or up.startswith(".TABLES")
        or up.startswith("SHOW")
        or up.startswith(".SCHEMA")
        or up.startswith("DESCRIBE")
    )


def is_readonly_shell_command(s: str) -> bool:
    """
    Return True iff `s` is a strictly read-only inspection shell command
    (matching `OsShell::is_readonly_command` in `target_enterprise/src/shell.rs`).
    State-changing commands must go through `/api/sql` or `/api/app` so they
    acquire `wal_lock`, append to the Triad WAL, and verify quorum acceptance.
    """
    trimmed = s.strip()
    if not trimmed:
        return True
    parts = trimmed.split(None, 1)
    cmd = parts[0].lower()
    rest = parts[1].strip() if len(parts) > 1 else ""
    if cmd in (
        "help",
        "?",
        "uname",
        "status",
        "uptime",
        "ps",
        "threads",
        "caps",
        "ls",
        "cat",
        "stat",
        "df",
        "net",
        "audit",
        "seal",
        "attest",
    ):
        return True
    if cmd in (
        "ima",
        "fw",
        "seccomp",
        "session",
        "smp",
        "service",
        "triad",
        "vault",
        "guard",
        "cron",
    ) and rest.lower() in ("", "status", "list", "alerts", "audit", "threads"):
        return True
    if cmd == "sql" and rest:
        return is_readonly_sql_query(rest)
    return False


def find_qemu() -> str:
    q = shutil.which("qemu-system-x86_64")
    if q:
        return q
    default_win = Path(r"C:\Program Files\qemu\qemu-system-x86_64.exe")
    if default_win.exists():
        return str(default_win)
    raise RuntimeError("qemu-system-x86_64 not found on PATH or C:\\Program Files\\qemu")


ACCELERATORS = ("auto", "whpx", "tcg")
# Under `auto`, a WHPX VM that prints nothing of its own this long after launch is relaunched on TCG.
WHPX_FIRST_OUTPUT_S = 8.0
_whpx_cache: dict = {}

GUEST_SERIAL_MARKERS = (
    "INFO :",
    "CUTTLE",
    "BOOT:",
    "GDT ",
    "IDT ",
    "PAGING ",
    "HEAP ",
    "SMP ",
    "NET SVC UP",
    "HTTPS UP",
    "Web UI:",
    "interactive shell ready",
)


def has_guest_serial_output(lines: list[str]) -> bool:
    """
    Return True iff `lines` contains a line with a known CuttleOS bootloader or kernel
    serial marker, ignoring QEMU host warnings/banners.
    """
    for ln in lines:
        if "qemu-system" in ln or ln.lower().startswith("whpx:"):
            continue
        if any(marker in ln for marker in GUEST_SERIAL_MARKERS):
            return True
    return False


def compact_wal_entries(entries: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """
    Compact a WAL entry list by dropping earlier key-level overwrites that are completely
    superseded by a later write to the same key (`UPDATE kv SET ... WHERE k = '<k>'`,
    `INSERT OR REPLACE INTO kv VALUES ('<k>', ...)`, or `UPDATE idx SET ... WHERE term = '<t>'`).
    Preserves monotonic `(tid, stmt)` order for all retained entries.
    """
    if len(entries) <= 1:
        return list(entries)
    kv_update_re = re.compile(
        r"^(?:UPDATE\s+kv\s+SET\s+.+\s+WHERE\s+k\s*=\s*'([^']+)'"
        r"|INSERT\s+OR\s+REPLACE\s+INTO\s+kv\s+VALUES\s*\(\s*'([^']+)')",
        re.IGNORECASE,
    )
    idx_update_re = re.compile(
        r"^UPDATE\s+idx\s+SET\s+.+\s+WHERE\s+term\s*=\s*'([^']+)'",
        re.IGNORECASE,
    )
    last_idx_for_key: dict[str, int] = {}
    key_at_pos: dict[int, str] = {}
    for pos, (_, stmt) in enumerate(entries):
        s = stmt.strip()
        m_kv = kv_update_re.match(s)
        if m_kv:
            k = "kv:" + (m_kv.group(1) or m_kv.group(2))
            last_idx_for_key[k] = pos
            key_at_pos[pos] = k
            continue
        m_idx = idx_update_re.match(s)
        if m_idx:
            k = "idx:" + m_idx.group(1)
            last_idx_for_key[k] = pos
            key_at_pos[pos] = k
    return [
        entry
        for pos, entry in enumerate(entries)
        if pos not in key_at_pos or last_idx_for_key[key_at_pos[pos]] == pos
    ]


def whpx_available(qemu_bin: str) -> bool:
    """
    True if QEMU can start a WHPX (Windows Hypervisor Platform) partition on this host.
    Probes once per process with a paused, device-less x86 machine; a parent process can
    pass its answer down in CUTTLE_WHPX_AVAILABLE=0/1 to skip the ~2 s probe.
    """
    env = os.environ.get("CUTTLE_WHPX_AVAILABLE")
    if env in ("0", "1"):
        return env == "1"
    if qemu_bin not in _whpx_cache:
        available = False
        if sys.platform == "win32":
            try:
                p = subprocess.Popen(
                    [qemu_bin, "-accel", "whpx", "-cpu", "max", "-M", "pc", "-display", "none", "-nodefaults",
                     "-S", "-no-reboot", "-monitor", "none", "-serial", "none"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                try:
                    p.wait(timeout=2.5)  # exiting this early means WHPX failed to initialize
                except subprocess.TimeoutExpired:
                    available = True
                    p.kill()
                    p.wait(timeout=5.0)
            except OSError:
                pass
        _whpx_cache[qemu_bin] = available
    return _whpx_cache[qemu_bin]


def resolve_accelerator(qemu_bin: str, requested: str) -> tuple:
    """
    Map a requested accelerator to (effective name, QEMU arguments).
      tcg  : software emulation, always available.
      whpx : Windows Hypervisor Platform (hardware virtualization); QEMU fails if unavailable.
      auto : WHPX when this host can start it, else TCG. Does not chain `-accel tcg` onto a
             WHPX launch so `node.accel` always reflects the accelerator QEMU actually runs;
             `await_boot` relaunches on TCG and updates `node.accel` if WHPX fails to run.
    """
    if requested not in ACCELERATORS:
        raise ValueError(f"accelerator must be one of {ACCELERATORS}, got {requested!r}")
    if requested == "tcg":
        return "tcg", ["-accel", "tcg"]
    if requested == "whpx":
        return "whpx", ["-accel", "whpx"]
    if whpx_available(qemu_bin):
        return "whpx", ["-accel", "whpx"]
    return "tcg", ["-accel", "tcg"]


def extract_text_sha256(elf_bytes: bytes) -> str:
    """Compute SHA-256 of the ELF binary to fingerprint the morphed machine code."""
    return hashlib.sha256(elf_bytes).hexdigest()


class TriadNode:
    def __init__(
        self,
        node_id: int,
        name: str,
        role: str,
        http_port: int,
        https_port: int,
        base_seed: int,
        show_gui: bool,
        state_dir: Path = TRIAD_DIR,
        key_context: str = "cuttle-triad-node-v1",
    ):
        self.node_id = node_id
        self.name = name
        self.role = role
        self.http_port = http_port
        self.https_port = https_port
        self.current_seed = base_seed
        self.show_gui = show_gui
        self.key_context = key_context

        self.node_dir = state_dir / f"node{node_id}"
        self.node_dir.mkdir(parents=True, exist_ok=True)
        self.bios_img = self.node_dir / f"bios_node{node_id}.img"
        self.morphed_elf = self.node_dir / f"kernel_node{node_id}.elf"
        self.ahci_img = self.node_dir / f"ahci_node{node_id}.img"
        self.virtio_img = self.node_dir / f"virtio_node{node_id}.img"
        self.nvme_img = self.node_dir / f"nvme_node{node_id}.img"
        self.serial_log = self.node_dir / f"serial_node{node_id}.log"
        self.device_key_path = self.node_dir / f"device_key_node{node_id}.bin"

        self.state = "INITIALIZING"  # INITIALIZING, ONLINE, DRAINING, MORPHING, CATCHING_UP, HEALING
        self.proc: subprocess.Popen | None = None
        self.cmd_lock = threading.Lock()
        self.response_lines: list[str] = []
        self.line_cond = threading.Condition()
        self.serial_tail: list[str] = []

        self.accel = "pending"  # accelerator this node's VM was launched with
        self.elf_sha256 = "pending"
        self.morph_stats = "pending"
        self.morph_count = 0
        self.boot_gen = 0
        self.tx_seq = 0
        self.state_digest = ""
        self.last_smp = "cpus=4 online=4 idle=hlt-ipi"
        self.last_sql_table = ""
        self.last_morph_ms = 0
        self.tampered = False
        # SHA-256 of the node's HTTPS certificate, from its `HTTPS UP ... cert_sha256=` serial line.
        self.tls_cert_sha256 = ""
        self.tls_entropy = ""
        self.tls_provisioned = False

    def ensure_disks(self, master_key_bytes: bytes):
        for img in (self.ahci_img, self.virtio_img, self.nvme_img):
            if not img.exists():
                with open(img, "wb") as f:
                    f.write(b"\x00" * (1024 * 1024))
        # Derive a unique 256-bit cryptographic device key for this Triad node so each VM
        # boots with its own seal_key, attest_key, net_auth_key, and initial service ELF variants.
        node_key = hmac.new(
            master_key_bytes,
            f"{self.key_context}:{self.node_id}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        write_secret_file(self.device_key_path, node_key)

    def wipe_disks(self):
        """Reset all 3 persistent disk images for this node to clean blank 1 MiB images."""
        for img in (self.ahci_img, self.virtio_img, self.nvme_img):
            with open(img, "wb") as f:
                f.write(b"\x00" * (1024 * 1024))
                f.flush()
                os.fsync(f.fileno())

    def read_sql_partition_bytes(self) -> bytes:
        if not self.ahci_img.exists():
            return b"\x00" * SQL_PART_SIZE
        try:
            with open(self.ahci_img, "rb") as f:
                f.seek(SQL_PART_OFFSET)
                data = f.read(SQL_PART_SIZE)
                if len(data) < SQL_PART_SIZE:
                    data += b"\x00" * (SQL_PART_SIZE - len(data))
                return data
        except OSError:
            return b"\x00" * SQL_PART_SIZE


class TriadController:
    def __init__(self, show_gui: bool = False, spec: TriadSpec | None = None):
        self.spec = spec or TriadSpec()
        self.qemu_bin = find_qemu()
        self.accel, self.accel_args = resolve_accelerator(self.qemu_bin, self.spec.accel)
        self.show_gui = show_gui
        state_dir = self.spec.state_dir
        state_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[dict] = []

        key_path = self.spec.master_key_path
        self.master_key_bytes = load_or_create_secret_file(key_path, 32, binary=True)

        # Generate a fresh ephemeral 128-bit session token on every controller startup.
        self.coordinator_token = secrets.token_hex(16)
        if self.spec.write_operator_token:
            write_secret_file(
                state_dir / "operator_token.txt",
                (self.coordinator_token + "\n").encode("ascii"),
            )

        self.base_elf_bytes = BASE_ELF.read_bytes()
        if not BASE_BIOS.exists() or BASE_BIOS.read_bytes().find(self.base_elf_bytes) < 0:
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "-p",
                    "factory_builder",
                    "--release",
                    "--quiet",
                    "--",
                    "--candidate",
                    str(BASE_ELF),
                    "--out",
                    str(BASE_BIOS),
                ],
                cwd=str(ROOT),
                check=True,
            )
        self.base_bios_bytes = BASE_BIOS.read_bytes()
        self.elf_offset_in_bios = self.base_bios_bytes.find(self.base_elf_bytes)
        if self.elf_offset_in_bios < 0:
            raise RuntimeError(
                "Base kernel ELF not found contiguously in run_bios.img; rebuild run_bios.img first."
            )

        s = self.spec
        self.nodes = [
            TriadNode(
                i,
                s.node_names[i - 1],
                s.node_roles[i - 1],
                s.http_base + i,
                s.https_base + i,
                s.base_seeds[i - 1],
                show_gui,
                state_dir=state_dir,
                key_context=s.key_context,
            )
            for i in (1, 2, 3)
        ]

        # Cron jobs live in each node's RAM and are cleared on every boot, so the controller
        # owns the desired list (spec defaults + jobs added through the API) and re-applies it.
        self.cron_file = state_dir / "cron_jobs.json"
        self.desired_cron: list[tuple[int, str]] = [
            (int(t), str(c)) for t, c in s.cron_jobs if is_readonly_shell_command(str(c))
        ]
        if self.cron_file.exists():
            try:
                loaded_cron = json.loads(self.cron_file.read_text(encoding="utf-8"))
                self.desired_cron = [
                    (int(t), str(c))
                    for t, c in loaded_cron
                    if int(t) > 0 and is_printable_ascii_command(str(c)) and is_readonly_shell_command(str(c))
                ]
            except Exception as e:
                self.log_event("WARN", f"Ignoring unreadable cron_jobs.json: {e}")

        # Monotonic Triad WAL for automatic catch-up after an OS morph bounce (persisted to disk)
        self.wal_lock = threading.Lock()
        self.wal_file = state_dir / "triad_wal.json"
        self.triad_tx_seq = 0
        self.triad_state_digest = ""
        self.wal_entries: list[tuple[int, str]] = []  # (tx_seq, sql_stmt)
        # Nodes whose applied tx_seq was restored from the WAL file (see `_load_wal_from_disk`).
        self.restored_tx_seq_nodes: set[int] = set()
        self.restored_node_digests: dict[int, str] = {}
        self._after_wal_write_ahead_hook = None
        self._load_wal_from_disk()
        self.parity_Buffer = b"\x00" * SQL_PART_SIZE
        self.parity_sha256 = hashlib.sha256(self.parity_Buffer).hexdigest()[:16] if s.has_sql else "n/a"
        self.parity_syndrome_ok = True
        self.quorum_status = "3/3 TMR MAJORITY VERIFIED (D1 ^ D2 = P)" if s.has_sql else "3/3 TMR MAJORITY VERIFIED"
        self.auto_morph_enabled = False
        self.auto_morph_interval = 45  # seconds
        self.next_rotate_idx = 0
        self.running = True
        self.morph_op_lock = threading.Lock()

    def _load_wal_from_disk(self):
        if not self.wal_file.exists():
            return
        try:
            raw_text = self.wal_file.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            if not isinstance(data, dict):
                raise ValueError("WAL root must be a JSON object")
            tx_seq = data.get("triad_tx_seq", 0)
            if not isinstance(tx_seq, int) or isinstance(tx_seq, bool) or tx_seq < 0:
                raise ValueError(f"invalid triad_tx_seq: {tx_seq!r}")
            raw_entries = data.get("wal_entries", [])
            if not isinstance(raw_entries, list):
                raise ValueError("wal_entries must be a list")
            parsed_entries: list[tuple[int, str]] = []
            for item in raw_entries:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    raise ValueError(f"malformed WAL entry: {item!r}")
                tid, stmt = item
                if not isinstance(tid, int) or isinstance(tid, bool) or tid <= 0:
                    raise ValueError(f"invalid WAL entry tx_id: {tid!r}")
                if not isinstance(stmt, str) or not is_printable_ascii_command(stmt):
                    raise ValueError(f"WAL entry #{tid} contains non-printable or empty command")
                parsed_entries.append((tid, stmt))
            self.triad_tx_seq = tx_seq
            self.wal_entries = parsed_entries
            self.triad_state_digest = str(data.get("triad_state_digest") or "")

            node_digests = data.get("node_state_digest", {})
            if isinstance(node_digests, dict):
                for n in self.nodes:
                    d = node_digests.get(str(n.node_id))
                    if isinstance(d, str) and d:
                        self.restored_node_digests[n.node_id] = d
                        n.state_digest = d

            node_seqs = data.get("node_tx_seq", {})
            if isinstance(node_seqs, dict):
                for n in self.nodes:
                    v = node_seqs.get(str(n.node_id))
                    if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= self.triad_tx_seq:
                        n.tx_seq = v
                        self.restored_tx_seq_nodes.add(n.node_id)
        except Exception as e:
            bad_copy = self.wal_file.with_suffix(".json.bad")
            try:
                shutil.copyfile(self.wal_file, bad_copy)
            except OSError:
                pass
            self.log_event("ALERT", f"Corrupt Triad WAL {self.wal_file} (saved to {bad_copy}): {e}")
            raise ValueError(f"corrupt Triad WAL {self.wal_file}: {e}") from e

    def _save_wal_to_disk(self):
        if len(self.wal_entries) > MAX_WAL_ENTRIES:
            min_applied = min((n.tx_seq for n in self.nodes if n.tx_seq > 0), default=0)
            head = [e for e in self.wal_entries if e[0] <= min_applied]
            tail = [e for e in self.wal_entries if e[0] > min_applied]
            self.wal_entries = compact_wal_entries(head) + tail
        payload = {
            "triad_tx_seq": self.triad_tx_seq,
            "triad_state_digest": self.triad_state_digest,
            "wal_entries": self.wal_entries,
            "node_tx_seq": {str(n.node_id): n.tx_seq for n in self.nodes},
            "node_state_digest": {str(n.node_id): n.state_digest for n in self.nodes if n.state_digest},
        }
        atomic_write_json(self.wal_file, payload)

    def _encrypt_wal_vault_cmd(self, cmd_str: str) -> str:
        """
        Encrypt a `vault put <key> <secret>` WAL command under `self.master_key_bytes`
        using a random 64-bit nonce, HMAC-SHA256 counter-mode keystream, and 128-bit
        HMAC-SHA256 authentication tag so plaintext secrets never touch `triad_wal.json`.
        """
        pt = cmd_str.strip().encode("ascii")
        nonce = os.urandom(8)
        ks = bytearray()
        blk = 0
        while len(ks) < len(pt):
            ks.extend(
                hmac.new(
                    self.master_key_bytes,
                    b"cuttle-triad-wal-ks-v1:" + nonce + blk.to_bytes(4, "little"),
                    hashlib.sha256,
                ).digest()
            )
            blk += 1
        ct = bytes(a ^ b for a, b in zip(pt, ks[: len(pt)]))
        mac = hmac.new(
            self.master_key_bytes,
            b"cuttle-triad-wal-mac-v1:" + nonce + ct,
            hashlib.sha256,
        ).digest()[:16]
        return f"ENC_WAL_V1:{nonce.hex()}:{ct.hex()}:{mac.hex()}"

    def _decrypt_wal_vault_cmd(self, wal_entry: str) -> str:
        """Verify and decrypt an `ENC_WAL_V1:<nonce>:<ct>:<mac>` WAL entry in constant time."""
        parts = wal_entry.strip().split(":")
        if len(parts) != 4 or parts[0] != "ENC_WAL_V1":
            raise ValueError("invalid encrypted WAL entry format")
        nonce = bytes.fromhex(parts[1])
        ct = bytes.fromhex(parts[2])
        mac = bytes.fromhex(parts[3])
        expected_mac = hmac.new(
            self.master_key_bytes,
            b"cuttle-triad-wal-mac-v1:" + nonce + ct,
            hashlib.sha256,
        ).digest()[:16]
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("WAL AEAD authentication tag mismatch")
        ks = bytearray()
        blk = 0
        while len(ks) < len(ct):
            ks.extend(
                hmac.new(
                    self.master_key_bytes,
                    b"cuttle-triad-wal-ks-v1:" + nonce + blk.to_bytes(4, "little"),
                    hashlib.sha256,
                ).digest()
            )
            blk += 1
        pt = bytes(a ^ b for a, b in zip(ct, ks[: len(ct)])).decode("ascii")
        if not is_printable_ascii_command(pt):
            raise ValueError("decrypted WAL entry contains non-printable characters")
        return pt

    @staticmethod
    def _redact_app_cmd(cmd_str: str) -> str:
        """Redact the secret value from `vault put <key> <secret>` before logging to events/stdout."""
        parts = cmd_str.strip().split()
        if len(parts) >= 3 and parts[0].lower() == "vault" and parts[1].lower() == "put":
            return f"vault put {parts[2]} [REDACTED]"
        return cmd_str.strip()

    def log_event(self, level: str, msg: str):
        ts = time.strftime("%H:%M:%S")
        entry = {"ts": ts, "level": level, "msg": msg}
        self.events.insert(0, entry)
        if len(self.events) > 60:
            self.events.pop()
        safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
        print(f"[{ts}] {self.spec.log_prefix}[{level}] {safe_msg}", flush=True)

    def morph_node_image(self, node: TriadNode, new_seed: int):
        """Run binmorph.exe (~250ms) and splice the morphed ELF directly into node's bios.img."""
        t0 = time.perf_counter()
        node.current_seed = new_seed
        cmd = [
            str(BINMORPH_EXE),
            "--in",
            str(BASE_ELF),
            "--out",
            str(node.morphed_elf),
            "--seed",
            str(new_seed),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        stderr_line = res.stderr.strip().splitlines()[-1] if res.stderr.strip() else ""
        morphed_bytes = node.morphed_elf.read_bytes()
        if len(morphed_bytes) != len(self.base_elf_bytes):
            raise RuntimeError("binmorph output ELF size mismatch")

        node.elf_sha256 = extract_text_sha256(morphed_bytes)
        node.morph_stats = stderr_line.replace("binmorph: ", "")

        # Splice morphed ELF directly into BIOS image at exact offset
        bios_copy = bytearray(self.base_bios_bytes)
        off = self.elf_offset_in_bios
        bios_copy[off : off + len(morphed_bytes)] = morphed_bytes
        node.bios_img.write_bytes(bios_copy)
        node.morph_count += 1
        node.last_morph_ms = int((time.perf_counter() - t0) * 1000)
        self.log_event(
            "MORPH",
            f"{node.name}: binmorph seed={new_seed} completed in {node.last_morph_ms}ms "
            f"(sha256={node.elf_sha256[:12]}.. | {node.morph_stats})",
        )

    def start_node_vm(self, node: TriadNode):
        node.ensure_disks(self.master_key_bytes)
        node.accel = self.accel
        mac_last = f"{0x50 + node.node_id:02x}"
        if self.spec.forward_node_ports:
            usernet_arg = (
                f"user,id=usernet0,"
                f"hostfwd=tcp:127.0.0.1:{node.http_port}-10.0.2.15:80,"
                f"hostfwd=tcp:127.0.0.1:{node.https_port}-10.0.2.15:443"
            )
        else:
            usernet_arg = "user,id=usernet0"
        cmd = [
            self.qemu_bin,
            *self.accel_args,
            "-cpu",
            "max",
            "-smp",
            str(self.spec.smp),
            "-m",
            self.spec.memory,
            "-fw_cfg",
            f"name=opt/cuttle_device_key,file={node.device_key_path}",
            "-drive",
            f"format=raw,file={node.bios_img},if=ide",
            "-drive",
            f"if=none,id=vd0,format=raw,file={node.virtio_img}",
            "-device",
            "virtio-blk-pci,drive=vd0,disable-legacy=off,disable-modern=on",
            "-netdev",
            "hubport,id=n0,hubid=1",
            "-device",
            "virtio-net-pci,netdev=n0,disable-legacy=off,disable-modern=on",
            "-netdev",
            "hubport,id=n1,hubid=1",
            "-device",
            "virtio-net-pci,netdev=n1,disable-legacy=off,disable-modern=on",
            "-netdev",
            usernet_arg,
            "-device",
            f"virtio-net-pci,netdev=usernet0,mac=52:54:00:12:34:{mac_last},disable-legacy=on,disable-modern=off",
            "-drive",
            f"if=none,id=ahd0,format=raw,file={node.ahci_img}",
            "-device",
            "ahci,id=ahci0",
            "-device",
            "ide-hd,drive=ahd0,bus=ahci0.0",
            "-netdev",
            "hubport,id=e0,hubid=2",
            "-device",
            "e1000,netdev=e0",
            "-netdev",
            "hubport,id=e1,hubid=2",
            "-device",
            "e1000,netdev=e1",
            "-drive",
            f"if=none,id=nvme0,format=raw,file={node.nvme_img}",
            "-device",
            f"nvme,drive=nvme0,serial=CUTTLE-NVME-{node.node_id}",
            "-serial",
            "stdio",
            "-no-reboot",
        ]
        if not self.show_gui:
            cmd.extend(["-display", "none"])

        with node.line_cond:
            node.serial_tail.clear()
            node.response_lines.clear()

        node.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        t = threading.Thread(target=self._serial_reader_loop, args=(node,), daemon=True)
        t.start()

    def _serial_reader_loop(self, node: TriadNode):
        proc = node.proc
        if not proc or not proc.stdout:
            return
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\r\n")
            if not line:
                continue
            with node.line_cond:
                node.serial_tail.append(line)
                if len(node.serial_tail) > 40:
                    node.serial_tail.pop(0)

                if line.startswith("HTTPS UP "):
                    m = re.search(
                        r"entropy=(\S+)\s+provisioned=([01])\s+cert_sha256=([0-9a-f]{64})",
                        line,
                    )
                    if m:
                        node.tls_entropy = m.group(1)
                        node.tls_provisioned = m.group(2) == "1"
                        node.tls_cert_sha256 = m.group(3)
                    else:
                        m2 = re.search(r"cert_sha256=([0-9a-f]{64})", line)
                        if m2:
                            node.tls_cert_sha256 = m2.group(1)
                if "CONTINUITY genesis" in line:
                    node.boot_gen = 1
                elif "CONTINUITY resume OK" in line:
                    m = re.search(r"boots=(\d+)", line)
                    if m:
                        node.boot_gen = int(m.group(1))

                node.response_lines.append(line)
                node.line_cond.notify_all()

    def _guest_started(self, node: TriadNode, timeout: float) -> bool:
        """True once the guest prints a recognized bootloader/kernel serial marker."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with node.line_cond:
                if has_guest_serial_output(node.serial_tail):
                    return True
                if not node.proc or node.proc.poll() is not None:
                    return False
                node.line_cond.wait(timeout=0.2)
        return False

    def await_boot(self, node: TriadNode, timeout: float) -> bool:
        """
        Wait for a just-launched node's shell. Under `auto`, a VM that WHPX accepts but never
        runs (seen on some Windows hosts: the BIOS never leaves reset and serial stays empty)
        is relaunched on TCG, and this Triad stays on TCG from then on.
        """
        wait_s = 0.2 if self.accel == "tcg" else WHPX_FIRST_OUTPUT_S
        if node.accel == "whpx" and self.spec.accel == "auto" and not self._guest_started(node, wait_s):
            self.log_event(
                "WARN",
                f"{node.name}: no guest output under WHPX after {WHPX_FIRST_OUTPUT_S:.0f}s; relaunching on TCG "
                f"and keeping this Triad on TCG.",
            )
            try:
                node.proc.kill()
                node.proc.wait(timeout=5.0)
            except Exception:
                pass
            self.accel, self.accel_args = "tcg", ["-accel", "tcg"]
            _whpx_cache[self.qemu_bin] = False
            os.environ["CUTTLE_WHPX_AVAILABLE"] = "0"
            self.start_node_vm(node)
        return self.wait_for_shell_ready(node, timeout=timeout)

    def wait_for_shell_ready(self, node: TriadNode, timeout: float = 25.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with node.line_cond:
                for ln in node.serial_tail:
                    if "Web UI:" in ln or "interactive shell ready" in ln:
                        break
                else:
                    node.line_cond.wait(timeout=0.2)
                    continue
                break
        else:
            return False
        time.sleep(0.08)
        return True

    def apply_node_profile(self, node: TriadNode) -> bool:
        """
        Re-apply what every boot resets: the kernel role profile (each boot starts as `full`)
        and the desired cron jobs (held in node RAM). Called once the shell is ready, before
        the node rejoins the pool. If applying the role fails after 3 attempts, terminates the
        VM, marks the node OFFLINE, logs an ALERT, and returns False so the node never joins
        the pool with an un-scoped `full` role.
        """
        role = self.spec.role
        if role != "full":
            last_out = ""
            applied = False
            for _ in range(3):
                last_out = self.send_shell_cmd(node, f"service role {role}")
                if f"role={role}" in last_out:
                    applied = True
                    break
                time.sleep(0.1)
            if not applied:
                self.log_event(
                    "ALERT",
                    f"{node.name}: failed to apply role '{role}' after 3 attempts ({last_out[:120]}); keeping node OFFLINE.",
                )
                node.state = "OFFLINE"
                if node.proc and node.proc.poll() is None:
                    try:
                        node.proc.kill()
                        node.proc.wait(timeout=3.0)
                    except Exception:
                        pass
                return False
        if self.spec.has_shell:
            for ticks, cmd in self.desired_cron:
                if is_readonly_shell_command(cmd):
                    self.send_shell_cmd(node, f"cron add {ticks} {cmd}")
        return True

    def send_shell_cmd(self, node: TriadNode, cmd_str: str, timeout: float = 5.0) -> str:
        """
        Send a single-line command over the node's serial console (paced for the 16-byte 16550 UART FIFO)
        and capture output. Rejects any command containing non-printable or control characters (such as
        0x08 BS or 0x7F DEL) so callers cannot manipulate the kernel's serial line buffer.
        """
        if any(not (0x20 <= ord(ch) <= 0x7E) for ch in cmd_str):
            raise ValueError("command contains non-printable or control characters")
        clean_cmd = cmd_str.strip()
        if not clean_cmd:
            return ""
        with node.cmd_lock:
            if not node.proc or node.proc.poll() is not None:
                return "error: node offline"
            with node.line_cond:
                node.response_lines.clear()
            payload = clean_cmd + "\n"
            try:
                for i in range(0, len(payload), 6):
                    node.proc.stdin.write(payload[i : i + 6])
                    node.proc.stdin.flush()
                    if i + 6 < len(payload):
                        time.sleep(0.025)
                # Send a second newline after a brief pause so the trailing `cuttle> ` prompt
                # is terminated with `\r\n` and flushed immediately through line-buffered stdout.
                time.sleep(0.030)
                node.proc.stdin.write("\n")
                node.proc.stdin.flush()
            except OSError:
                return "error: pipe closed"

            collected: list[str] = []
            sent_at = time.time()
            deadline = sent_at + timeout
            saw_prompt_end = False
            while time.time() < deadline:
                with node.line_cond:
                    while node.response_lines:
                        ln = node.response_lines.pop(0)
                        while ln.startswith("cuttle>"):
                            rest = ln[len("cuttle>") :].lstrip(" ")
                            if not rest:
                                if collected:
                                    saw_prompt_end = True
                                ln = ""
                                break
                            ln = rest
                        if not ln:
                            continue
                        if ln.strip() == clean_cmd:
                            continue
                        if clean_cmd.startswith("sql ") and ln.strip().startswith("sql "):
                            continue
                        if (
                            ln.startswith("AHCI_HW ")
                            or ln.startswith("Web UI:")
                            or "interactive shell ready" in ln
                        ):
                            continue
                        collected.append(ln)
                    if saw_prompt_end or (
                        collected
                        and (time.time() - sent_at) >= 0.30
                        and self._response_looks_complete(clean_cmd, collected)
                    ):
                        break
                    node.line_cond.wait(timeout=0.06)
            return "\n".join(collected).strip()

    def _response_looks_complete(self, cmd_str: str, lines: list[str]) -> bool:
        joined = "\n".join(lines)
        c = cmd_str.strip()
        if c.startswith("sql "):
            return (
                "INSERT " in joined
                or "REPLACE " in joined
                or "UPDATE " in joined
                or "DELETE " in joined
                or "CREATE TABLE" in joined
                or "DROP TABLE" in joined
                or "BEGIN" in joined
                or "COMMIT" in joined
                or "ROLLBACK" in joined
                or "error:" in joined
                or "tables:" in joined
            )
        if c.startswith("vault"):
            return "vault:" in joined or "k|v|rev" in joined or "error:" in joined
        if c.startswith("guard"):
            return "guard:" in joined or "error:" in joined
        if c.startswith("cron"):
            return "cron:" in joined or "error:" in joined
        if c == "smp":
            return "cpu3:" in joined
        if c.startswith("smp run"):
            return "smp: dispatched" in joined
        if c == "sync":
            return "sync:" in joined
        if c == "service status":
            return "svc-sh" in joined
        return len(lines) >= 1

    @staticmethod
    def _normalize_kv_for_tmr(sql_out: str) -> str:
        """
        Normalize raw `SELECT * FROM kv` output for 2-of-3 TMR comparison across Triad nodes:
        because each Triad node encrypts `CuttleVault` secrets (`k = 'v:<name>'`) under its own
        independent 256-bit hardware `seal_key`, the on-disk ciphertext (`v`) and MAC tag (`rev`)
        are cryptographically distinct per node while the key set (`v:<name>`) is identical.
        """
        norm_lines = []
        for ln in sql_out.splitlines():
            if ln.startswith("v:") and "|" in ln:
                kname = ln.split("|", 1)[0]
                norm_lines.append(f"{kname}|<HW_SEALED>")
            else:
                norm_lines.append(ln)
        return "\n".join(norm_lines)

    def refresh_node_telemetry(self, node: TriadNode):
        if node.state not in ("ONLINE", "CATCHING_UP", "HEALING"):
            return
        smp_out = self.send_shell_cmd(node, "smp", timeout=3.0)
        if smp_out and "cpus=" in smp_out:
            first_line = smp_out.splitlines()[0]
            node.last_smp = first_line
        if not self.spec.has_sql:
            return
        sql_out = self.send_shell_cmd(node, "sql /*triad*/ SELECT * FROM kv", timeout=3.0)
        if sql_out and "k|v|rev" in sql_out:
            node.last_sql_table = sql_out

    def _state_probe(self, node: TriadNode) -> str | None:
        """
        The node's replicated state as compared by the 2-of-3 vote, or None if unreadable.
        SQL-capable roles compare the spec's vote tables; a web front end (`wfe`, no svc-sql)
        compares every served file's path, size, and SHA-256 content digest.
        """
        if not self.spec.has_sql:
            ls_out = self.send_shell_cmd(node, "ls", timeout=4.0)
            if not ls_out or ls_out.lower().startswith("error"):
                return None
            file_entries = []
            for ln in ls_out.splitlines():
                m = re.match(r"^(\S+)\s+\((\d+)\s+B\)$", ln.strip())
                if not m:
                    continue
                fpath, flen = m.group(1), m.group(2)
                content = self.send_shell_cmd(node, f"cat {fpath}", timeout=3.0)
                digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
                file_entries.append(f"{fpath} ({flen} B) sha256={digest}")
            return "\n".join(file_entries) if file_entries else ls_out
        parts = []
        for table in self.spec.vote_tables:
            out = self.send_shell_cmd(node, f"sql /*triad*/ SELECT * FROM {table}", timeout=4.0)
            if not out or out.lower().startswith("error") or "|" not in out.splitlines()[0]:
                return None
            if table == "kv":
                node.last_sql_table = out
            parts.append(self._normalize_kv_for_tmr(out))
        return "\n--\n".join(parts)

    def _state_fingerprint(self, node: TriadNode) -> str | None:
        """SHA-256 hex digest of `node`'s replicated state probe, or None if unreadable."""
        probe = self._state_probe(node)
        if probe is None:
            return None
        return hashlib.sha256(probe.encode("utf-8")).hexdigest()

    def _sync_files_from_peer(self, target: TriadNode, peer: TriadNode):
        """Copy every file in `peer`'s shell filesystem onto `target` during a non-SQL heal."""
        ls_out = self.send_shell_cmd(peer, "ls", timeout=4.0)
        if not ls_out or ls_out.lower().startswith("error"):
            return
        for ln in ls_out.splitlines():
            m = re.match(r"^(\S+)\s+\(\d+\s+B\)$", ln.strip())
            if not m:
                continue
            fpath = m.group(1)
            peer_content = self.send_shell_cmd(peer, f"cat {fpath}", timeout=3.0)
            target_content = self.send_shell_cmd(target, f"cat {fpath}", timeout=3.0)
            if peer_content != target_content and is_printable_ascii_command(peer_content):
                self.send_shell_cmd(target, f"write {fpath} {peer_content}", timeout=3.0)
        self.send_shell_cmd(target, "sync", timeout=3.0)

    def compute_and_verify_raid_parity(self):
        """
        Compute 4 KiB RAID Parity P = D1 ^ D2 across OS-1 and OS-2 SQL partitions,
        and verify Triple Modular Redundancy (TMR) 2-of-3 majority consistency across all online Triad members.
        """
        n1, n2, n3 = self.nodes[0], self.nodes[1], self.nodes[2]
        online_nodes = [n for n in self.nodes if n.state == "ONLINE"]

        if len(online_nodes) >= 2:
            # Read each online node's replicated state to verify 2-of-3 majority consistency
            outputs = {n.node_id: self._state_probe(n) for n in online_nodes}

            # Check if any node diverges from the 2-of-3 majority!
            if len(online_nodes) == 3 and all(outputs.get(i) is not None for i in (1, 2, 3)):
                o1, o2, o3 = outputs[1], outputs[2], outputs[3]
                if o1 == o2 == o3:
                    self.parity_syndrome_ok = True
                    digest = hashlib.sha256(o1.encode("utf-8")).hexdigest()
                    with self.wal_lock:
                        changed = (self.triad_state_digest != digest) or any(
                            n.state_digest != digest for n in online_nodes
                        )
                        self.triad_state_digest = digest
                        for n in online_nodes:
                            n.state_digest = digest
                        if changed and self.wal_file.exists():
                            self._save_wal_to_disk()
                    if self.spec.has_sql:
                        self.quorum_status = f"3/3 TMR MAJORITY LOCKED | RAID PARITY D1⊕D2=P VERIFIED (tx_seq={self.triad_tx_seq})"
                    else:
                        self.quorum_status = "3/3 TMR MAJORITY LOCKED | SERVED CONTENT VERIFIED"
                else:
                    # 2-of-3 Majority Vote identifies the exact tampered/corrupted node!
                    corrupted = None
                    if o2 == o3 and o1 != o2:
                        corrupted = n1
                    elif o1 == o3 and o2 != o1:
                        corrupted = n2
                    elif o1 == o2 and o3 != o1:
                        corrupted = n3
                    if corrupted:
                        if corrupted.state == "HEALING":
                            return
                        corrupted.state = "HEALING"
                        self.parity_syndrome_ok = False
                        self.quorum_status = f"TMR PARITY FAULT ON {corrupted.name} — 2/3 MAJORITY HEALING!"
                        self.log_event(
                            "ALERT",
                            f"RAID Parity & 2/3 Majority mismatch on {corrupted.name}! "
                            f"Outvoted 2-to-1 by peers. Triggering automatic RAID reconstruction + Emergency Morph!",
                        )
                        threading.Thread(
                            target=self.heal_and_remorph_node, args=(corrupted,), daemon=True
                        ).start()
                        return
            else:
                names = " + ".join(n.name.split()[0] for n in online_nodes)
                self.quorum_status = f"2/3 DEGRADED TMR MAJORITY ACTIVE ({names}) — 0ms Downtime During Morph"

        if not self.spec.has_sql:
            return  # no SQL partition to protect with parity on this role

        # Update 4 KiB bitwise XOR parity across D1 and D2 AHCI SQL partitions
        d1 = n1.read_sql_partition_bytes()
        d2 = n2.read_sql_partition_bytes()
        p = bytes(a ^ b for a, b in zip(d1, d2))
        self.parity_Buffer = p
        self.parity_sha256 = hashlib.sha256(p).hexdigest()[:16]

    def execute_triad_sql(self, sql_query: str) -> dict:
        """
        Execute a SQL statement across the 3-as-1 Triad:
        - Strictly rejects any query containing non-printable or control characters (0x08 BS, 0x7F DEL, etc.).
        - Read-only queries (`SELECT`, `.tables`, `.schema`) execute with 2-of-3 majority verification.
        - Mutating queries (`INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`) increment `triad_tx_seq`,
          write-ahead and fsync to the Triad WAL BEFORE executing on the nodes, execute across all
          ONLINE nodes, and flush AHCI. If 0 nodes accept the syntax/statement, the unapplied WAL
          entry is rolled back.
        """
        if not is_printable_ascii_command(sql_query):
            raise ValueError("query contains non-printable or control characters")
        q = sql_query.strip()
        if not q:
            return {"ok": False, "error": "empty SQL query", "output": "error: empty SQL query", "quorum": "0/3"}
        is_read = is_readonly_sql_query(q)

        online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
        if not online_nodes:
            return {"ok": False, "output": "error: no online nodes in triad", "quorum": "0/3"}

        if is_read:
            results = {}
            for n in online_nodes:
                try:
                    results[n.name] = self.send_shell_cmd(n, f"sql /*triad*/ {q}")
                except ValueError as e:
                    return {
                        "ok": False,
                        "error": f"rejected: {e}",
                        "output": f"error: {e}",
                        "quorum": "0/3",
                    }
            # Perform majority vote across online nodes
            vals = list(results.values())
            chosen = max(set(vals), key=vals.count)
            agree = vals.count(chosen)
            return {
                "ok": True,
                "mode": "READ (2-of-3 Majority Verified)",
                "quorum": f"{agree}/{len(online_nodes)} ONLINE NODES AGREED",
                "tx_seq": self.triad_tx_seq,
                "output": chosen,
                "per_node": results,
            }

        # Mutating SQL write: write-ahead to the Triad WAL and fsync BEFORE executing on
        # any node, holding `self.wal_lock` across the write-ahead, replica execution, and
        # `n.tx_seq` + `state_digest` update.
        with self.wal_lock:
            online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
            if not online_nodes:
                return {"ok": False, "output": "error: no online nodes in triad", "quorum": "0/3"}

            prev_tx_seq = self.triad_tx_seq
            tx_id = prev_tx_seq + 1
            self.triad_tx_seq = tx_id
            self.wal_entries.append((tx_id, q))
            self._save_wal_to_disk()
            if self._after_wal_write_ahead_hook is not None:
                self._after_wal_write_ahead_hook(tx_id, q)

            per_node = {}
            accepted_nodes = []
            for n in online_nodes:
                try:
                    out = self.send_shell_cmd(n, f"sql /*triad*/ {q}")
                except ValueError as e:
                    if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                        self.wal_entries.pop()
                    self.triad_tx_seq = prev_tx_seq
                    self._save_wal_to_disk()
                    return {
                        "ok": False,
                        "error": f"rejected: {e}",
                        "output": f"error: {e}",
                        "quorum": "0/3",
                    }
                per_node[n.name] = out
                low_out = out.strip().lower()
                if (
                    low_out
                    and "error:" not in low_out
                    and "unknown command" not in low_out
                    and "usage:" not in low_out
                ):
                    accepted_nodes.append(n)

            primary_out = next(iter(per_node.values()), "")
            if not accepted_nodes:
                if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                    self.wal_entries.pop()
                self.triad_tx_seq = prev_tx_seq
                self._save_wal_to_disk()
                return {
                    "ok": False,
                    "error": primary_out or "error: SQL statement rejected by online nodes",
                    "output": primary_out,
                    "quorum": f"0/{len(online_nodes)} online nodes accepted",
                    "per_node": per_node,
                }

            for n in accepted_nodes:
                self.send_shell_cmd(n, "sync")
                n.tx_seq = tx_id
            fp = self._state_fingerprint(accepted_nodes[0])
            if fp:
                self.triad_state_digest = fp
                for n in accepted_nodes:
                    n.state_digest = fp
            self._save_wal_to_disk()  # persist each node's applied tx_seq and state digest

            for n in self.nodes:
                if n.state != "ONLINE":
                    per_node[n.name] = f"[QUEUED IN WAL tx #{tx_id} — will replay on wakeup]"

        self.log_event(
            "SQL-RAID",
            f"Committed tx #{tx_id} ({q}) to {len(accepted_nodes)}/3 online nodes; RAID parity updated.",
        )
        self.compute_and_verify_raid_parity()
        return {
            "ok": True,
            "mode": "WRITE (Parallel RAID + WAL)",
            "quorum": f"Committed on {len(accepted_nodes)}/3 online nodes (tx_seq={tx_id})",
            "tx_seq": tx_id,
            "output": primary_out,
            "per_node": per_node,
        }

    def execute_triad_app(self, app_cmd: str) -> dict:
        """
        Execute a Cuttle OS built-in application command (`vault`, `guard`, or `cron`) across the 3-as-1 Triad:
        - `vault put <key> <val>` / `vault del <key>`: encrypts `<val>` under each node's independent 256-bit
          hardware `seal_key`, persists an encrypted `ENC_WAL_V1:...` record to the Triad WAL ahead of
          execution, and flushes AHCI (`sync`).
        - `vault get <key>`: unseals and verifies `<key>` on all online nodes and returns a 2-of-3 Majority Vote!
        - `guard status` / `guard alerts` / `guard lockdown` / `guard unlock`: queries or enforces Blue-Team
          security posture across all 3 Triad nodes simultaneously.
        - `cron add <ticks> <cmd>` / `cron list` / `cron del <id>` / `cron run`: manages deterministic periodic
          read-only jobs across all 3 Triad nodes. State-changing cron commands are refused with 403.
        """
        if not is_printable_ascii_command(app_cmd):
            raise ValueError("command contains non-printable or control characters")
        c = app_cmd.strip()
        parts = c.split()
        if not parts or parts[0].lower() not in ("vault", "guard", "cron"):
            return {"ok": False, "error": "unsupported app command (expected vault, guard, or cron)", "quorum": "0/3"}

        app = parts[0].lower()
        sub = parts[1].lower() if len(parts) > 1 else "status"

        if app == "cron" and sub == "add":
            if len(parts) < 4 or not parts[2].isdigit() or int(parts[2]) <= 0:
                return {
                    "ok": False,
                    "error": "usage: cron add <ticks> <readonly_command>",
                    "quorum": "0/3",
                }
            cron_target_cmd = " ".join(parts[3:])
            if not is_readonly_shell_command(cron_target_cmd):
                return {
                    "ok": False,
                    "status_code": 403,
                    "error": "rejected: /api/cron allows only read-only inspection commands; state-changing operations must go through the Triad WAL",
                    "quorum": "0/3",
                }

        is_read = (
            (app == "vault" and sub in ("get", "list", "status"))
            or (app == "guard" and sub in ("status", "alerts"))
            or (app == "cron" and sub in ("list", "status"))
        )

        if is_read:
            online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
            if not online_nodes:
                return {"ok": False, "error": "no online nodes in triad", "quorum": "0/3"}
            per_node = {}
            accepted_nodes = []
            for n in online_nodes:
                out = self.send_shell_cmd(n, c)
                per_node[n.name] = out
                low_out = out.strip().lower()
                if low_out and not low_out.startswith("error:") and not low_out.startswith("usage:"):
                    accepted_nodes.append(n)
            vals = list(per_node.values())
            chosen = max(set(vals), key=vals.count) if vals else ""
            agree = vals.count(chosen)
            return {
                "ok": len(accepted_nodes) > 0,
                "mode": f"APP READ ({app.upper()} 2-of-3 Majority)",
                "quorum": f"{agree}/{len(online_nodes)} ONLINE NODES AGREED",
                "tx_seq": self.triad_tx_seq,
                "output": chosen,
                "per_node": per_node,
            }

        # Mutating app write: hold `self.wal_lock` across write-ahead, replica execution,
        # and updating `tx_seq` / `desired_cron`.
        with self.wal_lock:
            online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
            if not online_nodes:
                return {"ok": False, "error": "no online nodes in triad", "quorum": "0/3"}

            is_vault_mut = app == "vault" and sub in ("put", "del")
            prev_tx_seq = self.triad_tx_seq
            tx_id = prev_tx_seq
            if is_vault_mut:
                tx_id = prev_tx_seq + 1
                self.triad_tx_seq = tx_id
                wal_record = self._encrypt_wal_vault_cmd(c) if sub == "put" else c
                self.wal_entries.append((tx_id, wal_record))
                self._save_wal_to_disk()

            per_node = {}
            accepted_nodes = []
            for n in online_nodes:
                out = self.send_shell_cmd(n, c)
                per_node[n.name] = out
                low_out = out.strip().lower()
                if low_out and not low_out.startswith("error:") and not low_out.startswith("usage:"):
                    accepted_nodes.append(n)

            vals = list(per_node.values())
            chosen = max(set(vals), key=vals.count) if vals else ""
            if not accepted_nodes:
                if is_vault_mut:
                    if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                        self.wal_entries.pop()
                    self.triad_tx_seq = prev_tx_seq
                    self._save_wal_to_disk()
                return {
                    "ok": False,
                    "error": chosen or f"error: {app} command rejected by online nodes",
                    "output": chosen,
                    "quorum": f"0/{len(online_nodes)} online nodes accepted",
                    "per_node": per_node,
                }

            if is_vault_mut:
                for n in accepted_nodes:
                    self.send_shell_cmd(n, "sync")
                    n.tx_seq = tx_id
                fp = self._state_fingerprint(accepted_nodes[0])
                if fp:
                    self.triad_state_digest = fp
                    for n in accepted_nodes:
                        n.state_digest = fp
                self._save_wal_to_disk()  # persist each node's applied tx_seq and state digest
            if app == "cron" and sub in ("add", "del"):
                self._record_desired_cron(parts)

        if app == "vault" and sub in ("put", "del"):
            self.compute_and_verify_raid_parity()

        redacted_cmd = self._redact_app_cmd(c)
        self.log_event(
            f"APP-{app.upper()}",
            f"Executed '{redacted_cmd}' across {len(accepted_nodes)}/3 online Triad nodes (tx_seq={tx_id}).",
        )
        return {
            "ok": True,
            "mode": f"APP WRITE ({app.upper()} Replicated)",
            "quorum": f"Applied on {len(accepted_nodes)}/{len(online_nodes)} online nodes (tx_seq={tx_id})",
            "tx_seq": tx_id,
            "output": chosen,
            "per_node": per_node,
        }

    def _record_desired_cron(self, parts: list[str]):
        """
        Keep the desired cron list in step with an accepted `cron add <ticks> <cmd>` or
        `cron del <id>` under `self.wal_lock`, writing `cron_jobs.json` atomically.
        """
        if parts[1].lower() == "add" and len(parts) >= 4 and parts[2].isdigit():
            cmd = " ".join(parts[3:])
            if not is_readonly_shell_command(cmd):
                return
            self.desired_cron.append((int(parts[2]), cmd))
        elif parts[1].lower() == "del" and len(parts) >= 3 and parts[2].isdigit():
            idx = int(parts[2]) - 1
            if 0 <= idx < len(self.desired_cron):
                self.desired_cron.pop(idx)
            for n in self.nodes:
                if n.state == "ONLINE":
                    self._rebuild_cron_table(n)
        else:
            return
        atomic_write_json(self.cron_file, self.desired_cron)

    def _rebuild_cron_table(self, node: TriadNode):
        """Delete every job on `node` and re-add the desired list in order (ids become 1..n)."""
        listing = self.send_shell_cmd(node, "cron list")
        for job_id in re.findall(r"^\s*id=(\d+)", listing, re.M):
            self.send_shell_cmd(node, f"cron del {job_id}")
        for ticks, cmd in self.desired_cron:
            if is_readonly_shell_command(cmd):
                self.send_shell_cmd(node, f"cron add {ticks} {cmd}")

    def _replay_wal_entry(self, node: TriadNode, stmt: str):
        s = stmt.strip()
        if s.startswith("ENC_WAL_V1:"):
            decrypted_cmd = self._decrypt_wal_vault_cmd(s)
            self.send_shell_cmd(node, decrypted_cmd)
        elif s.lower().startswith("vault "):
            self.send_shell_cmd(node, s)
        else:
            self.send_shell_cmd(node, f"sql /*triad*/ {s}")

    def bounce_and_morph_node(
        self, node_id: int, _lock_held: bool = False, _wipe_disks: bool = False
    ) -> bool:
        """
        Perform a live zero-downtime MTD Morph on a single node while the other 2 nodes
        keep the logical SQL Appliance 100% online, followed by automatic WAL Delta Catch-Up.
        """
        if not _lock_held and not self.morph_op_lock.acquire(blocking=False):
            self.log_event("WARN", "Another node is currently morphing; keeping 2/3 majority intact.")
            return False

        try:
            node = self.nodes[node_id - 1]
            peers = [n for n in self.nodes if n.node_id != node_id and n.state == "ONLINE"]
            if len(peers) < 2:
                self.log_event("WARN", f"Cannot morph {node.name}: need 2 healthy peers for majority.")
                return False

            # 1. DRAINING: Flush state to AHCI disk
            node.state = "DRAINING"
            self.log_event(
                "MTD",
                f"{node.name}: Draining & sealing AHCI disk (peers {peers[0].name.split()[0]} + {peers[1].name.split()[0]} holding 2/3 majority)...",
            )
            if not _wipe_disks:
                self.send_shell_cmd(node, "sync", timeout=3.0)
            if node.proc and node.proc.poll() is None:
                try:
                    node.proc.stdin.write("\nhalt\n")
                    node.proc.stdin.flush()
                    node.proc.wait(timeout=4.0)
                except Exception:
                    try:
                        node.proc.kill()
                        node.proc.wait(timeout=5.0)
                    except Exception:
                        pass
            time.sleep(0.3)
            if _wipe_disks:
                node.wipe_disks()

            # 2. MORPHING: Rewrite kernel ELF with fresh seed via binmorph (~250ms)
            node.state = "MORPHING"
            self.quorum_status = f"2/3 TMR MAJORITY ACTIVE ({peers[0].name.split()[0]} + {peers[1].name.split()[0]}) | {node.name.split()[0]} MORPHING"
            new_seed = random.randint(100_000, 999_999)
            self.morph_node_image(node, new_seed)

            # 3. Boot freshly morphed VM
            self.start_node_vm(node)
            ok = self.await_boot(node, timeout=35.0)
            if not ok:
                tail_str = " | ".join(node.serial_tail[-5:])
                self.log_event("ERROR", f"{node.name}: Timed out waiting for shell ready after morph (tail: {tail_str}).")
                node.state = "OFFLINE"
                return False
            if _wipe_disks and not self.spec.has_sql and peers:
                self._sync_files_from_peer(node, peers[0])
            if not self.apply_node_profile(node):
                return False

            # 4. CATCHING_UP: Replay any SQL transactions committed while this node was morphing,
            #    holding `self.wal_lock` across the replay AND the `node.state = "ONLINE"` transition
            #    so no concurrent write can be missed in the gap.
            node.state = "CATCHING_UP"
            with self.wal_lock:
                missed = [(tid, stmt) for (tid, stmt) in self.wal_entries if tid > node.tx_seq]
                if missed:
                    self.log_event(
                        "RESYNC",
                        f"{node.name}: Woke up at tx_seq={node.tx_seq} (Triad is at tx_seq={self.triad_tx_seq}). "
                        f"Replaying {len(missed)} missed WAL transaction(s) from twin/parity majority...",
                    )
                    for tid, stmt in missed:
                        if not is_printable_ascii_command(stmt):
                            self.log_event("WARN", f"{node.name}: Skipping non-printable WAL entry #{tid}")
                            node.tx_seq = tid
                            continue
                        try:
                            self._replay_wal_entry(node, stmt)
                        except Exception as e:
                            self.log_event("WARN", f"{node.name}: Error replaying WAL entry #{tid}: {e}")
                        node.tx_seq = tid
                    self.send_shell_cmd(node, "sync")
                else:
                    self.log_event(
                        "RESYNC",
                        f"{node.name}: Woke up in sync at tx_seq={node.tx_seq} (CONTINUITY resume OK + SHELL resume OK).",
                    )
                fp = self._state_fingerprint(node)
                if fp:
                    node.state_digest = fp
                    self.triad_state_digest = fp
                self._save_wal_to_disk()
                node.tampered = False
                node.state = "ONLINE"

            self.refresh_node_telemetry(node)
            self.log_event(
                "ONLINE",
                f"{node.name}: Rejoined 3/3 Triad Pool on new binary {node.elf_sha256[:12]}.. (boot #{node.boot_gen}, tx_seq={node.tx_seq}).",
            )
        finally:
            if not _lock_held:
                self.morph_op_lock.release()

        self.compute_and_verify_raid_parity()
        return True

    def _reset_sql_vote_tables(self, node: TriadNode):
        """Drop and recreate all `self.spec.vote_tables` on `node` to clean genesis state."""
        for table in self.spec.vote_tables:
            self.send_shell_cmd(node, f"sql /*triad*/ DROP TABLE {table}")
            if table == "kv":
                self.send_shell_cmd(node, "sql /*triad*/ CREATE TABLE kv (k TEXT, v TEXT, rev INT)")
                self.send_shell_cmd(node, "sql /*triad*/ INSERT INTO kv VALUES ('cluster.role', 'primary', 1)")
                self.send_shell_cmd(node, "sql /*triad*/ INSERT INTO kv VALUES ('mtd.policy', 'binmorph-7pass', 1)")
                self.send_shell_cmd(node, "sql /*triad*/ INSERT INTO kv VALUES ('boot.state', 'ready', 1)")

    def heal_and_remorph_node(self, node: TriadNode):
        """
        Reconstruct a corrupted/tampered node from the 2-of-3 healthy majority (D1 = D2 ^ P),
        replay the canonical WAL across all `vote_tables`, and emergency-morph its binary
        under the same `morph_op_lock` critical section so no concurrent wave can leave the
        node stuck in HEALING.
        """
        with self.morph_op_lock:
            node.state = "HEALING"
            if not self.spec.has_sql:
                # Non-SQL role (e.g. `wfe`): wipe the diverged persistent disk images, boot a
                # freshly morphed kernel, sync served files from a healthy peer, and re-apply role.
                self.log_event(
                    "HEAL",
                    f"{node.name}: Isolating diverged node; wiping filesystem image and rebuilding from peer + morphed ELF...",
                )
                self.bounce_and_morph_node(node.node_id, _lock_held=True, _wipe_disks=True)
                return

            # Verify 4 KiB XOR block parity recovery (D_corrupted = D_peer ^ P)
            n1, n2 = self.nodes[0], self.nodes[1]
            if node.node_id == 1:
                peer_bytes = n2.read_sql_partition_bytes()
            else:
                peer_bytes = n1.read_sql_partition_bytes()
            xor_recovered = bytes(a ^ b for a, b in zip(peer_bytes, self.parity_Buffer))
            xor_tag = hashlib.sha256(xor_recovered).hexdigest()[:12]
            self.log_event(
                "HEAL",
                f"{node.name}: Isolating tampered node, verifying 4 KiB XOR parity block (D_peer ⊕ P = {xor_tag}..), and reconstructing {list(self.spec.vote_tables)} from 2/3 RAID Majority + WAL...",
            )

            # Reset all vote tables (`kv`, `idx`, etc.) and replay a WAL snapshot without
            # holding `wal_lock` across the bulk serial I/O; then briefly take `wal_lock` to
            # apply any tail entries committed during the heal.
            self._reset_sql_vote_tables(node)
            with self.wal_lock:
                snapshot = list(self.wal_entries)
            last_tid = 0
            for tid, stmt in snapshot:
                if not is_printable_ascii_command(stmt):
                    last_tid = tid
                    continue
                try:
                    self._replay_wal_entry(node, stmt)
                except Exception as e:
                    self.log_event("WARN", f"{node.name}: Error replaying WAL entry #{tid} during heal: {e}")
                last_tid = tid

            with self.wal_lock:
                for tid, stmt in self.wal_entries:
                    if tid <= last_tid:
                        continue
                    if is_printable_ascii_command(stmt):
                        try:
                            self._replay_wal_entry(node, stmt)
                        except Exception as e:
                            self.log_event("WARN", f"{node.name}: Error replaying WAL tail #{tid} during heal: {e}")
                    last_tid = tid
                node.tx_seq = last_tid
                self.send_shell_cmd(node, "sync")
                fp = self._state_fingerprint(node)
                if fp:
                    node.state_digest = fp
                self._save_wal_to_disk()
                node.tampered = False

            # Force an immediate binary re-morph under the same `morph_op_lock` hold
            self.bounce_and_morph_node(node.node_id, _lock_held=True)

    def simulate_byzantine_tamper(self, node_id: int):
        """Inject an unauthorized rogue modification onto a single node to test 2-of-3 RAID self-healing."""
        node = self.nodes[node_id - 1]
        if node.state != "ONLINE":
            return
        if not self.spec.has_sql:
            self.log_event("WARN", f"Tamper drill needs a SQL-capable role; this Triad runs '{self.spec.role}'.")
            return
        node.tampered = True
        self.log_event(
            "TAMPER",
            f"Injected unauthorized rogue row onto {node.name} ONLY: INSERT INTO kv VALUES ('hacked.backdoor', 'pwned', 999)",
        )
        self.send_shell_cmd(
            node, "sql /*triad*/ INSERT INTO kv VALUES ('hacked.backdoor', 'pwned', 999)"
        )
        if "idx" in self.spec.vote_tables:
            self.send_shell_cmd(
                node, "sql /*triad*/ INSERT INTO idx VALUES ('hacked', 'doc-pwned', 999)"
            )
        # Immediately run the RAID parity & 2-of-3 majority check so the controller catches and heals it
        self.compute_and_verify_raid_parity()

    def _verify_restored_tx_seq_at_boot(self):
        """
        Verify each restored node's on-disk state fingerprint against the digest saved in the
        WAL file. A node whose disk was rolled back or tampered while offline does not match
        the persisted digest, so its `tx_seq` is reset to 0 before majority adoption / parity check.
        """
        if not self.restored_tx_seq_nodes:
            return
        for n in list(self.restored_tx_seq_nodes):
            node = self.nodes[n - 1]
            if node.state != "ONLINE":
                continue
            actual_fp = self._state_fingerprint(node)
            expected_fp = self.restored_node_digests.get(node.node_id) or self.triad_state_digest
            if expected_fp and actual_fp != expected_fp:
                self.log_event(
                    "WARN",
                    f"{node.name}: on-disk state digest ({(actual_fp or 'none')[:12]}) != WAL digest ({expected_fp[:12]}) "
                    f"at tx_seq={node.tx_seq}; resetting tx_seq=0.",
                )
                node.tx_seq = 0
                node.state_digest = ""
                self.restored_tx_seq_nodes.discard(node.node_id)
            elif actual_fp:
                node.state_digest = actual_fp

    def _adopt_tx_seq_from_majority(self):
        """
        Reconcile nodes whose applied tx_seq could not be restored from the WAL file (files
        written before per-node tracking, or nodes whose digest was missing). Compares all
        `self.spec.vote_tables` across online nodes; nodes that match the 2-of-3 majority
        (and match `triad_state_digest` if recorded) adopt `self.triad_tx_seq`. If all nodes
        were rolled back to a state that disagrees with the WAL, replays the WAL onto all
        online nodes. Any single node that disagrees with the 2-of-3 majority keeps `tx_seq=0`
        and is healed by `compute_and_verify_raid_parity()`.
        """
        pending = [
            n for n in self.nodes
            if n.node_id not in self.restored_tx_seq_nodes and n.state == "ONLINE"
        ]
        if not pending or self.triad_tx_seq == 0 or not self.spec.has_sql:
            return
        probes = {}
        for n in self.nodes:
            if n.state != "ONLINE":
                continue
            p = self._state_probe(n)
            if p is not None:
                probes[n.node_id] = p
        vals = list(probes.values())
        if len(vals) < 2:
            return
        majority = max(set(vals), key=vals.count)
        maj_fp = hashlib.sha256(majority.encode("utf-8")).hexdigest()

        # Check if all disks were rolled back so even the majority disagrees with the WAL's
        # recorded state digest (or holds only the 3 genesis rows while `wal_entries` has writes).
        genesis_only = (
            "cluster.role|primary|1" in majority
            and len(majority.splitlines()) <= 4
            and len(self.wal_entries) > 0
        )
        if (self.triad_state_digest and maj_fp != self.triad_state_digest) or genesis_only:
            if vals.count(majority) >= 2 and all(n.node_id not in self.restored_tx_seq_nodes for n in self.nodes if n.state == "ONLINE"):
                self.log_event(
                    "WARN",
                    f"On-disk majority does not match WAL at tx_seq={self.triad_tx_seq}; replaying WAL on all online nodes.",
                )
                with self.wal_lock:
                    for n in self.nodes:
                        if n.state != "ONLINE":
                            continue
                        self._reset_sql_vote_tables(n)
                        for tid, stmt in self.wal_entries:
                            if is_printable_ascii_command(stmt):
                                self._replay_wal_entry(n, stmt)
                            n.tx_seq = tid
                        self.send_shell_cmd(n, "sync")
                        fp = self._state_fingerprint(n)
                        if fp:
                            n.state_digest = fp
                            self.triad_state_digest = fp
                        self.restored_tx_seq_nodes.add(n.node_id)
                    self._save_wal_to_disk()
                return

        if vals.count(majority) < 2:
            return
        with self.wal_lock:
            adopted = [n for n in pending if probes.get(n.node_id) == majority]
            for n in adopted:
                n.tx_seq = self.triad_tx_seq
                n.state_digest = maj_fp
                self.restored_tx_seq_nodes.add(n.node_id)
            if adopted:
                if not self.triad_state_digest:
                    self.triad_state_digest = maj_fp
                self._save_wal_to_disk()
        if adopted:
            names = " + ".join(n.name.split()[0] for n in adopted)
            self.log_event(
                "RESYNC",
                f"WAL had no per-node tx_seq: {names} match the 2/3 majority, adopting tx_seq={self.triad_tx_seq} (no replay needed).",
            )

    def boot_all_parallel(self):
        self.log_event("INIT", "Morphing 3 independent x86-64 kernel binaries via binmorph...")
        for n in self.nodes:
            self.morph_node_image(n, n.current_seed)

        self.log_event(
            "INIT",
            f"Launching 3 parallel {self.spec.smp}-core Cuttle VMs ({3 * self.spec.smp} vCPUs total, HLT idle, "
            f"role={self.spec.role}, accel={self.accel})...",
        )
        for n in self.nodes:
            self.start_node_vm(n)

        for n in self.nodes:
            ok = self.await_boot(n, timeout=30.0)
            if ok:
                if not self.apply_node_profile(n):
                    continue
                n.state = "ONLINE"
                self.refresh_node_telemetry(n)
                self.log_event(
                    "READY",
                    f"{n.name} ONLINE (port :{n.http_port} | binary sha256={n.elf_sha256[:12]}.. | boot #{n.boot_gen})",
                )
            else:
                n.state = "OFFLINE"
                self.log_event("ERROR", f"{n.name} failed to reach interactive shell ready.")

        self._verify_restored_tx_seq_at_boot()
        self._adopt_tx_seq_from_majority()
        self.compute_and_verify_raid_parity()
        self._provision_sql()
        threading.Thread(target=self._background_scheduler, daemon=True).start()

    def _provision_sql(self):
        """
        Commit the spec's one-time schema statements (e.g. an index Triad's `idx` table) through
        the WAL, so a node that morphs or heals later replays them like any other write.
        """
        if not self.spec.has_sql:
            return
        for stmt in self.spec.provision_sql:
            if any(s == stmt for _, s in self.wal_entries):
                continue
            res = self.execute_triad_sql(stmt)
            if not res.get("ok"):
                self.log_event("WARN", f"Provisioning statement failed: {stmt} -> {res.get('error') or res.get('output')}")

    def _background_scheduler(self):
        last_rot = time.time()
        while self.running:
            time.sleep(2.0)
            if self.auto_morph_enabled and (time.time() - last_rot) >= self.auto_morph_interval:
                nid = (self.next_rotate_idx % 3) + 1
                self.next_rotate_idx += 1
                last_rot = time.time()
                self.log_event("AUTO-MTD", f"Scheduled Rolling Morph triggered for OS-{nid}...")
                self.bounce_and_morph_node(nid)

    def shutdown(self):
        self.running = False
        for n in self.nodes:
            if n.proc and n.proc.poll() is None:
                try:
                    n.proc.kill()
                except Exception:
                    pass


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cuttle Triad — Three Hearts. One Appliance. (Cuttle OS RAID-SQL &amp; MTD)</title>
<style>
  :root {
    --bg: #070b14;
    --panel: #0f172a;
    --border: #1e293b;
    --accent: #38bdf8;
    --green: #22c55e;
    --amber: #f59e0b;
    --red: #ef4444;
    --purple: #a855f7;
    --text: #e2e8f0;
    --muted: #94a3b8;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 18px 24px;
    background: var(--bg); color: var(--text);
    font-family: 'JetBrains Mono', 'Cascadia Code', Consolas, monospace;
    font-size: 13px;
  }
  .header {
    display: flex; justify-content: space-between; align-items: center;
    padding: 14px 18px; background: var(--panel);
    border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px;
  }
  .header h1 { margin: 0; font-size: 18px; color: var(--accent); }
  .header .sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .quorum-pill {
    padding: 8px 14px; border-radius: 6px; font-weight: bold;
    background: rgba(34, 197, 94, 0.15); color: var(--green);
    border: 1px solid var(--green);
  }
  .quorum-pill.warn {
    background: rgba(245, 158, 11, 0.15); color: var(--amber); border-color: var(--amber);
  }
  .quorum-pill.fault {
    background: rgba(239, 68, 68, 0.2); color: var(--red); border-color: var(--red);
  }
  .triad-grid {
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 16px;
  }
  .node-card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 14px; position: relative;
  }
  .node-card.ONLINE { border-top: 3px solid var(--green); }
  .node-card.MORPHING, .node-card.DRAINING { border-top: 3px solid var(--amber); }
  .node-card.CATCHING_UP { border-top: 3px solid var(--purple); }
  .node-card.HEALING { border-top: 3px solid var(--red); }
  .node-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .node-title { font-size: 15px; font-weight: bold; color: #fff; }
  .node-role { font-size: 11px; color: var(--accent); margin-bottom: 10px; }
  .badge {
    padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;
  }
  .badge.ONLINE { background: rgba(34,197,94,0.2); color: var(--green); }
  .badge.MORPHING, .badge.DRAINING { background: rgba(245,158,11,0.2); color: var(--amber); }
  .badge.CATCHING_UP { background: rgba(168,85,247,0.2); color: var(--purple); }
  .badge.HEALING { background: rgba(239,68,68,0.25); color: var(--red); }
  .kv-row { display: flex; justify-content: space-between; padding: 3px 0; border-bottom: 1px solid #162032; }
  .kv-row span:first-child { color: var(--muted); }
  .hash { color: #fde047; font-weight: bold; }
  .btn-row { display: flex; gap: 6px; margin-top: 10px; }
  button {
    background: #0284c7; color: #fff; border: none; padding: 6px 11px;
    border-radius: 4px; font-family: inherit; font-size: 12px; cursor: pointer;
    font-weight: bold;
  }
  button:hover { background: #0369a1; }
  button.morph-btn { background: #7c3aed; }
  button.morph-btn:hover { background: #6d28d9; }
  button.tamper-btn { background: #b91c1c; }
  button.tamper-btn:hover { background: #991b1b; }
  .work-grid { display: grid; grid-template-columns: 1.2fr 1fr; gap: 14px; }
  .box {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 14px;
  }
  .box h2 { margin: 0 0 10px 0; font-size: 14px; color: var(--accent); }
  .input-bar { display: flex; gap: 8px; margin-bottom: 10px; }
  input[type=text] {
    flex: 1; background: #070b14; color: #38bdf8; border: 1px solid #334155;
    padding: 7px 10px; border-radius: 4px; font-family: inherit; font-size: 13px;
  }
  pre {
    background: #050811; color: #a7f3d0; border: 1px solid #1e293b;
    padding: 10px; border-radius: 6px; margin: 0; overflow-x: auto;
    max-height: 240px; overflow-y: auto; font-size: 12px;
  }
  .event-list { max-height: 240px; overflow-y: auto; font-size: 12px; }
  .ev { padding: 4px 6px; border-bottom: 1px solid #162032; }
  .ev .ts { color: var(--muted); margin-right: 6px; }
  .ev.MORPH { color: #c084fc; }
  .ev.RESYNC { color: #38bdf8; }
  .ev.ALERT, .ev.TAMPER, .ev.HEAL { color: #f87171; font-weight: bold; }
  .ev.SQL-RAID { color: #4ade80; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>CUTTLE TRIAD — "THREE HEARTS. ONE APPLIANCE." (TMR 2-OF-3 MAJORITY + RAID-SQL + ROLLING MTD)</h1>
    <div class="sub">
      A New Skin Every Boot | Cuttlebone Verified Core | 3 Independent 4-Core Cuttle OS Unikernels (12 vCPUs in HLT Idle | D1 ⊕ D2 = P Parity)
    </div>
  </div>
  <div style="display:flex; gap:10px; align-items:center;">
    <button class="morph-btn" onclick="rollingWave()">Rolling Wave Morph (1→2→3)</button>
    <button onclick="toggleAutoMorph()" id="autoBtn">Auto-Morph: OFF</button>
    <div id="quorumPill" class="quorum-pill">INITIALIZING...</div>
  </div>
</div>

<div class="triad-grid" id="nodesGrid"></div>

<div class="work-grid">
  <div class="box">
    <h2>UNIFIED TRIAD SQL & SHELL CONSOLE (Writes Replicate to 3 OSes + WAL + RAID Parity)</h2>
    <div class="input-bar">
      <input id="tokInput" type="text" placeholder="Operator Session Token (from terminal or triad/operator_token.txt)" onchange="saveToken()" />
    </div>
    <div class="input-bar">
      <input id="sqlInput" type="text" value="INSERT INTO kv VALUES ('sensor.temp', '72F', 1)" />
      <button onclick="runSql()">Execute SQL</button>
      <button onclick="setSql(&quot;SELECT * FROM kv&quot;)">SELECT kv</button>
      <button onclick="setSql(&quot;SELECT * FROM services&quot;)">SELECT services</button>
    </div>
    <div class="input-bar">
      <input id="shInput" type="text" value="smp run 16" />
      <button onclick="runSh()">Run Shell on Triad</button>
      <button onclick="runShCmd('smp')">smp</button>
      <button onclick="runShCmd('attest')">attest</button>
      <button onclick="runShCmd('seal')">seal</button>
    </div>
    <div class="input-bar">
      <input id="appInput" type="text" value="vault put cluster.key Cuttle99" />
      <button onclick="runApp()">Run App (3-Node TMR)</button>
      <button onclick="runAppCmd('vault get cluster.key')">Vault Get</button>
      <button onclick="runAppCmd('guard status')">Guard</button>
      <button class="tamper-btn" onclick="runAppCmd('guard lockdown')">Lockdown</button>
      <button onclick="runAppCmd('guard unlock')">Unlock</button>
      <button onclick="runAppCmd('cron list')">Cron</button>
    </div>
    <pre id="consoleOut">Ready. Enter your Operator Session Token above, then execute a SQL write or CuttleVault/CuttleGuard/CuttleChronos app command across the 3-as-1 Triad!</pre>
  </div>

  <div class="box">
    <h2>HYPERVISOR MTD, RAID PARITY & TMR MAJORITY EVENT STREAM</h2>
    <div class="event-list" id="eventList"></div>
  </div>
</div>

<script>
function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

(function initToken() {
  try {
    const saved = sessionStorage.getItem('cuttle_app_session_token') || '';
    document.getElementById('tokInput').value = saved;
  } catch (e) {}
})();

function saveToken() {
  try {
    sessionStorage.setItem('cuttle_app_session_token', document.getElementById('tokInput').value.trim());
  } catch (e) {}
}

function authHeaders() {
  const t = document.getElementById('tokInput').value.trim();
  return t ? {'X-Cuttle-Session': t} : {};
}

async function refresh() {
  try {
    const r = await fetch('/api/triad');
    const d = await r.json();
    const pill = document.getElementById('quorumPill');
    pill.textContent = d.quorum_status;
    pill.className = 'quorum-pill' + (d.quorum_status.includes('FAULT') ? ' fault' : (d.quorum_status.includes('2/3') ? ' warn' : ''));
    document.getElementById('autoBtn').textContent = 'Auto-Morph: ' + (d.auto_morph ? 'ON (45s)' : 'OFF');

    const grid = document.getElementById('nodesGrid');
    grid.innerHTML = d.nodes.map(n => {
      const nid = Number(n.node_id) || 0;
      const port = Number(n.http_port) || 0;
      return `
      <div class="node-card ${esc(n.state)}">
        <div class="node-top">
          <div class="node-title">${esc(n.name)}</div>
          <span class="badge ${esc(n.state)}">${esc(n.state)}</span>
        </div>
        <div class="node-role">${esc(n.role)} (HTTP :${port} | 4x SMP vCPUs)</div>
        <div class="kv-row"><span>Kernel Seed / Morphs:</span><span>#${Number(n.seed) || 0} (${Number(n.morph_count) || 0}x | ${Number(n.last_morph_ms) || 0}ms)</span></div>
        <div class="kv-row"><span>Binary SHA-256:</span><span class="hash">${esc(String(n.elf_sha256 || '').slice(0, 20))}…</span></div>
        <div class="kv-row"><span>Binmorph Rewrite:</span><span>${esc(String(n.morph_stats || '').slice(0, 38))}</span></div>
        <div class="kv-row"><span>AHCI Boot Gen / SQL tx:</span><span>boot #${Number(n.boot_gen) || 0} | tx_seq=${Number(n.tx_seq) || 0}</span></div>
        <div class="kv-row"><span>4-Core HLT / IPI:</span><span>${esc(n.last_smp)}</span></div>
        <div class="kv-row"><span>RAID Parity Tag:</span><span class="hash">${esc(d.parity_sha256)} (D1⊕D2=P)</span></div>
        <div class="btn-row">
          <button class="morph-btn" onclick="morphNode(${nid})">⚡ Morph & Bounce OS-${nid}</button>
          <button class="tamper-btn" onclick="tamperNode(${nid})">☣ Simulate Hack on OS-${nid}</button>
          <button onclick="window.open('http://127.0.0.1:${port}/app','_blank')">Direct UI</button>
        </div>
      </div>
    `;}).join('');

    const evEl = document.getElementById('eventList');
    evEl.innerHTML = d.events.map(e => `
      <div class="ev ${esc(e.level)}"><span class="ts">[${esc(e.ts)}]</span><strong>[${esc(e.level)}]</strong> ${esc(e.msg)}</div>
    `).join('');
  } catch (e) {}
}

async function runSql() {
  const q = document.getElementById('sqlInput').value;
  const out = document.getElementById('consoleOut');
  out.textContent = 'Executing across Triad 2-of-3 Majority...';
  const r = await fetch('/api/sql', {method:'POST', headers: authHeaders(), body: q});
  const d = await r.json();
  if (!d.ok) {
    out.textContent = `Error (${r.status}): ${d.error || d.output}`;
    return;
  }
  let txt = `[${d.mode}] ${d.quorum}\n\n${d.output}\n\n--- Per-OS Execution Breakdown ---\n`;
  for (const [k, v] of Object.entries(d.per_node || {})) {
    txt += `> ${k}:\n${v}\n\n`;
  }
  out.textContent = txt;
  refresh();
}

function setSql(q) {
  document.getElementById('sqlInput').value = q;
  runSql();
}

async function runSh() {
  const c = document.getElementById('shInput').value;
  runShCmd(c);
}

async function runShCmd(c) {
  document.getElementById('shInput').value = c;
  const out = document.getElementById('consoleOut');
  out.textContent = `Running '${c}' across all 3 Cuttle OS instances...`;
  const r = await fetch('/api/sh', {method:'POST', headers: authHeaders(), body: c});
  const d = await r.json();
  if (!d.ok) {
    out.textContent = `Error (${r.status}): ${d.error || 'unauthorized'}`;
    return;
  }
  let txt = `Command: ${c}\n\n`;
  for (const [k, v] of Object.entries(d.per_node || {})) {
    txt += `=== ${k} ===\n${v}\n\n`;
  }
  out.textContent = txt;
  refresh();
}

async function runApp() {
  const c = document.getElementById('appInput').value;
  runAppCmd(c);
}

async function runAppCmd(c) {
  document.getElementById('appInput').value = c;
  const out = document.getElementById('consoleOut');
  out.textContent = `Executing '${c}' across Triad 2-of-3 Majority...`;
  const r = await fetch('/api/app', {method:'POST', headers: authHeaders(), body: c});
  const d = await r.json();
  if (!d.ok) {
    out.textContent = `Error (${r.status}): ${d.error || d.output}`;
    return;
  }
  let txt = `[${d.mode}] ${d.quorum}\n\n${d.output}\n\n--- Per-OS Execution Breakdown ---\n`;
  for (const [k, v] of Object.entries(d.per_node || {})) {
    txt += `> ${k}:\n${v}\n\n`;
  }
  out.textContent = txt;
  refresh();
}

async function morphNode(id) {
  fetch('/api/morph/' + id, {method:'POST', headers: authHeaders()});
  setTimeout(refresh, 200);
}

async function tamperNode(id) {
  fetch('/api/tamper/' + id, {method:'POST', headers: authHeaders()});
  setTimeout(refresh, 300);
}

async function rollingWave() {
  fetch('/api/rolling_wave', {method:'POST', headers: authHeaders()});
  setTimeout(refresh, 200);
}

async function toggleAutoMorph() {
  await fetch('/api/toggle_auto', {method:'POST', headers: authHeaders()});
  refresh();
}

setInterval(refresh, 1000);
refresh();
</script>
</body>
</html>
"""


class TriadHttpHandler(BaseHTTPRequestHandler):
    ctrl: TriadController = None

    def log_message(self, fmt, *args):
        pass

    def _is_authenticated(self) -> bool:
        expected = self.ctrl.coordinator_token
        for hdr in ("X-Cuttle-Session", "X-Session-Token"):
            val = (self.headers.get(hdr) or "").strip()
            if val and safe_token_eq(val, expected):
                return True
        auth = (self.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            if tok and safe_token_eq(tok, expected):
                return True
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            kv = part.strip()
            if kv.startswith("triad_sid="):
                tok = kv[len("triad_sid="):].strip()
                if tok and safe_token_eq(tok, expected):
                    return True
        return False

    def _send_security_headers(self):
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )
        self.send_header("X-Frame-Options", "DENY")

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code: int, ctype: str, text: str):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self._send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_bounded_body(self) -> str | None:
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except ValueError:
            self._send_json(400, {"ok": False, "error": "invalid Content-Length"})
            return None
        if length < 0:
            self._send_json(400, {"ok": False, "error": "negative Content-Length"})
            return None
        if length > MAX_HTTP_BODY_BYTES:
            self._send_json(
                413,
                {"ok": False, "error": f"payload exceeds {MAX_HTTP_BODY_BYTES} bytes"},
            )
            return None
        return self.rfile.read(length).decode("utf-8", errors="replace").strip() if length else ""

    def do_GET(self):
        base_path = self.path.split("?", 1)[0]
        if base_path in ("/", "/app", "/dashboard", "/triad"):
            return self._send_text(200, "text/html; charset=utf-8", DASHBOARD_HTML)

        if base_path == "/console":
            # Read per request so the page can be edited without restarting the Triad.
            try:
                page = CONSOLE_HTML.read_text(encoding="utf-8")
            except OSError:
                return self._send_text(404, "text/plain", "console page not found\n")
            return self._send_text(200, "text/html; charset=utf-8", page)

        if base_path == "/api/triad":
            c = self.ctrl
            data = {
                "quorum_status": c.quorum_status,
                "triad_tx_seq": c.triad_tx_seq,
                "parity_sha256": c.parity_sha256,
                "parity_syndrome_ok": c.parity_syndrome_ok,
                "auto_morph": c.auto_morph_enabled,
                "name": c.spec.name,
                "job": c.spec.job,
                "role": c.spec.role,
                "has_sql": c.spec.has_sql,
                "has_shell": c.spec.has_shell,
                "accel": c.accel,
                "desired_cron": [{"every": t, "cmd": cmd} for t, cmd in c.desired_cron],
                "nodes": [
                    {
                        "node_id": n.node_id,
                        "name": n.name,
                        "role": n.role,
                        "state": n.state,
                        "http_port": n.http_port,
                        "accel": n.accel,
                        "seed": n.current_seed,
                        "elf_sha256": n.elf_sha256,
                        "morph_stats": n.morph_stats,
                        "morph_count": n.morph_count,
                        "last_morph_ms": n.last_morph_ms,
                        "boot_gen": n.boot_gen,
                        "tx_seq": n.tx_seq,
                        "last_smp": n.last_smp,
                    }
                    for n in c.nodes
                ],
                "events": c.events[:25],
            }
            return self._send_json(200, data)

        if self.path.startswith("/sql"):
            if not self._is_authenticated():
                return self._send_text(
                    401,
                    "text/plain; charset=utf-8",
                    "error: unauthorized (provide valid X-Cuttle-Session or Authorization: Bearer token)\n",
                )
            q = "SELECT * FROM kv"
            if "?" in self.path:
                q = urllib.parse.unquote_plus(self.path.split("?", 1)[1]).strip()
            if not is_printable_ascii_command(q):
                return self._send_text(
                    400,
                    "text/plain; charset=utf-8",
                    "error: query contains non-printable or control characters\n",
                )
            up = q.upper()
            if not (
                up.startswith("SELECT")
                or up.startswith(".TABLES")
                or up.startswith("SHOW")
                or up.startswith(".SCHEMA")
                or up.startswith("DESCRIBE")
            ):
                return self._send_text(
                    401,
                    "text/plain; charset=utf-8",
                    "error: unauthorized (use authenticated POST /sql for mutations)\n",
                )
            try:
                res = self.ctrl.execute_triad_sql(q)
            except ValueError as e:
                return self._send_text(
                    400,
                    "text/plain; charset=utf-8",
                    f"error: {e}\n",
                )
            return self._send_text(200, "text/plain; charset=utf-8", res.get("output", "") + "\n")

        return self._send_text(404, "text/plain", "not found\n")

    def do_POST(self):
        if not self._is_authenticated():
            return self._send_json(
                401,
                {"ok": False, "error": "unauthorized: provide valid X-Cuttle-Session or Authorization: Bearer token"},
            )

        body = self._read_bounded_body()
        if body is None:
            return

        if self.path == "/api/whoami":
            # Side-effect-free token check for the /console page's Connect dialog.
            return self._send_json(200, {"ok": True, "role": "operator"})

        if self.path in ("/api/sql", "/sql"):
            if not is_printable_ascii_command(body):
                return self._send_json(
                    400,
                    {"ok": False, "error": "rejected: query contains non-printable or control characters"},
                )
            try:
                res = self.ctrl.execute_triad_sql(body)
            except ValueError as e:
                return self._send_json(400, {"ok": False, "error": f"rejected: {e}"})
            return self._send_json(200 if res.get("ok") else 400, res)

        if self.path == "/api/sh":
            if not is_printable_ascii_command(body):
                return self._send_json(
                    400,
                    {"ok": False, "error": "rejected: command contains non-printable or control characters"},
                )
            first_word = body.split()[0].lower() if body.split() else ""
            if first_word in ("halt", "reboot"):
                return self._send_json(
                    403,
                    {"ok": False, "error": "Use the Hypervisor Morph controls to bounce nodes safely."},
                )
            if not is_readonly_shell_command(body):
                return self._send_json(
                    403,
                    {
                        "ok": False,
                        "error": "rejected: /api/sh allows only read-only inspection commands; use /api/sql or /api/app for state-changing operations",
                    },
                )
            per_node = {}
            try:
                for n in self.ctrl.nodes:
                    if n.state == "ONLINE":
                        per_node[n.name] = self.ctrl.send_shell_cmd(n, body)
                        if body.startswith("smp"):
                            self.ctrl.refresh_node_telemetry(n)
                    else:
                        per_node[n.name] = f"[{n.state}]"
            except ValueError as e:
                return self._send_json(400, {"ok": False, "error": f"rejected: {e}"})
            return self._send_json(200, {"ok": True, "per_node": per_node})

        if self.path in ("/api/app", "/api/vault", "/api/guard", "/api/cron"):
            if not is_printable_ascii_command(body):
                return self._send_json(
                    400,
                    {"ok": False, "error": "rejected: command contains non-printable or control characters"},
                )
            cmd_str = body
            if self.path == "/api/vault" and not cmd_str.lower().startswith("vault"):
                cmd_str = f"vault {cmd_str}"
            elif self.path == "/api/guard" and not cmd_str.lower().startswith("guard"):
                cmd_str = f"guard {cmd_str}"
            elif self.path == "/api/cron" and not cmd_str.lower().startswith("cron"):
                cmd_str = f"cron {cmd_str}"
            try:
                res = self.ctrl.execute_triad_app(cmd_str)
            except ValueError as e:
                return self._send_json(400, {"ok": False, "error": f"rejected: {e}"})
            code = res.get("status_code", 200 if res.get("ok") else 400)
            return self._send_json(code, res)

        if self.path.startswith("/api/morph/"):
            raw_nid = self.path.rsplit("/", 1)[-1]
            if not raw_nid.isdigit() or int(raw_nid) not in (1, 2, 3):
                return self._send_json(400, {"ok": False, "error": "node_id must be 1, 2, or 3"})
            nid = int(raw_nid)
            threading.Thread(
                target=self.ctrl.bounce_and_morph_node, args=(nid,), daemon=True
            ).start()
            return self._send_json(200, {"ok": True})

        if self.path.startswith("/api/tamper/"):
            raw_nid = self.path.rsplit("/", 1)[-1]
            if not raw_nid.isdigit() or int(raw_nid) not in (1, 2, 3):
                return self._send_json(400, {"ok": False, "error": "node_id must be 1, 2, or 3"})
            nid = int(raw_nid)
            threading.Thread(
                target=self.ctrl.simulate_byzantine_tamper, args=(nid,), daemon=True
            ).start()
            return self._send_json(200, {"ok": True})

        if self.path == "/api/rolling_wave":
            def _wave():
                for nid in (1, 2, 3):
                    self.ctrl.bounce_and_morph_node(nid)
                    time.sleep(1.0)
            threading.Thread(target=_wave, daemon=True).start()
            return self._send_json(200, {"ok": True})

        if self.path == "/api/toggle_auto":
            self.ctrl.auto_morph_enabled = not self.ctrl.auto_morph_enabled
            state_str = "ENABLED (45s wave)" if self.ctrl.auto_morph_enabled else "DISABLED"
            self.ctrl.log_event("CONFIG", f"Automatic Rolling Morph {state_str}")
            return self._send_json(200, {"ok": True, "auto_morph": self.ctrl.auto_morph_enabled})

        return self._send_json(404, {"error": "unknown endpoint"})


def https_probe(node: TriadNode, path: str = "/healthz") -> tuple[str, str, str]:
    """GET `path` from the node's HTTPS port with Python's ssl (OpenSSL) over TLS 1.3,
    trusting only the certificate whose SHA-256 the node printed on its serial console.
    Returns (certificate sha256, TLS version, cipher)."""
    assert node.tls_cert_sha256, f"{node.name}: no HTTPS UP line on its serial console"
    assert node.tls_entropy in ("rdrand", "tpm", "rdrand+tpm"), (
        f"{node.name}: expected hardware entropy in HTTPS UP line, got {node.tls_entropy!r}"
    )
    assert node.tls_provisioned is True, (
        f"{node.name}: expected provisioned=true in HTTPS UP line, got {node.tls_provisioned!r}"
    )
    pem = ssl.get_server_certificate(("127.0.0.1", node.https_port), timeout=10)
    sha = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
    assert sha == node.tls_cert_sha256, f"{node.name}: served certificate {sha} != serial {node.tls_cert_sha256}"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cadata=pem)
    with socket.create_connection(("127.0.0.1", node.https_port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            tls.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
            resp = b""
            while chunk := tls.recv(4096):
                resp += chunk
            version, cipher = tls.version(), tls.cipher()[0]
    assert resp.startswith(b"HTTP/1.1 200") and b"CUTTLE-STATUS" in resp, f"{node.name}: {resp[:120]!r}"
    return sha, version, cipher


def run_unit_self_tests():
    """Fast deterministic unit tests for controller hardening before booting QEMU VMs."""
    with tempfile.TemporaryDirectory(prefix="cuttle_triad_unit_") as tmp:
        tmp_dir = Path(tmp)

        # #30: Guest serial output detector distinguishes QEMU stderr warnings from guest markers
        assert not has_guest_serial_output([]), "Empty buffer must not count as guest output"
        assert not has_guest_serial_output(
            ["qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.01H:ECX.vmx"]
        ), "QEMU stderr warning must not count as guest output"
        assert has_guest_serial_output(["INFO : stage1 bootloader starting"]), "Stage1 INFO marker must count as guest output"
        assert has_guest_serial_output(["CUTTLE_OS_READY"]), "Kernel marker must count as guest output"

        # #8 & #23: Secret loader creates owner-only files and refuses malformed existing secrets
        sec_bin = tmp_dir / "device_key.bin"
        created_key = load_or_create_secret_file(sec_bin, 32, binary=True)
        assert len(created_key) == 32 and sec_bin.read_bytes() == created_key
        for bad_bytes in (b"short", b"x" * 33, b"\x00" * 32):
            bad_path = tmp_dir / "bad_key.bin"
            bad_path.write_bytes(bad_bytes)
            try:
                load_or_create_secret_file(bad_path, 32, binary=True)
                raise AssertionError(f"load_or_create_secret_file must reject {len(bad_bytes)}-byte malformed key")
            except ValueError:
                assert bad_path.read_bytes() == bad_bytes, "Malformed secret file must not be overwritten"

        bad_tok_path = tmp_dir / "bad_token.txt"
        bad_tok_path.write_text("é" * 48, encoding="utf-8")
        try:
            load_or_create_secret_file(bad_tok_path, 24, binary=False)
            raise AssertionError("load_or_create_secret_file must reject non-ASCII text tokens")
        except ValueError:
            pass

        # #22: safe_token_eq handles non-ASCII inputs without raising TypeError
        assert safe_token_eq("abc123", "abc123")
        assert not safe_token_eq("abc123", "abc124")
        assert not safe_token_eq("é" * 20, "a" * 20)
        assert not safe_token_eq("", "abc123")

        # #8: write_operator_token=False suppresses operator_token.txt creation on disk
        no_tok_dir = tmp_dir / "no_op_token"
        no_tok_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="no-tok", state_dir=no_tok_dir, write_operator_token=False),
        )
        no_tok_ctrl.shutdown()
        assert not (no_tok_dir / "operator_token.txt").exists(), (
            "write_operator_token=False must not write operator_token.txt"
        )

        # #9: Corrupt WAL file is refused and backed up to .json.bad
        corrupt_dir = tmp_dir / "corrupt_wal"
        corrupt_dir.mkdir(parents=True, exist_ok=True)
        (corrupt_dir / "triad_wal.json").write_text("{corrupt json", encoding="utf-8")
        try:
            TriadController(show_gui=False, spec=TriadSpec(name="corrupt", state_dir=corrupt_dir))
            raise AssertionError("Corrupt triad_wal.json must raise ValueError at startup")
        except ValueError:
            assert (corrupt_dir / "triad_wal.json.bad").exists(), "Corrupt WAL must be saved to triad_wal.json.bad"

        # #32.6: WAL compaction bounds superseded key updates while preserving final values
        raw_wal = [(i, f"INSERT OR REPLACE INTO kv VALUES ('hot.key', 'v{i}', {i})") for i in range(1, 20)]
        raw_wal.append((20, "INSERT OR REPLACE INTO kv VALUES ('other.key', 'keep', 20)"))
        compacted = compact_wal_entries(raw_wal)
        assert len(compacted) == 2 and compacted[0] == (19, "INSERT OR REPLACE INTO kv VALUES ('hot.key', 'v19', 19)")
        assert compacted[1] == (20, "INSERT OR REPLACE INTO kv VALUES ('other.key', 'keep', 20)")

        # #12: apply_node_profile keeps node OFFLINE and logs ALERT when role application fails
        role_dir = tmp_dir / "role_fail"
        role_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="role-fail", state_dir=role_dir, role="sql", write_operator_token=False),
        )
        role_ctrl.shutdown()
        rn = role_ctrl.nodes[0]
        rn.state = "BOOTING"
        role_ctrl.send_shell_cmd = lambda node, cmd, timeout=4.0: "role=other" if cmd.startswith("service role") else "ok"
        assert not role_ctrl.apply_node_profile(rn), "apply_node_profile must return False when service role fails"
        assert rn.state == "OFFLINE", f"Node must remain OFFLINE when role application fails, got {rn.state}"
        assert any(e["level"] == "ALERT" and "failed to apply role" in e["msg"] for e in role_ctrl.events)

        # #11: wfe _state_probe hashes file contents and non-SQL heal re-syncs files from healthy peer
        wfe_dir = tmp_dir / "wfe_probe"
        wfe_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="wfe-test", state_dir=wfe_dir, job="web", role="wfe", write_operator_token=False),
        )
        wfe_ctrl.shutdown()
        fake_fs = {
            1: {"/index.html": "hello"},
            2: {"/index.html": "world"},  # same length (5 bytes), different content!
            3: {"/index.html": "hello"},
        }
        for n in wfe_ctrl.nodes:
            n.state = "ONLINE"

        def fake_wfe_cmd(node, cmd, timeout=4.0):
            fs = fake_fs[node.node_id]
            if cmd == "ls":
                return "\n".join(f"{p} ({len(c)} B)" for p, c in sorted(fs.items()))
            if cmd.startswith("cat "):
                p = cmd[4:].strip()
                return fs.get(p, "")
            if cmd.startswith("rm "):
                p = cmd[3:].strip()
                fs.pop(p, None)
                return "ok"
            if cmd.startswith("write "):
                parts = cmd.split(" ", 2)
                fs[parts[1]] = parts[2] if len(parts) > 2 else ""
                return "ok"
            return "ok"

        wfe_ctrl.send_shell_cmd = fake_wfe_cmd
        p1 = wfe_ctrl._state_probe(wfe_ctrl.nodes[0])
        p2 = wfe_ctrl._state_probe(wfe_ctrl.nodes[1])
        p3 = wfe_ctrl._state_probe(wfe_ctrl.nodes[2])
        assert p1 == p3 and p1 != p2, "wfe _state_probe must detect same-length content changes"
        wfe_ctrl._sync_files_from_peer(wfe_ctrl.nodes[1], wfe_ctrl.nodes[0])
        assert fake_fs[2]["/index.html"] == "hello" and wfe_ctrl._state_probe(wfe_ctrl.nodes[1]) == p1

        # #3: Multi-table heal (vote_tables=("kv", "idx")) resets all tables in spec.vote_tables
        idx_dir = tmp_dir / "idx_heal"
        idx_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(
                name="idx-test",
                state_dir=idx_dir,
                job="index",
                role="sql",
                vote_tables=("kv", "idx"),
                write_operator_token=False,
            ),
        )
        idx_ctrl.shutdown()
        idx_tables = {
            1: {"kv": ["doc.1|alpha|1"], "idx": ["alpha|doc.1|1"]},
            2: {"kv": ["doc.1|TAMPER|9"], "idx": ["alpha|doc.1|1", "bogus|doc.9|9"]},
            3: {"kv": ["doc.1|alpha|1"], "idx": ["alpha|doc.1|1"]},
        }
        for n in idx_ctrl.nodes:
            n.state = "ONLINE"
        idx_ctrl.wal_entries = [
            (1, "CREATE TABLE IF NOT EXISTS idx (term TEXT, doc TEXT, weight INT)"),
            (2, "INSERT OR REPLACE INTO kv VALUES ('doc.1', 'alpha', 1)"),
            (3, "INSERT INTO idx VALUES ('alpha', 'doc.1', 1)"),
        ]
        idx_ctrl.triad_tx_seq = 3

        def fake_idx_cmd(node, cmd, timeout=4.0):
            t = idx_tables[node.node_id]
            if "DROP TABLE" in cmd and "kv" in cmd:
                t["kv"] = []
                return "ok"
            if "DROP TABLE" in cmd and "idx" in cmd:
                t["idx"] = []
                return "ok"
            if "SELECT * FROM kv" in cmd:
                return "\n".join(["k|v|rev"] + t["kv"])
            if "SELECT * FROM idx" in cmd:
                return "\n".join(["term|doc|weight"] + t["idx"])
            if "INSERT OR REPLACE INTO kv VALUES ('doc.1', 'alpha', 1)" in cmd:
                t["kv"] = ["doc.1|alpha|1"]
                return "1 row inserted"
            if "INSERT INTO idx VALUES ('alpha', 'doc.1', 1)" in cmd:
                t["idx"].append("alpha|doc.1|1")
                return "1 row inserted"
            return "ok"

        idx_ctrl.send_shell_cmd = fake_idx_cmd
        idx_ctrl.bounce_and_morph_node = lambda nid, _lock_held=False, _wipe_disks=False: (
            setattr(idx_ctrl.nodes[nid - 1], "state", "ONLINE") or True
        )
        idx_ctrl.heal_and_remorph_node(idx_ctrl.nodes[1])
        assert idx_tables[2] == idx_tables[1] == idx_tables[3], (
            f"Multi-table heal left duplicate or stale rows in idx: {idx_tables[2]}"
        )
        assert idx_ctrl._state_probe(idx_ctrl.nodes[1]) == idx_ctrl._state_probe(idx_ctrl.nodes[0])


def main():
    parser = argparse.ArgumentParser(description="Cuttle 3-as-1 Triad Hypervisor Controller")
    parser.add_argument("--port", type=int, default=18080, help="Unified Triad HTTP port")
    parser.add_argument("--gui", action="store_true", help="Show 3 QEMU VGA windows")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Boot the 3-node Triad, test SQL RAID writes during a live node morph, test 2-of-3 self-healing, and exit",
    )
    parser.add_argument(
        "--accel",
        choices=ACCELERATORS,
        default=os.environ.get("CUTTLE_ACCEL") or "auto",
        help="QEMU accelerator: auto (WHPX if available, else TCG), whpx, or tcg. Default: $CUTTLE_ACCEL or auto",
    )
    args = parser.parse_args()

    selftest_dir: Path | None = None
    if args.self_test:
        run_unit_self_tests()
        IMAGES_DIR.mkdir(parents=True, exist_ok=True)
        selftest_dir = Path(tempfile.mkdtemp(prefix="cuttle_triad_selftest_", dir=str(IMAGES_DIR)))
        spec = TriadSpec(state_dir=selftest_dir, accel=args.accel)
    else:
        spec = TriadSpec(accel=args.accel)

    ctrl = TriadController(show_gui=args.gui, spec=spec)
    TriadHttpHandler.ctrl = ctrl
    ctrl.boot_all_parallel()

    if args.self_test:
        try:
            print("\n=== RUNNING TRIAD 3-AS-1 LIVE SELF-TEST ===", flush=True)
            print(f"accelerator: {ctrl.accel} (requested {args.accel})", flush=True)
            # 0. Accelerator fallback: a host where WHPX cannot start resolves `auto` to TCG.
            #    sys.executable stands in for a QEMU whose WHPX probe exits immediately.
            saved_whpx_env = os.environ.pop("CUTTLE_WHPX_AVAILABLE", None)
            try:
                _whpx_cache.pop(sys.executable, None)
                assert resolve_accelerator(sys.executable, "auto") == ("tcg", ["-accel", "tcg"]), \
                    "auto must fall back to TCG when the WHPX probe fails"
                assert resolve_accelerator(sys.executable, "tcg")[0] == "tcg"
            finally:
                if saved_whpx_env is not None:
                    os.environ["CUTTLE_WHPX_AVAILABLE"] = saved_whpx_env
            print("accelerator: auto falls back to TCG when WHPX cannot start", flush=True)

            # 0b. A VM that WHPX accepts but never runs (BIOS stuck in reset on some hosts) is
            #     relaunched on TCG. Simulated on one extra VM with its own state and ports.
            if ctrl.accel == "whpx":
                probe = TriadController(
                    show_gui=False,
                    spec=TriadSpec(name="accel-fallback-probe", state_dir=selftest_dir / "accel_fallback_probe",
                                   http_base=18190, https_base=18590, smp=2, accel="auto"),
                )
                probe._guest_started = lambda node, timeout: False  # "no guest output under WHPX"
                pn = probe.nodes[0]
                try:
                    probe.morph_node_image(pn, pn.current_seed)
                    probe.start_node_vm(pn)
                    assert pn.accel == "whpx", f"probe VM should start on WHPX, got {pn.accel}"
                    assert probe.await_boot(pn, timeout=40.0), "fallback VM did not reach its shell on TCG"
                    assert pn.accel == "tcg" and probe.accel == "tcg", (pn.accel, probe.accel)
                    assert any(e["level"] == "WARN" and "relaunching on TCG" in e["msg"] for e in probe.events)
                finally:
                    probe.shutdown()
                print("accelerator: a WHPX VM with no guest output is relaunched on TCG and boots", flush=True)
            # 1. Verify each node received a distinct 256-bit cryptographic key AND booted distinct service ELF variants
            node_keys = [n.device_key_path.read_bytes() for n in ctrl.nodes]
            assert len(set(node_keys)) == 3, "Each Triad node must have a distinct 256-bit device key"
            svc_outputs = [ctrl.send_shell_cmd(n, "service status") for n in ctrl.nodes]
            assert len(set(svc_outputs)) == 3, f"Each Triad node must boot distinct service ELF variants:\n{svc_outputs}"

            # 2. Verify serial line-editing injection (0x08 backspace / 0x7F DEL) is strictly rejected
            try:
                ctrl.send_shell_cmd(
                    ctrl.nodes[0],
                    "sql SELECT " + ("\x08" * 11) + "write /var/pwn hacked",
                )
                raise AssertionError("send_shell_cmd must reject commands containing 0x08 backspace")
            except ValueError:
                pass

            # 3. Verify Coordinator HTTP authentication & control-character rejection:
            #    unauthenticated reads/writes return 401, control-character payloads return 400, authenticated return 200
            test_srv = ThreadingHTTPServer(("127.0.0.1", 0), TriadHttpHandler)
            test_port = test_srv.server_address[1]
            threading.Thread(target=test_srv.serve_forever, daemon=True).start()
            try:
                # #17 & #22: Every authenticated endpoint refuses {no token, wrong token, non-ASCII token} with 401
                auth_endpoints = [
                    ("GET", "/sql?SELECT+*+FROM+kv", None),
                    ("POST", "/sql", b"SELECT * FROM kv"),
                    ("POST", "/api/sql", b"SELECT * FROM kv"),
                    ("POST", "/api/sh", b"status"),
                    ("POST", "/api/app", b"guard status"),
                    ("POST", "/api/vault", b"get cluster.secret"),
                    ("POST", "/api/guard", b"status"),
                    ("POST", "/api/cron", b"list"),
                    ("POST", "/api/whoami", b""),
                    ("POST", "/api/morph/1", b""),
                    ("POST", "/api/tamper/1", b""),
                    ("POST", "/api/rolling_wave", b""),
                    ("POST", "/api/toggle_auto", b""),
                ]
                for method, ep_path, ep_body in auth_endpoints:
                    for bad_hdr in ({}, {"X-Cuttle-Session": "wrong-token"}, {"X-Cuttle-Session": "é" * 32}):
                        req = urllib.request.Request(
                            f"http://127.0.0.1:{test_port}{ep_path}",
                            data=ep_body,
                            headers=bad_hdr,
                            method=method,
                        )
                        try:
                            urllib.request.urlopen(req, timeout=5.0)
                            raise AssertionError(f"Unauthenticated {method} {ep_path} ({bad_hdr}) must return 401")
                        except urllib.error.HTTPError as e:
                            assert e.code == 401, f"Expected 401 on {method} {ep_path} ({bad_hdr}), got {e.code}"

                # #22: Content-Length validation (negative -> 400, non-numeric -> 400, oversized -> 413)
                for bad_cl, expected_code in (("-5", 400), ("notanumber", 400), (str(MAX_HTTP_BODY_BYTES + 1024), 413)):
                    with socket.create_connection(("127.0.0.1", test_port), timeout=5.0) as raw_sock:
                        raw_req = (
                            f"POST /api/sql HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{test_port}\r\n"
                            f"X-Cuttle-Session: {ctrl.coordinator_token}\r\n"
                            f"Content-Length: {bad_cl}\r\n"
                            f"Connection: close\r\n\r\n"
                        ).encode("ascii")
                        raw_sock.sendall(raw_req)
                        raw_resp = raw_sock.recv(4096).decode("utf-8", errors="replace")
                    assert f"HTTP/1.0 {expected_code}" in raw_resp or f"HTTP/1.1 {expected_code}" in raw_resp, (
                        f"Expected {expected_code} for Content-Length {bad_cl}, got: {raw_resp[:120]!r}"
                    )

                # #32.4: Invalid node IDs on /api/morph/<nid> and /api/tamper/<nid> return 400
                for bad_nid_path in ("/api/morph/0", "/api/morph/4", "/api/morph/abc", "/api/tamper/0", "/api/tamper/4"):
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{test_port}{bad_nid_path}",
                        data=b"",
                        headers={"X-Cuttle-Session": ctrl.coordinator_token},
                        method="POST",
                    )
                    try:
                        urllib.request.urlopen(req, timeout=5.0)
                        raise AssertionError(f"POST {bad_nid_path} must be refused with 400")
                    except urllib.error.HTTPError as e:
                        assert e.code == 400, f"Expected 400 on POST {bad_nid_path}, got {e.code}"

                bs_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/sql",
                    data=b"SELECT \x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08write /var/pwn hacked",
                    headers={"X-Cuttle-Session": ctrl.coordinator_token},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(bs_req, timeout=5.0)
                    raise AssertionError("Backspace-injected POST /api/sql must be refused with 400")
                except urllib.error.HTTPError as e:
                    assert e.code == 400, f"Expected 400 on backspace-injected POST /api/sql, got {e.code}"

                # 3-console & #18: /console and /app include CSP + frame-ancestors 'none' and X-Frame-Options: DENY
                with urllib.request.urlopen(f"http://127.0.0.1:{test_port}/console", timeout=5.0) as resp:
                    assert resp.status == 200, f"Expected 200 on GET /console, got {resp.status}"
                    csp = resp.headers.get("Content-Security-Policy", "")
                    assert "frame-ancestors 'none'" in csp, f"Missing frame-ancestors in CSP: {csp}"
                    assert resp.headers.get("X-Frame-Options") == "DENY"
                    console_page = resp.read().decode("utf-8")
                assert "Cuttle Triad Console" in console_page, "GET /console did not serve the console page"
                assert ctrl.coordinator_token not in console_page, "GET /console must not embed the operator token"
                with urllib.request.urlopen(f"http://127.0.0.1:{test_port}/app", timeout=5.0) as resp:
                    app_page = resp.read().decode("utf-8")
                assert "function esc(s)" in app_page and "sessionStorage" in app_page
                whoami_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/whoami",
                    data=b"",
                    headers={"X-Cuttle-Session": ctrl.coordinator_token},
                    method="POST",
                )
                with urllib.request.urlopen(whoami_req, timeout=5.0) as resp:
                    assert resp.status == 200, f"Expected 200 on authenticated POST /api/whoami, got {resp.status}"
                    assert json.loads(resp.read().decode("utf-8")).get("ok") is True

                # #9: Verify write-ahead logging: WAL entry is on disk BEFORE node execution runs
                wal_seen_before_exec = []

                def _check_wal_on_disk(tid: int, stmt: str):
                    disk_data = json.loads(ctrl.wal_file.read_text(encoding="utf-8"))
                    disk_tids = [entry[0] for entry in disk_data.get("wal_entries", [])]
                    wal_seen_before_exec.append(tid in disk_tids)

                ctrl._after_wal_write_ahead_hook = _check_wal_on_disk
                try:
                    auth_req = urllib.request.Request(
                        f"http://127.0.0.1:{test_port}/api/sql",
                        data=b"INSERT OR REPLACE INTO kv VALUES ('triad.init', 'active', 1)",
                        headers={"X-Cuttle-Session": ctrl.coordinator_token},
                        method="POST",
                    )
                    with urllib.request.urlopen(auth_req, timeout=10.0) as resp:
                        assert resp.status == 200
                        r1 = json.loads(resp.read().decode("utf-8"))
                        assert r1["ok"] and "3/3" in r1["quorum"], f"Expected 3/3 majority write: {r1}"
                    assert wal_seen_before_exec == [True], "WAL entry must be persisted to disk before node execution"
                finally:
                    ctrl._after_wal_write_ahead_hook = None

                # 3a. Verify /api/sh allows read-only inspection commands (`status`) and refuses state-changing commands with 403:
                sh_ro_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/sh",
                    data=b"status",
                    headers={"X-Cuttle-Session": ctrl.coordinator_token},
                    method="POST",
                )
                with urllib.request.urlopen(sh_ro_req, timeout=10.0) as resp:
                    assert resp.status == 200
                    r_sh = json.loads(resp.read().decode("utf-8"))
                    assert r_sh["ok"], f"Expected read-only /api/sh status to succeed: {r_sh}"

                for mut_cmd in (
                    b"sql DELETE FROM kv",
                    b"vault put bypass secret",
                    b"write /var/bypass 1",
                    b"cron add 5 status",
                ):
                    sh_mut_req = urllib.request.Request(
                        f"http://127.0.0.1:{test_port}/api/sh",
                        data=mut_cmd,
                        headers={"X-Cuttle-Session": ctrl.coordinator_token},
                        method="POST",
                    )
                    try:
                        urllib.request.urlopen(sh_mut_req, timeout=5.0)
                        raise AssertionError(f"State-changing /api/sh ({mut_cmd!r}) must be refused with 403")
                    except urllib.error.HTTPError as e:
                        assert e.code == 403, f"Expected 403 on state-changing /api/sh ({mut_cmd!r}), got {e.code}"

                # 3b. Verify CuttleVault, CuttleGuard, and CuttleChronos across the 3-node Triad:
                vault_put_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/vault",
                    data=b"put cluster.secret ThreeHearts9",
                    headers={"X-Cuttle-Session": ctrl.coordinator_token},
                    method="POST",
                )
                with urllib.request.urlopen(vault_put_req, timeout=10.0) as resp:
                    rv_put = json.loads(resp.read().decode("utf-8"))
                    assert rv_put["ok"] and "3/3" in rv_put["quorum"], f"Expected 3/3 vault put: {rv_put}"
                    # Verify each node encrypted `ThreeHearts9` with its own distinct hardware seal_key!
                    assert len(set(rv_put["per_node"].values())) == 3, (
                        f"Each Triad node must produce a distinct hardware-sealed ciphertext: {rv_put['per_node']}"
                    )

                vault_get_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/vault",
                    data=b"get cluster.secret",
                    headers={"X-Cuttle-Session": ctrl.coordinator_token},
                    method="POST",
                )
                with urllib.request.urlopen(vault_get_req, timeout=10.0) as resp:
                    rv_get = json.loads(resp.read().decode("utf-8"))
                    assert (
                        rv_get["ok"]
                        and "3/3 ONLINE NODES AGREED" in rv_get["quorum"]
                        and "value=ThreeHearts9 verified=true" in rv_get["output"]
                    ), f"Expected 3/3 verified vault unseal: {rv_get}"

                guard_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/guard",
                    data=b"status",
                    headers={"X-Cuttle-Session": ctrl.coordinator_token},
                    method="POST",
                )
                with urllib.request.urlopen(guard_req, timeout=10.0) as resp:
                    rg = json.loads(resp.read().decode("utf-8"))
                    assert rg["ok"] and "posture=NORMAL" in rg["output"], f"Expected NORMAL guard posture: {rg}"

                cron_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/cron",
                    data=b"add 4 status",
                    headers={"X-Cuttle-Session": ctrl.coordinator_token},
                    method="POST",
                )
                with urllib.request.urlopen(cron_req, timeout=10.0) as resp:
                    rc = json.loads(resp.read().decode("utf-8"))
                    assert rc["ok"] and "3/3" in rc["quorum"], f"Expected 3/3 cron schedule: {rc}"

                # #7: Mutating cron commands via /api/cron or /api/app must be refused with 403
                for bad_cron in (b"add 5 sql DELETE FROM kv", b"add 5 write /var/pwn 1", b"add 5 vault put k v"):
                    bad_cron_req = urllib.request.Request(
                        f"http://127.0.0.1:{test_port}/api/cron",
                        data=bad_cron,
                        headers={"X-Cuttle-Session": ctrl.coordinator_token},
                        method="POST",
                    )
                    try:
                        urllib.request.urlopen(bad_cron_req, timeout=5.0)
                        raise AssertionError(f"Mutating /api/cron ({bad_cron!r}) must be refused with 403")
                    except urllib.error.HTTPError as e:
                        assert e.code == 403, f"Expected 403 on mutating /api/cron ({bad_cron!r}), got {e.code}"
                assert all("DELETE" not in cmd and "write" not in cmd for _, cmd in ctrl.desired_cron)
            finally:
                test_srv.shutdown()

            assert ctrl.wal_file.exists(), "Triad WAL must be persisted to triad_wal.json"
            wal_disk_txt = ctrl.wal_file.read_text(encoding="utf-8")
            assert "ThreeHearts9" not in wal_disk_txt and "ENC_WAL_V1:" in wal_disk_txt, (
                f"Plaintext vault secret leaked into triad_wal.json: {wal_disk_txt}"
            )
            events_txt = json.dumps(ctrl.events)
            assert "ThreeHearts9" not in events_txt and "[REDACTED]" in events_txt, (
                f"Plaintext vault secret leaked into /api/triad events: {events_txt}"
            )
            wal_len_before = len(ctrl.wal_entries)
            try:
                ctrl.execute_triad_sql("INSERT INTO kv VALUES ('bad\x08key', 'val', 1)")
                raise AssertionError("Control-character SQL write must raise ValueError before WAL append")
            except ValueError:
                pass
            assert len(ctrl.wal_entries) == wal_len_before, "Control-character SQL write must not append to WAL"
            bad_sql_res = ctrl.execute_triad_sql("INSERT INTO nonexistent_table VALUES ('a', 'b', 1)")
            assert not bad_sql_res["ok"], "Invalid SQL table write must return ok=False"
            assert len(ctrl.wal_entries) == wal_len_before, "Failed SQL write must not poison the Triad WAL"

            # 3c. Fire 4 conflicting writes in parallel threads to the same key ('concurrent.key') and verify
            #     `wal_lock` serializes replica execution + WAL order so all 3 replicas converge identically:
            barrier = threading.Barrier(4)
            concurrent_results = [None] * 4

            def _parallel_writer(idx: int):
                barrier.wait(timeout=10.0)
                concurrent_results[idx] = ctrl.execute_triad_sql(
                    f"INSERT OR REPLACE INTO kv VALUES ('concurrent.key', 'thread_{idx}', {10 + idx})"
                )

            threads = [threading.Thread(target=_parallel_writer, args=(i,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30.0)
            assert all(r is not None and r.get("ok") for r in concurrent_results), (
                f"Parallel conflicting writes failed: {concurrent_results}"
            )
            tx_seqs = sorted(r["tx_seq"] for r in concurrent_results)
            assert tx_seqs == list(range(tx_seqs[0], tx_seqs[0] + 4)), (
                f"Expected 4 consecutive monotonic tx_seqs from parallel writes, got {tx_seqs}"
            )
            last_wal_tid, last_wal_stmt = ctrl.wal_entries[-1]
            assert last_wal_tid == tx_seqs[-1] and "concurrent.key" in last_wal_stmt, (
                f"Final WAL entry mismatch: {(last_wal_tid, last_wal_stmt)}"
            )
            replica_tables = [
                ctrl._normalize_kv_for_tmr(ctrl.send_shell_cmd(n, "sql /*triad*/ SELECT * FROM kv"))
                for n in ctrl.nodes
            ]
            assert replica_tables[0] == replica_tables[1] == replica_tables[2], (
                f"Replicas diverged after concurrent writes:\n{replica_tables}"
            )
            winning_Thread = re.search(r"thread_\d+", last_wal_stmt).group(0)
            assert f"concurrent.key|{winning_Thread}|" in replica_tables[0], (
                f"Replicas do not match final WAL entry ({last_wal_stmt}):\n{replica_tables[0]}"
            )

            # 3d. HTTPS on every node: TLS 1.3 from an independent client (OpenSSL via Python ssl),
            #     pinned to the certificate fingerprint each node printed at boot. Distinct device
            #     keys give distinct certificates.
            tls_before = {}
            for n in ctrl.nodes:
                sha, version, cipher = https_probe(n)
                tls_before[n.node_id] = sha
                print(f"HTTPS {n.name} :{n.https_port}: {version} {cipher} cert={sha[:16]} (pinned)", flush=True)
            assert len(set(tls_before.values())) == 3, "Each Triad node must present its own certificate"

            # 4. Start morphing OS-1 in background thread, and fire a SQL write while OS-1 is MORPHING!
            t_morph = threading.Thread(target=ctrl.bounce_and_morph_node, args=(1,))
            t_morph.start()
            while ctrl.nodes[0].state == "ONLINE":
                time.sleep(0.05)
            r2 = ctrl.execute_triad_sql("INSERT INTO kv VALUES ('while.morphing', 'zero_downtime', 2)")
            print(f"Write during OS-1 morph: {r2['quorum']}", flush=True)
            t_morph.join()

            # Verify OS-1 caught up automatically!
            q_out = ctrl.send_shell_cmd(ctrl.nodes[0], "sql SELECT * FROM kv")
            assert "zero_downtime" in q_out, f"OS-1 failed to catch up missed write! Output:\n{q_out}"
            print("OS-1 successfully morphed AND caught up missed SQL write from WAL!", flush=True)

            # 4a. The morphed OS-1 serves HTTPS again with the SAME certificate: its TLS identity
            #     derives from the device key, so pinned clients survive a morph cycle.
            sha, version, cipher = https_probe(ctrl.nodes[0])
            assert sha == tls_before[1], "OS-1 certificate changed across a morph cycle"
            print(f"HTTPS after OS-1 morph: {version} {cipher}, same pinned certificate", flush=True)

            # 5. Simulate single-node tamper on OS-2 while another thread contends for morph_op_lock (#20),
            #    and verify automatic 2-of-3 self-healing + 4 KiB XOR parity check completes cleanly.
            old_morphs = ctrl.nodes[1].morph_count
            ctrl.morph_op_lock.acquire()
            threading.Timer(0.4, ctrl.morph_op_lock.release).start()
            ctrl.simulate_byzantine_tamper(2)
            deadline = time.time() + 45.0
            while time.time() < deadline:
                if ctrl.nodes[1].state == "ONLINE" and ctrl.nodes[1].morph_count > old_morphs:
                    break
                time.sleep(0.5)
            assert ctrl.nodes[1].state == "ONLINE", f"OS-2 stuck in {ctrl.nodes[1].state} after lock contention"
            q2_out = ctrl.send_shell_cmd(ctrl.nodes[1], "sql SELECT * FROM kv")
            assert "pwned" not in q2_out and "zero_downtime" in q2_out, f"OS-2 heal failed:\n{q2_out}"
            # Also verify OS-2 reconstructed and re-sealed `cluster.secret` from the WAL during heal!
            v2_out = ctrl.send_shell_cmd(ctrl.nodes[1], "vault get cluster.secret")
            assert "value=ThreeHearts9 verified=true" in v2_out, f"OS-2 vault heal failed:\n{v2_out}"

            # 6. Controller restart: each node's AHCI SQL partition survives a restart, so the
            #    controller must restore every node's applied tx_seq instead of assuming 0.
            #    Otherwise a node's first morph replays the whole WAL onto data it already holds
            #    and the 2-of-3 vote raises a false mismatch (ALERT + HEAL + emergency morph).
            def restart_controller(old, before_boot=None):
                old.shutdown()
                for n in old.nodes:
                    if n.proc:
                        try:
                            n.proc.wait(timeout=10.0)
                        except Exception:
                            pass
                time.sleep(1.0)
                if before_boot:
                    before_boot()
                new = TriadController(show_gui=args.gui, spec=TriadSpec(state_dir=selftest_dir, accel=args.accel))
                TriadHttpHandler.ctrl = new
                new.boot_all_parallel()
                return new

            def kv_of(c, n):
                return c._normalize_kv_for_tmr(c.send_shell_cmd(n, "sql /*triad*/ SELECT * FROM kv"))

            def tmr_alarms(c):
                return [e for e in c.events if e["level"] in ("ALERT", "HEAL")]

            # 6a. Restart with the per-node tx_seq map, then morph a node: nothing to replay.
            tx_before = ctrl.triad_tx_seq
            ctrl = restart_controller(ctrl)
            assert all(n.state == "ONLINE" for n in ctrl.nodes), "All nodes must be ONLINE after restart"
            assert ctrl.triad_tx_seq == tx_before, f"Triad tx_seq lost across restart: {ctrl.triad_tx_seq} != {tx_before}"
            seqs = [n.tx_seq for n in ctrl.nodes]
            assert seqs == [tx_before] * 3, f"Node tx_seq must survive a restart: got {seqs}, Triad at {tx_before}"
            assert ctrl.bounce_and_morph_node(2), "OS-2 morph after restart failed"
            assert not tmr_alarms(ctrl), f"False TMR alarm after restart + morph: {tmr_alarms(ctrl)}"
            assert kv_of(ctrl, ctrl.nodes[1]) == kv_of(ctrl, ctrl.nodes[0]), "OS-2 diverged from OS-1 after restart + morph"
            print("Restart: node tx_seq restored, morph replayed nothing, no false TMR alarm", flush=True)

            # 6b. WAL file from before per-node tracking: nodes that match the 2/3 majority adopt
            #     the Triad's tx_seq at boot instead of replaying the whole WAL.
            wal_path = selftest_dir / "triad_wal.json"

            def strip_node_tx_seq():
                data = json.loads(wal_path.read_text(encoding="utf-8"))
                assert data.get("triad_state_digest") and data.get("node_state_digest"), (
                    "triad_wal.json must record triad_state_digest and node_state_digest (#10)"
                )
                data.pop("node_tx_seq", None)
                wal_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

            ctrl = restart_controller(ctrl, before_boot=strip_node_tx_seq)
            seqs = [n.tx_seq for n in ctrl.nodes]
            assert seqs == [ctrl.triad_tx_seq] * 3, f"Legacy WAL: majority nodes must adopt tx_seq, got {seqs}"
            assert any(e["level"] == "RESYNC" and "adopting tx_seq" in e["msg"] for e in ctrl.events), "Legacy WAL adoption not logged"
            assert not tmr_alarms(ctrl), f"False TMR alarm after legacy-WAL restart: {tmr_alarms(ctrl)}"
            print("Restart with legacy WAL: majority nodes adopted tx_seq without replay", flush=True)

            # 6c. A restored tx_seq must not hide real divergence: wipe OS-3's disk while the Triad
            #     is down. The WAL still says OS-3 is current, but the boot parity check must outvote
            #     it, rebuild it from the majority + WAL, and emergency-morph it.
            ctrl = restart_controller(ctrl, before_boot=lambda: (selftest_dir / "node3" / "ahci_node3.img").unlink())
            os3 = ctrl.nodes[2]
            deadline = time.time() + 60.0
            while time.time() < deadline:
                if os3.state == "ONLINE" and os3.morph_count >= 2:
                    break
                time.sleep(0.5)
            assert any(e["level"] == "ALERT" and "OS-3" in e["msg"] for e in ctrl.events), "Wiped OS-3 disk not detected at boot"
            assert any(e["level"] == "HEAL" and "OS-3" in e["msg"] for e in ctrl.events), "Wiped OS-3 disk not healed"
            assert os3.state == "ONLINE" and os3.morph_count >= 2, f"OS-3 did not rejoin after heal (state={os3.state})"
            assert kv_of(ctrl, os3) == kv_of(ctrl, ctrl.nodes[0]), "OS-3 not rebuilt to match the majority"
            print("Restart with a wiped OS-3 disk: divergence detected, healed and re-morphed", flush=True)
            print("=== TRIAD 3-AS-1 SELF-TEST PASSED ===", flush=True)
        finally:
            ctrl.shutdown()
            if selftest_dir and selftest_dir.exists():
                shutil.rmtree(selftest_dir, ignore_errors=True)
        return

    server = ThreadingHTTPServer(("127.0.0.1", args.port), TriadHttpHandler)
    print("\n============================================================================", flush=True)
    print(f"  CUTTLE 3-AS-1 TRIAD APPLIANCE ONLINE!", flush=True)
    print(f"  Unified Command Center : http://127.0.0.1:{args.port}/app", flush=True)
    print(f"  Live Ops Console       : http://127.0.0.1:{args.port}/console", flush=True)
    print(f"  Operator Session Token : {ctrl.coordinator_token} (saved to triad/operator_token.txt)", flush=True)
    print(f"  Unified SQL Endpoint   : POST http://127.0.0.1:{args.port}/api/sql (with X-Cuttle-Session header)", flush=True)
    print(f"  Individual OS Ports    : OS-1 :18101 | OS-2 :18102 | OS-3 (Parity) :18103", flush=True)
    print(f"  Accelerator            : {ctrl.accel} (requested {args.accel})", flush=True)
    print(f"  Press Ctrl+C to shut down all 3 VMs cleanly.", flush=True)
    print("============================================================================\n", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Triad VMs...", flush=True)
    finally:
        ctrl.shutdown()


if __name__ == "__main__":
    main()
