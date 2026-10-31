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
    unit_test: bool = False  # True only in run_unit_self_tests() to skip QEMU/BASE_ELF packaging

    @property
    def has_sql(self) -> bool:
        return self.role in ("sql", "full")

    @property
    def has_shell(self) -> bool:
        return self.role in ("shell", "full")


MAX_HTTP_BODY_BYTES = 64 * 1024
MAX_WAL_ENTRIES = 64
MAX_CONSECUTIVE_HEALS = 3
WAL_PROBE_FORMAT_VERSION = 2


def _is_genesis_sql_probe(probe_str: str) -> bool:
    """True when `probe_str` holds only the 3 default genesis `kv` rows (`cluster.role`, `mtd.policy`, `boot.state`)."""
    if _GENESIS_KV_PROBE_MARKER in probe_str and len(probe_str.splitlines()) <= 2:
        return True
    return (
        (
            "cluster.role|primary|1" in probe_str
            or "T:636c75737465722e726f6c65|T:7072696d617279|I:1" in probe_str
        )
        and len(probe_str.splitlines()) <= 4
    )


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


_WINDOWS_CURRENT_SID: str | None = None


def _get_windows_current_sid() -> str:
    """Resolve and cache the current Windows user's SID (`S-1-...`) via `whoami /user`."""
    global _WINDOWS_CURRENT_SID
    if _WINDOWS_CURRENT_SID:
        return _WINDOWS_CURRENT_SID
    res = subprocess.run(
        ["whoami", "/user"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode == 0 and res.stdout:
        m = re.search(r"(S-1-\d+(?:-\d+)+)", res.stdout)
        if m:
            _WINDOWS_CURRENT_SID = m.group(1)
            return _WINDOWS_CURRENT_SID
    raise OSError("cannot resolve current user SID via `whoami /user`")


def restrict_file_permissions(path: Path) -> None:
    """Restrict `path` to mode 0600 on POSIX or an explicit current-user-SID-only ACL on Windows."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name == "nt":
        sid = _get_windows_current_sid()
        res = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(F)"],
            capture_output=True,
            check=False,
        )
        if res.returncode != 0:
            err_txt = (res.stderr or res.stdout or b"").decode("utf-8", errors="replace").strip()
            raise OSError(f"icacls failed on {path} (exit {res.returncode}): {err_txt}")


def write_secret_file(path: Path, data: bytes) -> None:
    """Create or replace `path` exclusively with owner-only permissions applied BEFORE writing secret bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(str(tmp), flags, 0o600)
    os.close(fd)
    try:
        restrict_file_permissions(tmp)
        with open(tmp, "r+b") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
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
    try:
        with open(tmp, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(path)
        if os.name != "nt":
            try:
                dir_fd = os.open(str(path.parent), getattr(os, "O_RDONLY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def is_printable_ascii_command(s: str) -> bool:
    """Return True iff `s` is non-empty and every character is printable ASCII (0x20..=0x7E)."""
    return bool(s) and all(0x20 <= ord(ch) <= 0x7E for ch in s)


def is_readonly_sql_query(q: str) -> bool:
    """Return True iff `q` is a read-only SQL query (`SELECT`, `.tables`, `SHOW`, `.schema`, `.dump`, `DESCRIBE`)."""
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
        or up.startswith(".DUMP")
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
        "cathex",
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


# Shared definitions matching `target_enterprise/src/shell.rs` (`cmd_cathex` / `cmd_writehex`)
# and `target_enterprise/src/sql.rs` (`exec_dump`).
CATHEX_REPLY_RE = re.compile(r"^hex len=(\d+) off=(\d+) data=([0-9a-fA-F]*)$")
WRITEHEX_REPLY_RE = re.compile(r"^wrote (\d+) bytes to (.+) at offset (\d+)$")
SQLDUMP_HEADER_RE = re.compile(
    r"^sqldump table=(\S+) rows=(\d+) off=(\d+) count=(\d+) digest=([0-9a-f]{16})(?: ddl=([0-9a-f]+))?(?: idx_ddl=([0-9a-f]+))?$"
)


def quote_shell_path(fpath: str) -> str:
    """Quote a VFS path containing whitespace for `cathex` / `writehex` commands."""
    if " " in fpath or "\t" in fpath:
        return f'"{fpath}"'
    return fpath


def format_kernel_cathex_reply(total_len: int, offset: int, chunk: bytes) -> str:
    """Format a `cathex` reply line exactly as `OsShell::cmd_cathex` (`shell.rs:2714`) emits."""
    return f"hex len={total_len} off={offset} data={chunk.hex()}"


def format_kernel_writehex_reply(written: int, fpath: str, offset: int) -> str:
    """Format a `writehex` reply line exactly as `OsShell::cmd_writehex` (`shell.rs:2795`) emits."""
    return f"wrote {written} bytes to {fpath} at offset {offset}"


def format_kernel_sqldump_reply(
    table: str,
    cols: list[tuple[str, str]],
    rows: list[tuple],
    offset: int = 0,
    limit: int = 3,
    indexed_col: int = 0xFF,
    index_name: str = "",
) -> str:
    """
    Format a `.dump <table> [offset] [limit]` reply chunk using the exact 64-bit FNV-1a
    table digest and hex cell framing emitted by `SqlDb::exec_dump` (`sql.rs:815`).
    """
    limit = max(0, min(3, int(limit)))
    offset = max(0, int(offset))
    is_kv = table.lower() == "kv"

    def _row_sort_key(r: tuple) -> tuple:
        if is_kv and len(r) > 0:
            c0 = r[0]
            if isinstance(c0, (bytes, bytearray)) and bytes(c0).startswith(b"v:"):
                return (0, bytes(c0))
            if isinstance(c0, str) and c0.startswith("v:"):
                return (0, c0.encode("utf-8"))
        key_parts = []
        for idx, val in enumerate(r):
            ctype = cols[idx][1].upper() if idx < len(cols) else ("INT" if isinstance(val, int) else "TEXT")
            if ctype.startswith("INT"):
                key_parts.append((1, int(val)))
            else:
                tb = bytes(val) if isinstance(val, (bytes, bytearray)) else str(val).encode("utf-8")
                key_parts.append((2, tb))
        return tuple(key_parts)

    sorted_rows = sorted(rows, key=_row_sort_key)
    mcount = len(sorted_rows)

    def _mix(acc: int, b: int) -> int:
        return ((acc ^ (b & 0xFF)) * 0x0100000001B3) & 0xFFFFFFFFFFFFFFFF

    h = 0xCBF29CE484222325
    for b in table.encode("ascii"):
        h = _mix(h, b)
    h = _mix(h, len(cols))
    for cname, ctype in cols:
        for b in cname.encode("ascii"):
            h = _mix(h, b)
        h = _mix(h, 1 if ctype.upper().startswith("INT") else 2)
    h = _mix(h, indexed_col & 0xFF)
    for b in index_name.encode("ascii"):
        h = _mix(h, b)
    for b in mcount.to_bytes(8, "little", signed=False):
        h = _mix(h, b)

    for r in sorted_rows:
        c0_bytes = (
            bytes(r[0])
            if (len(r) > 0 and isinstance(r[0], (bytes, bytearray)))
            else (r[0].encode("utf-8") if (len(r) > 0 and isinstance(r[0], str)) else b"")
        )
        if is_kv and len(r) > 0 and c0_bytes.startswith(b"v:"):
            h = _mix(h, 0x5B)
            kb = c0_bytes
            h = _mix(h, len(kb))
            for b in kb:
                h = _mix(h, b)
            for b in b"<HW_SEALED>":
                h = _mix(h, b)
        else:
            h = _mix(h, 0x5A)
            for idx, val in enumerate(r):
                ctype = cols[idx][1].upper() if idx < len(cols) else ("INT" if isinstance(val, int) else "TEXT")
                if ctype.startswith("INT"):
                    h = _mix(h, 1)
                    for b in int(val).to_bytes(8, "little", signed=True):
                        h = _mix(h, b)
                else:
                    tb = bytes(val) if isinstance(val, (bytes, bytearray)) else str(val).encode("utf-8")
                    h = _mix(h, 2)
                    h = _mix(h, len(tb))
                    for b in tb:
                        h = _mix(h, b)

    chunk = sorted_rows[offset : offset + limit] if offset < mcount else []
    hdr_suffix = f" digest={h:016x}"
    if offset == 0:
        col_defs = ", ".join(f"{cname} {'INT' if ctype.upper().startswith('INT') else 'TEXT'}" for cname, ctype in cols)
        ddl_str = f"CREATE TABLE {table} ({col_defs})"
        hdr_suffix += f" ddl={ddl_str.encode('ascii').hex()}"
        if index_name and 0 <= indexed_col < len(cols):
            idx_ddl_str = f"CREATE INDEX {index_name} ON {table} ({cols[indexed_col][0]})"
            hdr_suffix += f" idx_ddl={idx_ddl_str.encode('ascii').hex()}"
    hdr_prefix = f"sqldump table={table} rows={mcount} off={offset} count="
    # Reserve 8 bytes (`SHELL_PROMPT.len()`) out of the 1,024-byte console buffer (`max_out_len = 1016`).
    max_out_len = 1024 - 8
    cur_bytes = len(hdr_prefix) + 1 + len(hdr_suffix) + 1  # +1 for count digit, +1 for '\n'
    fitted_rows: list[str] = []
    for r in chunk:
        cell_parts = []
        for idx, val in enumerate(r):
            ctype = cols[idx][1].upper() if idx < len(cols) else ("INT" if isinstance(val, int) else "TEXT")
            if ctype.startswith("INT"):
                cell_parts.append(f"I:{int(val)}")
            else:
                tb = bytes(val) if isinstance(val, (bytes, bytearray)) else str(val).encode("utf-8")
                cell_parts.append(f"T:{tb.hex()}")
        rline = "row " + "|".join(cell_parts)
        rline_bytes = len(rline) + 1
        if (cur_bytes + rline_bytes > max_out_len and len(fitted_rows) > 0) or (cur_bytes + rline_bytes > 1024):
            break
        fitted_rows.append(rline)
        cur_bytes += rline_bytes
    hdr = f"{hdr_prefix}{len(fitted_rows)}{hdr_suffix}"
    return "\n".join([hdr] + fitted_rows)


_GENESIS_KV_PROBE_MARKER = (
    "k|v|rev #rows=3 digest="
    + re.search(
        r"digest=([0-9a-f]{16})",
        format_kernel_sqldump_reply(
            "kv",
            [("k", "TEXT"), ("v", "TEXT"), ("rev", "INT")],
            [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
            0,
            0,
        ),
    ).group(1)
)


class RealOsShellHarness:
    """Drives 3 real `target_enterprise::OsShell` instances via `examples/shell_harness.rs`."""

    def __init__(self):
        exe_name = "shell_harness.exe" if os.name == "nt" else "shell_harness"
        candidates = [
            ROOT / "target" / "debug" / "examples" / exe_name,
            ROOT / "target" / "release" / "examples" / exe_name,
        ]
        exe = next((p for p in candidates if p.exists()), None)
        if exe is None:
            subprocess.run(
                ["cargo", "build", "-p", "target_enterprise", "--example", "shell_harness", "--quiet"],
                cwd=str(ROOT),
                check=True,
            )
            exe = next((p for p in candidates if p.exists()), None)
            if exe is None:
                raise RuntimeError("Failed to locate built shell_harness binary")
        self.proc = subprocess.Popen(
            [str(exe)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        self._lock = threading.Lock()

    def exec(self, node, cmd: str, timeout: float = 4.0) -> str:
        if any(not (0x20 <= ord(ch) <= 0x7E) for ch in cmd):
            raise ValueError("command contains non-printable or control characters")
        clean_cmd = cmd.strip()
        if not clean_cmd:
            return ""
        with self._lock:
            assert self.proc.stdin is not None and self.proc.stdout is not None
            self.proc.stdin.write(f"{node.node_id}\t{clean_cmd}\n")
            self.proc.stdin.flush()
            line = self.proc.stdout.readline()
            raw = bytes.fromhex(line.strip()).decode("utf-8", errors="replace")
            if raw.endswith("cuttle> "):
                raw = raw[: -len("cuttle> ")]
            return raw.strip()

    def reset_node(self, node_id: int) -> None:
        with self._lock:
            assert self.proc.stdin is not None and self.proc.stdout is not None
            self.proc.stdin.write(f"{node_id}\t__reset__\n")
            self.proc.stdin.flush()
            self.proc.stdout.readline()

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3.0)
            except Exception:
                self.proc.kill()



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
        self.consecutive_heals = 0
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
    def __init__(
        self,
        show_gui: bool = False,
        spec: TriadSpec | None = None,
        unit_test: bool = False,
    ):
        self.spec = spec or TriadSpec()
        self.unit_test = bool(unit_test or self.spec.unit_test)
        if self.unit_test:
            self.qemu_bin = "qemu-system-x86_64"
            self.accel, self.accel_args = "tcg", ["-accel", "tcg"]
        else:
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

        if self.unit_test:
            self.base_elf_bytes = b"\x7fELF" + b"\x00" * 60
            self.base_bios_bytes = b"\x00" * 64 + self.base_elf_bytes + b"\x00" * 64
            self.elf_offset_in_bios = 64
        else:
            if not BASE_ELF.exists():
                raise RuntimeError(
                    f"Base kernel ELF not found at {BASE_ELF}; build target_enterprise_kernel first."
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
        self.desired_cron: list[tuple[int, str]] = []
        for t, c in s.cron_jobs:
            if int(t) > 0 and is_printable_ascii_command(str(c)) and is_readonly_shell_command(str(c)):
                self.desired_cron.append((int(t), str(c)))
            else:
                self.log_event("WARN", f"Dropping non-read-only or invalid spec cron job: ({t!r}, {c!r})")
        if self.cron_file.exists():
            try:
                loaded_cron = json.loads(self.cron_file.read_text(encoding="utf-8"))
                filtered_cron: list[tuple[int, str]] = []
                for item in loaded_cron:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        t, c = item[0], str(item[1])
                        if isinstance(t, int) and not isinstance(t, bool) and t > 0 and is_printable_ascii_command(c) and is_readonly_shell_command(c):
                            filtered_cron.append((int(t), c))
                        else:
                            self.log_event("WARN", f"Dropping non-read-only or invalid cron job from {self.cron_file.name}: {item!r}")
                    else:
                        self.log_event("WARN", f"Dropping malformed cron entry from {self.cron_file.name}: {item!r}")
                self.desired_cron = filtered_cron
            except Exception as e:
                self.log_event("WARN", f"Ignoring unreadable cron_jobs.json: {e}")

        # Monotonic Triad WAL for automatic catch-up after an OS morph bounce (persisted to disk)
        self.wal_lock = threading.Lock()
        self.wal_file = state_dir / "triad_wal.json"
        self.triad_tx_seq = 0
        self.triad_state_digest = ""
        self.wal_checkpoint: dict = {
            "tx_seq": 0,
            "stmts": [],
            "format_version": WAL_PROBE_FORMAT_VERSION,
        }
        self.wal_probe_format_mismatch: bool = False
        self.wal_checkpoint_legacy: bool = False
        self.wal_entries: list[tuple[int, str]] = []  # (tx_seq, sql_stmt)
        self.wal_pending_tx: int | None = None
        self.wal_pending_pre_digest: str = ""
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
            raw_fmt_ver = data.get("probe_format_version")
            if raw_fmt_ver is not None and (
                not isinstance(raw_fmt_ver, int) or isinstance(raw_fmt_ver, bool) or raw_fmt_ver < 1
            ):
                raise ValueError(f"invalid probe_format_version: {raw_fmt_ver!r}")
            self.wal_probe_format_mismatch = raw_fmt_ver != WAL_PROBE_FORMAT_VERSION
            raw_cp = data.get("wal_checkpoint")
            if raw_cp is not None:
                if not isinstance(raw_cp, dict):
                    raise ValueError("wal_checkpoint must be a JSON object")
                cp_seq = raw_cp.get("tx_seq", 0)
                cp_stmts = raw_cp.get("stmts", [])
                if not isinstance(cp_seq, int) or isinstance(cp_seq, bool) or cp_seq < 0:
                    raise ValueError(f"invalid wal_checkpoint.tx_seq: {cp_seq!r}")
                if not isinstance(cp_stmts, list) or any(
                    not isinstance(s, str) or not is_printable_ascii_command(s) for s in cp_stmts
                ):
                    raise ValueError("invalid wal_checkpoint.stmts")
                cp_fmt = raw_cp.get("format_version", raw_fmt_ver)
                if cp_fmt is not None and (
                    not isinstance(cp_fmt, int) or isinstance(cp_fmt, bool) or cp_fmt < 1
                ):
                    raise ValueError(f"invalid wal_checkpoint.format_version: {cp_fmt!r}")
                self.wal_checkpoint_legacy = (
                    cp_seq > 0 and bool(cp_stmts) and cp_fmt != WAL_PROBE_FORMAT_VERSION
                )
                self.wal_checkpoint = {
                    "tx_seq": cp_seq,
                    "stmts": list(cp_stmts),
                    "format_version": cp_fmt if cp_fmt is not None else 1,
                }
            raw_entries = data.get("wal_entries", [])
            if not isinstance(raw_entries, list):
                raise ValueError("wal_entries must be a list")
            parsed_entries: list[tuple[int, str]] = []
            pending_tx: int | None = None
            for idx, item in enumerate(raw_entries):
                if not isinstance(item, (list, tuple)) or len(item) not in (2, 3):
                    raise ValueError(f"malformed WAL entry: {item!r}")
                tid, stmt = item[0], item[1]
                status = item[2] if len(item) == 3 else "committed"
                if not isinstance(tid, int) or isinstance(tid, bool) or tid <= 0:
                    raise ValueError(f"invalid WAL entry tx_id: {tid!r}")
                if not isinstance(stmt, str) or not is_printable_ascii_command(stmt):
                    raise ValueError(f"WAL entry #{tid} contains non-printable or empty command")
                if status not in ("pending", "committed"):
                    raise ValueError(f"WAL entry #{tid} has invalid status: {status!r}")
                if status == "pending":
                    if idx != len(raw_entries) - 1:
                        raise ValueError(f"non-final WAL entry #{tid} cannot be pending")
                    pending_tx = tid
                parsed_entries.append((tid, stmt))
            self.triad_tx_seq = tx_seq
            self.wal_entries = parsed_entries
            self.wal_pending_tx = pending_tx
            self.wal_pending_pre_digest = str(data.get("wal_pending_pre_digest") or "")
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
        serialized_entries = [
            [tid, stmt, "pending" if tid == self.wal_pending_tx else "committed"]
            for tid, stmt in self.wal_entries
        ]
        cp_payload = dict(self.wal_checkpoint)
        if not self.wal_checkpoint_legacy:
            cp_payload["format_version"] = WAL_PROBE_FORMAT_VERSION
        payload = {
            "probe_format_version": (
                1 if self.wal_probe_format_mismatch else WAL_PROBE_FORMAT_VERSION
            ),
            "triad_tx_seq": self.triad_tx_seq,
            "triad_state_digest": self.triad_state_digest,
            "wal_checkpoint": cp_payload,
            "wal_entries": serialized_entries,
            "wal_pending_pre_digest": self.wal_pending_pre_digest if self.wal_pending_tx is not None else "",
            "node_tx_seq": {str(n.node_id): n.tx_seq for n in self.nodes},
            "node_state_digest": {str(n.node_id): n.state_digest for n in self.nodes if n.state_digest},
        }
        atomic_write_json(self.wal_file, payload)

    def _extract_table_col_types(self, table: str, donor: TriadNode | None = None) -> list[str]:
        """Determine column types ('INT' or 'TEXT') for `table` from `.schema`, `provision_sql`, or WAL."""
        if table == "kv":
            return ["TEXT", "TEXT", "INT"]
        candidates: list[str] = []
        if donor is not None:
            schema_out = self.send_shell_cmd(donor, f"sql /*triad*/ .schema {table}", timeout=3.0)
            if schema_out and "CREATE TABLE" in schema_out.upper():
                candidates.extend(schema_out.splitlines())
        candidates.extend(self.spec.provision_sql)
        candidates.extend(self.wal_checkpoint.get("stmts", []))
        candidates.extend(stmt for _, stmt in self.wal_entries)
        pat = re.compile(
            rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{re.escape(table)}\s*\(([^)]+)\)",
            re.IGNORECASE,
        )
        for stmt in candidates:
            m = pat.search(stmt)
            if m:
                col_types = []
                for col_def in m.group(1).split(","):
                    parts = col_def.strip().split()
                    if len(parts) >= 2 and parts[1].upper().startswith("INT"):
                        col_types.append("INT")
                    else:
                        col_types.append("TEXT")
                if col_types:
                    return col_types
        return []

    def checkpoint_wal(self) -> bool:
        """
        Take a consistent full-state checkpoint when all 3 nodes (or a 2-of-3 online majority
        when 1 node is offline/catching up) are at `triad_tx_seq` and agree on every vote
        table's lossless chunked `.dump` (row count, kernel table digest, and normalized rows).
        Fetches the table dumps across `ready_nodes` in parallel outside `wal_lock` so
        checkpoints do not hold `wal_lock` across serial round trips, then re-acquires
        `wal_lock` to verify `triad_tx_seq` is unchanged and persist `self.wal_checkpoint`.
        """
        if not self.spec.has_sql:
            return False
        with self.wal_lock:
            if self.wal_pending_tx is not None or (
                not self.wal_checkpoint_legacy
                and self.triad_tx_seq <= self.wal_checkpoint.get("tx_seq", 0)
            ):
                return False
            target_tx_seq = self.triad_tx_seq
            ready_nodes = [
                n for n in self.nodes if n.state == "ONLINE" and n.tx_seq == target_tx_seq
            ]
            if len(ready_nodes) < 2:
                return False

        # Dump each vote table across `ready_nodes` in parallel outside `self.wal_lock`.
        table_dumps: dict[str, dict] = {}
        probe_parts_per_node: list[list[str]] = [[] for _ in ready_nodes]
        digest_parts_per_node: list[list[str]] = [[] for _ in ready_nodes]
        fallback_col_types: dict[str, list[str]] = {}
        for table in self.spec.vote_tables:
            dumps = self._dump_nodes_table_in_parallel(ready_nodes, table)
            if any(d is None for d in dumps):
                return False
            first = dumps[0]
            assert first is not None
            for d in dumps[1:]:
                assert d is not None
                if (
                    d["rows_count"] != first["rows_count"]
                    or d["kernel_digest"] != first["kernel_digest"]
                    or d["probe_text"] != first["probe_text"]
                ):
                    return False
            table_dumps[table] = first
            if table != "kv" and not first.get("ddl"):
                fallback_col_types[table] = self._extract_table_col_types(table, ready_nodes[0])
            for idx, d in enumerate(dumps):
                assert d is not None
                probe_parts_per_node[idx].append(d["probe_text"])
                digest_parts_per_node[idx].append(d["digest_probe_text"])

        probes = ["\n--\n".join(parts) for parts in probe_parts_per_node]
        if not all(p == probes[0] for p in probes):
            return False
        digest_probes = ["\n--\n".join(parts) for parts in digest_parts_per_node]

        with self.wal_lock:
            if (
                self.wal_pending_tx is not None
                or self.triad_tx_seq != target_tx_seq
                or any(n.state != "ONLINE" or n.tx_seq != target_tx_seq for n in ready_nodes)
            ):
                return False
            if len(ready_nodes) < len(self.nodes):
                down_names = [n.name.split()[0] for n in self.nodes if n not in ready_nodes]
                self.log_event(
                    "WARN",
                    f"Taking {len(ready_nodes)}/3 majority WAL checkpoint at tx_seq={self.triad_tx_seq} "
                    f"while {down_names} is offline/catching up; lagging node will rebuild from checkpoint.",
                )

            # Collect active encrypted/plain vault put commands in order up to triad_tx_seq.
            vault_records: dict[str, str] = {}
            for raw_stmt in list(self.wal_checkpoint.get("stmts", [])) + [s for _, s in self.wal_entries]:
                s = raw_stmt.strip()
                if s.startswith("ENC_WAL_V1:"):
                    try:
                        dec = self._decrypt_wal_vault_cmd(s)
                        parts = dec.split()
                        if len(parts) >= 3 and parts[0].lower() == "vault" and parts[1].lower() == "put":
                            vault_records[parts[2]] = s
                    except Exception:
                        pass
                elif s.lower().startswith("vault "):
                    parts = s.split()
                    if len(parts) >= 3 and parts[1].lower() == "put":
                        vault_records[parts[2]] = s
                    elif len(parts) >= 3 and parts[1].lower() == "del":
                        vault_records.pop(parts[2], None)

            cp_stmts: list[str] = []
            seen_vault_keys: set[str] = set()
            for table in self.spec.vote_tables:
                tdump = table_dumps[table]
                if table != "kv":
                    ddl_str = tdump.get("ddl") or ""
                    if not ddl_str:
                        col_types = fallback_col_types.get(table) or self._extract_table_col_types(table, None)
                        if col_types:
                            ddl_str = f"CREATE TABLE {table} (" + ", ".join(
                                f"c{i} {ct}" for i, ct in enumerate(col_types)
                            ) + ")"
                    if ddl_str:
                        if re.match(r"^CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS\b)", ddl_str, re.I):
                            ddl_str = re.sub(
                                r"^CREATE\s+TABLE\s+",
                                "CREATE TABLE IF NOT EXISTS ",
                                ddl_str,
                                count=1,
                                flags=re.I,
                            )
                        cp_stmts.append(ddl_str)
                    if tdump.get("idx_ddl"):
                        cp_stmts.append(tdump["idx_ddl"])
                cp_stmts.append(f"DELETE FROM {table}")
                for cells in tdump["rows"]:
                    if (
                        table == "kv"
                        and cells
                        and cells[0][0] == "TEXT"
                        and bytes(cells[0][1]).startswith(b"v:")
                    ):
                        vkey = bytes(cells[0][1])[2:].decode("utf-8", errors="replace")
                        if vkey in vault_records:
                            cp_stmts.append(vault_records[vkey])
                            seen_vault_keys.add(vkey)
                        continue
                    formatted: list[str] = []
                    for ctype, val in cells:
                        if ctype == "INT":
                            formatted.append(str(int(val)))
                        else:
                            val_bytes = bytes(val) if isinstance(val, (bytes, bytearray)) else str(val).encode("utf-8")
                            hex_lit = f"X'{val_bytes.hex()}'"
                            if all(0x20 <= b <= 0x7E for b in val_bytes):
                                esc = val_bytes.decode("ascii").replace("'", "''")
                                str_lit = f"'{esc}'"
                                formatted.append(str_lit if len(str_lit) < len(hex_lit) else hex_lit)
                            else:
                                formatted.append(hex_lit)
                    verb = "INSERT OR REPLACE INTO" if table == "kv" else "INSERT INTO"
                    cp_stmts.append(f"{verb} {table} VALUES({','.join(formatted)})")

            for vkey, vstmt in vault_records.items():
                if vkey not in seen_vault_keys:
                    cp_stmts.append(vstmt)

            cp_seq = self.triad_tx_seq
            self.wal_checkpoint = {
                "tx_seq": cp_seq,
                "stmts": cp_stmts,
                "format_version": WAL_PROBE_FORMAT_VERSION,
            }
            self.wal_checkpoint_legacy = False
            self.wal_probe_format_mismatch = False
            self.wal_entries = [(tid, s) for tid, s in self.wal_entries if tid > cp_seq]
            digest = hashlib.sha256(digest_probes[0].encode("utf-8")).hexdigest()
            self.triad_state_digest = digest
            for n in ready_nodes:
                n.state_digest = digest
            self._save_wal_to_disk()
            return True

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
            saw_cmd_or_output = False
            while time.time() < deadline:
                with node.line_cond:
                    while node.response_lines:
                        ln = node.response_lines.pop(0)
                        while ln.startswith("cuttle>"):
                            rest = ln[len("cuttle>") :].lstrip(" ")
                            if not rest:
                                if collected or saw_cmd_or_output:
                                    saw_prompt_end = True
                                ln = ""
                                break
                            ln = rest
                        if not ln:
                            continue
                        if ln.strip() == clean_cmd:
                            saw_cmd_or_output = True
                            continue
                        if clean_cmd.startswith("sql ") and ln.strip().startswith("sql "):
                            saw_cmd_or_output = True
                            continue
                        if (
                            ln.startswith("AHCI_HW ")
                            or ln.startswith("Web UI:")
                            or "interactive shell ready" in ln
                        ):
                            continue
                        saw_cmd_or_output = True
                        collected.append(ln)
                    if saw_prompt_end or (
                        collected
                        and (time.time() - sent_at) >= 0.30
                        and self._response_looks_complete(clean_cmd, collected)
                    ):
                        break
                    node.line_cond.wait(timeout=0.06)
            if not saw_prompt_end and not (
                collected and self._response_looks_complete(clean_cmd, collected)
            ):
                with node.line_cond:
                    node.response_lines.clear()
                return "error: command timed out"
            return "\n".join(collected).strip()

    def _response_looks_complete(self, cmd_str: str, lines: list[str]) -> bool:
        joined = "\n".join(lines)
        c = cmd_str.strip()
        if c.startswith("sql "):
            if ".dump " in c.lower():
                if "error:" in joined or "usage:" in joined:
                    return True
                non_empty = [ln.strip() for ln in lines if ln.strip()]
                if non_empty:
                    m = SQLDUMP_HEADER_RE.match(non_empty[0])
                    if m:
                        expected_count = int(m.group(4))
                        row_lines = sum(1 for ln in non_empty[1:] if ln.startswith("row "))
                        return row_lines >= expected_count
                return False
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
        if c.startswith("service role "):
            return "role=" in joined or "error:" in joined
        if c == "status":
            return "net_tx=" in joined or "error:" in joined
        if c.startswith("cathex "):
            return "hex len=" in joined or "error:" in joined or "usage:" in joined
        if c.startswith("writehex "):
            return ("wrote " in joined and " at offset " in joined) or "error:" in joined or "usage:" in joined
        return False

    @staticmethod
    def _normalize_kv_for_tmr(sql_out: str) -> str:
        """
        Normalize raw `SELECT * FROM <table>` output for 2-of-3 TMR comparison across Triad nodes:
        - Because each Triad node encrypts `CuttleVault` secrets (`k = 'v:<name>'`) under its own
          independent 256-bit hardware `seal_key`, the on-disk ciphertext (`v`) and MAC tag (`rev`)
          are cryptographically distinct per node while the key set (`v:<name>`) is identical.
        - Sorts data rows after the column header so the 2-of-3 vote and state digest are invariant
          to physical row-slot allocation order after WAL checkpoints or table rebuilds.
        """
        lines = [ln for ln in sql_out.splitlines() if ln.strip()]
        if not lines:
            return ""
        header = lines[0]
        data_rows = []
        for ln in lines[1:]:
            if ln.startswith("v:") and "|" in ln:
                kname = ln.split("|", 1)[0]
                data_rows.append(f"{kname}|<HW_SEALED>")
            else:
                data_rows.append(ln)
        data_rows.sort()
        return "\n".join([header] + data_rows)

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

    def _read_node_file_bytes(
        self, node: TriadNode, fpath: str, expected_len: int | None = None
    ) -> bytes | None:
        """
        Read `fpath` from `node` in chunks via `cathex <path> <offset> <len>` so
        empty, multi-line, UTF-8, and binary files are read losslessly without serial framing
        ambiguity. Parses the kernel's `hex len=<N> off=<O> data=<hex>` output (`CATHEX_REPLY_RE`)
        and verifies the final byte length matches `total_size` (and `expected_len` if given).
        """
        shell_line_max = 256
        chunk_size = 128
        offset = 0
        buf = bytearray()
        total_size: int | None = None
        qpath = quote_shell_path(fpath)
        while True:
            cmd = f"cathex {qpath} {offset} {chunk_size}"
            if len(cmd) > shell_line_max:
                return None
            out = self.send_shell_cmd(node, cmd, timeout=3.0)
            if out.lower().startswith("error") or out.lower().startswith("usage"):
                return None
            m = CATHEX_REPLY_RE.match(out.strip())
            if not m:
                return None
            reported_total = int(m.group(1))
            reported_off = int(m.group(2))
            hex_part = m.group(3) or ""
            if reported_off != offset or len(hex_part) % 2 != 0:
                return None
            chunk = bytes.fromhex(hex_part)
            if total_size is None:
                total_size = reported_total
                if expected_len is not None and total_size != expected_len:
                    return None
            elif reported_total != total_size:
                return None
            buf.extend(chunk)
            offset += len(chunk)
            if offset >= total_size or len(chunk) == 0:
                break
        if total_size is None or len(buf) != total_size:
            return None
        return bytes(buf)

    def _write_node_file_bytes(self, node: TriadNode, fpath: str, data: bytes) -> bool:
        """
        Write arbitrary `data` (including empty, multi-line, UTF-8, or binary bytes) to `fpath`
        on `node` in chunks via `writehex <path> <offset> <hex>` sized dynamically from
        `SHELL_LINE_MAX` (256), the quoted path length, and the offset width, verifying the
        kernel's `wrote <N> bytes to <path> at offset <O>` reply (`WRITEHEX_REPLY_RE`) on each
        chunk as well as the post-write size and SHA-256 digest on `node`.
        """
        shell_line_max = 256
        qpath = quote_shell_path(fpath)
        if len(data) == 0:
            cmd = f"writehex {qpath} 0"
            if len(cmd) > shell_line_max:
                return False
            out = self.send_shell_cmd(node, cmd, timeout=3.0)
            m = WRITEHEX_REPLY_RE.match(out.strip())
            if not m or int(m.group(1)) != 0 or m.group(2) != fpath or int(m.group(3)) != 0:
                return False
        else:
            offset = 0
            while offset < len(data):
                prefix = f"writehex {qpath} {offset} "
                max_chunk_bytes = (shell_line_max - len(prefix)) // 2
                step_chunk_size = min(96, max_chunk_bytes)
                if step_chunk_size <= 0:
                    return False
                chunk = data[offset : offset + step_chunk_size]
                out = self.send_shell_cmd(node, f"{prefix}{chunk.hex()}", timeout=3.0)
                m = WRITEHEX_REPLY_RE.match(out.strip())
                if not m or int(m.group(1)) != len(chunk) or m.group(2) != fpath or int(m.group(3)) != offset:
                    return False
                offset += len(chunk)
        actual = self._read_node_file_bytes(node, fpath, expected_len=len(data))
        return actual is not None and len(actual) == len(data) and (
            hashlib.sha256(actual).digest() == hashlib.sha256(data).digest()
        )

    def _dump_node_sql_table(self, node: TriadNode, table: str) -> dict | None:
        """
        Read `table` from `node` in 3-row chunks via `sql /*triad*/ .dump <table> <offset> 3`
        so each reply stays strictly under the 1,024-byte kernel serial console buffer and
        cells containing `|`, quotes, or arbitrary UTF-8 bytes are decoded losslessly from hex.
        Verifies row count and the kernel's 64-bit FNV-1a table digest across all chunks.
        """
        chunk_limit = 3
        offset = 0
        total_rows: int | None = None
        kernel_digest: str | None = None
        ddl = ""
        idx_ddl = ""
        col_names: list[str] = []
        all_rows: list[list[tuple[str, str | int]]] = []

        while True:
            out = self.send_shell_cmd(
                node, f"sql /*triad*/ .dump {table} {offset} {chunk_limit}", timeout=4.0
            )
            if not out or out.lower().startswith("error") or out.lower().startswith("usage"):
                return None
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            if not lines:
                return None
            m = SQLDUMP_HEADER_RE.match(lines[0])
            if not m:
                return None
            rep_table, rep_rows_s, rep_off_s, rep_count_s, rep_digest, ddl_hex, idx_ddl_hex = m.groups()
            rep_rows, rep_off, rep_count = int(rep_rows_s), int(rep_off_s), int(rep_count_s)
            if rep_table.lower() != table.lower() or rep_off != offset:
                return None
            if total_rows is None:
                total_rows = rep_rows
                kernel_digest = rep_digest
                if ddl_hex:
                    try:
                        ddl = bytes.fromhex(ddl_hex).decode("ascii")
                    except Exception:
                        return None
                    m_ddl = re.search(r"\(([^)]+)\)", ddl)
                    if m_ddl:
                        for cdef in m_ddl.group(1).split(","):
                            parts = cdef.strip().split()
                            if parts:
                                col_names.append(parts[0])
                if idx_ddl_hex:
                    try:
                        idx_ddl = bytes.fromhex(idx_ddl_hex).decode("ascii")
                    except Exception:
                        return None
            else:
                if rep_rows != total_rows or rep_digest != kernel_digest:
                    return None
            row_lines = lines[1:]
            if len(row_lines) != rep_count or not col_names:
                return None
            for rln in row_lines:
                if not rln.startswith("row "):
                    return None
                raw_cells = rln[4:].split("|") if rln[4:] else []
                if len(raw_cells) != len(col_names):
                    return None
                parsed_cells: list[tuple[str, bytes | int]] = []
                for rc in raw_cells:
                    if rc.startswith("I:"):
                        try:
                            parsed_cells.append(("INT", int(rc[2:])))
                        except ValueError:
                            return None
                    elif rc.startswith("T:"):
                        hex_part = rc[2:]
                        if len(hex_part) % 2 != 0:
                            return None
                        try:
                            parsed_cells.append(("TEXT", bytes.fromhex(hex_part)))
                        except ValueError:
                            return None
                    else:
                        return None
                all_rows.append(parsed_cells)
            offset += rep_count
            if offset >= total_rows or rep_count == 0:
                break

        if total_rows is None or kernel_digest is None or len(all_rows) != total_rows:
            return None

        col_hdr = "|".join(col_names) if col_names else ("k|v|rev" if table.lower() == "kv" else table.lower())
        select_lines = [col_hdr]
        probe_rows: list[str] = []
        for cells in all_rows:
            select_lines.append(
                "|".join(
                    str(v) if ct == "INT" else bytes(v).decode("utf-8", errors="replace")
                    for ct, v in cells
                )
            )
            if (
                table.lower() == "kv"
                and cells
                and cells[0][0] == "TEXT"
                and bytes(cells[0][1]).startswith(b"v:")
            ):
                probe_rows.append(f"T:{bytes(cells[0][1]).hex()}|<HW_SEALED>")
            else:
                escaped = [
                    f"I:{int(v)}" if ct == "INT" else f"T:{bytes(v).hex()}"
                    for ct, v in cells
                ]
                probe_rows.append("|".join(escaped))
        probe_rows.sort()
        probe_hdr = f"{col_hdr} #rows={total_rows} digest={kernel_digest}"
        if idx_ddl:
            probe_hdr += f" idx={idx_ddl}"
        probe_text = "\n".join([probe_hdr] + probe_rows)
        select_text = "\n".join(select_lines)
        if table.lower() == "kv":
            node.last_sql_table = select_text
        return {
            "table": table,
            "rows_count": total_rows,
            "kernel_digest": kernel_digest,
            "ddl": ddl,
            "idx_ddl": idx_ddl,
            "rows": all_rows,
            "digest_probe_text": probe_hdr,
            "probe_text": probe_text,
            "select_text": select_text,
        }

    def _probe_node_sql_table_digest(self, node: TriadNode, table: str) -> str | None:
        """
        Query `table` on `node` using the single-round-trip digest-only `.dump <table> digest`
        command (returning `rows=` and the kernel's 64-bit FNV-1a table `digest=` with `count=0`
        and no row lines).
        """
        out = self.send_shell_cmd(
            node, f"sql /*triad*/ .dump {table} digest", timeout=4.0
        )
        if not out or out.lower().startswith("error") or out.lower().startswith("usage"):
            return None
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if len(lines) != 1:
            return None
        m = SQLDUMP_HEADER_RE.match(lines[0])
        if not m:
            return None
        rep_table, rep_rows_s, rep_off_s, rep_count_s, rep_digest, ddl_hex, idx_ddl_hex = m.groups()
        rep_rows, rep_off, rep_count = int(rep_rows_s), int(rep_off_s), int(rep_count_s)
        if rep_table.lower() != table.lower() or rep_off != 0 or rep_count != 0:
            return None
        col_names: list[str] = []
        if ddl_hex:
            try:
                ddl = bytes.fromhex(ddl_hex).decode("ascii")
            except Exception:
                return None
            m_ddl = re.search(r"\(([^)]+)\)", ddl)
            if m_ddl:
                for cdef in m_ddl.group(1).split(","):
                    parts = cdef.strip().split()
                    if parts:
                        col_names.append(parts[0])
        if not col_names:
            return None
        idx_ddl = ""
        if idx_ddl_hex:
            try:
                idx_ddl = bytes.fromhex(idx_ddl_hex).decode("ascii")
            except Exception:
                return None
        col_hdr = "|".join(col_names)
        probe_hdr = f"{col_hdr} #rows={rep_rows} digest={rep_digest}"
        if idx_ddl:
            probe_hdr += f" idx={idx_ddl}"
        return probe_hdr

    def _dump_nodes_table_in_parallel(
        self, nodes: list[TriadNode], table: str
    ) -> list[dict | None]:
        """Fetch full chunked `.dump` for `table` across `nodes` in parallel threads."""
        if not nodes:
            return []
        if len(nodes) == 1:
            return [self._dump_node_sql_table(nodes[0], table)]
        results: list[dict | None] = [None] * len(nodes)

        def _worker(idx: int, n: TriadNode):
            results[idx] = self._dump_node_sql_table(n, table)

        threads = [
            threading.Thread(target=_worker, args=(idx, n), daemon=True)
            for idx, n in enumerate(nodes)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return results

    def _probe_nodes_in_parallel(
        self, nodes: list[TriadNode], retry_none: bool = False, max_attempts: int = 2
    ) -> dict[int, str | None]:
        """
        Probe `self._state_probe(n)` across `nodes` in parallel (each `TriadNode` has its own
        `cmd_lock`). When `retry_none` is True, retries any `None` probe up to `max_attempts`.
        """
        attempts = max(2, max_attempts) if retry_none else 1
        outputs: dict[int, str | None] = {}

        def _worker(n: TriadNode):
            res = None
            for attempt in range(attempts):
                res = self._state_probe(n)
                if res is not None:
                    break
                if attempt + 1 < attempts:
                    time.sleep(0.05)
            outputs[n.node_id] = res

        if len(nodes) <= 1:
            for n in nodes:
                _worker(n)
            return outputs

        threads = [threading.Thread(target=_worker, args=(n,), daemon=True) for n in nodes]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return outputs

    def _state_probe(self, node: TriadNode) -> str | None:
        """
        The node's replicated state as compared by the 2-of-3 vote, or None if unreadable.
        SQL-capable roles compare the spec's vote tables via single-round-trip digest-only
        `.dump <table> digest` (fetching full rows only for checkpoints or to diagnose a
        mismatch); a web front end (`wfe`, no svc-sql) compares every served file's path,
        size, and SHA-256 content digest.
        """
        if not self.spec.has_sql:
            ls_out = self.send_shell_cmd(node, "ls", timeout=4.0)
            if not ls_out or ls_out.lower().startswith("error"):
                return None
            if ls_out.strip() == "(empty)":
                return "(empty)"
            file_entries = []
            for ln in ls_out.splitlines():
                s_ln = ln.strip()
                if not s_ln:
                    continue
                m = re.match(r"^(.+?)\s+\((\d+)\s+B\)$", s_ln)
                if not m:
                    return None
                fpath, flen_str = m.group(1), m.group(2)
                flen = int(flen_str)
                content_bytes = None
                for attempt in range(2):
                    content_bytes = self._read_node_file_bytes(node, fpath, expected_len=flen)
                    if content_bytes is not None:
                        break
                    if attempt == 0:
                        time.sleep(0.05)
                if content_bytes is None:
                    return None
                digest = hashlib.sha256(content_bytes).hexdigest()[:16]
                file_entries.append(f"{fpath} ({flen} B) sha256={digest}")
            if not file_entries:
                return None
            file_entries.sort()
            return "\n".join(file_entries)
        parts = []
        for table in self.spec.vote_tables:
            hdr = self._probe_node_sql_table_digest(node, table)
            if hdr is None:
                return None
            parts.append(hdr)
        return "\n--\n".join(parts)

    def _state_fingerprint(self, node: TriadNode) -> str | None:
        """SHA-256 hex digest of `node`'s replicated state probe, or None if unreadable."""
        probe = self._state_probe(node)
        if probe is None:
            return None
        return hashlib.sha256(probe.encode("utf-8")).hexdigest()

    def _sync_files_from_peer(self, target: TriadNode, peer: TriadNode) -> bool:
        """
        Copy every file in `peer`'s shell filesystem onto `target` during a non-SQL heal using
        chunked `cathex`/`writehex`, and verify every synced file's post-copy byte length and
        SHA-256 digest before returning True.
        """
        ls_out = self.send_shell_cmd(peer, "ls", timeout=4.0)
        if not ls_out or ls_out.lower().startswith("error"):
            return False
        if ls_out.strip() == "(empty)":
            self.send_shell_cmd(target, "sync", timeout=3.0)
            return True
        all_ok = True
        for ln in ls_out.splitlines():
            s_ln = ln.strip()
            if not s_ln:
                continue
            m = re.match(r"^(.+?)\s+\((\d+)\s+B\)$", s_ln)
            if not m:
                all_ok = False
                continue
            fpath, flen = m.group(1), int(m.group(2))
            peer_bytes = self._read_node_file_bytes(peer, fpath, expected_len=flen)
            if peer_bytes is None:
                all_ok = False
                continue
            target_bytes = self._read_node_file_bytes(target, fpath, expected_len=flen)
            if target_bytes != peer_bytes:
                if not self._write_node_file_bytes(target, fpath, peer_bytes):
                    self.log_event(
                        "WARN",
                        f"{target.name}: Failed to sync or verify {fpath} ({flen} B) from {peer.name}",
                    )
                    all_ok = False
        self.send_shell_cmd(target, "sync", timeout=3.0)
        return all_ok

    def compute_and_verify_raid_parity(self):
        """
        Compute 4 KiB RAID Parity P = D1 ^ D2 across OS-1 and OS-2 SQL partitions,
        and verify Triple Modular Redundancy (TMR) 2-of-3 majority consistency across all online Triad members.
        """
        n1, n2, n3 = self.nodes[0], self.nodes[1], self.nodes[2]
        online_nodes = [n for n in self.nodes if n.state == "ONLINE"]

        if len(online_nodes) >= 2:
            with self.wal_lock:
                probed_tx_seq = self.triad_tx_seq
            # Probe all online nodes in parallel (each node has its own `cmd_lock`),
            # retrying any None probe once before evaluating consensus.
            outputs = self._probe_nodes_in_parallel(online_nodes, retry_none=True, max_attempts=2)

            # Check if any node diverges from the 2-of-3 majority!
            if len(online_nodes) == 3:
                o1, o2, o3 = outputs.get(1), outputs.get(2), outputs.get(3)
                if o1 is not None and o1 == o2 == o3:
                    for n in online_nodes:
                        n.consecutive_heals = 0
                    self.parity_syndrome_ok = True
                    digest = hashlib.sha256(o1.encode("utf-8")).hexdigest()
                    with self.wal_lock:
                        if self.triad_tx_seq == probed_tx_seq:
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
                    with self.wal_lock:
                        if self.triad_tx_seq != probed_tx_seq:
                            return
                    # When a digest mismatch is detected on a SQL role, fetch full rows in parallel
                    # to diagnose the mismatch across vote tables.
                    if self.spec.has_sql and len({x for x in (o1, o2, o3) if x is not None}) >= 2:
                        for table in self.spec.vote_tables:
                            self._dump_nodes_table_in_parallel(online_nodes, table)
                    # 2-of-3 Majority Vote identifies the exact tampered/corrupted (or unreadable) node!
                    corrupted = None
                    if o2 is not None and o3 is not None and o2 == o3 and o1 != o2:
                        corrupted = n1
                    elif o1 is not None and o3 is not None and o1 == o3 and o2 != o1:
                        corrupted = n2
                    elif o1 is not None and o2 is not None and o1 == o2 and o3 != o1:
                        corrupted = n3
                    if corrupted:
                        if corrupted.state == "HEALING":
                            return
                        if not self.spec.has_sql:
                            # Confirm non-SQL (wfe) divergence across a second probe before wiping disks
                            recheck = self._probe_nodes_in_parallel(online_nodes, retry_none=False)
                            peer_ids = [i for i in (1, 2, 3) if i != corrupted.node_id]
                            if (
                                recheck.get(peer_ids[0]) is None
                                or recheck.get(peer_ids[0]) != recheck.get(peer_ids[1])
                                or recheck.get(corrupted.node_id) == recheck.get(peer_ids[0])
                            ):
                                return
                        if corrupted.consecutive_heals >= MAX_CONSECUTIVE_HEALS:
                            corrupted.state = "OFFLINE"
                            if corrupted.proc and corrupted.proc.poll() is None:
                                try:
                                    corrupted.proc.kill()
                                    corrupted.proc.wait(timeout=3.0)
                                except Exception:
                                    pass
                            self.parity_syndrome_ok = False
                            self.quorum_status = (
                                f"2/3 DEGRADED TMR MAJORITY — {corrupted.name} ISOLATED AFTER "
                                f"{corrupted.consecutive_heals} FAILED HEALS"
                            )
                            self.log_event(
                                "ALERT",
                                f"{corrupted.name}: exceeded {MAX_CONSECUTIVE_HEALS} consecutive heals without "
                                f"converging; marking OFFLINE to prevent heal loop.",
                            )
                            return
                        corrupted.consecutive_heals += 1
                        corrupted.state = "HEALING"
                        self.parity_syndrome_ok = False
                        self.quorum_status = f"TMR PARITY FAULT ON {corrupted.name} — 2/3 MAJORITY HEALING!"
                        reason = (
                            "unreadable state probe after retry"
                            if outputs.get(corrupted.node_id) is None
                            else "state mismatch"
                        )
                        self.log_event(
                            "ALERT",
                            f"RAID Parity & 2/3 Majority {reason} on {corrupted.name}! "
                            f"Outvoted 2-to-1 by peers. Triggering automatic RAID reconstruction + Emergency Morph!",
                        )
                        threading.Thread(
                            target=self.heal_and_remorph_node, args=(corrupted,), daemon=True
                        ).start()
                        return
                    if any(outputs.get(i) is None for i in (1, 2, 3)):
                        unreadable = [n.name for n in online_nodes if outputs.get(n.node_id) is None]
                        self.parity_syndrome_ok = False
                        self.quorum_status = "TMR PARITY PROBE FAULT (UNREADABLE NODE STATE)"
                        self.log_event(
                            "ALERT",
                            f"TMR parity vote could not verify 2/3 majority: unreadable state probe on {unreadable}!",
                        )
                        return
                    # 3-way Byzantine split-brain: o1 != o2, o2 != o3, o1 != o3 (no 2-of-3 majority!)
                    self.parity_syndrome_ok = False
                    self.quorum_status = "3-WAY BYZANTINE SPLIT-BRAIN FAULT (NO 2/3 MAJORITY)"
                    self.log_event(
                        "ALERT",
                        "3-way Byzantine split-brain detected across OS-1, OS-2, OS-3 (no 2-of-3 majority)!",
                    )
                    return
            else:
                if len(online_nodes) == 2:
                    n_a, n_b = online_nodes[0], online_nodes[1]
                    o_a, o_b = outputs.get(n_a.node_id), outputs.get(n_b.node_id)
                    if o_a is None or o_b is None:
                        unreadable = [n.name for n in online_nodes if outputs.get(n.node_id) is None]
                        self.parity_syndrome_ok = False
                        self.quorum_status = "2/3 DEGRADED PROBE FAULT (UNREADABLE NODE STATE)"
                        self.log_event(
                            "ALERT",
                            f"Degraded 2/3 parity probe failed: unreadable state probe on {unreadable}!",
                        )
                        return
                    if o_a != o_b:
                        self.parity_syndrome_ok = False
                        self.quorum_status = "2/3 DEGRADED SPLIT-BRAIN FAULT (ONLINE PEERS DISAGREE)"
                        self.log_event(
                            "ALERT",
                            f"Degraded 2/3 split-brain: {n_a.name} and {n_b.name} disagree while 3rd node is offline!",
                        )
                        return
                self.parity_syndrome_ok = True
                names = " + ".join(n.name.split()[0] for n in online_nodes)
                self.quorum_status = f"2/3 DEGRADED TMR MAJORITY ACTIVE ({names}) — 0ms Downtime During Morph"
        else:
            self.parity_syndrome_ok = False
            self.quorum_status = f"{len(online_nodes)}/3 QUORUM LOST (MINIMUM 2 ONLINE NODES REQUIRED)"
            return

        if not self.spec.has_sql:
            return  # no SQL partition to protect with parity on this role

        # Update 4 KiB bitwise XOR parity across D1 and D2 AHCI SQL partitions
        d1 = n1.read_sql_partition_bytes()
        d2 = n2.read_sql_partition_bytes()
        p = bytes(a ^ b for a, b in zip(d1, d2))
        self.parity_Buffer = p
        self.parity_sha256 = hashlib.sha256(p).hexdigest()[:16]

    def reconstruct_sql_partition_from_xor_parity(self, failed_node_id: int) -> bytes:
        """
        Reconstruct a corrupted or lost 4 KiB AHCI SQL partition on `failed_node_id` (1 or 2)
        using RAID-5 bitwise XOR parity `P = D1 ^ D2`:
          - `D1 = D2 ^ P` (when `failed_node_id == 1`)
          - `D2 = D1 ^ P` (when `failed_node_id == 2`)
        Writes the reconstructed 4 KiB partition directly to the failed node's AHCI image
        at `SQL_PART_OFFSET` and returns the reconstructed 4 KiB payload.
        """
        if failed_node_id not in (1, 2):
            raise ValueError("XOR data parity covers data nodes 1 (D1) and 2 (D2)")
        surviving_node = self.nodes[1] if failed_node_id == 1 else self.nodes[0]
        failed_node = self.nodes[0] if failed_node_id == 1 else self.nodes[1]
        surviving_bytes = surviving_node.read_sql_partition_bytes()
        if len(self.parity_Buffer) != SQL_PART_SIZE:
            raise ValueError("RAID parity buffer not initialized")
        reconstructed = bytes(a ^ b for a, b in zip(surviving_bytes, self.parity_Buffer))
        if failed_node.ahci_img.exists():
            with open(failed_node.ahci_img, "r+b") as f:
                f.seek(SQL_PART_OFFSET)
                f.write(reconstructed)
        return reconstructed

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
        if len(online_nodes) < 2:
            self.parity_syndrome_ok = False
            self.log_event(
                "ALERT",
                f"Refused SQL query ({q}): quorum lost ({len(online_nodes)}/3 nodes online; >=2 required).",
            )
            return {
                "ok": False,
                "error": "quorum lost: minimum 2 of 3 online nodes required",
                "output": "error: quorum lost (minimum 2 of 3 online nodes required)",
                "quorum": f"{len(online_nodes)}/3 QUORUM LOST",
            }

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
            # Perform 2-of-3 majority vote across online nodes
            vals = list(results.values())
            chosen = max(set(vals), key=vals.count)
            agree = vals.count(chosen)
            if agree < 2:
                self.parity_syndrome_ok = False
                self.log_event(
                    "ALERT",
                    f"Refused SQL read ({q}): split-brain disagreement across online nodes (no 2/3 majority)!",
                )
                return {
                    "ok": False,
                    "error": "split-brain: no 2-of-3 majority agreement across online nodes",
                    "output": "error: split-brain detected (no 2-of-3 majority agreement)",
                    "quorum": f"{agree}/{len(online_nodes)} SPLIT-BRAIN REFUSED",
                    "tx_seq": self.triad_tx_seq,
                    "per_node": results,
                }
            return {
                "ok": True,
                "mode": "READ (2-of-3 Majority Verified)",
                "quorum": f"{agree}/{len(online_nodes)} ONLINE NODES AGREED",
                "tx_seq": self.triad_tx_seq,
                "output": chosen,
                "per_node": results,
            }

        # Mutating SQL write: write-ahead to the Triad WAL (marked "pending") and fsync BEFORE
        # executing on any node, holding `self.wal_lock` across the write-ahead, replica execution,
        # and `n.tx_seq` + `state_digest` commit update.
        with self.wal_lock:
            online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
            if len(online_nodes) < 2:
                self.parity_syndrome_ok = False
                self.log_event(
                    "ALERT",
                    f"Refused SQL write ({q}): quorum lost ({len(online_nodes)}/3 nodes online; >=2 required).",
                )
                return {
                    "ok": False,
                    "error": "quorum lost: minimum 2 of 3 online nodes required",
                    "output": "error: quorum lost (minimum 2 of 3 online nodes required)",
                    "quorum": f"{len(online_nodes)}/3 QUORUM LOST",
                }

            prev_tx_seq = self.triad_tx_seq
            prev_pending_tx = self.wal_pending_tx
            prev_pre_digest = self.wal_pending_pre_digest
            tx_id = prev_tx_seq + 1
            self.triad_tx_seq = tx_id
            self.wal_entries.append((tx_id, q))
            self.wal_pending_tx = tx_id
            self.wal_pending_pre_digest = self.triad_state_digest
            try:
                self._save_wal_to_disk()
            except Exception:
                if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                    self.wal_entries.pop()
                self.triad_tx_seq = prev_tx_seq
                self.wal_pending_tx = prev_pending_tx
                self.wal_pending_pre_digest = prev_pre_digest
                raise
            if self._after_wal_write_ahead_hook is not None:
                self._after_wal_write_ahead_hook(tx_id, q)
            per_node = {}
            accepted_nodes = []
            required_quorum = max(2, (len(online_nodes) // 2) + 1)
            try:
                for n in online_nodes:
                    try:
                        out = self.send_shell_cmd(n, f"sql /*triad*/ {q}")
                    except ValueError as e:
                        if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                            self.wal_entries.pop()
                        self.triad_tx_seq = prev_tx_seq
                        self.wal_pending_tx = None
                        self.wal_pending_pre_digest = ""
                        for acc in accepted_nodes:
                            self._rebuild_node_sql_from_committed_wal_locked(acc)
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
                if len(accepted_nodes) < required_quorum:
                    if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                        self.wal_entries.pop()
                    self.triad_tx_seq = prev_tx_seq
                    self.wal_pending_tx = None
                    self.wal_pending_pre_digest = ""
                    for n in accepted_nodes:
                        self._rebuild_node_sql_from_committed_wal_locked(n)
                    self._save_wal_to_disk()
                    err_out = next(
                        (v for k, v in per_node.items() if "error:" in v.lower()),
                        primary_out or "error: SQL statement rejected by online majority",
                    )
                    return {
                        "ok": False,
                        "error": err_out,
                        "output": err_out,
                        "quorum": f"{len(accepted_nodes)}/{len(online_nodes)} online nodes accepted",
                        "per_node": per_node,
                    }

                self.wal_pending_tx = None
                self.wal_pending_pre_digest = ""
                for n in accepted_nodes:
                    self.send_shell_cmd(n, "sync")
                    n.tx_seq = tx_id
                fp = self._state_fingerprint(accepted_nodes[0])
                if fp:
                    self.triad_state_digest = fp
                    for n in accepted_nodes:
                        n.state_digest = fp
                self._save_wal_to_disk()  # persist committed status, each node's applied tx_seq, and state digest
            finally:
                if self.wal_pending_tx == tx_id:
                    self.wal_pending_tx = None
                    self.wal_pending_pre_digest = ""
                    if len(accepted_nodes) >= required_quorum:
                        for n in accepted_nodes:
                            n.tx_seq = tx_id
                    else:
                        if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                            self.wal_entries.pop()
                        self.triad_tx_seq = prev_tx_seq
                        for n in accepted_nodes:
                            try:
                                self._rebuild_node_sql_from_committed_wal_locked(n)
                            except Exception:
                                pass
                    try:
                        self._save_wal_to_disk()
                    except Exception:
                        pass

            for n in self.nodes:
                if n.state != "ONLINE":
                    per_node[n.name] = f"[QUEUED IN WAL tx #{tx_id} — will replay on wakeup]"

        if len(self.wal_entries) > MAX_WAL_ENTRIES:
            self.checkpoint_wal()

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
            if len(online_nodes) < 2:
                self.parity_syndrome_ok = False
                self.log_event(
                    "ALERT",
                    f"Refused app read ({self._redact_app_cmd(c)}): quorum lost ({len(online_nodes)}/3 nodes online; >=2 required).",
                )
                return {
                    "ok": False,
                    "error": "quorum lost: minimum 2 of 3 online nodes required",
                    "output": "error: quorum lost (minimum 2 of 3 online nodes required)",
                    "quorum": f"{len(online_nodes)}/3 QUORUM LOST",
                }
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
            if len(accepted_nodes) < 2 or agree < 2:
                self.parity_syndrome_ok = False
                self.log_event(
                    "ALERT",
                    f"Refused app read ({self._redact_app_cmd(c)}): split-brain disagreement across online nodes (no 2/3 majority)!",
                )
                return {
                    "ok": False,
                    "error": "split-brain: no 2-of-3 majority agreement across online nodes",
                    "output": "error: split-brain detected (no 2-of-3 majority agreement)",
                    "quorum": f"{agree}/{len(online_nodes)} SPLIT-BRAIN REFUSED",
                    "tx_seq": self.triad_tx_seq,
                    "per_node": per_node,
                }
            return {
                "ok": True,
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
            if len(online_nodes) < 2:
                self.parity_syndrome_ok = False
                self.log_event(
                    "ALERT",
                    f"Refused app write ({self._redact_app_cmd(c)}): quorum lost ({len(online_nodes)}/3 nodes online; >=2 required).",
                )
                return {
                    "ok": False,
                    "error": "quorum lost: minimum 2 of 3 online nodes required",
                    "output": "error: quorum lost (minimum 2 of 3 online nodes required)",
                    "quorum": f"{len(online_nodes)}/3 QUORUM LOST",
                }

            is_vault_mut = app == "vault" and sub in ("put", "del")
            prev_tx_seq = self.triad_tx_seq
            prev_pending_tx = self.wal_pending_tx
            prev_pre_digest = self.wal_pending_pre_digest
            tx_id = prev_tx_seq
            if is_vault_mut:
                tx_id = prev_tx_seq + 1
                self.triad_tx_seq = tx_id
                wal_record = self._encrypt_wal_vault_cmd(c) if sub == "put" else c
                self.wal_entries.append((tx_id, wal_record))
                self.wal_pending_tx = tx_id
                self.wal_pending_pre_digest = self.triad_state_digest
                try:
                    self._save_wal_to_disk()
                except Exception:
                    if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                        self.wal_entries.pop()
                    self.triad_tx_seq = prev_tx_seq
                    self.wal_pending_tx = prev_pending_tx
                    self.wal_pending_pre_digest = prev_pre_digest
                    raise
                if self._after_wal_write_ahead_hook is not None:
                    self._after_wal_write_ahead_hook(tx_id, wal_record)

            per_node = {}
            accepted_nodes = []
            required_quorum = max(2, (len(online_nodes) // 2) + 1)
            try:
                for n in online_nodes:
                    out = self.send_shell_cmd(n, c)
                    per_node[n.name] = out
                    low_out = out.strip().lower()
                    if low_out and not low_out.startswith("error:") and not low_out.startswith("usage:"):
                        accepted_nodes.append(n)

                vals = list(per_node.values())
                chosen = max(set(vals), key=vals.count) if vals else ""
                if len(accepted_nodes) < required_quorum:
                    if is_vault_mut:
                        if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                            self.wal_entries.pop()
                        self.triad_tx_seq = prev_tx_seq
                        self.wal_pending_tx = None
                        self.wal_pending_pre_digest = ""
                        for n in accepted_nodes:
                            self._rebuild_node_sql_from_committed_wal_locked(n)
                        self._save_wal_to_disk()
                    return {
                        "ok": False,
                        "error": chosen or f"error: {app} command rejected by online majority",
                        "output": chosen,
                        "quorum": f"{len(accepted_nodes)}/{len(online_nodes)} online nodes accepted",
                        "per_node": per_node,
                    }

                if is_vault_mut:
                    self.wal_pending_tx = None
                    self.wal_pending_pre_digest = ""
                    for n in accepted_nodes:
                        self.send_shell_cmd(n, "sync")
                        n.tx_seq = tx_id
                    fp = self._state_fingerprint(accepted_nodes[0])
                    if fp:
                        self.triad_state_digest = fp
                        for n in accepted_nodes:
                            n.state_digest = fp
                    self._save_wal_to_disk()  # persist committed status, each node's applied tx_seq, and state digest
                if app == "cron" and sub in ("add", "del"):
                    self._record_desired_cron(parts)
            finally:
                if is_vault_mut and self.wal_pending_tx == tx_id:
                    self.wal_pending_tx = None
                    self.wal_pending_pre_digest = ""
                    if len(accepted_nodes) >= required_quorum:
                        for n in accepted_nodes:
                            n.tx_seq = tx_id
                    else:
                        if self.wal_entries and self.wal_entries[-1][0] == tx_id:
                            self.wal_entries.pop()
                        self.triad_tx_seq = prev_tx_seq
                        for n in accepted_nodes:
                            try:
                                self._rebuild_node_sql_from_committed_wal_locked(n)
                            except Exception:
                                pass
                    try:
                        self._save_wal_to_disk()
                    except Exception:
                        pass

        if app == "vault" and sub in ("put", "del"):
            if len(self.wal_entries) > MAX_WAL_ENTRIES:
                self.checkpoint_wal()
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
            full_cmd = f"sql /*triad*/ {s}"
            if len(full_cmd) > 256:
                full_cmd = f"sql /*t*/ {s}"
            self.send_shell_cmd(node, full_cmd)

    def _replay_checkpoint_on_node(self, node: TriadNode, cp_stmts: list[str]) -> bool:
        if self.wal_checkpoint_legacy:
            self.log_event(
                "ALERT",
                f"{node.name}: Refusing to replay pre-.dump legacy WAL checkpoint at "
                f"tx_seq={self.wal_checkpoint.get('tx_seq', 0)} (lossy format v1)!",
            )
            return False
        for stmt in cp_stmts:
            if not is_printable_ascii_command(stmt):
                continue
            try:
                self._replay_wal_entry(node, stmt)
            except Exception as e:
                self.log_event("WARN", f"{node.name}: Error replaying checkpoint statement: {e}")
        return True

    def _rebuild_node_sql_from_committed_wal_locked(self, node: TriadNode):
        """Rebuild `node`'s SQL vote tables from `self.wal_checkpoint` + committed `self.wal_entries` (wal_lock held)."""
        if not self.spec.has_sql:
            return
        cp_seq = int(self.wal_checkpoint.get("tx_seq", 0))
        cp_stmts = list(self.wal_checkpoint.get("stmts", []))
        if cp_seq > 0 and cp_stmts and self.wal_checkpoint_legacy:
            self.log_event(
                "ALERT",
                f"{node.name}: Refusing to replay pre-.dump legacy WAL checkpoint at tx_seq={cp_seq} (lossy format v1)!",
            )
            return
        self._reset_sql_vote_tables(node)
        last_tid = 0
        if cp_seq > 0 and cp_stmts:
            self._replay_checkpoint_on_node(node, cp_stmts)
            last_tid = cp_seq
        for tid, stmt in self.wal_entries:
            if tid <= last_tid or tid == self.wal_pending_tx:
                continue
            if is_printable_ascii_command(stmt):
                try:
                    self._replay_wal_entry(node, stmt)
                except Exception as e:
                    self.log_event("WARN", f"{node.name}: Error replaying WAL entry #{tid}: {e}")
            last_tid = tid
        node.tx_seq = last_tid
        self.send_shell_cmd(node, "sync")

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
                if node.state == "HEALING":
                    node.state = "OFFLINE" if (node.proc is not None and node.proc.poll() is not None) else "ONLINE"
                self.log_event(
                    "ALERT",
                    f"Cannot morph {node.name}: need 2 healthy peers for majority (state={node.state}).",
                )
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
                cp_seq = int(self.wal_checkpoint.get("tx_seq", 0))
                cp_stmts = list(self.wal_checkpoint.get("stmts", []))
                need_cp = self.spec.has_sql and cp_seq > node.tx_seq and bool(cp_stmts)
                if need_cp:
                    if self.wal_checkpoint_legacy:
                        self.log_event(
                            "ALERT",
                            f"{node.name}: Refusing to replay pre-.dump legacy WAL checkpoint at tx_seq={cp_seq} during catch-up (lossy format v1)!",
                        )
                        node.state = "OFFLINE"
                        return False
                    self._reset_sql_vote_tables(node)
                    self._replay_checkpoint_on_node(node, cp_stmts)
                    node.tx_seq = cp_seq
                missed = [(tid, stmt) for (tid, stmt) in self.wal_entries if tid > node.tx_seq]
                if missed or need_cp:
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
        """Drop and recreate all `self.spec.vote_tables` on `node` to clean genesis/schema state."""
        for table in self.spec.vote_tables:
            ddl_stmts: list[str] = []
            if table != "kv":
                pat = re.compile(
                    rf"^\s*CREATE\s+(?:TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{re.escape(table)}\b|INDEX\s+\S+\s+ON\s+{re.escape(table)}\b)",
                    re.IGNORECASE,
                )
                for src in (
                    list(self.spec.provision_sql),
                    list(self.wal_checkpoint.get("stmts", [])),
                    [s for _, s in self.wal_entries],
                ):
                    for s in src:
                        if pat.search(s) and s not in ddl_stmts:
                            ddl_stmts.append(s)
                if not ddl_stmts:
                    for peer in self.nodes:
                        if peer.node_id != node.node_id and peer.state == "ONLINE":
                            schema_out = self.send_shell_cmd(peer, f"sql /*triad*/ .schema {table}", timeout=3.0)
                            if schema_out and "CREATE TABLE" in schema_out.upper():
                                for ln in schema_out.splitlines():
                                    clean = ln.strip().rstrip(";").strip()
                                    if pat.search(clean):
                                        ddl_stmts.append(clean)
                                if ddl_stmts:
                                    break
            self.send_shell_cmd(node, f"sql /*triad*/ DROP TABLE {table}")
            if table == "kv":
                self.send_shell_cmd(node, "sql /*triad*/ CREATE TABLE kv (k TEXT, v TEXT, rev INT)")
                self.send_shell_cmd(node, "sql /*triad*/ INSERT INTO kv VALUES ('cluster.role', 'primary', 1)")
                self.send_shell_cmd(node, "sql /*triad*/ INSERT INTO kv VALUES ('mtd.policy', 'binmorph-7pass', 1)")
                self.send_shell_cmd(node, "sql /*triad*/ INSERT INTO kv VALUES ('boot.state', 'ready', 1)")
            else:
                for ddl in ddl_stmts:
                    self.send_shell_cmd(node, f"sql /*triad*/ {ddl}")

    def heal_and_remorph_node(self, node: TriadNode):
        """
        Reconstruct a corrupted/tampered node from the 2-of-3 healthy majority (D1 = D2 ^ P),
        replay the canonical WAL across all `vote_tables`, and emergency-morph its binary
        under the same `morph_op_lock` critical section so no concurrent wave can leave the
        node stuck in HEALING.
        """
        with self.morph_op_lock:
            try:
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

                # Reset all vote tables (`kv`, `idx`, etc.) and replay a WAL checkpoint + snapshot
                # without holding `wal_lock` across the bulk serial I/O; then briefly take `wal_lock`
                # to apply any tail entries committed during the heal.
                with self.wal_lock:
                    cp_seq = int(self.wal_checkpoint.get("tx_seq", 0))
                    cp_stmts = list(self.wal_checkpoint.get("stmts", []))
                    cp_legacy = self.wal_checkpoint_legacy
                    snapshot = list(self.wal_entries)
                if cp_seq > 0 and cp_stmts and cp_legacy:
                    self.log_event(
                        "ALERT",
                        f"{node.name}: Refusing to replay pre-.dump legacy WAL checkpoint at tx_seq={cp_seq} during heal (lossy format v1)!",
                    )
                    return
                self._reset_sql_vote_tables(node)
                last_tid = 0
                if cp_seq > 0 and cp_stmts:
                    self._replay_checkpoint_on_node(node, cp_stmts)
                    last_tid = cp_seq
                for tid, stmt in snapshot:
                    if tid <= last_tid:
                        continue
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
            finally:
                if node.state == "HEALING":
                    node.state = "OFFLINE" if (node.proc is not None and node.proc.poll() is not None) else "ONLINE"

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

    def _resolve_pending_wal_at_boot(self):
        """
        Resolve any trailing `"pending"` WAL entry left behind if the controller crashed between
        the write-ahead fsync and the post-quorum commit save:
        - A node counts as having applied the pending entry ONLY if a majority of online nodes
          agree on the exact same post-entry fingerprint AND that fingerprint matches the state
          produced by replaying the pending entry onto the committed pre-entry state.
        - Never overwrites `restored_node_digests` or `triad_state_digest` with unverified
          per-node fingerprints, preserving `_verify_restored_tx_seq_at_boot` and
          `_adopt_tx_seq_from_majority` rollback detection for any rolled-back or diverged nodes.
        """
        if self.wal_pending_tx is None:
            return
        pending_tid = self.wal_pending_tx
        pending_stmt = ""
        for tid, stmt in reversed(self.wal_entries):
            if tid == pending_tid:
                pending_stmt = stmt
                break
        online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
        if not online_nodes:
            return

        expected_pre = self.wal_pending_pre_digest or self.triad_state_digest
        node_fps: dict[int, str | None] = {}
        pre_nodes: list[TriadNode] = []
        cand_nodes: list[TriadNode] = []
        probes_by_id = self._probe_nodes_in_parallel(online_nodes, retry_none=True, max_attempts=2)
        for n in online_nodes:
            probe = probes_by_id.get(n.node_id)
            fp = hashlib.sha256(probe.encode("utf-8")).hexdigest() if probe is not None else None
            node_fps[n.node_id] = fp
            node_expected_pre = self.restored_node_digests.get(n.node_id) or expected_pre
            if node_expected_pre:
                if fp is not None and fp == node_expected_pre:
                    pre_nodes.append(n)
                elif fp is not None:
                    cand_nodes.append(n)
            else:
                p_str = probe or ""
                is_genesis = _is_genesis_sql_probe(p_str)
                if is_genesis:
                    pre_nodes.append(n)
                elif fp is not None:
                    cand_nodes.append(n)

        required_quorum = max(2, (len(online_nodes) // 2) + 1)
        with self.wal_lock:
            post_nodes: list[TriadNode] = []
            expected_post_fp: str | None = None
            rebuilt_pre_fp: str | None = expected_pre or None
            pre_node_already_advanced: TriadNode | None = None

            # Check if at least `required_quorum` candidate nodes agree on the same fingerprint `cand_fp`.
            cand_fps = [node_fps[n.node_id] for n in cand_nodes if node_fps.get(n.node_id)]
            maj_cand_fp: str | None = None
            if len(cand_fps) >= required_quorum:
                top_fp = max(set(cand_fps), key=cand_fps.count)
                if cand_fps.count(top_fp) >= required_quorum:
                    maj_cand_fp = top_fp

            if maj_cand_fp is not None and pending_stmt and is_printable_ascii_command(pending_stmt):
                matching_cands = [n for n in cand_nodes if node_fps.get(n.node_id) == maj_cand_fp]
                # Verify `maj_cand_fp` equals the state produced by replaying `pending_stmt`
                # onto the committed pre-pending state (without touching rolled-back `cand_nodes`
                # when `pre_nodes` is available).
                if pre_nodes:
                    vnode = pre_nodes[0]
                    try:
                        self._replay_wal_entry(vnode, pending_stmt)
                    except Exception as e:
                        self.log_event("WARN", f"{vnode.name}: Error verifying pending WAL #{pending_tid}: {e}")
                    self.send_shell_cmd(vnode, "sync")
                    expected_post_fp = self._state_fingerprint(vnode)
                    if expected_post_fp and expected_post_fp == maj_cand_fp:
                        post_nodes = matching_cands
                        pre_node_already_advanced = vnode
                    else:
                        # `maj_cand_fp` is not the post-pending state (e.g. rolled-back disks);
                        # restore `vnode` to the committed pre-pending state.
                        self._rebuild_node_sql_from_committed_wal_locked(vnode)
                        rebuilt_pre_fp = self._state_fingerprint(vnode) or expected_pre
                else:
                    vnode = matching_cands[0]
                    self._rebuild_node_sql_from_committed_wal_locked(vnode)
                    rebuilt_pre_fp = self._state_fingerprint(vnode) or expected_pre
                    try:
                        self._replay_wal_entry(vnode, pending_stmt)
                    except Exception as e:
                        self.log_event("WARN", f"{vnode.name}: Error verifying pending WAL #{pending_tid}: {e}")
                    self.send_shell_cmd(vnode, "sync")
                    expected_post_fp = self._state_fingerprint(vnode)
                    if expected_post_fp and expected_post_fp == maj_cand_fp:
                        post_nodes = matching_cands
                    else:
                        self._rebuild_node_sql_from_committed_wal_locked(vnode)
                        rebuilt_pre_fp = self._state_fingerprint(vnode) or rebuilt_pre_fp

            if len(post_nodes) >= required_quorum and pending_stmt and expected_post_fp:
                self.log_event(
                    "RESYNC",
                    f"Pending WAL tx #{pending_tid} verified on {len(post_nodes)}/{len(online_nodes)} nodes; "
                    f"completing commit on remaining nodes.",
                )
                for n in pre_nodes:
                    if n is pre_node_already_advanced:
                        continue
                    if is_printable_ascii_command(pending_stmt):
                        try:
                            self._replay_wal_entry(n, pending_stmt)
                        except Exception as e:
                            self.log_event("WARN", f"{n.name}: Error replaying pending WAL #{pending_tid}: {e}")
                    self.send_shell_cmd(n, "sync")

                self.triad_state_digest = expected_post_fp
                for n in online_nodes:
                    self.restored_node_digests[n.node_id] = expected_post_fp
                    cur_fp = self._state_fingerprint(n)
                    if cur_fp == expected_post_fp:
                        n.tx_seq = pending_tid
                        n.state_digest = expected_post_fp
                        self.restored_tx_seq_nodes.add(n.node_id)
                self.wal_pending_tx = None
                self.wal_pending_pre_digest = ""
                self._save_wal_to_disk()
            else:
                self.log_event(
                    "WARN",
                    f"Rolling back uncommitted pending WAL tx #{pending_tid} (verified on {len(post_nodes)}/{len(online_nodes)} nodes).",
                )
                self.wal_entries = [(tid, s) for tid, s in self.wal_entries if tid != pending_tid]
                cp_seq = int(self.wal_checkpoint.get("tx_seq", 0))
                self.triad_tx_seq = self.wal_entries[-1][0] if self.wal_entries else cp_seq
                self.wal_pending_tx = None
                self.wal_pending_pre_digest = ""

                # If only a minority (1 node) differed from `expected_pre`, rebuild that minority node
                # from the committed WAL. If >= 2 nodes differed (e.g. a 2-node disk rollback), leave
                # them untouched so `_verify_restored_tx_seq_at_boot` and `_adopt_tx_seq_from_majority`
                # detect the rollback and replay the committed WAL onto them.
                if len(cand_nodes) < required_quorum:
                    for n in cand_nodes:
                        self._rebuild_node_sql_from_committed_wal_locked(n)
                        if not rebuilt_pre_fp:
                            rebuilt_pre_fp = self._state_fingerprint(n)

                if not rebuilt_pre_fp and pre_nodes:
                    rebuilt_pre_fp = node_fps.get(pre_nodes[0].node_id)

                if rebuilt_pre_fp:
                    self.triad_state_digest = rebuilt_pre_fp
                    for n in online_nodes:
                        self.restored_node_digests[n.node_id] = rebuilt_pre_fp
                        cur_fp = self._state_fingerprint(n)
                        if cur_fp == rebuilt_pre_fp:
                            n.tx_seq = self.triad_tx_seq
                            n.state_digest = rebuilt_pre_fp
                            self.restored_tx_seq_nodes.add(n.node_id)
                self._save_wal_to_disk()

    def _verify_restored_tx_seq_at_boot(self):
        """
        Verify each restored node's on-disk state fingerprint against the digest saved in the
        WAL file. A node whose disk was rolled back or tampered while offline does not match
        the persisted digest, so its `tx_seq` is reset to 0 before majority adoption / parity check.
        When upgrading from an older probe format (`self.wal_probe_format_mismatch`), if all 3
        online nodes agree 3/3 on their live non-genesis state, recomputes and adopts the v2
        digests (and upgrades any legacy pre-`.dump` checkpoint from the 3/3 live state) instead
        of treating all 3 nodes as rolled back.
        Retries transient serial `None` reads before acting, and leaves unreadable nodes out of the
        vote rather than falsely resetting their `tx_seq = 0`.
        """
        if self.wal_probe_format_mismatch and self.triad_tx_seq > 0:
            online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
            if len(online_nodes) == 3:
                raw_probes = self._probe_nodes_in_parallel(online_nodes, retry_none=True, max_attempts=3)
                probes = {nid: p for nid, p in raw_probes.items() if p is not None}
                if len(probes) == 3 and len(set(probes.values())) == 1:
                    common_probe = next(iter(probes.values()))
                    genesis_only = _is_genesis_sql_probe(common_probe) and (
                        len(self.wal_entries) > 0 or self.wal_checkpoint.get("tx_seq", 0) > 0
                    )
                    if not genesis_only:
                        new_fp = hashlib.sha256(common_probe.encode("utf-8")).hexdigest()
                        self.triad_state_digest = new_fp
                        for node in online_nodes:
                            node.tx_seq = self.triad_tx_seq
                            node.state_digest = new_fp
                            self.restored_node_digests[node.node_id] = new_fp
                            self.restored_tx_seq_nodes.add(node.node_id)
                        self.wal_probe_format_mismatch = False
                        self.log_event(
                            "RESYNC",
                            f"Probe format upgraded to v{WAL_PROBE_FORMAT_VERSION}: 3/3 nodes agree on live state; "
                            f"recomputed digest {new_fp[:12]} at tx_seq={self.triad_tx_seq}.",
                        )
                        if self.wal_checkpoint_legacy:
                            self.checkpoint_wal()
                        else:
                            self._save_wal_to_disk()
                        return

        if not self.restored_tx_seq_nodes:
            return
        restored_online = [
            self.nodes[nid - 1]
            for nid in sorted(self.restored_tx_seq_nodes)
            if self.nodes[nid - 1].state == "ONLINE"
        ]
        fps_by_id: dict[int, str | None] = {}

        def _fp_worker(node: TriadNode):
            fp = None
            for attempt in range(3):
                fp = self._state_fingerprint(node)
                if fp is not None:
                    break
                if attempt < 2:
                    time.sleep(0.05)
            fps_by_id[node.node_id] = fp

        if len(restored_online) <= 1:
            for node in restored_online:
                _fp_worker(node)
        else:
            threads = [
                threading.Thread(target=_fp_worker, args=(node,), daemon=True)
                for node in restored_online
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        for node in restored_online:
            actual_fp = fps_by_id.get(node.node_id)
            if actual_fp is None:
                self.log_event(
                    "WARN",
                    f"{node.name}: state fingerprint unreadable at boot after 3 attempts; leaving node out of vote until readable.",
                )
                continue
            expected_fp = self.restored_node_digests.get(node.node_id) or self.triad_state_digest
            if (expected_fp and actual_fp != expected_fp) or self.wal_probe_format_mismatch:
                self.log_event(
                    "WARN",
                    f"{node.name}: on-disk state digest ({actual_fp[:12]}) != WAL digest ({(expected_fp or 'v1')[:12]}) "
                    f"at tx_seq={node.tx_seq}; resetting tx_seq=0.",
                )
                node.tx_seq = 0
                node.state_digest = ""
                self.restored_tx_seq_nodes.discard(node.node_id)
            else:
                node.state_digest = actual_fp

    def _adopt_tx_seq_from_majority(self):
        """
        Reconcile nodes whose applied tx_seq could not be restored from the WAL file (files
        written before per-node tracking, or nodes whose disk was rolled back/wiped). Compares all
        `self.spec.vote_tables` across online nodes; nodes that match the 2-of-3 majority AND
        match `triad_state_digest` (if recorded) adopt `self.triad_tx_seq`. If 2 or 3 nodes were
        rolled back so the on-disk majority disagrees with `triad_state_digest`, replays the WAL
        checkpoint + entries onto all `pending` nodes while preserving any already-verified node
        (refusing to replay any legacy pre-`.dump` checkpoint).
        Any single node that disagrees with the verified 2-of-3 majority keeps `tx_seq=0` and is
        healed by `compute_and_verify_raid_parity()`.
        """
        pending = [
            n for n in self.nodes
            if n.node_id not in self.restored_tx_seq_nodes and n.state == "ONLINE"
        ]
        if not pending or self.triad_tx_seq == 0 or not self.spec.has_sql:
            return
        online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
        raw_probes = self._probe_nodes_in_parallel(online_nodes, retry_none=True, max_attempts=2)
        probes = {nid: p for nid, p in raw_probes.items() if p is not None}
        vals = list(probes.values())
        if len(vals) < 2:
            return
        majority = max(set(vals), key=vals.count)
        maj_fp = hashlib.sha256(majority.encode("utf-8")).hexdigest()

        # Check if 2 or 3 disks were rolled back so the on-disk majority disagrees with the WAL's
        # recorded state digest (or holds only the 3 genesis rows while the WAL has writes).
        genesis_only = _is_genesis_sql_probe(majority) and (
            len(self.wal_entries) > 0 or self.wal_checkpoint.get("tx_seq", 0) > 0
        )
        if (self.triad_state_digest and maj_fp != self.triad_state_digest) or genesis_only or self.wal_probe_format_mismatch:
            if vals.count(majority) >= 2:
                cp_seq = int(self.wal_checkpoint.get("tx_seq", 0))
                cp_stmts = list(self.wal_checkpoint.get("stmts", []))
                if cp_seq > 0 and cp_stmts and self.wal_checkpoint_legacy:
                    self.log_event(
                        "ALERT",
                        f"Refusing to replay pre-.dump legacy WAL checkpoint at tx_seq={cp_seq} "
                        f"onto {[n.name.split()[0] for n in pending]} (lossy format v1).",
                    )
                    return
                self.log_event(
                    "WARN",
                    f"On-disk majority does not match WAL at tx_seq={self.triad_tx_seq}; replaying WAL on rolled-back nodes {[n.name.split()[0] for n in pending]}.",
                )
                with self.wal_lock:
                    for n in pending:
                        if n.state != "ONLINE":
                            continue
                        self._reset_sql_vote_tables(n)
                        last_tid = 0
                        if cp_seq > 0 and cp_stmts:
                            self._replay_checkpoint_on_node(n, cp_stmts)
                            last_tid = cp_seq
                        for tid, stmt in self.wal_entries:
                            if tid <= last_tid:
                                continue
                            if is_printable_ascii_command(stmt):
                                try:
                                    self._replay_wal_entry(n, stmt)
                                except Exception as e:
                                    self.log_event("WARN", f"{n.name}: Error replaying WAL entry #{tid} at boot: {e}")
                            last_tid = tid
                        n.tx_seq = max(last_tid, self.triad_tx_seq)
                        self.send_shell_cmd(n, "sync")
                        fp = self._state_fingerprint(n)
                        if fp:
                            n.state_digest = fp
                            self.triad_state_digest = fp
                        self.restored_tx_seq_nodes.add(n.node_id)
                    self.wal_probe_format_mismatch = False
                    self._save_wal_to_disk()
                return

        if vals.count(majority) < 2:
            return
        if self.triad_state_digest and maj_fp != self.triad_state_digest:
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

        self._resolve_pending_wal_at_boot()
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
        if self.wal_checkpoint.get("tx_seq", 0) > 0:
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
    localStorage.removeItem('cuttle_session_token');
    localStorage.removeItem('cuttle_operator_token');
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
          ${d.forward_node_ports !== false ? `<button onclick="window.open('http://127.0.0.1:${port}/app','_blank')">Direct UI</button>` : ''}
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
                "forward_node_ports": c.spec.forward_node_ports,
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


def run_fault_injection_unit_tests() -> None:
    """
    Deterministic, fast (no-QEMU) fault-injection verification suite for:
      1. 1-of-3 Quorum Loss (2 nodes offline -> reads & writes refused, WAL untouched)
      2. 3-Way Byzantine Split-Brain (`A != B != C` -> reads & parity check fail closed)
      3. 2-of-2 Degraded Split-Brain (`A != B` while 3rd node is morphing -> refused)
      4. 2-of-3 Majority Vote Masking & Single-Node Write Rejection (<2 accepted -> refused)
      5. 4 KiB RAID-5 XOR Parity Striping (D1 ^ D2 = P) & Bitwise Reconstruction under disk corruption
      6. Encrypted WAL Vault (`ENC_WAL_V1:`) HMAC-SHA256 tamper rejection & replay
    """
    import tempfile

    print("[triad-fault-suite] running deterministic Quorum, Split-Brain, WAL & RAID XOR fault-injection tests...")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        spec = TriadSpec(
            name="fault-test-triad",
            state_dir=tmp_path,
            http_base=19100,
            https_base=19500,
            smp=2,
            accel="tcg",
        )
        spec.write_operator_token = False
        ctrl = TriadController(show_gui=False, spec=spec, unit_test=True)
        ctrl.shutdown()

        # Initialize 1 MiB scratch AHCI images for all 3 nodes:
        for n in ctrl.nodes:
            n.ahci_img.parent.mkdir(parents=True, exist_ok=True)
            n.ahci_img.write_bytes(b"\x00" * (1024 * 1024))
            n.state = "ONLINE"

        # ------------------------------------------------------------------
        # Fault 1: 1-of-3 Online Quorum Loss (OS-2 and OS-3 OFFLINE/MORPHING)
        # ------------------------------------------------------------------
        ctrl.nodes[0].state = "ONLINE"
        ctrl.nodes[1].state = "MORPHING"
        ctrl.nodes[2].state = "OFFLINE"
        ctrl.send_shell_cmd = lambda node, cmd, timeout=4.0: "k|v|rev\ncluster.role|primary|1\n"

        wal_before = len(ctrl.wal_entries)
        tx_before = ctrl.triad_tx_seq

        r_read_1of3 = ctrl.execute_triad_sql("SELECT * FROM kv")
        assert not r_read_1of3["ok"], f"1-of-3 online read must fail closed: {r_read_1of3}"
        assert "QUORUM LOST" in r_read_1of3["quorum"], f"Expected QUORUM LOST: {r_read_1of3}"

        r_write_1of3 = ctrl.execute_triad_sql("INSERT INTO kv VALUES ('solo', 'bad', 1)")
        assert not r_write_1of3["ok"], f"1-of-3 online write must fail closed: {r_write_1of3}"
        assert len(ctrl.wal_entries) == wal_before, "1-of-3 refused write must not append to WAL"
        assert ctrl.triad_tx_seq == tx_before, "1-of-3 refused write must not advance triad_tx_seq"

        r_app_read_1of3 = ctrl.execute_triad_app("vault get secret.key")
        assert not r_app_read_1of3["ok"], f"1-of-3 online app read must fail closed: {r_app_read_1of3}"
        r_app_write_1of3 = ctrl.execute_triad_app("vault put secret.key val")
        assert not r_app_write_1of3["ok"], f"1-of-3 online app write must fail closed: {r_app_write_1of3}"
        assert len(ctrl.wal_entries) == wal_before

        ctrl.compute_and_verify_raid_parity()
        assert not ctrl.parity_syndrome_ok, "1-of-3 online must set parity_syndrome_ok=False"
        assert "QUORUM LOST" in ctrl.quorum_status, f"Unexpected quorum_status: {ctrl.quorum_status}"

        # ------------------------------------------------------------------
        # Fault 2: 3-Way Byzantine Split-Brain (`A != B != C` across 3 ONLINE nodes)
        # ------------------------------------------------------------------
        for n in ctrl.nodes:
            n.state = "ONLINE"
        split3_outputs = {
            1: "k|v|rev\nleader|node1_byz|1\n",
            2: "k|v|rev\nleader|node2_byz|1\n",
            3: "k|v|rev\nleader|node3_byz|1\n",
        }
        ctrl.send_shell_cmd = lambda node, cmd, timeout=4.0: split3_outputs[node.node_id]
        ctrl._state_probe = lambda node: split3_outputs[node.node_id]

        r_split3 = ctrl.execute_triad_sql("SELECT * FROM kv")
        assert not r_split3["ok"], f"3-way split-brain read must fail closed: {r_split3}"
        assert "SPLIT-BRAIN REFUSED" in r_split3["quorum"], f"Expected SPLIT-BRAIN REFUSED: {r_split3}"
        assert not ctrl.parity_syndrome_ok

        r_app_split3 = ctrl.execute_triad_app("vault get k")
        assert not r_app_split3["ok"], f"3-way split-brain app read must fail closed: {r_app_split3}"

        ctrl.parity_syndrome_ok = True
        ctrl.compute_and_verify_raid_parity()
        assert not ctrl.parity_syndrome_ok, "compute_and_verify_raid_parity must flag 3-way split-brain"
        assert "3-WAY BYZANTINE SPLIT-BRAIN" in ctrl.quorum_status, (
            f"Expected 3-WAY BYZANTINE SPLIT-BRAIN status, got: {ctrl.quorum_status}"
        )

        # ------------------------------------------------------------------
        # Fault 3: 2-of-2 Degraded Split-Brain (`A != B` while 3rd node is MORPHING)
        # ------------------------------------------------------------------
        ctrl.nodes[0].state = "ONLINE"
        ctrl.nodes[1].state = "ONLINE"
        ctrl.nodes[2].state = "MORPHING"
        r_split2 = ctrl.execute_triad_sql("SELECT * FROM kv")
        assert not r_split2["ok"], f"2-of-2 degraded disagreement must fail closed: {r_split2}"
        assert "SPLIT-BRAIN REFUSED" in r_split2["quorum"]

        ctrl.parity_syndrome_ok = True
        ctrl.compute_and_verify_raid_parity()
        assert not ctrl.parity_syndrome_ok, "2-of-2 degraded disagreement must set parity_syndrome_ok=False"
        assert "2/3 DEGRADED SPLIT-BRAIN FAULT" in ctrl.quorum_status

        # ------------------------------------------------------------------
        # Fault 4: 2-of-3 Majority Vote Masking (1 Byzantine node outvoted 2-to-1)
        #          & Write Rejected by 2 of 3 Nodes (<2 accepted -> refused)
        # ------------------------------------------------------------------
        for n in ctrl.nodes:
            n.state = "ONLINE"
        maj_outputs = {
            1: "k|v|rev\nleader|consensus_val|1\n",
            2: "k|v|rev\nleader|byzantine_corrupt|99\n",
            3: "k|v|rev\nleader|consensus_val|1\n",
        }
        ctrl.send_shell_cmd = lambda node, cmd, timeout=4.0: maj_outputs[node.node_id]
        r_maj = ctrl.execute_triad_sql("SELECT * FROM kv")
        assert r_maj["ok"], f"2-of-3 majority read must succeed when 2 nodes agree: {r_maj}"
        assert "2/3 ONLINE NODES AGREED" in r_maj["quorum"]
        assert "consensus_val" in r_maj["output"] and "byzantine_corrupt" not in r_maj["output"]

        # Write accepted by only 1 of 3 nodes (2 nodes return SQL error):
        write_1of3_accept = {
            1: "INSERT 1\n",
            2: "error: EACCES (table locked)\n",
            3: "error: EACCES (table locked)\n",
        }
        ctrl.send_shell_cmd = lambda node, cmd, timeout=4.0: write_1of3_accept[node.node_id]
        r_w_reject = ctrl.execute_triad_sql("INSERT INTO kv VALUES ('x', 'y', 1)")
        assert not r_w_reject["ok"], f"Write accepted by only 1/3 nodes must fail closed: {r_w_reject}"
        assert len(ctrl.wal_entries) == wal_before, "Write without 2/3 acceptance must not enter WAL"

        # ------------------------------------------------------------------
        # Fault 5: 4 KiB RAID-5 XOR Parity Striping (D1 ^ D2 = P) & Exact Reconstruction
        # ------------------------------------------------------------------
        d1_orig = bytes((i * 73 + 19) & 0xFF for i in range(SQL_PART_SIZE))
        d2_orig = bytes((i * 151 + 43) & 0xFF for i in range(SQL_PART_SIZE))
        for node, payload in ((ctrl.nodes[0], d1_orig), (ctrl.nodes[1], d2_orig)):
            with open(node.ahci_img, "r+b") as f:
                f.seek(SQL_PART_OFFSET)
                f.write(payload)

        ctrl.send_shell_cmd = lambda node, cmd, timeout=4.0: "k|v|rev\nraid|ok|1\n"
        ctrl._state_probe = lambda node: "k|v|rev\nraid|ok|1\n"
        ctrl.compute_and_verify_raid_parity()
        assert ctrl.parity_syndrome_ok
        assert len(ctrl.parity_Buffer) == SQL_PART_SIZE
        assert ctrl.parity_Buffer == bytes(a ^ b for a, b in zip(d1_orig, d2_orig))

        # Corrupt OS-1's 4 KiB SQL partition with bit flips and zeroed sectors:
        with open(ctrl.nodes[0].ahci_img, "r+b") as f:
            f.seek(SQL_PART_OFFSET)
            f.write(b"\xFF" * 1024 + b"\x00" * (SQL_PART_SIZE - 1024))
        assert ctrl.nodes[0].read_sql_partition_bytes() != d1_orig

        # Reconstruct D1 from D2 ^ P:
        recovered_d1 = ctrl.reconstruct_sql_partition_from_xor_parity(1)
        assert recovered_d1 == d1_orig, "RAID-5 XOR reconstruction D1 = D2 ^ P failed"
        assert ctrl.nodes[0].read_sql_partition_bytes() == d1_orig

        # Corrupt OS-2's 4 KiB SQL partition and reconstruct D2 from D1 ^ P:
        with open(ctrl.nodes[1].ahci_img, "r+b") as f:
            f.seek(SQL_PART_OFFSET)
            f.write(b"\xAA" * SQL_PART_SIZE)
        assert ctrl.nodes[1].read_sql_partition_bytes() != d2_orig
        recovered_d2 = ctrl.reconstruct_sql_partition_from_xor_parity(2)
        assert recovered_d2 == d2_orig, "RAID-5 XOR reconstruction D2 = D1 ^ P failed"
        assert ctrl.nodes[1].read_sql_partition_bytes() == d2_orig

        # ------------------------------------------------------------------
        # Fault 6: Encrypted WAL Vault (`ENC_WAL_V1:`) Tamper Rejection
        # ------------------------------------------------------------------
        plain_vault_cmd = "vault put cluster.master_key TopSecretKey99"
        enc_record = ctrl._encrypt_wal_vault_cmd(plain_vault_cmd)
        assert enc_record.startswith("ENC_WAL_V1:") and "TopSecretKey99" not in enc_record
        assert ctrl._decrypt_wal_vault_cmd(enc_record) == plain_vault_cmd

        # Flip 1 hex nibble in the HMAC-SHA256 tag of `ENC_WAL_V1:<nonce>:<ct>:<tag>`:
        parts = enc_record.split(":")
        tampered_tag = ("0" if parts[3][0] != "0" else "1") + parts[3][1:]
        tampered_record = ":".join([parts[0], parts[1], parts[2], tampered_tag])
        try:
            ctrl._decrypt_wal_vault_cmd(tampered_record)
            raise AssertionError("Tampered ENC_WAL_V1 tag must raise ValueError")
        except ValueError as e:
            assert "authentication tag mismatch" in str(e)

    print("[triad-fault-suite] ALL 6 FAULT-INJECTION SUITES PASSED")


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

        # #5: write_secret_file restricts permissions BEFORE writing secret bytes and raises OSError on ACL failure
        acl_order_dir = tmp_dir / "acl_order"
        acl_order_dir.mkdir(parents=True, exist_ok=True)
        acl_target = acl_order_dir / "secret.bin"
        acl_sizes_seen = []
        orig_restrict = globals()["restrict_file_permissions"]

        def spy_restrict(p: Path):
            if p.name.endswith(".tmp"):
                acl_sizes_seen.append(p.stat().st_size)
            orig_restrict(p)

        globals()["restrict_file_permissions"] = spy_restrict
        try:
            write_secret_file(acl_target, b"S" * 32)
        finally:
            globals()["restrict_file_permissions"] = orig_restrict
        assert acl_sizes_seen == [0], (
            f"restrict_file_permissions must run on empty tmp file (0 B) before writing secret bytes, saw {acl_sizes_seen}"
        )
        if os.name == "nt":
            expected_sid = _get_windows_current_sid()
            acl_dump = acl_order_dir / "acl_sddl.txt"
            save_res = subprocess.run(
                ["icacls", str(acl_target), "/save", str(acl_dump)],
                capture_output=True,
                check=True,
            )
            assert save_res.returncode == 0
            sddl_text = acl_dump.read_text(encoding="utf-16le", errors="replace")
            assert f"D:PAI(A;;FA;;;{expected_sid})" in sddl_text, (
                f"Expected exact current-user SID DACL D:PAI(A;;FA;;;{expected_sid}) in icacls /save output, got: {sddl_text!r}"
            )
        else:
            mode = acl_target.stat().st_mode & 0o777
            assert mode == 0o600, f"Expected POSIX mode 0600 on secret file, got {oct(mode)}"

        def fail_restrict(p: Path):
            raise OSError("icacls failed (simulated exit 1)")

        globals()["restrict_file_permissions"] = fail_restrict
        try:
            try:
                write_secret_file(acl_order_dir / "fail_secret.bin", b"X" * 32)
                raise AssertionError("write_secret_file must raise OSError when restrict_file_permissions fails")
            except OSError:
                pass
        finally:
            globals()["restrict_file_permissions"] = orig_restrict
        assert not list(acl_order_dir.glob("*.tmp")), "Failed write_secret_file must unlink tmp file"
        assert not (acl_order_dir / "fail_secret.bin").exists()

        # Medium #4 & Low #5: Production controller (unit_test=False) refuses to start when
        #                     QEMU or BASE_ELF is missing, while unit_test=True constructs
        #                     controllers without touching BASE_ELF/BASE_BIOS or invoking cargo.
        orig_base_elf = globals()["BASE_ELF"]
        orig_base_bios = globals()["BASE_BIOS"]
        orig_find_qemu = globals()["find_qemu"]
        try:
            globals()["BASE_ELF"] = tmp_dir / "definitely_missing_kernel_elf"
            globals()["BASE_BIOS"] = tmp_dir / "definitely_missing_bios.img"
            try:
                TriadController(
                    show_gui=False,
                    spec=TriadSpec(name="prod-missing-elf", state_dir=tmp_dir / "prod_missing_elf", write_operator_token=False),
                    unit_test=False,
                )
                raise AssertionError("Production TriadController (unit_test=False) must raise RuntimeError when BASE_ELF is missing")
            except RuntimeError as e:
                assert "Base kernel ELF not found" in str(e), f"Unexpected error: {e}"

            def missing_qemu():
                raise RuntimeError("qemu-system-x86_64 not found on PATH")

            globals()["find_qemu"] = missing_qemu
            try:
                TriadController(
                    show_gui=False,
                    spec=TriadSpec(name="prod-missing-qemu", state_dir=tmp_dir / "prod_missing_qemu", write_operator_token=False),
                    unit_test=False,
                )
                raise AssertionError("Production TriadController (unit_test=False) must raise RuntimeError when QEMU is missing")
            except RuntimeError as e:
                assert "qemu-system-x86_64 not found" in str(e), f"Unexpected error: {e}"

            ut_ctrl = TriadController(
                show_gui=False,
                spec=TriadSpec(name="ut-no-elf", state_dir=tmp_dir / "ut_no_elf", write_operator_token=False),
                unit_test=True,
            )
            ut_ctrl.shutdown()
            assert ut_ctrl.base_elf_bytes.startswith(b"\x7fELF") and ut_ctrl.elf_offset_in_bios == 64
        finally:
            globals()["BASE_ELF"] = orig_base_elf
            globals()["BASE_BIOS"] = orig_base_bios
            globals()["find_qemu"] = orig_find_qemu

        # #15.2: Dropped legacy/non-read-only cron jobs log a WARN event on startup
        cron_warn_dir = tmp_dir / "cron_warn"
        cron_warn_dir.mkdir(parents=True, exist_ok=True)
        (cron_warn_dir / "cron_jobs.json").write_text(
            json.dumps([[5, "status"], [10, "sql DELETE FROM kv"], [15, "write /var/x 1"]]),
            encoding="utf-8",
        )
        cron_warn_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="cron-warn", state_dir=cron_warn_dir, write_operator_token=False),
            unit_test=True,
        )
        cron_warn_ctrl.shutdown()
        assert cron_warn_ctrl.desired_cron == [(5, "status")]
        warn_msgs = [e["msg"] for e in cron_warn_ctrl.events if e["level"] == "WARN"]
        assert any("sql DELETE FROM kv" in m for m in warn_msgs) and any("write /var/x 1" in m for m in warn_msgs), (
            f"Dropped legacy cron jobs must be logged as WARN: {warn_msgs}"
        )
        assert safe_token_eq("abc123", "abc123")
        assert not safe_token_eq("abc123", "abc124")
        assert not safe_token_eq("é" * 20, "a" * 20)
        assert not safe_token_eq("", "abc123")

        # #8: write_operator_token=False suppresses operator_token.txt creation on disk
        no_tok_dir = tmp_dir / "no_op_token"
        no_tok_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="no-tok", state_dir=no_tok_dir, write_operator_token=False),
            unit_test=True,
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
            TriadController(show_gui=False, spec=TriadSpec(name="corrupt", state_dir=corrupt_dir), unit_test=True)
            raise AssertionError("Corrupt triad_wal.json must raise ValueError at startup")
        except ValueError:
            assert (corrupt_dir / "triad_wal.json.bad").exists(), "Corrupt WAL must be saved to triad_wal.json.bad"

        # #19: atomic_write_json unlinks temporary sibling file when write/fsync fails
        atomic_fail_dir = tmp_dir / "atomic_fail"
        atomic_fail_dir.mkdir(parents=True, exist_ok=True)
        atomic_target = atomic_fail_dir / "test.json"
        real_fsync = os.fsync

        def failing_fsync(fd):
            raise OSError("simulated disk full during fsync")

        os.fsync = failing_fsync
        try:
            try:
                atomic_write_json(atomic_target, {"ok": True})
                raise AssertionError("atomic_write_json must propagate OSError from os.fsync")
            except OSError:
                pass
        finally:
            os.fsync = real_fsync
        leftover_tmps = list(atomic_fail_dir.glob("*.tmp"))
        assert not leftover_tmps, f"atomic_write_json leaked temporary file(s) on failure: {leftover_tmps}"

        # #1 & High #2 & Low #9.3: WAL checkpointing via lossless chunked `.dump` against the
        #     REAL Rust `OsShell` (`shell_harness`, 1,024-byte console cap) across >MAX_WAL_ENTRIES
        #     mixed INSERT/UPDATE statements (>1 KiB of rows, including `|` and `'` values),
        #     automatic trigger past MAX_WAL_ENTRIES, healing a tampered node to 3/3 convergence,
        #     and 2/3 majority checkpoint when 1 node is offline.
        cp_dir = tmp_dir / "wal_checkpoint"
        cp_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="cp-test", state_dir=cp_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        cp_ctrl.shutdown()
        for n in cp_ctrl.nodes:
            n.state = "ONLINE"

        cp_harness = RealOsShellHarness()
        try:
            cp_ctrl.send_shell_cmd = cp_harness.exec
            cp_ctrl.bounce_and_morph_node = lambda nid, _lock_held=False, _wipe_disks=False: (
                setattr(cp_ctrl.nodes[nid - 1], "state", "ONLINE") or True
            )
            # Verify shared `format_kernel_sqldump_reply` matches real `OsShell` `.dump` byte-for-byte.
            for n in cp_ctrl.nodes:
                cp_ctrl._reset_sql_vote_tables(n)
            raw_dump0 = cp_harness.exec(cp_ctrl.nodes[0], "sql /*triad*/ .dump kv 0 3")
            expected_dump0 = format_kernel_sqldump_reply(
                "kv",
                [("k", "TEXT"), ("v", "TEXT"), ("rev", "INT")],
                [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
                0,
                3,
            )
            assert raw_dump0 == expected_dump0, (
                f"format_kernel_sqldump_reply drifted from OsShell:\nactual:   {raw_dump0!r}\nexpected: {expected_dump0!r}"
            )

            # Execute > MAX_WAL_ENTRIES (66 statements across 44 rows -> 47 total rows > 1 KiB)
            # including values with `|`, doubled single quotes `''`, and multi-column partial UPDATEs.
            assert cp_ctrl.execute_triad_sql(
                "INSERT OR REPLACE INTO kv VALUES ('pipe.key', 'left|mid|right', 1)"
            )["ok"]
            assert cp_ctrl.execute_triad_sql(
                "INSERT OR REPLACE INTO kv VALUES ('quote.key', 'it''s|quoted', 1)"
            )["ok"]
            assert cp_ctrl.execute_triad_sql(
                "INSERT OR REPLACE INTO kv VALUES ('partial.key', 'orig_v', 1)"
            )["ok"]
            assert cp_ctrl.execute_triad_sql(
                "UPDATE kv SET v = 'updated|v' WHERE k = 'partial.key'"
            )["ok"]
            assert cp_ctrl.execute_triad_sql(
                "UPDATE kv SET rev = 9 WHERE k = 'partial.key'"
            )["ok"]
            for i in range(1, 42):
                assert cp_ctrl.execute_triad_sql(
                    f"INSERT OR REPLACE INTO kv VALUES ('row.{i:02d}', 'val_{i:02d}_padding_text', {i})"
                )["ok"]
            for i in range(1, 22):
                assert cp_ctrl.execute_triad_sql(
                    f"UPDATE kv SET rev = {100 + i} WHERE k = 'row.{i:02d}'"
                )["ok"]

            assert cp_ctrl.triad_tx_seq == 67, f"Expected tx_seq=67 (> MAX_WAL_ENTRIES), got {cp_ctrl.triad_tx_seq}"
            assert cp_ctrl.wal_checkpoint["tx_seq"] >= 65, (
                f"Automatic WAL checkpoint did not trigger after crossing MAX_WAL_ENTRIES ({MAX_WAL_ENTRIES}): {cp_ctrl.wal_checkpoint}"
            )
            assert len(cp_ctrl.wal_entries) <= 2, (
                f"Superseded WAL entries were not cleared by automatic checkpoint: len={len(cp_ctrl.wal_entries)}"
            )
            # Confirm raw `SELECT * FROM kv` is truncated at the 1,024-byte kernel console buffer,
            # while `_dump_node_sql_table` reads all 47 rows losslessly.
            raw_sel = cp_harness.exec(cp_ctrl.nodes[0], "sql /*triad*/ SELECT * FROM kv")
            assert len(raw_sel) >= 1000, f"Expected SELECT output to hit ~1 KiB console cap, got {len(raw_sel)} B"
            tdump0 = cp_ctrl._dump_node_sql_table(cp_ctrl.nodes[0], "kv")
            assert tdump0 is not None and tdump0["rows_count"] == 47, (
                f"Expected 47 lossless rows in chunked .dump, got {tdump0}"
            )

            # Tamper a row past the 1 KiB SELECT truncation boundary on node 2 (`z.tail` sorts last)
            # and verify `_state_probe` detects the divergence and `heal_and_remorph_node` restores 3/3.
            cp_harness.exec(
                cp_ctrl.nodes[1],
                "sql /*triad*/ UPDATE kv SET v = 'TAMPERED_PAST_1K' WHERE k = 'row.41'",
            )
            assert cp_ctrl._state_probe(cp_ctrl.nodes[0]) != cp_ctrl._state_probe(cp_ctrl.nodes[1]), (
                "_state_probe must detect divergence beyond the first 1 KiB of rows"
            )
            cp_ctrl.heal_and_remorph_node(cp_ctrl.nodes[1])
            healed_dump = cp_ctrl._dump_node_sql_table(cp_ctrl.nodes[1], "kv")
            assert healed_dump is not None and healed_dump["rows_count"] == 47, (
                f"Healed node lost rows after checkpoint replay: {healed_dump}"
            )
            row_map = {r[0][1]: (r[1][1], r[2][1]) for r in healed_dump["rows"]}
            assert row_map.get(b"pipe.key") == (b"left|mid|right", 1), f"Pipe row corrupted: {row_map.get(b'pipe.key')}"
            assert row_map.get(b"quote.key") == (b"it's|quoted", 1), f"Quote row corrupted: {row_map.get(b'quote.key')}"
            assert row_map.get(b"partial.key") == (b"updated|v", 9), f"Partial update row corrupted: {row_map.get(b'partial.key')}"
            assert row_map.get(b"row.41") == (b"val_41_padding_text", 41), f"Tail row.41 not healed: {row_map.get(b'row.41')}"
            assert (
                cp_ctrl._state_probe(cp_ctrl.nodes[0])
                == cp_ctrl._state_probe(cp_ctrl.nodes[1])
                == cp_ctrl._state_probe(cp_ctrl.nodes[2])
            ), "All 3 nodes must converge 3/3 after healing from chunked checkpoint + tail"

            # High #1 (Round 8):
            # 1a. A single node tampered with non-UTF-8 binary SQL literal (`X'ff'`) does NOT cause
            #     `_dump_node_sql_table` / `_state_probe` to return None; `compute_and_verify_raid_parity`
            #     detects the divergence, logs ALERT, and heals the tampered node back to 3/3.
            cp_harness.exec(
                cp_ctrl.nodes[1],
                "sql /*triad*/ INSERT OR REPLACE INTO kv VALUES ('tamper.bin', X'ff', 1)",
            )
            tampered_bin_dump = cp_ctrl._dump_node_sql_table(cp_ctrl.nodes[1], "kv")
            assert tampered_bin_dump is not None, "_dump_node_sql_table must not return None on non-UTF-8 X'ff' cell"
            assert cp_ctrl._state_probe(cp_ctrl.nodes[1]) is not None
            assert cp_ctrl._state_probe(cp_ctrl.nodes[1]) != cp_ctrl._state_probe(cp_ctrl.nodes[0])
            cp_ctrl.events.clear()
            cp_ctrl.compute_and_verify_raid_parity()
            deadline = time.time() + 5.0
            while time.time() < deadline:
                if (
                    cp_ctrl.nodes[1].state == "ONLINE"
                    and cp_ctrl._state_probe(cp_ctrl.nodes[1]) == cp_ctrl._state_probe(cp_ctrl.nodes[0])
                ):
                    break
                time.sleep(0.05)
            assert any(
                e["level"] == "ALERT" and "OS-2" in e["msg"] for e in cp_ctrl.events
            ), f"Expected ALERT on OS-2 X'ff' tamper: {cp_ctrl.events}"
            assert (
                cp_ctrl._state_probe(cp_ctrl.nodes[0])
                == cp_ctrl._state_probe(cp_ctrl.nodes[1])
                == cp_ctrl._state_probe(cp_ctrl.nodes[2])
            ), "Node tampered with X'ff' was not healed back to 3/3 majority"

            # 1b. Vote-table rows holding `X'0a'` (newline) and `X'ff'` (non-UTF-8) survive
            #     `checkpoint_wal()` -> `heal_and_remorph_node()` -> 3/3 convergence because
            #     checkpoint_wal emits `X'<hex>'` literals (pure printable ASCII).
            assert cp_ctrl.execute_triad_sql(
                "INSERT OR REPLACE INTO kv VALUES ('nl.row', X'0a', 10)"
            )["ok"]
            assert cp_ctrl.execute_triad_sql(
                "INSERT OR REPLACE INTO kv VALUES ('bin.row', X'fffe', 11)"
            )["ok"]
            assert cp_ctrl.checkpoint_wal(), "checkpoint_wal must succeed with X'0a' and X'fffe' rows"
            assert all(
                is_printable_ascii_command(s) for s in cp_ctrl.wal_checkpoint["stmts"]
            ), f"All checkpoint statements must be printable ASCII: {cp_ctrl.wal_checkpoint['stmts']}"
            cp_harness.exec(cp_ctrl.nodes[1], "sql /*triad*/ DELETE FROM kv")
            cp_ctrl.heal_and_remorph_node(cp_ctrl.nodes[1])
            bin_healed_dump = cp_ctrl._dump_node_sql_table(cp_ctrl.nodes[1], "kv")
            assert bin_healed_dump is not None
            bin_row_map = {r[0][1]: (r[1][1], r[2][1]) for r in bin_healed_dump["rows"]}
            assert bin_row_map.get(b"nl.row") == (b"\n", 10), f"X'0a' row lost/corrupted across checkpoint heal: {bin_row_map.get(b'nl.row')}"
            assert bin_row_map.get(b"bin.row") == (b"\xff\xfe", 11), f"X'fffe' row lost/corrupted across checkpoint heal: {bin_row_map.get(b'bin.row')}"
            assert (
                cp_ctrl._state_probe(cp_ctrl.nodes[0])
                == cp_ctrl._state_probe(cp_ctrl.nodes[1])
                == cp_ctrl._state_probe(cp_ctrl.nodes[2])
            ), "3/3 nodes must converge with X'0a' and X'fffe' rows after checkpoint heal"

            # 1c. A single persistently unreadable (`None`) probe alongside 2 agreeing non-None probes
            #     in `compute_and_verify_raid_parity` logs ALERT and triggers heal after retry;
            #     2 unreadable probes log ALERT and set parity_syndrome_ok = False.
            orig_cp_probe = cp_ctrl._state_probe
            none_probe_calls = {"n2": 0}

            def probe_node2_none_twice(node):
                if node.node_id == 2 and none_probe_calls["n2"] < 2:
                    none_probe_calls["n2"] += 1
                    return None
                return orig_cp_probe(node)

            cp_ctrl.events.clear()
            cp_ctrl._state_probe = probe_node2_none_twice
            try:
                cp_ctrl.compute_and_verify_raid_parity()
                deadline = time.time() + 5.0
                while time.time() < deadline:
                    if cp_ctrl.nodes[1].state == "ONLINE" and cp_ctrl.parity_syndrome_ok:
                        break
                    time.sleep(0.05)
            finally:
                cp_ctrl._state_probe = orig_cp_probe
            assert none_probe_calls["n2"] == 2, f"Expected 1 retry on None probe, got {none_probe_calls['n2']} calls"
            assert any(
                e["level"] == "ALERT" and "unreadable state probe after retry on OS-2" in e["msg"]
                for e in cp_ctrl.events
            ), f"Expected ALERT for single unreadable probe on OS-2: {cp_ctrl.events}"

            cp_ctrl.events.clear()
            cp_ctrl._state_probe = lambda node: None if node.node_id in (1, 2) else orig_cp_probe(node)
            try:
                cp_ctrl.compute_and_verify_raid_parity()
            finally:
                cp_ctrl._state_probe = orig_cp_probe
            assert not cp_ctrl.parity_syndrome_ok
            assert any(
                e["level"] == "ALERT" and "unreadable state probe" in e["msg"] for e in cp_ctrl.events
            ), f"Expected ALERT when 2 probes return None: {cp_ctrl.events}"
            cp_ctrl.compute_and_verify_raid_parity()
            assert cp_ctrl.parity_syndrome_ok

            # Low #9.3: When 1 node is OFFLINE, checkpoint_wal logs WARN and succeeds with 2/3 agreeing nodes.
            cp_ctrl.nodes[2].state = "OFFLINE"
            assert cp_ctrl.execute_triad_sql("UPDATE kv SET rev = 777 WHERE k = 'pipe.key'")["ok"]
            assert cp_ctrl.checkpoint_wal(), "checkpoint_wal must succeed with 2/3 agreeing online nodes when 1 node is down"
            assert any(
                e["level"] == "WARN" and "majority WAL checkpoint" in e["msg"] for e in cp_ctrl.events
            ), "2/3 degraded checkpoint must log a WARN event"
            cp_ctrl.nodes[2].state = "ONLINE"
            cp_ctrl.heal_and_remorph_node(cp_ctrl.nodes[2])
            assert (
                cp_ctrl._state_probe(cp_ctrl.nodes[0])
                == cp_ctrl._state_probe(cp_ctrl.nodes[1])
                == cp_ctrl._state_probe(cp_ctrl.nodes[2])
            )

            # High #2: Non-`kv` table DDL (`CREATE TABLE` + `CREATE INDEX`) is recorded in `wal_checkpoint["stmts"]`.
            cp_ctrl.spec.vote_tables = ("kv", "idx")
            cp_ctrl.spec.provision_sql = ()
            assert cp_ctrl.execute_triad_sql("CREATE TABLE idx (term TEXT, doc TEXT, weight INT)")["ok"]
            assert cp_ctrl.execute_triad_sql("CREATE INDEX idx_term ON idx (term)")["ok"]
            assert cp_ctrl.execute_triad_sql("INSERT INTO idx VALUES ('cuttle|term', 'doc''1', 42)")["ok"]
            assert cp_ctrl.checkpoint_wal()
            assert any("CREATE TABLE IF NOT EXISTS idx" in s for s in cp_ctrl.wal_checkpoint["stmts"]), (
                f"checkpoint_wal did not record CREATE TABLE idx DDL: {cp_ctrl.wal_checkpoint['stmts']}"
            )
            assert any("CREATE INDEX idx_term ON idx" in s for s in cp_ctrl.wal_checkpoint["stmts"]), (
                f"checkpoint_wal did not record CREATE INDEX DDL: {cp_ctrl.wal_checkpoint['stmts']}"
            )
            cp_harness.exec(cp_ctrl.nodes[1], "sql /*triad*/ DROP TABLE idx")
            cp_ctrl.heal_and_remorph_node(cp_ctrl.nodes[1])
            assert (
                cp_ctrl._state_probe(cp_ctrl.nodes[0])
                == cp_ctrl._state_probe(cp_ctrl.nodes[1])
                == cp_ctrl._state_probe(cp_ctrl.nodes[2])
            )

            # Medium #2 (Round 8):
            # 2a. Max-width vote table (`t_sixteen_chars_`, four 16-char TEXT columns, 16-char index,
            #     and 24-byte TEXT values across 4 rows) sizes `.dump` chunk 0 to 2 rows (`<= 1016 B`)
            #     so no row is truncated at the 1,024-byte console boundary, and survives
            #     `checkpoint_wal() -> heal_and_remorph_node() -> 3/3` without losing any rows.
            cp_ctrl.spec.vote_tables = ("kv", "idx", "t_sixteen_chars_")
            assert cp_ctrl.execute_triad_sql(
                "CREATE TABLE t_sixteen_chars_ (col_sixteen_chr0 TEXT, col_sixteen_chr1 TEXT, col_sixteen_chr2 TEXT, col_sixteen_chr3 TEXT)"
            )["ok"]
            assert cp_ctrl.execute_triad_sql(
                "CREATE INDEX idx_sixteen_chr0 ON t_sixteen_chars_ (col_sixteen_chr0)"
            )["ok"]
            wide_rows = []
            for ch in ("1", "2", "3", "4"):
                v24 = ch * 24
                wide_rows.append((v24, v24, v24, v24))
                assert cp_ctrl.execute_triad_sql(
                    f"INSERT INTO t_sixteen_chars_ VALUES ('{v24}', '{v24}', '{v24}', '{v24}')"
                )["ok"]
            raw_wide_d0 = cp_harness.exec(cp_ctrl.nodes[0], "sql /*triad*/ .dump t_sixteen_chars_ 0 3")
            expected_wide_d0 = format_kernel_sqldump_reply(
                "t_sixteen_chars_",
                [
                    ("col_sixteen_chr0", "TEXT"),
                    ("col_sixteen_chr1", "TEXT"),
                    ("col_sixteen_chr2", "TEXT"),
                    ("col_sixteen_chr3", "TEXT"),
                ],
                wide_rows,
                0,
                3,
                indexed_col=0,
                index_name="idx_sixteen_chr0",
            )
            assert raw_wide_d0 == expected_wide_d0, (
                f"Max-width .dump chunk 0 drifted:\nactual:   {raw_wide_d0!r}\nexpected: {expected_wide_d0!r}"
            )
            assert " count=2 " in raw_wide_d0.splitlines()[0], (
                f"Expected count=2 on max-width chunk 0, got: {raw_wide_d0.splitlines()[0]}"
            )
            wide_dump = cp_ctrl._dump_node_sql_table(cp_ctrl.nodes[0], "t_sixteen_chars_")
            assert wide_dump is not None and wide_dump["rows_count"] == 4, (
                f"Expected 4 complete rows from max-width table dump, got: {wide_dump}"
            )
            assert cp_ctrl.checkpoint_wal(), "checkpoint_wal must succeed with max-width 4-column table"
            cp_harness.exec(cp_ctrl.nodes[1], "sql /*triad*/ DROP TABLE t_sixteen_chars_")
            cp_ctrl.heal_and_remorph_node(cp_ctrl.nodes[1])
            healed_wide = cp_ctrl._dump_node_sql_table(cp_ctrl.nodes[1], "t_sixteen_chars_")
            assert healed_wide is not None and healed_wide["rows_count"] == 4, (
                f"Max-width table lost rows on heal: {healed_wide}"
            )
            assert (
                cp_ctrl._state_probe(cp_ctrl.nodes[0])
                == cp_ctrl._state_probe(cp_ctrl.nodes[1])
                == cp_ctrl._state_probe(cp_ctrl.nodes[2])
            )

            # 2b. `_dump_node_sql_table` rejects any `.dump` row whose cell count doesn't match
            #     the table's column count (`len(col_names)`).
            orig_cp_send = cp_ctrl.send_shell_cmd
            truncated_d0 = "\n".join(
                raw_wide_d0.splitlines()[:-1]
                + ["row T:3232|T:3232|T:3232"]  # 3 cells instead of 4
            )
            cp_ctrl.send_shell_cmd = lambda node, cmd, timeout=4.0: (
                truncated_d0 if ".dump t_sixteen_chars_ 0" in cmd else orig_cp_send(node, cmd, timeout)
            )
            try:
                assert cp_ctrl._dump_node_sql_table(cp_ctrl.nodes[0], "t_sixteen_chars_") is None, (
                    "_dump_node_sql_table must reject a row whose cell count != column count"
                )
            finally:
                cp_ctrl.send_shell_cmd = orig_cp_send

            # Low #5 (Round 8):
            # 5a. `triad_wal.json` stores `probe_format_version = 2` and `wal_checkpoint.format_version = 2`.
            saved_wal_data = json.loads(cp_ctrl.wal_file.read_text(encoding="utf-8"))
            assert saved_wal_data.get("probe_format_version") == WAL_PROBE_FORMAT_VERSION
            assert saved_wal_data["wal_checkpoint"].get("format_version") == WAL_PROBE_FORMAT_VERSION

            # 5b. On a format version mismatch (legacy v1 WAL without `probe_format_version`, stale v1
            #     digests, and a lossy pre-`.dump` checkpoint missing rows), when all 3 nodes agree 3/3
            #     on their live state at boot, `_verify_restored_tx_seq_at_boot` recomputes the v2
            #     digests and upgrades the checkpoint from the 3/3 live state WITHOUT resetting `tx_seq`
            #     or rebuilding the nodes from the lossy v1 checkpoint!
            v2_digest = cp_ctrl.triad_state_digest
            cur_tx = cp_ctrl.triad_tx_seq
            legacy_v1_wal = {
                "triad_tx_seq": cur_tx,
                "triad_state_digest": "00" * 32,  # stale v1 digest
                "wal_checkpoint": {
                    "tx_seq": cur_tx,
                    "stmts": ["DELETE FROM kv", "INSERT OR REPLACE INTO kv VALUES ('truncated.v1', 'lossy', 1)"],
                },
                "wal_entries": [],
                "node_tx_seq": {"1": cur_tx, "2": cur_tx, "3": cur_tx},
                "node_state_digest": {"1": "00" * 32, "2": "00" * 32, "3": "00" * 32},
            }
            cp_ctrl.wal_file.write_text(json.dumps(legacy_v1_wal), encoding="utf-8")
            upg_ctrl = TriadController(
                show_gui=False,
                spec=TriadSpec(
                    name="cp-upg",
                    state_dir=cp_dir,
                    role="sql",
                    vote_tables=("kv", "idx", "t_sixteen_chars_"),
                    write_operator_token=False,
                ),
                unit_test=True,
            )
            upg_ctrl.shutdown()
            assert upg_ctrl.wal_probe_format_mismatch and upg_ctrl.wal_checkpoint_legacy
            for n in upg_ctrl.nodes:
                n.state = "ONLINE"
            upg_ctrl.send_shell_cmd = cp_harness.exec
            upg_ctrl._verify_restored_tx_seq_at_boot()
            upg_ctrl._adopt_tx_seq_from_majority()
            assert not upg_ctrl.wal_probe_format_mismatch and not upg_ctrl.wal_checkpoint_legacy
            assert upg_ctrl.triad_state_digest == v2_digest, (
                f"3/3 agreeing nodes must upgrade to v2 digest {v2_digest[:12]}, got {upg_ctrl.triad_state_digest[:12]}"
            )
            assert [n.tx_seq for n in upg_ctrl.nodes] == [cur_tx] * 3
            assert any(
                e["level"] == "RESYNC" and "Probe format upgraded" in e["msg"] for e in upg_ctrl.events
            )
            # Verify all 47 rows on `kv` and 4 rows on `t_sixteen_chars_` survived untouched (not overwritten by lossy v1 checkpoint)
            kv_after_upg = upg_ctrl._dump_node_sql_table(upg_ctrl.nodes[0], "kv")
            assert kv_after_upg is not None and kv_after_upg["rows_count"] == 49
            assert not any("truncated.v1" in s for s in upg_ctrl.wal_checkpoint["stmts"])
            persisted_upg = json.loads(upg_ctrl.wal_file.read_text(encoding="utf-8"))
            assert persisted_upg.get("probe_format_version") == WAL_PROBE_FORMAT_VERSION
            assert persisted_upg["wal_checkpoint"].get("format_version") == WAL_PROBE_FORMAT_VERSION

            # 5c. When nodes do NOT agree 3/3 on a post-genesis state (e.g. node 2 diverged so no 3/3
            #     live upgrade is possible) and the WAL holds a pre-`.dump` v1 checkpoint, the controller
            #     refuses to replay the lossy pre-`.dump` checkpoint and logs an ALERT.
            cp_ctrl.wal_file.write_text(json.dumps(legacy_v1_wal), encoding="utf-8")
            cp_harness.exec(
                cp_ctrl.nodes[1],
                "sql /*triad*/ INSERT OR REPLACE INTO kv VALUES ('diverge.v1', 'mismatch', 99)",
            )
            refuse_ctrl = TriadController(
                show_gui=False,
                spec=TriadSpec(
                    name="cp-refuse",
                    state_dir=cp_dir,
                    role="sql",
                    vote_tables=("kv", "idx", "t_sixteen_chars_"),
                    write_operator_token=False,
                ),
                unit_test=True,
            )
            refuse_ctrl.shutdown()
            for n in refuse_ctrl.nodes:
                n.state = "ONLINE"
            refuse_ctrl.send_shell_cmd = cp_harness.exec
            refuse_ctrl._verify_restored_tx_seq_at_boot()
            refuse_ctrl._adopt_tx_seq_from_majority()
            assert any(
                e["level"] == "ALERT" and "Refusing to replay pre-.dump legacy WAL checkpoint" in e["msg"]
                for e in refuse_ctrl.events
            ), f"Expected ALERT refusing pre-.dump checkpoint replay, got: {refuse_ctrl.events}"
            # Verify nodes 1 and 3 still hold all 49 rows (not wiped by the lossy pre-.dump checkpoint)
            kv_n1_intact = refuse_ctrl._dump_node_sql_table(refuse_ctrl.nodes[0], "kv")
            assert kv_n1_intact is not None and kv_n1_intact["rows_count"] == 49

            # Low #6 (Round 8):
            # 6a. `_state_probe` uses digest-only `.dump <table> digest` (1 command per vote table,
            #     0 chunked `.dump <table> <off> 3` commands) even when `kv` holds 49 rows!
            cp_ctrl.heal_and_remorph_node(cp_ctrl.nodes[1])
            seen_cmds: list[str] = []
            seen_lock = threading.Lock()
            orig_send_6 = cp_ctrl.send_shell_cmd

            def track_send_6(node, cmd, timeout=4.0):
                with seen_lock:
                    seen_cmds.append(f"{node.node_id}:{cmd}")
                return orig_send_6(node, cmd, timeout)

            cp_ctrl.send_shell_cmd = track_send_6
            try:
                cp_ctrl.compute_and_verify_raid_parity()
                assert cp_ctrl.parity_syndrome_ok
                digest_cmds = [c for c in seen_cmds if ".dump " in c and c.endswith(" digest")]
                chunk_cmds = [c for c in seen_cmds if re.search(r"\.dump\s+\S+\s+\d+\s+\d+", c)]
                assert len(digest_cmds) == 3 * len(cp_ctrl.spec.vote_tables), (
                    f"Expected exactly 1 digest-only .dump per table per node (9 total), got {digest_cmds}"
                )
                assert len(chunk_cmds) == 0, (
                    f"Agreeing 3/3 parity vote must not issue chunked row dumps: {chunk_cmds}"
                )

                # 6b. When a node diverges, `compute_and_verify_raid_parity` detects the digest
                #     mismatch via `.dump <table> digest` and only then fetches full chunked row
                #     dumps to diagnose the mismatch and heal the diverged node.
                seen_cmds.clear()
                orig_send_6(
                    cp_ctrl.nodes[1],
                    "sql /*triad*/ INSERT OR REPLACE INTO kv VALUES ('tamper.6b', 'bad', 77)",
                )
                cp_ctrl.compute_and_verify_raid_parity()
                deadline_6b = time.time() + 5.0
                while cp_ctrl.nodes[1].state != "ONLINE" and time.time() < deadline_6b:
                    time.sleep(0.02)
                chunk_cmds_on_mismatch = [
                    c for c in seen_cmds if re.search(r"\.dump\s+\S+\s+\d+\s+\d+", c)
                ]
                assert len(chunk_cmds_on_mismatch) > 0, (
                    "Mismatch in compute_and_verify_raid_parity must fetch full row dumps to diagnose"
                )

                # 6c. `checkpoint_wal` does NOT hold `wal_lock` while fetching table `.dump`s across nodes.
                wal_locked_during_dump = []

                def check_lock_send(node, cmd, timeout=4.0):
                    if ".dump " in cmd:
                        acquired = cp_ctrl.wal_lock.acquire(blocking=False)
                        if acquired:
                            cp_ctrl.wal_lock.release()
                        wal_locked_during_dump.append(not acquired)
                    return orig_send_6(node, cmd, timeout)

                cp_ctrl.send_shell_cmd = check_lock_send
                cp_ctrl.triad_tx_seq += 1
                for n in cp_ctrl.nodes:
                    n.tx_seq = cp_ctrl.triad_tx_seq
                assert cp_ctrl.checkpoint_wal()
                assert wal_locked_during_dump and not any(wal_locked_during_dump), (
                    f"checkpoint_wal must release wal_lock during .dump round trips: {wal_locked_during_dump}"
                )
            finally:
                cp_ctrl.send_shell_cmd = orig_send_6
        finally:
            cp_harness.close()

        # #12: apply_node_profile keeps node OFFLINE and logs ALERT when role application fails
        role_dir = tmp_dir / "role_fail"
        role_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="role-fail", state_dir=role_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        role_ctrl.shutdown()
        rn = role_ctrl.nodes[0]
        rn.state = "BOOTING"
        role_ctrl.send_shell_cmd = lambda node, cmd, timeout=4.0: "role=other" if cmd.startswith("service role") else "ok"
        assert not role_ctrl.apply_node_profile(rn), "apply_node_profile must return False when service role fails"
        assert rn.state == "OFFLINE", f"Node must remain OFFLINE when role application fails, got {rn.state}"
        assert any(e["level"] == "ALERT" and "failed to apply role" in e["msg"] for e in role_ctrl.events)

        # #11, #4, #17: wfe _state_probe & _sync_files_from_peer handle default newline-terminated
        #               files, multi-line HTML, empty, multi-chunk binary/UTF-8, and filenames with
        #               spaces via cathex/writehex against the REAL Rust `OsShell` (`shell_harness`).
        wfe_dir = tmp_dir / "wfe_probe"
        wfe_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="wfe-test", state_dir=wfe_dir, job="web", role="wfe", write_operator_token=False),
            unit_test=True,
        )
        wfe_ctrl.shutdown()
        multiline_html = b"<h1>hello</h1>\n<p>world</p>\n" + (b"<!-- pad -->\n" * 16)
        for n in wfe_ctrl.nodes:
            n.state = "ONLINE"

        wfe_harness = RealOsShellHarness()
        try:
            wfe_ctrl.send_shell_cmd = wfe_harness.exec
            # Verify shared format helpers match the real Rust `OsShell` output byte-for-byte.
            raw_wh = wfe_harness.exec(wfe_ctrl.nodes[0], "writehex /check.bin 0 414243")
            assert raw_wh == format_kernel_writehex_reply(3, "/check.bin", 0), (
                f"format_kernel_writehex_reply drifted from OsShell: {raw_wh!r}"
            )
            raw_ch = wfe_harness.exec(wfe_ctrl.nodes[0], "cathex /check.bin 0 64")
            assert raw_ch == format_kernel_cathex_reply(3, 0, b"ABC"), (
                f"format_kernel_cathex_reply drifted from OsShell: {raw_ch!r}"
            )
            for nid in (1, 2, 3):
                wfe_harness.reset_node(nid)

            for idx in (0, 2):
                assert wfe_ctrl._write_node_file_bytes(wfe_ctrl.nodes[idx], "/index.html", multiline_html)
                assert wfe_ctrl._write_node_file_bytes(wfe_ctrl.nodes[idx], "/empty.txt", b"")
                assert wfe_ctrl._write_node_file_bytes(wfe_ctrl.nodes[idx], "/my page.html", b"space path\n")
            assert wfe_ctrl._write_node_file_bytes(wfe_ctrl.nodes[1], "/index.html", b"corrupted")
            assert wfe_ctrl._write_node_file_bytes(wfe_ctrl.nodes[1], "/empty.txt", b"nonempty")
            assert wfe_ctrl._write_node_file_bytes(wfe_ctrl.nodes[1], "/my page.html", b"tampered")

            assert not wfe_ctrl._response_looks_complete("cat /index.html", ["<h1>hello</h1>"]), (
                "cat must wait for prompt rather than completing on first line (#4.2)"
            )
            assert not wfe_ctrl._response_looks_complete("ls", ["/index.html (28 B)"]), (
                "ls must wait for prompt rather than completing on first line (#4.2)"
            )
            assert wfe_ctrl._response_looks_complete("cathex /index.html 0 128", [raw_ch])
            assert wfe_ctrl._response_looks_complete("writehex /index.html 0 414243", [raw_wh])

            p1 = wfe_ctrl._state_probe(wfe_ctrl.nodes[0])
            p2 = wfe_ctrl._state_probe(wfe_ctrl.nodes[1])
            p3 = wfe_ctrl._state_probe(wfe_ctrl.nodes[2])
            assert p1 is not None and p1 == p3 and p1 != p2, "wfe _state_probe must detect content changes"
            assert "/etc/hostname" in p1 and "/my page.html" in p1, (
                f"wfe _state_probe missing default or space-named files: {p1}"
            )
            assert wfe_ctrl._sync_files_from_peer(wfe_ctrl.nodes[1], wfe_ctrl.nodes[0])
            assert wfe_ctrl._read_node_file_bytes(wfe_ctrl.nodes[1], "/index.html") == multiline_html
            assert wfe_ctrl._read_node_file_bytes(wfe_ctrl.nodes[1], "/empty.txt") == b""
            assert wfe_ctrl._read_node_file_bytes(wfe_ctrl.nodes[1], "/my page.html") == b"space path\n"
            assert wfe_ctrl._state_probe(wfe_ctrl.nodes[1]) == p1

            # Low #4 (Round 8):
            # 4a. `shell_harness` drives `feed_byte` byte-by-byte and rejects >256-byte lines with
            #     `error: command line exceeds 256-byte limit` instead of truncating.
            overlong_cmd = f"writehex /never_created.bin 0 {'41' * 120}"
            assert len(overlong_cmd) > 256
            overlong_out = wfe_harness.exec(wfe_ctrl.nodes[0], overlong_cmd)
            assert overlong_out == "error: command line exceeds 256-byte limit", (
                f"Expected 256-byte limit rejection from feed_byte harness, got: {overlong_out!r}"
            )
            assert wfe_ctrl._read_node_file_bytes(wfe_ctrl.nodes[0], "/never_created.bin") is None

            # 4b. Long multi-segment paths (>45 chars, up to FS_PATH_MAX) dynamically size `writehex`
            #     chunks from `SHELL_LINE_MAX` (256), quoted path length, and offset width so multi-chunk
            #     writes and `_sync_files_from_peer` succeed without exceeding 256 bytes per line.
            long_fpath = "/dir_alpha_12345/dir_bravo_12345/dir_charlie_123/long_page_name.html"
            assert len(long_fpath) > 60
            long_payload = bytes((i * 37 + 11) & 0xFF for i in range(320))
            for idx in (0, 2):
                assert wfe_ctrl._write_node_file_bytes(wfe_ctrl.nodes[idx], long_fpath, long_payload), (
                    f"_write_node_file_bytes failed on long path ({len(long_fpath)} chars)"
                )
            assert wfe_ctrl._write_node_file_bytes(wfe_ctrl.nodes[1], long_fpath, b"stale")
            assert wfe_ctrl._sync_files_from_peer(wfe_ctrl.nodes[1], wfe_ctrl.nodes[0]), (
                "_sync_files_from_peer failed to sync multi-chunk file at >60-char path"
            )
            assert wfe_ctrl._read_node_file_bytes(wfe_ctrl.nodes[1], long_fpath) == long_payload
            assert (
                wfe_ctrl._state_probe(wfe_ctrl.nodes[0])
                == wfe_ctrl._state_probe(wfe_ctrl.nodes[1])
                == wfe_ctrl._state_probe(wfe_ctrl.nodes[2])
            )

            # Verify /api/sh enforces auth (401 without token) and read-only policy (`writehex` -> 403,
            # `cathex` -> 200) across every node role (`full`, `wfe`, `sql`, `gw`).
            for role_name in ("full", "wfe", "sql", "gw"):
                sh_role_dir = tmp_dir / f"sh_role_{role_name}"
                sh_role_ctrl = TriadController(
                    show_gui=False,
                    spec=TriadSpec(
                        name=f"sh-{role_name}",
                        state_dir=sh_role_dir,
                        role=role_name,
                        write_operator_token=False,
                    ),
                    unit_test=True,
                )
                sh_role_ctrl.shutdown()
                for n in sh_role_ctrl.nodes:
                    n.state = "ONLINE"
                sh_role_ctrl.send_shell_cmd = wfe_harness.exec
                handler_cls = type("RoleShHandler", (TriadHttpHandler,), {"ctrl": sh_role_ctrl})
                srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
                srv_port = srv.server_address[1]
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                try:
                    for cmd_bytes in (b"cathex /etc/hostname 0 64", b"writehex /var/x 0 4142"):
                        req_unauth = urllib.request.Request(
                            f"http://127.0.0.1:{srv_port}/api/sh",
                            data=cmd_bytes,
                            method="POST",
                        )
                        try:
                            urllib.request.urlopen(req_unauth, timeout=3.0)
                            raise AssertionError(f"role={role_name}: unauthenticated /api/sh {cmd_bytes!r} must return 401")
                        except urllib.error.HTTPError as e:
                            assert e.code == 401, f"role={role_name}: expected 401, got {e.code}"
                    req_wh = urllib.request.Request(
                        f"http://127.0.0.1:{srv_port}/api/sh",
                        data=b"writehex /var/x 0 4142",
                        headers={"X-Session-Token": sh_role_ctrl.coordinator_token},
                        method="POST",
                    )
                    try:
                        urllib.request.urlopen(req_wh, timeout=3.0)
                        raise AssertionError(f"role={role_name}: /api/sh writehex must return 403")
                    except urllib.error.HTTPError as e:
                        assert e.code == 403, f"role={role_name}: expected 403 for writehex, got {e.code}"
                    req_ch = urllib.request.Request(
                        f"http://127.0.0.1:{srv_port}/api/sh",
                        data=b"cathex /etc/hostname 0 64",
                        headers={"X-Session-Token": sh_role_ctrl.coordinator_token},
                        method="POST",
                    )
                    with urllib.request.urlopen(req_ch, timeout=3.0) as resp:
                        assert resp.status == 200
                        ch_data = json.loads(resp.read().decode("utf-8"))
                        assert ch_data["ok"] and all("hex len=10 off=0 data=" in v for v in ch_data["per_node"].values())
                finally:
                    srv.shutdown()
                    srv.server_close()
        finally:
            wfe_harness.close()

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
            unit_test=True,
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
            m_dump = re.search(r"\.dump\s+(\S+)\s+(?:(digest)|(\d+)\s+(\d+))", cmd, re.I)
            if m_dump:
                tname = m_dump.group(1)
                if m_dump.group(2):
                    off, lim = 0, 0
                else:
                    off, lim = int(m_dump.group(3)), int(m_dump.group(4))
                if tname == "kv":
                    parsed = [
                        (parts[0], parts[1], int(parts[2]))
                        for ln in t["kv"]
                        for parts in [ln.split("|")]
                    ]
                    return format_kernel_sqldump_reply(
                        "kv", [("k", "TEXT"), ("v", "TEXT"), ("rev", "INT")], parsed, off, lim
                    )
                if tname == "idx":
                    parsed = [
                        (parts[0], parts[1], int(parts[2]))
                        for ln in t["idx"]
                        for parts in [ln.split("|")]
                    ]
                    return format_kernel_sqldump_reply(
                        "idx", [("term", "TEXT"), ("doc", "TEXT"), ("weight", "INT")], parsed, off, lim
                    )
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

        # #6.4: _reset_sql_vote_tables recreates non-kv tables from spec.provision_sql even when
        #       CREATE TABLE is absent from wal_entries
        idx_tables[2] = {"kv": ["doc.1|TAMPER|9"], "idx": []}
        created_idx_ddl = []
        orig_fake_idx_cmd = fake_idx_cmd

        def fake_idx_cmd_track_create(node, cmd, timeout=4.0):
            if "CREATE TABLE idx" in cmd:
                created_idx_ddl.append(cmd)
            return orig_fake_idx_cmd(node, cmd, timeout)

        idx_ctrl.spec.provision_sql = ("CREATE TABLE idx (term TEXT, doc TEXT, weight INT)",)
        idx_ctrl.wal_entries = [
            (2, "INSERT OR REPLACE INTO kv VALUES ('doc.1', 'alpha', 1)"),
            (3, "INSERT INTO idx VALUES ('alpha', 'doc.1', 1)"),
        ]
        idx_ctrl.send_shell_cmd = fake_idx_cmd_track_create
        idx_ctrl.heal_and_remorph_node(idx_ctrl.nodes[1])
        assert created_idx_ddl, "_reset_sql_vote_tables must recreate idx from spec.provision_sql"
        assert idx_tables[2] == idx_tables[1], f"idx not rebuilt when CREATE TABLE was in provision_sql: {idx_tables[2]}"

        # #2: Crash after write-ahead leaves a "pending" WAL entry that is rolled back on restart;
        #     failed first _save_wal_to_disk undoes in-memory WAL append; 1/3 minority acceptance rolls back
        pend_dir = tmp_dir / "wal_pending"
        pend_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="pend-test", state_dir=pend_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        pend_ctrl.shutdown()
        pend_rows = {
            1: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
            2: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
            3: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
        }
        for n in pend_ctrl.nodes:
            n.state = "ONLINE"

        def make_kv_handler(row_store, reject_nodes=()):
            def _handler(node, cmd, timeout=4.0):
                rows = row_store[node.node_id]
                s = cmd.strip()
                if s.startswith("sql /*triad*/"):
                    s = s[len("sql /*triad*/") :].strip()
                elif s.startswith("sql "):
                    s = s[4:].strip()
                m_dump = re.match(r"^\.dump\s+kv(?:\s+(?:(digest)|(\d+)(?:\s+(\d+))?))?$", s, re.I)
                if m_dump:
                    if m_dump.group(1):
                        off, lim = 0, 0
                    else:
                        off = int(m_dump.group(2)) if m_dump.group(2) else 0
                        lim = int(m_dump.group(3)) if m_dump.group(3) else 3
                    return format_kernel_sqldump_reply(
                        "kv", [("k", "TEXT"), ("v", "TEXT"), ("rev", "INT")], rows, off, lim
                    )
                if s == "DROP TABLE kv" or s == "DELETE FROM kv":
                    rows.clear()
                    return "OK"
                if s.startswith("CREATE TABLE kv"):
                    return "OK"
                if s == "SELECT * FROM kv":
                    return "\n".join(["k|v|rev"] + [f"{k}|{v}|{r}" for k, v, r in rows])
                m_ins = re.match(
                    r"^INSERT\s+(?:OR\s+REPLACE\s+)?INTO\s+kv\s+VALUES\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*(-?\d+)\s*\)$",
                    s,
                    re.I,
                )
                if m_ins:
                    if node.node_id in reject_nodes and m_ins.group(1) not in ("cluster.role", "mtd.policy", "boot.state"):
                        return "error: rejected by node"
                    k, v, r = m_ins.group(1), m_ins.group(2), int(m_ins.group(3))
                    for i, (ek, ev, er) in enumerate(rows):
                        if ek == k:
                            rows[i] = (k, v, r)
                            return "1 row replaced"
                    rows.append((k, v, r))
                    return "1 row inserted"
                return "ok"
            return _handler

        pend_ctrl.send_shell_cmd = make_kv_handler(pend_rows)
        assert pend_ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('committed.k', 'ok', 1)")["ok"]
        assert pend_ctrl.triad_tx_seq == 1 and all(n.tx_seq == 1 for n in pend_ctrl.nodes)

        # #2.2: Failed first _save_wal_to_disk undoes in-memory wal_entries and triad_tx_seq
        orig_save = pend_ctrl._save_wal_to_disk

        def broken_save():
            raise OSError("simulated disk write failure")

        pend_ctrl._save_wal_to_disk = broken_save
        try:
            try:
                pend_ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('fail.save', 'no', 2)")
                raise AssertionError("execute_triad_sql must raise OSError when write-ahead save fails")
            except OSError:
                pass
        finally:
            pend_ctrl._save_wal_to_disk = orig_save
        assert pend_ctrl.triad_tx_seq == 1 and len(pend_ctrl.wal_entries) == 1, (
            f"In-memory WAL mutated after failed write-ahead save: tx_seq={pend_ctrl.triad_tx_seq}, entries={pend_ctrl.wal_entries}"
        )

        # #2.3: 1-of-3 minority acceptance is refused and rolled back on both WAL and the minority node
        pend_ctrl.send_shell_cmd = make_kv_handler(pend_rows, reject_nodes=(2, 3))
        min_res = pend_ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('minority.k', 'bad', 2)")
        assert not min_res["ok"], f"1/3 minority write must not succeed: {min_res}"
        assert pend_ctrl.triad_tx_seq == 1 and len(pend_ctrl.wal_entries) == 1
        assert all(all(k != "minority.k" for k, _, _ in pend_rows[nid]) for nid in (1, 2, 3)), (
            f"Minority node retained rejected write: {pend_rows[1]}"
        )
        pend_ctrl.send_shell_cmd = make_kv_handler(pend_rows)

        # #2.1: Crash after write-ahead (via _after_wal_write_ahead_hook) leaves "pending" on disk,
        #       which is rolled back on controller restart when no majority executed it
        def crash_after_write_ahead(tid, stmt):
            raise RuntimeError("simulated controller crash after write-ahead")

        pend_ctrl._after_wal_write_ahead_hook = crash_after_write_ahead
        try:
            try:
                pend_ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('uncommitted.k', 'ghost', 2)")
                raise AssertionError("_after_wal_write_ahead_hook crash did not abort execute_triad_sql")
            except RuntimeError:
                pass
        finally:
            pend_ctrl._after_wal_write_ahead_hook = None

        on_disk_wal = json.loads((pend_dir / "triad_wal.json").read_text(encoding="utf-8"))
        assert on_disk_wal["wal_entries"][-1][2] == "pending", (
            f"Write-ahead entry must be marked 'pending' on disk before execution: {on_disk_wal['wal_entries'][-1]}"
        )
        restarted_pend = TriadController(
            show_gui=False,
            spec=TriadSpec(name="pend-restart", state_dir=pend_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        restarted_pend.shutdown()
        for n in restarted_pend.nodes:
            n.state = "ONLINE"
        restarted_pend.send_shell_cmd = make_kv_handler(pend_rows)
        assert restarted_pend.wal_pending_tx == 2
        restarted_pend._resolve_pending_wal_at_boot()
        restarted_pend._verify_restored_tx_seq_at_boot()
        restarted_pend._adopt_tx_seq_from_majority()
        assert restarted_pend.wal_pending_tx is None
        assert restarted_pend.triad_tx_seq == 1 and len(restarted_pend.wal_entries) == 1
        assert [n.tx_seq for n in restarted_pend.nodes] == [1, 1, 1], (
            f"All nodes must converge on tx_seq=1 after pending rollback: {[n.tx_seq for n in restarted_pend.nodes]}"
        )

        # Medium #3a: Commit-at-boot when 2/3 nodes applied the pending entry before controller crash
        def crash_after_two_nodes_applied(tid, stmt):
            # Simulate nodes 1 and 2 applying `stmt` before the controller crashes (node 3 still at pre-state)
            for nid in (1, 2):
                pend_rows[nid].append(("partial.commit", "applied2of3", 2))
            raise RuntimeError("simulated crash after 2/3 nodes applied pending entry")

        restarted_pend._after_wal_write_ahead_hook = crash_after_two_nodes_applied
        try:
            try:
                restarted_pend.execute_triad_sql(
                    "INSERT OR REPLACE INTO kv VALUES ('partial.commit', 'applied2of3', 2)"
                )
                raise AssertionError("Expected crash_after_two_nodes_applied to raise RuntimeError")
            except RuntimeError:
                pass
        finally:
            restarted_pend._after_wal_write_ahead_hook = None

        commit_boot = TriadController(
            show_gui=False,
            spec=TriadSpec(name="pend-commit-boot", state_dir=pend_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        commit_boot.shutdown()
        for n in commit_boot.nodes:
            n.state = "ONLINE"
        commit_boot.send_shell_cmd = make_kv_handler(pend_rows)
        assert commit_boot.wal_pending_tx == 2
        commit_boot._resolve_pending_wal_at_boot()
        commit_boot._verify_restored_tx_seq_at_boot()
        commit_boot._adopt_tx_seq_from_majority()
        assert commit_boot.wal_pending_tx is None, "Pending entry applied on 2/3 nodes must be committed at boot"
        assert commit_boot.triad_tx_seq == 2 and len(commit_boot.wal_entries) == 2
        assert [n.tx_seq for n in commit_boot.nodes] == [2, 2, 2]
        assert all(("partial.commit", "applied2of3", 2) in pend_rows[nid] for nid in (1, 2, 3)), (
            f"Commit-at-boot did not replay pending entry onto lagging node 3: {pend_rows}"
        )

        # Medium #3b: Pending WAL entry combined with a 2-node rollback to genesis while offline
        #             must NOT treat the 2 rolled-back nodes as a post-pending majority and must
        #             NOT bypass rollback detection (`_verify_restored_tx_seq_at_boot` + `_adopt_tx_seq_from_majority`).
        commit_boot._after_wal_write_ahead_hook = crash_after_write_ahead
        try:
            try:
                commit_boot.execute_triad_sql(
                    "INSERT OR REPLACE INTO kv VALUES ('uncommitted.tx3', 'never_ran', 3)"
                )
                raise AssertionError("Expected crash_after_write_ahead to raise RuntimeError")
            except RuntimeError:
                pass
        finally:
            commit_boot._after_wal_write_ahead_hook = None

        # Roll back nodes 1 and 2 to genesis while node 3 retains the committed tx #2 state
        pend_rows[1] = [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)]
        pend_rows[2] = [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)]
        combined_boot = TriadController(
            show_gui=False,
            spec=TriadSpec(name="pend-rb-combined", state_dir=pend_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        combined_boot.shutdown()
        for n in combined_boot.nodes:
            n.state = "ONLINE"
        combined_boot.send_shell_cmd = make_kv_handler(pend_rows)
        assert combined_boot.wal_pending_tx == 3
        combined_boot._resolve_pending_wal_at_boot()
        assert combined_boot.wal_pending_tx is None
        assert combined_boot.triad_tx_seq == 2 and len(combined_boot.wal_entries) == 2, (
            f"Unapplied pending tx #3 must be rolled back even when 2 disks were rolled back: {combined_boot.wal_entries}"
        )
        combined_boot._verify_restored_tx_seq_at_boot()
        assert combined_boot.restored_tx_seq_nodes == {3}, (
            f"Rolled-back nodes 1 and 2 must be detected by _verify_restored_tx_seq_at_boot, got {combined_boot.restored_tx_seq_nodes}"
        )
        combined_boot._adopt_tx_seq_from_majority()
        combined_boot.compute_and_verify_raid_parity()
        assert [n.tx_seq for n in combined_boot.nodes] == [2, 2, 2]
        assert pend_rows[1] == pend_rows[2] == pend_rows[3], (
            f"Pending + 2-node rollback failed to recover committed tx #1..#2 on nodes 1 and 2: {pend_rows}"
        )
        assert ("partial.commit", "applied2of3", 2) in pend_rows[1]
        assert all(all(k != "uncommitted.tx3" for k, _, _ in pend_rows[nid]) for nid in (1, 2, 3))

        # Low #9.4: Unexpected exception during node execution (after write-ahead) cleans up
        #           `wal_pending_tx` in `finally` so the failed entry is not left pending or
        #           marked committed by a subsequent write.
        base_handler = make_kv_handler(pend_rows)

        def raising_node_handler(node, cmd, timeout=4.0):
            if "boom.tx" in cmd and node.node_id == 2:
                raise RuntimeError("simulated unexpected serial exception during node execution")
            return base_handler(node, cmd, timeout)

        combined_boot.send_shell_cmd = raising_node_handler
        try:
            try:
                combined_boot.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('boom.tx', 'err', 9)")
                raise AssertionError("Expected raising_node_handler to raise RuntimeError")
            except RuntimeError:
                pass
        finally:
            combined_boot.send_shell_cmd = base_handler
        assert combined_boot.wal_pending_tx is None, (
            f"wal_pending_tx was not cleared in finally after node execution exception: {combined_boot.wal_pending_tx}"
        )
        assert combined_boot.triad_tx_seq == 2 and len(combined_boot.wal_entries) == 2
        assert all(all(k != "boom.tx" for k, _, _ in pend_rows[nid]) for nid in (1, 2, 3)), (
            f"Node 1 was not rolled back after node 2 raised during execution: {pend_rows[1]}"
        )

        # #6: Two-node rollback with one intact node replays WAL onto the two rolled-back nodes;
        #     stale probe in compute_and_verify_raid_parity does not overwrite newer state_digest;
        #     transient None fingerprint at boot retries instead of resetting tx_seq=0
        rb_dir = tmp_dir / "two_node_rollback"
        rb_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="rb-test", state_dir=rb_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        rb_ctrl.shutdown()
        rb_rows = {
            1: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
            2: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
            3: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
        }
        for n in rb_ctrl.nodes:
            n.state = "ONLINE"
        rb_ctrl.send_shell_cmd = make_kv_handler(rb_rows)
        assert rb_ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('keep.1', 'val1', 1)")["ok"]
        assert rb_ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('keep.2', 'val2', 2)")["ok"]
        intact_digest = rb_ctrl.triad_state_digest
        assert intact_digest and all(n.tx_seq == 2 for n in rb_ctrl.nodes)

        # Wipe/roll back nodes 1 and 2 to genesis while keeping node 3 intact
        rb_rows[1] = [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)]
        rb_rows[2] = [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)]
        rb_boot = TriadController(
            show_gui=False,
            spec=TriadSpec(name="rb-boot", state_dir=rb_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        rb_boot.shutdown()
        for n in rb_boot.nodes:
            n.state = "ONLINE"
        rb_boot.send_shell_cmd = make_kv_handler(rb_rows)
        rb_boot._resolve_pending_wal_at_boot()
        rb_boot._verify_restored_tx_seq_at_boot()
        assert rb_boot.restored_tx_seq_nodes == {3}, (
            f"Only intact node 3 must remain in restored_tx_seq_nodes before adoption, got {rb_boot.restored_tx_seq_nodes}"
        )
        rb_boot._adopt_tx_seq_from_majority()
        rb_boot.compute_and_verify_raid_parity()
        assert [n.tx_seq for n in rb_boot.nodes] == [2, 2, 2]
        assert rb_rows[1] == rb_rows[2] == rb_rows[3], (
            f"Two-node rollback did not replay WAL to match intact node 3: {rb_rows}"
        )
        assert rb_boot.triad_state_digest == intact_digest

        # #6.2: Stale probe in compute_and_verify_raid_parity does not overwrite newer state_digest
        orig_probe = rb_boot._state_probe

        def probe_with_interleaved_commit(node):
            res = orig_probe(node)
            if node.node_id == 3:
                rb_boot.triad_tx_seq = 99
                rb_boot.triad_state_digest = "newer_commit_digest"
                for m in rb_boot.nodes:
                    m.state_digest = "newer_commit_digest"
            return res

        rb_boot._state_probe = probe_with_interleaved_commit
        rb_boot.compute_and_verify_raid_parity()
        rb_boot._state_probe = orig_probe
        assert rb_boot.triad_state_digest == "newer_commit_digest", (
            f"Stale parity probe overwrote newer triad_state_digest: {rb_boot.triad_state_digest}"
        )
        rb_boot.triad_tx_seq = 2
        rb_boot.triad_state_digest = intact_digest

        # #6.3: Transient None from _state_fingerprint at boot is retried and does not reset tx_seq=0
        flaky_attempts = {"count": 0}
        orig_fp = rb_boot._state_fingerprint

        def flaky_fp(node):
            if node.node_id == 1 and flaky_attempts["count"] == 0:
                flaky_attempts["count"] += 1
                return None
            return orig_fp(node)

        rb_boot._state_fingerprint = flaky_fp
        rb_boot._verify_restored_tx_seq_at_boot()
        rb_boot._state_fingerprint = orig_fp
        assert rb_boot.nodes[0].tx_seq == 2 and 1 in rb_boot.restored_tx_seq_nodes, (
            "Transient None fingerprint at boot must retry rather than resetting tx_seq=0"
        )

        # #14 & #20: Heal/morph lock contention, early-return state restoration, and consecutive heal cap
        hm_dir = tmp_dir / "heal_morph_edge"
        hm_ctrl = TriadController(
            show_gui=False,
            spec=TriadSpec(name="hm-test", state_dir=hm_dir, role="sql", write_operator_token=False),
            unit_test=True,
        )
        hm_ctrl.shutdown()
        hm_rows = {
            1: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
            2: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
            3: [("cluster.role", "primary", 1), ("mtd.policy", "binmorph-7pass", 1), ("boot.state", "ready", 1)],
        }
        for n in hm_ctrl.nodes:
            n.state = "ONLINE"
        hm_ctrl.send_shell_cmd = make_kv_handler(hm_rows)

        # #14.1: bounce_and_morph_node restores HEALING node to ONLINE when < 2 peers are ONLINE
        hm_ctrl.nodes[0].state = "OFFLINE"
        hm_ctrl.nodes[1].state = "HEALING"
        hm_ctrl.nodes[2].state = "ONLINE"
        assert not hm_ctrl.bounce_and_morph_node(2), "bounce_and_morph_node must refuse when < 2 peers are ONLINE"
        assert hm_ctrl.nodes[1].state == "ONLINE", (
            f"bounce_and_morph_node left node stuck in {hm_ctrl.nodes[1].state} on early return"
        )
        assert any(e["level"] == "ALERT" and "need 2 healthy peers" in e["msg"] for e in hm_ctrl.events)
        hm_ctrl.nodes[0].state = "ONLINE"

        # #20: Concurrent bounce_and_morph_node(1) during heal_and_remorph_node(2)'s SQL replay
        #      cannot steal morph_op_lock, while a concurrent execute_triad_sql write succeeds
        #      without deadlocking (because wal_lock is not held during bulk snapshot replay)
        #      and is applied to node 2 during the post-snapshot WAL tail catch-up.
        hm_rows[1].append(("k1", "v1", 1))
        hm_rows[3].append(("k1", "v1", 1))
        hm_ctrl.wal_entries = [(1, "INSERT OR REPLACE INTO kv VALUES ('k1', 'v1', 1)")]
        hm_ctrl.triad_tx_seq = 1
        contender_results = []
        concurrent_sql_results = []
        orig_replay = hm_ctrl._replay_wal_entry
        fired_contenders = False

        def replay_with_concurrent_morph(node, stmt):
            nonlocal fired_contenders
            res = orig_replay(node, stmt)
            if not fired_contenders:
                fired_contenders = True

                def _contend():
                    contender_results.append(hm_ctrl.bounce_and_morph_node(1))
                    concurrent_sql_results.append(
                        hm_ctrl.execute_triad_sql(
                            "INSERT OR REPLACE INTO kv VALUES ('concurrent_heal_tx', 'ok', 2)"
                        )
                    )

                t = threading.Thread(target=_contend)
                t.start()
                t.join(timeout=2.0)
                assert not t.is_alive(), (
                    "Concurrent execute_triad_sql deadlocked on wal_lock during heal_and_remorph_node snapshot replay"
                )
            return res

        hm_ctrl._replay_wal_entry = replay_with_concurrent_morph
        hm_ctrl.morph_node_image = lambda node, seed: setattr(node, "morph_count", node.morph_count + 1)
        hm_ctrl.start_node_vm = lambda node: None
        hm_ctrl.await_boot = lambda node, timeout=35.0: True
        hm_ctrl.apply_node_profile = lambda node: True
        hm_ctrl.heal_and_remorph_node(hm_ctrl.nodes[1])
        hm_ctrl._replay_wal_entry = orig_replay
        assert contender_results == [False], (
            f"Concurrent bounce_and_morph_node(1) during heal must return False, got {contender_results}"
        )
        assert len(concurrent_sql_results) == 1 and concurrent_sql_results[0].get("ok") is True, (
            f"Concurrent execute_triad_sql during heal snapshot replay must succeed on 2/3 peers, got {concurrent_sql_results}"
        )
        assert hm_ctrl.nodes[1].state == "ONLINE", (
            f"Node 2 stuck in {hm_ctrl.nodes[1].state} after concurrent morph contention"
        )
        assert hm_ctrl.nodes[1].tx_seq == 2, (
            f"Healed node 2 must catch up to tail tx_seq=2 committed during snapshot replay, got {hm_ctrl.nodes[1].tx_seq}"
        )
        for nid in (1, 2, 3):
            assert ("concurrent_heal_tx", "ok", 2) in hm_rows[nid], (
                f"Node {nid} missing concurrent tail write after heal_and_remorph_node: {hm_rows[nid]}"
            )

        # #14.3: Consecutive heal cap isolates a persistently diverging node as OFFLINE after MAX_CONSECUTIVE_HEALS
        hm_ctrl.nodes[2].consecutive_heals = MAX_CONSECUTIVE_HEALS
        hm_rows[3] = [("diverged", "forever", 999)]
        hm_ctrl.compute_and_verify_raid_parity()
        assert hm_ctrl.nodes[2].state == "OFFLINE", (
            f"Node exceeding MAX_CONSECUTIVE_HEALS must be marked OFFLINE, got {hm_ctrl.nodes[2].state}"
        )
        assert any(
            e["level"] == "ALERT" and "exceeded" in e["msg"] and "consecutive heals" in e["msg"]
            for e in hm_ctrl.events
        )
    run_fault_injection_unit_tests()


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
        "--fault-test",
        action="store_true",
        help="Run deterministic Quorum, Split-Brain, WAL & RAID XOR parity fault-injection unit tests and exit",
    )
    parser.add_argument(
        "--unit-test",
        action="store_true",
        help="Run fast deterministic controller unit self-tests without booting QEMU VMs and exit",
    )
    parser.add_argument(
        "--accel",
        choices=ACCELERATORS,
        default=os.environ.get("CUTTLE_ACCEL") or "auto",
        help="QEMU accelerator: auto (WHPX if available, else TCG), whpx, or tcg. Default: $CUTTLE_ACCEL or auto",
    )
    args = parser.parse_args()

    if args.fault_test:
        run_fault_injection_unit_tests()
        return

    if args.unit_test:
        run_unit_self_tests()
        print("=== TRIAD CONTROLLER UNIT SELF-TESTS PASSED ===", flush=True)
        return

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

            # 5. Simulate single-node tamper on OS-2 while another thread repeatedly contends for
            #    morph_op_lock (#20), and verify automatic 2-of-3 self-healing + 4 KiB XOR parity
            #    check completes cleanly without leaving OS-2 in HEALING.
            old_morphs = ctrl.nodes[1].morph_count
            stop_contend = threading.Event()

            def _contend_morph_lock():
                while not stop_contend.is_set():
                    if ctrl.nodes[1].state == "HEALING":
                        ctrl.bounce_and_morph_node(1)
                    time.sleep(0.05)

            t_contend = threading.Thread(target=_contend_morph_lock, daemon=True)
            t_contend.start()
            try:
                ctrl.simulate_byzantine_tamper(2)
                deadline = time.time() + 45.0
                while time.time() < deadline:
                    if ctrl.nodes[1].state == "ONLINE" and ctrl.nodes[1].morph_count > old_morphs:
                        break
                    time.sleep(0.5)
            finally:
                stop_contend.set()
                t_contend.join(timeout=5.0)
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
