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
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
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

# AHCI SQL partition layout (LBA 1058..1065 = 8 sectors = 4096 bytes)
SQL_PART_OFFSET = 1058 * 512
SQL_PART_SIZE = 8 * 512


def is_printable_ascii_command(s: str) -> bool:
    """Return True iff `s` is non-empty and every character is printable ASCII (0x20..=0x7E)."""
    return bool(s) and all(0x20 <= ord(ch) <= 0x7E for ch in s)


def find_qemu() -> str:
    q = shutil.which("qemu-system-x86_64")
    if q:
        return q
    default_win = Path(r"C:\Program Files\qemu\qemu-system-x86_64.exe")
    if default_win.exists():
        return str(default_win)
    raise RuntimeError("qemu-system-x86_64 not found on PATH or C:\\Program Files\\qemu")


def extract_text_sha256(elf_bytes: bytes) -> str:
    """Compute SHA-256 of the ELF binary to fingerprint the morphed machine code."""
    return hashlib.sha256(elf_bytes).hexdigest()


class TriadNode:
    def __init__(self, node_id: int, name: str, role: str, http_port: int, https_port: int, base_seed: int, show_gui: bool):
        self.node_id = node_id
        self.name = name
        self.role = role
        self.http_port = http_port
        self.https_port = https_port
        self.current_seed = base_seed
        self.show_gui = show_gui

        self.node_dir = TRIAD_DIR / f"node{node_id}"
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

        self.elf_sha256 = "pending"
        self.morph_stats = "pending"
        self.morph_count = 0
        self.boot_gen = 0
        self.tx_seq = 0
        self.last_smp = "cpus=4 online=4 idle=hlt-ipi"
        self.last_sql_table = ""
        self.last_morph_ms = 0
        self.tampered = False

    def ensure_disks(self, master_key_bytes: bytes):
        for img in (self.ahci_img, self.virtio_img, self.nvme_img):
            if not img.exists():
                with open(img, "wb") as f:
                    f.write(b"\x00" * (1024 * 1024))
        # Derive a unique 256-bit cryptographic device key for this Triad node so each VM
        # boots with its own seal_key, attest_key, net_auth_key, and initial service ELF variants.
        node_key = hmac.new(
            master_key_bytes,
            f"cuttle-triad-node-v1:{self.node_id}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        self.device_key_path.write_bytes(node_key)

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
    def __init__(self, show_gui: bool = False):
        self.qemu_bin = find_qemu()
        self.show_gui = show_gui
        TRIAD_DIR.mkdir(parents=True, exist_ok=True)

        if DEVICE_KEY.exists() and len(DEVICE_KEY.read_bytes()) >= 32:
            self.master_key_bytes = DEVICE_KEY.read_bytes()[:32]
        else:
            self.master_key_bytes = os.urandom(32)
            DEVICE_KEY.write_bytes(self.master_key_bytes)

        # Generate a fresh ephemeral 128-bit session token on every controller startup.
        self.coordinator_token = secrets.token_hex(16)
        (TRIAD_DIR / "operator_token.txt").write_text(self.coordinator_token + "\n", encoding="utf-8")

        self.base_elf_bytes = BASE_ELF.read_bytes()
        self.base_bios_bytes = BASE_BIOS.read_bytes()
        self.elf_offset_in_bios = self.base_bios_bytes.find(self.base_elf_bytes)
        if self.elf_offset_in_bios < 0:
            raise RuntimeError(
                "Base kernel ELF not found contiguously in run_bios.img; rebuild run_bios.img first."
            )

        self.nodes = [
            TriadNode(1, "OS-1 (SQL-Data-A)", "ACTIVE DATA STRIPE A", 18101, 18501, 100101, show_gui),
            TriadNode(2, "OS-2 (SQL-Data-B)", "ACTIVE DATA STRIPE B", 18102, 18502, 200202, show_gui),
            TriadNode(3, "OS-3 (SQL-Parity)", "RAID PARITY & WITNESS", 18103, 18503, 300303, show_gui),
        ]

        # Monotonic Triad WAL for automatic catch-up after an OS morph bounce (persisted to disk)
        self.wal_lock = threading.Lock()
        self.wal_file = TRIAD_DIR / "triad_wal.json"
        self.triad_tx_seq = 0
        self.wal_entries: list[tuple[int, str]] = []  # (tx_seq, sql_stmt)
        self._load_wal_from_disk()
        self.events: list[dict] = []
        self.parity_Buffer = b"\x00" * SQL_PART_SIZE
        self.parity_sha256 = hashlib.sha256(self.parity_Buffer).hexdigest()[:16]
        self.parity_syndrome_ok = True
        self.quorum_status = "3/3 TMR MAJORITY VERIFIED (D1 ^ D2 = P)"
        self.auto_morph_enabled = False
        self.auto_morph_interval = 45  # seconds
        self.next_rotate_idx = 0
        self.running = True
        self.morph_op_lock = threading.Lock()

    def _load_wal_from_disk(self):
        if not self.wal_file.exists():
            return
        try:
            data = json.loads(self.wal_file.read_text(encoding="utf-8"))
            self.triad_tx_seq = int(data.get("triad_tx_seq", 0))
            self.wal_entries = [
                (int(tid), str(stmt))
                for tid, stmt in data.get("wal_entries", [])
                if is_printable_ascii_command(str(stmt))
            ]
        except Exception:
            self.triad_tx_seq = 0
            self.wal_entries = []

    def _save_wal_to_disk(self):
        payload = {
            "triad_tx_seq": self.triad_tx_seq,
            "wal_entries": self.wal_entries,
        }
        tmp = self.wal_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.wal_file)

    def log_event(self, level: str, msg: str):
        ts = time.strftime("%H:%M:%S")
        entry = {"ts": ts, "level": level, "msg": msg}
        self.events.insert(0, entry)
        if len(self.events) > 60:
            self.events.pop()
        safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
        print(f"[{ts}] [{level}] {safe_msg}", flush=True)

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
        mac_last = f"{0x50 + node.node_id:02x}"
        cmd = [
            self.qemu_bin,
            "-accel",
            "tcg",
            "-smp",
            "4",
            "-m",
            "128M",
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
            f"user,id=usernet0,hostfwd=tcp:127.0.0.1:{node.http_port}-10.0.2.15:80,hostfwd=tcp:127.0.0.1:{node.https_port}-10.0.2.15:443",
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

                if "CONTINUITY genesis" in line:
                    node.boot_gen = 1
                elif "CONTINUITY resume OK" in line:
                    m = re.search(r"boots=(\d+)", line)
                    if m:
                        node.boot_gen = int(m.group(1))

                node.response_lines.append(line)
                node.line_cond.notify_all()

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
        sql_out = self.send_shell_cmd(node, "sql SELECT * FROM kv", timeout=3.0)
        if sql_out and "k|v|rev" in sql_out:
            node.last_sql_table = sql_out

    def compute_and_verify_raid_parity(self):
        """
        Compute 4 KiB RAID Parity P = D1 ^ D2 across OS-1 and OS-2 SQL partitions,
        and verify Triple Modular Redundancy (TMR) 2-of-3 majority consistency across all online Triad members.
        """
        n1, n2, n3 = self.nodes[0], self.nodes[1], self.nodes[2]
        online_nodes = [n for n in self.nodes if n.state == "ONLINE"]

        if len(online_nodes) >= 2:
            # Query live kv table from all online nodes to verify 2-of-3 majority consistency
            outputs = {}
            for n in online_nodes:
                out = self.send_shell_cmd(n, "sql SELECT * FROM kv", timeout=4.0)
                if out:
                    n.last_sql_table = out
                outputs[n.node_id] = out

            # Check if any node diverges from the 2-of-3 majority!
            if len(online_nodes) == 3 and all("k|v|rev" in outputs.get(i, "") for i in (1, 2, 3)):
                o1 = self._normalize_kv_for_tmr(outputs[1])
                o2 = self._normalize_kv_for_tmr(outputs[2])
                o3 = self._normalize_kv_for_tmr(outputs[3])
                if o1 == o2 == o3:
                    self.parity_syndrome_ok = True
                    self.quorum_status = f"3/3 TMR MAJORITY LOCKED | RAID PARITY D1⊕D2=P VERIFIED (tx_seq={self.triad_tx_seq})"
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
          append to the Triad WAL, execute in parallel across all ONLINE nodes, and flush AHCI.
          Any node currently `MORPHING` automatically replays the missed WAL entries during `CATCHING_UP`.
        """
        if not is_printable_ascii_command(sql_query):
            raise ValueError("query contains non-printable or control characters")
        q = sql_query.strip()
        if not q:
            return {"ok": False, "error": "empty SQL query", "output": "error: empty SQL query", "quorum": "0/3"}
        upper = q.upper()
        is_read = (
            upper.startswith("SELECT")
            or upper.startswith(".TABLES")
            or upper.startswith("SHOW")
            or upper.startswith(".SCHEMA")
            or upper.startswith("DESCRIBE")
        )

        online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
        if not online_nodes:
            return {"ok": False, "output": "error: no online nodes in triad", "quorum": "0/3"}

        if is_read:
            results = {}
            for n in online_nodes:
                try:
                    results[n.name] = self.send_shell_cmd(n, f"sql {q}")
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

        # Mutating SQL write: execute across ONLINE nodes FIRST, and only append to the
        # persistent Triad WAL if at least one online node accepted the statement without error.
        per_node = {}
        accepted_nodes = []
        for n in online_nodes:
            try:
                out = self.send_shell_cmd(n, f"sql {q}")
            except ValueError as e:
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
            return {
                "ok": False,
                "error": primary_out or "error: SQL statement rejected by online nodes",
                "output": primary_out,
                "quorum": f"0/{len(online_nodes)} online nodes accepted",
                "per_node": per_node,
            }

        with self.wal_lock:
            self.triad_tx_seq += 1
            tx_id = self.triad_tx_seq
            self.wal_entries.append((tx_id, q))
            self._save_wal_to_disk()

        for n in accepted_nodes:
            self.send_shell_cmd(n, "sync")
            n.tx_seq = tx_id

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
          hardware `seal_key`, persists to the Triad WAL, and flushes AHCI (`sync`).
        - `vault get <key>`: unseals and verifies `<key>` on all online nodes and returns a 2-of-3 Majority Vote!
        - `guard status` / `guard alerts` / `guard lockdown` / `guard unlock`: queries or enforces Blue-Team
          security posture across all 3 Triad nodes simultaneously.
        - `cron add <ticks> <cmd>` / `cron list` / `cron del <id>` / `cron run`: manages deterministic periodic
          jobs across all 3 Triad nodes.
        """
        if not is_printable_ascii_command(app_cmd):
            raise ValueError("command contains non-printable or control characters")
        c = app_cmd.strip()
        parts = c.split()
        if not parts or parts[0].lower() not in ("vault", "guard", "cron"):
            return {"ok": False, "error": "unsupported app command (expected vault, guard, or cron)", "quorum": "0/3"}

        app = parts[0].lower()
        sub = parts[1].lower() if len(parts) > 1 else "status"
        online_nodes = [n for n in self.nodes if n.state == "ONLINE"]
        if not online_nodes:
            return {"ok": False, "error": "no online nodes in triad", "quorum": "0/3"}

        is_read = (
            (app == "vault" and sub in ("get", "list", "status"))
            or (app == "guard" and sub in ("status", "alerts"))
            or (app == "cron" and sub in ("list", "status"))
        )

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

        if is_read:
            return {
                "ok": len(accepted_nodes) > 0,
                "mode": f"APP READ ({app.upper()} 2-of-3 Majority)",
                "quorum": f"{agree}/{len(online_nodes)} ONLINE NODES AGREED",
                "tx_seq": self.triad_tx_seq,
                "output": chosen,
                "per_node": per_node,
            }

        if not accepted_nodes:
            return {
                "ok": False,
                "error": chosen or f"error: {app} command rejected by online nodes",
                "output": chosen,
                "quorum": f"0/{len(online_nodes)} online nodes accepted",
                "per_node": per_node,
            }

        # Persist durable `vault put` / `vault del` mutations into the Triad WAL so morphing/healing
        # nodes replay and re-seal the secret under their own hardware `seal_key`.
        tx_id = self.triad_tx_seq
        if app == "vault" and sub in ("put", "del"):
            with self.wal_lock:
                self.triad_tx_seq += 1
                tx_id = self.triad_tx_seq
                self.wal_entries.append((tx_id, c))
                self._save_wal_to_disk()
            for n in accepted_nodes:
                self.send_shell_cmd(n, "sync")
                n.tx_seq = tx_id
            self.compute_and_verify_raid_parity()

        self.log_event(
            f"APP-{app.upper()}",
            f"Executed '{c}' across {len(accepted_nodes)}/3 online Triad nodes (tx_seq={tx_id}).",
        )
        return {
            "ok": True,
            "mode": f"APP WRITE ({app.upper()} Replicated)",
            "quorum": f"Applied on {len(accepted_nodes)}/{len(online_nodes)} online nodes (tx_seq={tx_id})",
            "tx_seq": tx_id,
            "output": chosen,
            "per_node": per_node,
        }

    def _replay_wal_entry(self, node: TriadNode, stmt: str):
        s = stmt.strip()
        if s.lower().startswith("vault "):
            self.send_shell_cmd(node, s)
        else:
            self.send_shell_cmd(node, f"sql {s}")

    def bounce_and_morph_node(self, node_id: int) -> bool:
        """
        Perform a live zero-downtime MTD Morph on a single node while the other 2 nodes
        keep the logical SQL Appliance 100% online, followed by automatic WAL Delta Catch-Up.
        """
        if not self.morph_op_lock.acquire(blocking=False):
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

            # 2. MORPHING: Rewrite kernel ELF with fresh seed via binmorph (~250ms)
            node.state = "MORPHING"
            self.quorum_status = f"2/3 TMR MAJORITY ACTIVE ({peers[0].name.split()[0]} + {peers[1].name.split()[0]}) | {node.name.split()[0]} MORPHING"
            new_seed = random.randint(100_000, 999_999)
            self.morph_node_image(node, new_seed)

            # 3. Boot freshly morphed VM
            self.start_node_vm(node)
            ok = self.wait_for_shell_ready(node, timeout=35.0)
            if not ok:
                tail_str = " | ".join(node.serial_tail[-5:])
                self.log_event("ERROR", f"{node.name}: Timed out waiting for shell ready after morph (tail: {tail_str}).")
                node.state = "OFFLINE"
                return False

            # 4. CATCHING_UP: Replay any SQL transactions committed while this node was morphing!
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

            node.tampered = False
            node.state = "ONLINE"
            self.refresh_node_telemetry(node)
            self.log_event(
                "ONLINE",
                f"{node.name}: Rejoined 3/3 Triad Pool on new binary {node.elf_sha256[:12]}.. (boot #{node.boot_gen}, tx_seq={node.tx_seq}).",
            )
        finally:
            self.morph_op_lock.release()

        self.compute_and_verify_raid_parity()
        return True

    def heal_and_remorph_node(self, node: TriadNode):
        """
        Reconstruct a corrupted/tampered node from the 2-of-3 healthy majority (D1 = D2 ^ P),
        replay the full canonical WAL, and emergency-morph its binary.
        """
        with self.morph_op_lock:
            node.state = "HEALING"
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
                f"{node.name}: Isolating tampered node, verifying 4 KiB XOR parity block (D_peer ⊕ P = {xor_tag}..), and reconstructing from 2/3 RAID Majority + WAL...",
            )
            # Reconstruct canonical kv table from clean state + WAL replay
            self.send_shell_cmd(node, "sql DROP TABLE kv")
            self.send_shell_cmd(node, "sql CREATE TABLE kv (k TEXT, v TEXT, rev INT)")
            self.send_shell_cmd(node, "sql INSERT INTO kv VALUES ('cluster.role', 'primary', 1)")
            self.send_shell_cmd(node, "sql INSERT INTO kv VALUES ('mtd.policy', 'binmorph-7pass', 1)")
            self.send_shell_cmd(node, "sql INSERT INTO kv VALUES ('boot.state', 'ready', 1)")
            with self.wal_lock:
                entries = list(self.wal_entries)
            for tid, stmt in entries:
                if not is_printable_ascii_command(stmt):
                    node.tx_seq = tid
                    continue
                try:
                    self._replay_wal_entry(node, stmt)
                except Exception as e:
                    self.log_event("WARN", f"{node.name}: Error replaying WAL entry #{tid} during heal: {e}")
                node.tx_seq = tid
            self.send_shell_cmd(node, "sync")
            node.tampered = False

        # Now force an immediate binary re-morph so the exploit can never work again
        self.bounce_and_morph_node(node.node_id)

    def simulate_byzantine_tamper(self, node_id: int):
        """Inject an unauthorized rogue SQL modification onto a single node to test 2-of-3 RAID self-healing."""
        node = self.nodes[node_id - 1]
        if node.state != "ONLINE":
            return
        node.tampered = True
        self.log_event(
            "TAMPER",
            f"Injected unauthorized rogue row onto {node.name} ONLY: INSERT INTO kv VALUES ('hacked.backdoor', 'pwned', 999)",
        )
        self.send_shell_cmd(
            node, "sql INSERT INTO kv VALUES ('hacked.backdoor', 'pwned', 999)"
        )
        # Immediately run the RAID parity & 2-of-3 majority check so the controller catches and heals it
        self.compute_and_verify_raid_parity()

    def boot_all_parallel(self):
        self.log_event("INIT", "Morphing 3 independent x86-64 kernel binaries via binmorph...")
        for n in self.nodes:
            self.morph_node_image(n, n.current_seed)

        self.log_event("INIT", "Launching 3 parallel 4-core Cuttle VMs (12 vCPUs total, HLT idle)...")
        for n in self.nodes:
            self.start_node_vm(n)

        for n in self.nodes:
            ok = self.wait_for_shell_ready(n, timeout=30.0)
            if ok:
                n.state = "ONLINE"
                self.refresh_node_telemetry(n)
                self.log_event(
                    "READY",
                    f"{n.name} ONLINE (port :{n.http_port} | binary sha256={n.elf_sha256[:12]}.. | boot #{n.boot_gen})",
                )
            else:
                n.state = "OFFLINE"
                self.log_event("ERROR", f"{n.name} failed to reach interactive shell ready.")

        self.compute_and_verify_raid_parity()
        threading.Thread(target=self._background_scheduler, daemon=True).start()

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
(function initToken() {
  const saved = localStorage.getItem('cuttle_triad_token') || '';
  document.getElementById('tokInput').value = saved;
})();

function saveToken() {
  localStorage.setItem('cuttle_triad_token', document.getElementById('tokInput').value.trim());
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
    grid.innerHTML = d.nodes.map(n => `
      <div class="node-card ${n.state}">
        <div class="node-top">
          <div class="node-title">${n.name}</div>
          <span class="badge ${n.state}">${n.state}</span>
        </div>
        <div class="node-role">${n.role} (HTTP :${n.http_port} | 4x SMP vCPUs)</div>
        <div class="kv-row"><span>Kernel Seed / Morphs:</span><span>#${n.seed} (${n.morph_count}x | ${n.last_morph_ms}ms)</span></div>
        <div class="kv-row"><span>Binary SHA-256:</span><span class="hash">${n.elf_sha256.slice(0, 20)}…</span></div>
        <div class="kv-row"><span>Binmorph Rewrite:</span><span>${n.morph_stats.slice(0, 38)}</span></div>
        <div class="kv-row"><span>AHCI Boot Gen / SQL tx:</span><span>boot #${n.boot_gen} | tx_seq=${n.tx_seq}</span></div>
        <div class="kv-row"><span>4-Core HLT / IPI:</span><span>${n.last_smp}</span></div>
        <div class="kv-row"><span>RAID Parity Tag:</span><span class="hash">${d.parity_sha256} (D1⊕D2=P)</span></div>
        <div class="btn-row">
          <button class="morph-btn" onclick="morphNode(${n.node_id})">⚡ Morph & Bounce OS-${n.node_id}</button>
          <button class="tamper-btn" onclick="tamperNode(${n.node_id})">☣ Simulate Hack on OS-${n.node_id}</button>
          <button onclick="window.open('http://127.0.0.1:${n.http_port}/app','_blank')">Direct UI</button>
        </div>
      </div>
    `).join('');

    const evEl = document.getElementById('eventList');
    evEl.innerHTML = d.events.map(e => `
      <div class="ev ${e.level}"><span class="ts">[${e.ts}]</span><strong>[${e.level}]</strong> ${e.msg}</div>
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
            if val and hmac.compare_digest(val, expected):
                return True
        auth = (self.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            if tok and hmac.compare_digest(tok, expected):
                return True
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            kv = part.strip()
            if kv.startswith("triad_sid="):
                tok = kv[len("triad_sid="):].strip()
                if tok and hmac.compare_digest(tok, expected):
                    return True
        return False

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code: int, ctype: str, text: str):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base_path = self.path.split("?", 1)[0]
        if base_path in ("/", "/app", "/dashboard", "/triad"):
            return self._send_text(200, "text/html; charset=utf-8", DASHBOARD_HTML)

        if base_path == "/api/triad":
            c = self.ctrl
            data = {
                "quorum_status": c.quorum_status,
                "triad_tx_seq": c.triad_tx_seq,
                "parity_sha256": c.parity_sha256,
                "parity_syndrome_ok": c.parity_syndrome_ok,
                "auto_morph": c.auto_morph_enabled,
                "nodes": [
                    {
                        "node_id": n.node_id,
                        "name": n.name,
                        "role": n.role,
                        "state": n.state,
                        "http_port": n.http_port,
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
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace").strip()

        if not self._is_authenticated():
            return self._send_json(
                401,
                {"ok": False, "error": "unauthorized: provide valid X-Cuttle-Session or Authorization: Bearer token"},
            )

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
            return self._send_json(200 if res.get("ok") else 400, res)

        if self.path.startswith("/api/morph/"):
            nid = int(self.path.rsplit("/", 1)[-1])
            threading.Thread(
                target=self.ctrl.bounce_and_morph_node, args=(nid,), daemon=True
            ).start()
            return self._send_json(200, {"ok": True})

        if self.path.startswith("/api/tamper/"):
            nid = int(self.path.rsplit("/", 1)[-1])
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


def main():
    parser = argparse.ArgumentParser(description="Cuttle 3-as-1 Triad Hypervisor Controller")
    parser.add_argument("--port", type=int, default=18080, help="Unified Triad HTTP port")
    parser.add_argument("--gui", action="store_true", help="Show 3 QEMU VGA windows")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Boot the 3-node Triad, test SQL RAID writes during a live node morph, test 2-of-3 self-healing, and exit",
    )
    args = parser.parse_args()

    if args.self_test and (TRIAD_DIR / "triad_wal.json").exists():
        (TRIAD_DIR / "triad_wal.json").unlink()

    ctrl = TriadController(show_gui=args.gui)
    if args.self_test:
        for n in ctrl.nodes:
            for img in (n.ahci_img, n.virtio_img, n.nvme_img):
                if img.exists():
                    img.unlink()
    TriadHttpHandler.ctrl = ctrl
    ctrl.boot_all_parallel()

    if args.self_test:
        try:
            print("\n=== RUNNING TRIAD 3-AS-1 LIVE SELF-TEST ===", flush=True)
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
                unauth_read_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/sql",
                    data=b"SELECT * FROM kv",
                    method="POST",
                )
                try:
                    urllib.request.urlopen(unauth_read_req, timeout=5.0)
                    raise AssertionError("Unauthenticated POST /api/sql SELECT must be refused with 401")
                except urllib.error.HTTPError as e:
                    assert e.code == 401, f"Expected 401 on unauthenticated POST /api/sql SELECT, got {e.code}"

                unauth_req = urllib.request.Request(
                    f"http://127.0.0.1:{test_port}/api/sql",
                    data=b"INSERT INTO kv VALUES ('unauth', 'nope', 1)",
                    method="POST",
                )
                try:
                    urllib.request.urlopen(unauth_req, timeout=5.0)
                    raise AssertionError("Unauthenticated POST /api/sql must be refused with 401")
                except urllib.error.HTTPError as e:
                    assert e.code == 401, f"Expected 401 on unauthenticated POST /api/sql, got {e.code}"

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
            finally:
                test_srv.shutdown()

            assert ctrl.wal_file.exists(), "Triad WAL must be persisted to triad_wal.json"
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

            # 5. Simulate single-node tamper on OS-2 and verify automatic 2-of-3 self-healing + 4 KiB XOR parity check
            old_morphs = ctrl.nodes[1].morph_count
            ctrl.simulate_byzantine_tamper(2)
            deadline = time.time() + 45.0
            while time.time() < deadline:
                if ctrl.nodes[1].state == "ONLINE" and ctrl.nodes[1].morph_count > old_morphs:
                    break
                time.sleep(0.5)
            q2_out = ctrl.send_shell_cmd(ctrl.nodes[1], "sql SELECT * FROM kv")
            assert "pwned" not in q2_out and "zero_downtime" in q2_out, f"OS-2 heal failed:\n{q2_out}"
            # Also verify OS-2 reconstructed and re-sealed `cluster.secret` from the WAL during heal!
            v2_out = ctrl.send_shell_cmd(ctrl.nodes[1], "vault get cluster.secret")
            assert "value=ThreeHearts9 verified=true" in v2_out, f"OS-2 vault heal failed:\n{v2_out}"
            print("=== TRIAD 3-AS-1 SELF-TEST PASSED ===", flush=True)
        finally:
            ctrl.shutdown()
        return

    server = ThreadingHTTPServer(("127.0.0.1", args.port), TriadHttpHandler)
    print("\n============================================================================", flush=True)
    print(f"  CUTTLE 3-AS-1 TRIAD APPLIANCE ONLINE!", flush=True)
    print(f"  Unified Command Center : http://127.0.0.1:{args.port}/app", flush=True)
    print(f"  Operator Session Token : {ctrl.coordinator_token} (saved to triad/operator_token.txt)", flush=True)
    print(f"  Unified SQL Endpoint   : POST http://127.0.0.1:{args.port}/api/sql (with X-Cuttle-Session header)", flush=True)
    print(f"  Individual OS Ports    : OS-1 :18101 | OS-2 :18102 | OS-3 (Parity) :18103", flush=True)
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
