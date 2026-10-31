#!/usr/bin/env python3
"""CuttleOS Deterministic Chaos & Fault-Injection Harness (R11).

Executes seeded fault-injection scenarios against TriadController + RealOsShellHarness
(the real Rust target_enterprise kernel shell / SQL / BTree / Triad voter engine) and
enforces four end-to-end invariants after every scenario:
  1. Zero lost acknowledged writes (every write that returned ok=True is present in state).
  2. Convergence to 3/3 ONLINE agreement across all nodes once faults are cleared.
  3. At least one structured JSON ALERT event emitted with a registered runbook code.
  4. Prometheus /metrics oracle matches ground truth (3 online nodes, 0 WAL lag).
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import triad_controller as tc

SCENARIOS = (
    "kill_mid_write",
    "enospc_wal",
    "hung_node",
    "delayed_quorum",
    "crash_pending_wal",
)


def _new_controller(name: str, sdir: Path, harness: tc.RealOsShellHarness, reset_tables: bool = True) -> tc.TriadController:
    ctrl = tc.TriadController(
        show_gui=False,
        spec=tc.TriadSpec(name=name, state_dir=sdir, write_operator_token=False),
        unit_test=True,
    )
    ctrl.running = False
    ctrl.send_shell_cmd = harness.exec
    ctrl.morph_node_image = lambda node, seed, release_version=None: setattr(
        node, "morph_count", node.morph_count + 1
    )
    ctrl.start_node_vm = lambda node: None
    ctrl.await_boot = lambda node, timeout=35.0: True
    ctrl.apply_node_profile = lambda node: True
    for n in ctrl.nodes:
        n.state = "ONLINE"
        if reset_tables:
            ctrl._reset_sql_vote_tables(n)
    return ctrl


def verify_chaos_invariants(
    ctrl: tc.TriadController,
    acknowledged_markers: list[str],
    scenario_name: str,
) -> None:
    """Enforce the 4 chaos invariants on `ctrl` after fault recovery."""
    # Invariant 2: 3/3 ONLINE & identical state probe + tx_seq across all 3 nodes.
    states = {n.node_id: n.state for n in ctrl.nodes}
    if any(s != "ONLINE" for s in states.values()):
        raise AssertionError(f"[{scenario_name}] nodes did not converge to ONLINE: {states}")

    probes = {n.node_id: ctrl._state_probe(n) for n in ctrl.nodes}
    if len(set(probes.values())) != 1 or not probes[1]:
        raise AssertionError(f"[{scenario_name}] 3/3 state probe divergence: {probes}")

    seqs = {n.node_id: n.tx_seq for n in ctrl.nodes}
    if any(seq != ctrl.triad_tx_seq for seq in seqs.values()):
        raise AssertionError(
            f"[{scenario_name}] per-node tx_seq {seqs} != controller triad_tx_seq {ctrl.triad_tx_seq}"
        )

    # Invariant 1: Every acknowledged write marker is present in all 3 nodes' SQL state.
    for n in ctrl.nodes:
        out = ctrl.send_shell_cmd(n, "sql SELECT * FROM kv")
        for marker in acknowledged_markers:
            if marker not in out:
                raise AssertionError(
                    f"[{scenario_name}] acknowledged write marker {marker!r} missing on {n.name}:\n{out}"
                )

    # Invariant 3: At least one structured ALERT event with a valid registered code.
    alerts = [e for e in ctrl.events if e.get("level") == "ALERT"]
    if not alerts:
        raise AssertionError(f"[{scenario_name}] expected at least one ALERT event, found none")
    for a in alerts:
        code = a.get("code")
        if code not in tc.ALERT_CODES:
            raise AssertionError(f"[{scenario_name}] unregistered ALERT code {code!r} in {a}")
        sj = a.get("structured_json")
        if not sj:
            raise AssertionError(f"[{scenario_name}] ALERT missing structured_json: {a}")
        parsed = json.loads(sj)
        if parsed.get("code") != code or not parsed.get("runbook"):
            raise AssertionError(f"[{scenario_name}] malformed structured_json: {parsed}")

    # Invariant 4: Prometheus /metrics oracle matches ground truth after recovery.
    prom = ctrl.render_prometheus_metrics()
    if "cuttle_triad_quorum_online_nodes 3" not in prom:
        raise AssertionError(
            f"[{scenario_name}] /metrics did not report 3 online nodes:\n{prom}"
        )
    for nid in (1, 2, 3):
        expected_lag = f'cuttle_triad_wal_lag_entries{{node="{nid}"}} 0'
        if expected_lag not in prom:
            raise AssertionError(
                f"[{scenario_name}] /metrics reported non-zero WAL lag for node {nid}:\n{prom}"
            )


def scenario_kill_mid_write(work: Path, harness: tc.RealOsShellHarness, rng: random.Random) -> dict:
    """Kill one node mid-transaction; verify 2/3 commit and subsequent 3/3 heal."""
    sdir = work / "kill_mid_write"
    ctrl = _new_controller("chaos-kmw", sdir, harness, reset_tables=True)
    acked: list[str] = []
    try:
        victim_idx = rng.choice((0, 1, 2))
        victim = ctrl.nodes[victim_idx]
        r0 = ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('chaos.kmw.0', 'baseline', 1)")
        assert r0["ok"], r0
        acked.append("baseline")

        # Drop victim mid-write so only 2/3 nodes apply the next mutating SQL write.
        drop_active = {"on": True}
        orig_heal = ctrl.heal_and_remorph_node
        ctrl.heal_and_remorph_node = lambda bad_node: None

        def _drop_send(node: tc.TriadNode, cmd: str, timeout: float = 4.0) -> str:
            if drop_active["on"] and node.node_id == victim.node_id and "INSERT" in cmd:
                return ""
            return harness.exec(node, cmd, timeout)

        ctrl.send_shell_cmd = _drop_send
        marker = f"kmw-survived-v{victim.node_id}-s{rng.randint(1000, 9999)}"
        r1 = ctrl.execute_triad_sql(f"INSERT OR REPLACE INTO kv VALUES ('chaos.kmw.1', '{marker}', 2)")
        assert r1["ok"] and "2/3" in r1["quorum"], r1
        acked.append(marker)
        assert victim.tx_seq == 1 and ctrl.triad_tx_seq == 2

        # Restore send + heal and bring victim back to 3/3 via bounce_and_morph_node + parity check.
        drop_active["on"] = False
        ctrl.send_shell_cmd = harness.exec
        ctrl.heal_and_remorph_node = orig_heal
        assert ctrl.bounce_and_morph_node(victim.node_id), "bounce_and_morph_node must catch up victim via WAL"
        verify_chaos_invariants(ctrl, acked, "kill_mid_write")
        return {"scenario": "kill_mid_write", "victim": victim.node_id, "tx_seq": ctrl.triad_tx_seq}
    finally:
        ctrl.shutdown()


def scenario_enospc_wal(work: Path, harness: tc.RealOsShellHarness, rng: random.Random) -> dict:
    """Simulate ENOSPC during WAL persistence; verify fail-closed refusal and clean recovery."""
    sdir = work / "enospc_wal"
    ctrl = _new_controller("chaos-enospc", sdir, harness, reset_tables=True)
    acked: list[str] = []
    try:
        r0 = ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('chaos.enospc.0', 'pre-fault', 1)")
        assert r0["ok"], r0
        acked.append("pre-fault")
        wal_before = ctrl.wal_file.read_text(encoding="utf-8")

        orig_save = ctrl._save_wal_to_disk

        def _enospc_save():
            raise OSError(28, "No space left on device (simulated ENOSPC)")

        ctrl._save_wal_to_disk = _enospc_save
        try:
            ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('chaos.enospc.blocked', 'must-not-run', 2)")
            raise AssertionError("Write must fail closed when WAL persistence raises ENOSPC")
        except OSError:
            pass
        finally:
            ctrl._save_wal_to_disk = orig_save

        assert any(e.get("code") == "WAL_CORRUPT" for e in ctrl.events), ctrl.events
        assert ctrl.wal_file.read_text(encoding="utf-8") == wal_before
        assert ctrl.triad_tx_seq == 1 and len(ctrl.wal_entries) == 1

        # Clear ENOSPC fault and verify subsequent writes succeed cleanly.
        marker = f"post-enospc-{rng.randint(1000, 9999)}"
        r_ok = ctrl.execute_triad_sql(f"INSERT OR REPLACE INTO kv VALUES ('chaos.enospc.1', '{marker}', 2)")
        assert r_ok["ok"], r_ok
        acked.append(marker)

        verify_chaos_invariants(ctrl, acked, "enospc_wal")
        return {"scenario": "enospc_wal", "tx_seq": ctrl.triad_tx_seq}
    finally:
        ctrl.shutdown()


def scenario_hung_node(work: Path, harness: tc.RealOsShellHarness, rng: random.Random) -> dict:
    """Freeze one node's serial shell while its process lives; verify heartbeat kill + heal."""
    sdir = work / "hung_node"
    ctrl = _new_controller("chaos-hung", sdir, harness, reset_tables=True)
    acked: list[str] = []
    try:
        r0 = ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('chaos.hung.0', 'before-hang', 1)")
        assert r0["ok"], r0
        acked.append("before-hang")

        hung_node = ctrl.nodes[rng.choice((0, 1, 2))]
        is_hung = {"active": True}

        def _hung_send(node: tc.TriadNode, cmd: str, timeout: float = 4.0) -> str:
            if is_hung["active"] and node.node_id == hung_node.node_id:
                return ""
            return harness.exec(node, cmd, timeout)

        orig_heal = ctrl.heal_and_remorph_node

        def _sync_heal(bad_node: tc.TriadNode) -> None:
            is_hung["active"] = False
            assert ctrl.bounce_and_morph_node(bad_node.node_id)

        ctrl.send_shell_cmd = _hung_send
        ctrl.heal_and_remorph_node = _sync_heal

        for _ in range(tc.MAX_HEARTBEAT_MISSES):
            for n in ctrl.nodes:
                if n.state == "ONLINE":
                    ctrl.check_node_heartbeat(n, timeout=0.05)

        assert any(e.get("code") == "NODE_HUNG" for e in ctrl.events), ctrl.events
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and hung_node.state != "ONLINE":
            time.sleep(0.02)
        ctrl.heal_and_remorph_node = orig_heal
        ctrl.send_shell_cmd = harness.exec

        marker = f"after-hang-healed-{rng.randint(1000, 9999)}"
        r1 = ctrl.execute_triad_sql(f"INSERT OR REPLACE INTO kv VALUES ('chaos.hung.1', '{marker}', 2)")
        assert r1["ok"], r1
        acked.append(marker)

        verify_chaos_invariants(ctrl, acked, "hung_node")
        return {"scenario": "hung_node", "hung_node": hung_node.node_id, "tx_seq": ctrl.triad_tx_seq}
    finally:
        ctrl.shutdown()


def scenario_delayed_quorum(work: Path, harness: tc.RealOsShellHarness, rng: random.Random) -> dict:
    """Inject seeded response jitter and a minority Byzantine fault during writes + heal."""
    sdir = work / "delayed_quorum"
    ctrl = _new_controller("chaos-dq", sdir, harness, reset_tables=True)
    acked: list[str] = []
    try:
        byz_node = ctrl.nodes[rng.choice((0, 1, 2))]

        def _jittered_send(node: tc.TriadNode, cmd: str, timeout: float = 4.0) -> str:
            time.sleep(rng.uniform(0.001, 0.006))
            return harness.exec(node, cmd, timeout)

        ctrl.send_shell_cmd = _jittered_send
        for idx in range(3):
            marker = f"dq-{idx}-{rng.randint(1000, 9999)}"
            res = ctrl.execute_triad_sql(
                f"INSERT OR REPLACE INTO kv VALUES ('chaos.dq.{idx}', '{marker}', {idx + 1})"
            )
            assert res["ok"], res
            acked.append(marker)

        # Inject a single-node Byzantine row tamper on byz_node and trigger parity check + synchronous heal.
        prev_morph = byz_node.morph_count
        harness.exec(
            byz_node,
            "sql /*triad*/ INSERT OR REPLACE INTO kv VALUES ('chaos.dq.0', 'byzantine_tamper', 999)",
        )
        ctrl.compute_and_verify_raid_parity()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if (
                byz_node.state == "ONLINE"
                and byz_node.morph_count > prev_morph
                and ctrl._state_probe(byz_node) == ctrl._state_probe(ctrl.nodes[(byz_node.node_id) % 3])
            ):
                break
            time.sleep(0.02)

        verify_chaos_invariants(ctrl, acked, "delayed_quorum")
        return {"scenario": "delayed_quorum", "byzantine_node": byz_node.node_id, "tx_seq": ctrl.triad_tx_seq}
    finally:
        ctrl.shutdown()


def scenario_crash_pending_wal(work: Path, harness: tc.RealOsShellHarness, rng: random.Random) -> dict:
    """Crash controller with pending WAL entry on disk; verify restart recovery & epoch bump."""
    sdir = work / "crash_pending_wal"
    ctrl1 = _new_controller("chaos-cpw", sdir, harness, reset_tables=True)
    acked: list[str] = []
    try:
        marker1 = f"cpw-committed-{rng.randint(1000, 9999)}"
        r1 = ctrl1.execute_triad_sql(f"INSERT OR REPLACE INTO kv VALUES ('chaos.cpw.1', '{marker1}', 1)")
        assert r1["ok"], r1
        acked.append(marker1)

        # Simulate a controller crash right after write-ahead save AND 2/3 nodes applying seq=2.
        marker2 = f"cpw-pending-{rng.randint(1000, 9999)}"
        stmt2 = f"INSERT OR REPLACE INTO kv VALUES ('chaos.cpw.2', '{marker2}', 2)"

        def _crash_after_2of3_apply(tx_id: int, q: str) -> None:
            for n in ctrl1.nodes[:2]:
                harness.exec(n, f"sql /*triad*/ {q}")
            raise RuntimeError("simulated controller crash after 2/3 applied pending WAL entry")

        ctrl1._after_wal_write_ahead_hook = _crash_after_2of3_apply
        try:
            ctrl1.execute_triad_sql(stmt2)
            raise AssertionError("Expected simulated crash in _after_wal_write_ahead_hook")
        except RuntimeError:
            pass
        finally:
            ctrl1._after_wal_write_ahead_hook = None
        acked.append(marker2)
        epoch1 = ctrl1.coordinator_epoch
    finally:
        ctrl1.shutdown()

    # Restart a new controller on the same state_dir without resetting node tables.
    ctrl2 = _new_controller("chaos-cpw", sdir, harness, reset_tables=False)
    try:
        assert ctrl2.coordinator_epoch > epoch1, (ctrl2.coordinator_epoch, epoch1)
        assert ctrl2.wal_pending_tx == 2, ctrl2.wal_pending_tx
        ctrl2._resolve_pending_wal_at_boot()
        ctrl2._verify_restored_tx_seq_at_boot()
        ctrl2._adopt_tx_seq_from_majority()
        assert ctrl2.wal_pending_tx is None
        assert ctrl2.triad_tx_seq == 2, ctrl2.triad_tx_seq
        assert any(e.get("code") == "WAL_CORRUPT" for e in ctrl2.events), ctrl2.events

        verify_chaos_invariants(ctrl2, acked, "crash_pending_wal")
        return {
            "scenario": "crash_pending_wal",
            "epoch_before": epoch1,
            "epoch_after": ctrl2.coordinator_epoch,
            "tx_seq": ctrl2.triad_tx_seq,
        }
    finally:
        ctrl2.shutdown()


def verify_oracle_catches_planted_divergence(work: Path, harness: tc.RealOsShellHarness) -> None:
    """Negative test: ensure verify_chaos_invariants catches a planted missing write."""
    sdir = work / "oracle_negative"
    ctrl = _new_controller("chaos-neg", sdir, harness, reset_tables=True)
    try:
        ctrl.execute_triad_sql("INSERT OR REPLACE INTO kv VALUES ('chaos.neg', 'present', 1)")
        ctrl.log_event("ALERT", "Synthetic alert for oracle test", code="SPLIT_BRAIN")
        try:
            verify_chaos_invariants(ctrl, ["present", "planted-missing-write"], "oracle_negative")
            raise AssertionError("Chaos oracle must fail when an acknowledged write is missing")
        except AssertionError as e:
            assert "planted-missing-write" in str(e), e
    finally:
        ctrl.shutdown()


def run_chaos(selected: str, seed: int) -> int:
    tc.IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"cuttle_chaos_s{seed}_", dir=str(tc.IMAGES_DIR)))
    rng = random.Random(seed)
    harness = tc.RealOsShellHarness()
    dispatch = {
        "kill_mid_write": scenario_kill_mid_write,
        "enospc_wal": scenario_enospc_wal,
        "hung_node": scenario_hung_node,
        "delayed_quorum": scenario_delayed_quorum,
        "crash_pending_wal": scenario_crash_pending_wal,
    }
    to_run = list(SCENARIOS) if selected == "all" else [selected]
    results = []
    ok = False
    try:
        verify_oracle_catches_planted_divergence(work, harness)
        for name in to_run:
            res = dispatch[name](work, harness, rng)
            results.append(res)
            print(f"[CHAOS PASS] {json.dumps(res, sort_keys=True)}", flush=True)
        print(
            f"CHAOS SUITE PASSED ({len(results)}/{len(to_run)} scenarios, seed={seed})",
            flush=True,
        )
        ok = True
        return 0
    finally:
        harness.close()
        if ok:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"(chaos state retained for debugging: {work})", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="CuttleOS Chaos & Fault-Injection Harness")
    ap.add_argument(
        "--scenario",
        default="all",
        choices=("all",) + SCENARIOS,
        help="Chaos scenario to run (default: all)",
    )
    ap.add_argument("--seed", type=int, default=1, help="Deterministic PRNG seed")
    args = ap.parse_args()
    sys.exit(run_chaos(args.scenario, args.seed))


if __name__ == "__main__":
    main()
