# Cuttle SQL Engine Plan

**Status:** draft v1 (2026-10-18)
**Owners:** builder (Antigravity / Gemini) implements; reviewer (Claude) verifies.
**Rule:** progress is measured only by passing tests and gate metrics in this file. "Done" follows the definition of done in `GEMINI.md`: a test proves it, or it isn't done.

---

## 1. Why

The current engine (`target_enterprise/src/sql.rs`) is a fixed-size in-memory demo:

| Limit | Today |
|---|---|
| Tables / columns / rows | 4 / 4 / 64 |
| Identifier / text length | 16 / 24 bytes |
| Types | `INT`, `TEXT` |
| Storage | 8-sector (4 KiB) `CTTLSQL1` partition |
| Transactions | one shared, database-wide transaction with an 8-row undo log |

Cuttle needs a real embedded database: durable on NVMe, sized by the disk instead of by constants, safe under concurrent clients, and able to feed a write-ahead log to the triad and to Azure.

## 2. Goals and non-goals

**Goals**
- A memory-safe Rust engine (`cuttle-sql`) that is `no_std` + `alloc` in its core and can be tested on the host with `std`.
- **SQLite 3 file-format compatibility,** so real SQLite can open our files and we can open theirs. That makes differential testing and recovery tooling possible.
- Crash safety: committed data survives power loss at any instant, and uncommitted data never appears.
- Per-connection transactions, plus prepared statements with bind parameters.
- A write-ahead log that can be shipped to triad peers and to an Azure sync bridge.

**Non-goals for v1:** triggers, views, window functions, CTEs, full-text search, JSON functions, virtual tables, `ATTACH`, most `PRAGMA`s, multiple writer processes, and text encodings other than UTF-8.

## 3. Two tracks

| Track | What | When |
|---|---|---|
| **A, ship now** | Keep the current engine working: fix review bugs and enforce limits with clear errors. Optionally run real SQLite in an isolated service, but only once services truly run in user space; not in the kernel. | Ongoing |
| **B, long term** | Build `cuttle-sql` (this plan) and swap it in once it passes the M6 gate. | Milestones below |

Track B must never block Track A.

## 4. v1 SQL feature subset

| Area | In v1 |
|---|---|
| Types | `NULL`, `INTEGER`, `REAL`, `TEXT`, `BLOB`, with SQLite type affinity |
| DDL | `CREATE TABLE` (incl. `PRIMARY KEY`, `NOT NULL`, `UNIQUE`, `DEFAULT`), `DROP TABLE`, `CREATE INDEX`, `DROP INDEX` |
| DML | `INSERT` (incl. `OR REPLACE` / `OR IGNORE`, multi-row `VALUES`), `UPDATE`, `DELETE` |
| Queries | `SELECT` with `WHERE`, `ORDER BY`, `LIMIT`/`OFFSET`, `DISTINCT`; `COUNT`, `SUM`, `MIN`, `MAX`, `AVG`; `GROUP BY`/`HAVING`; `INNER` and `LEFT JOIN` (M5) |
| Expressions | Comparisons, `AND`/`OR`/`NOT`, `IS NULL`, `IN (...)`, `BETWEEN`, `LIKE`, arithmetic, `||`, `CAST` |
| Transactions | `BEGIN`, `COMMIT`, `ROLLBACK`, scoped per connection |
| API | Connection, prepared statement, `?` bind parameters, row iterator |
| Collation | `BINARY`, `NOCASE` |

All network-facing callers (`/sql`, the shell, the triad) move to bind parameters, so no caller builds SQL by string concatenation.

## 5. Architecture (bottom-up, following SQLite's layering)

| Layer | Responsibility | Notes |
|---|---|---|
| **L0 Storage interface** | Read, write, sync, truncate, size and lock on a byte-addressed store | Implementations: in-memory (tests), host file (tests), a fault-injecting wrapper (crash tests), and later Cuttle's NVMe and mirrored-NVMe block devices |
| **L1 Pager** | Page cache, atomic commit, write-ahead log, checkpoints, crash recovery | The durability core. Uses SQLite's WAL format with an in-process index (exclusive single-process mode). |
| **L2 B-tree** | Table (rowid) and index B-trees, overflow pages, freelist | Must pass SQLite's `PRAGMA integrity_check` |
| **L3 Records** | SQLite record encoding, type affinity, comparison and collation | Byte-compatible with the file format |
| **L4 Executor** | Runs query plans | Start with a simple tree-walking executor; adopt a bytecode VM only if profiling demands it |
| **L5 SQL front end** | Tokenizer, parser to an AST, name resolution, simple planner (index choice) | Fuzzed from day one |
| **L6 API** | Connections, statements, binds, per-connection transactions | Plus an optional host-only shim for running external test suites |

**Placement in Cuttle:** the engine runs inside the `svc-sql` service. Its storage interface sits on the NVMe block layer, with encryption and per-page checksums keyed by the device key below the pager.

## 6. Test strategy

Every layer has unit tests. On top of those:

1. **Differential testing against real SQLite** (host only, using `rusqlite`): run random schemas, queries and data on both engines and fail on any difference in results or errors. Also cross-check files: SQLite must open our files with a clean `integrity_check`, and we must read SQLite-created files.
2. **SQL Logic Test:** run the public suite (the `sqllogictest` Rust runner is one option), filtered to the v1 feature subset. The pass rate is the headline progress metric.
3. **Crash and power-loss testing:** a fault-injecting storage layer drops, tears or reorders writes at every sync point. After recovery, committed data must be present, uncommitted data absent, and `integrity_check` clean. Repeat at the QEMU level with real power cuts in M6.
4. **Fuzzing** (`cargo-fuzz`): the tokenizer, parser, record decoder and B-tree page decoder, plus opening corrupted database files, which must return errors and never panic.
5. **Concurrency:** deterministic simulation of interleaved connections to check transaction isolation and locking.

All of this runs in CI on every push. Confirm the license of any external test material before adding it to the repo.

## 7. Milestones and gates

A milestone is complete only when **every** gate item passes in CI. Record the evidence (test names and metric values) in the status table in §9.

| Milestone | Scope | Gate (all required) |
|---|---|---|
| **M0 Foundations** | `cuttle-sql` crate skeleton (`no_std` + `alloc`, `std` feature for tests); storage interface with in-memory and fault-injecting versions; differential harness and SQL Logic Test runner wired up | Harnesses run in CI (failures expected); fuzz targets build |
| **M1 Pager** | Database header, page cache, WAL, commit, rollback, checkpoint, recovery | SQLite opens our empty database with a clean `integrity_check`; crash tests pass at **100%** of injected sync points across the defined scenarios |
| **M2 B-tree** | Table B-trees: insert, lookup, delete, range scan, overflow pages, freelist | Our files pass SQLite's `integrity_check` after randomized operations; we read B-trees written by SQLite; crash tests still 100% |
| **M3 Minimal SQL** | Records, `CREATE TABLE`, `INSERT`, `SELECT` (scan + `WHERE`), `DELETE` | Differential fuzzing finds 0 mismatches over a fixed budget (e.g. 1M random cases); first SQL Logic Test subset at the agreed pass rate |
| **M4 Indexes and transactions** | Index B-trees, `UPDATE`, constraints, per-connection `BEGIN`/`COMMIT`/`ROLLBACK`, bind parameters | Isolation tests pass under simulated concurrency; rollback of any size restores the exact prior state; differential fuzzing still clean |
| **M5 Query features** | `ORDER BY`, `GROUP BY`/`HAVING`, aggregates, `LIMIT`/`OFFSET`, joins, `LIKE`, `CAST` | SQL Logic Test pass rate on the v1 subset ≥ target (e.g. 99%); parser fuzzing clean over a fixed budget |
| **M6 Integration** | `svc-sql` on the NVMe storage layer in Cuttle; migrate existing `CTTLSQL1` data; switch `/sql`, the shell and the triad to the new API | QEMU power-cut tests pass; all existing workspace and QEMU tests pass; the old engine is removed |
| **M7 Replication** | WAL shipping to triad peers and to the Azure sync bridge | Replicas match byte-for-byte after randomized workloads with node bounces; the sync resumes correctly after an outage |

## 8. Open decisions (record each as it's made)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Keep SQLite file-format compatibility? | **Yes.** It enables differential and file-level testing. |
| D2 | Journal mode | **WAL**, in exclusive single-process mode |
| D3 | Executor design | Tree-walking first; bytecode VM only if needed |
| D4 | Where the engine runs | `svc-sql` in user space, once ring-3 services run real handlers |
| D5 | Adopt or contribute to an existing Rust SQLite effort (e.g. Turso)? | Evaluate at M0: license, `no_std` feasibility, maturity |
| D6 | SQL Logic Test pass-rate target per milestone | Set at M0 |
| D7 | Page size and the maximum database size for v1 | 4 KiB pages; maximum size to be set |

## 9. Status

| Milestone | State | Evidence (tests, metrics, commit) |
|---|---|---|
| M0 | Not started | — |
| M1 | Not started | — |
| M2 | Not started | — |
| M3 | Not started | — |
| M4 | Not started | — |
| M5 | Not started | — |
| M6 | Not started | — |
| M7 | Not started | — |

Only the builder updates this table, and only with evidence. The reviewer verifies each update in `Claude-Recommendations.md`.
