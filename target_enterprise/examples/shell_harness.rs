//! Host-side stdio harness driving three real `target_enterprise::OsShell`
//! instances with the kernel's exact 1,024-byte console reply buffer
//! (`target_enterprise_kernel/src/main.rs:846`) and byte-by-byte `feed_byte`
//! serial line discipline (`SHELL_LINE_MAX = 256`).
//!
//! Used by `tools/triad_controller.py --unit-test` so controller unit tests
//! exercise the real kernel shell parser, 256-byte input line limit, and
//! 1,024-byte shared output+prompt buffer rather than hand-written Python mocks.

use std::io::{self, BufRead, Write};
use target_enterprise::OsShell;

const CONSOLE_REPLY_CAP: usize = 1024;

fn new_node_shell(node_id: usize) -> Box<OsShell> {
    let key_byte = match node_id {
        1 => 0x11,
        2 => 0x22,
        _ => 0x33,
    };
    Box::new(OsShell::with_seal_key([key_byte; 32]))
}

fn main() {
    let mut shells = [new_node_shell(1), new_node_shell(2), new_node_shell(3)];
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout());

    for line_res in stdin.lock().lines() {
        let Ok(line) = line_res else { break };
        let Some((node_str, cmd)) = line.split_once('\t') else {
            continue;
        };
        let Ok(node_id) = node_str.trim().parse::<usize>() else {
            continue;
        };
        if !(1..=3).contains(&node_id) {
            continue;
        }
        let idx = node_id - 1;
        if cmd == "__reset__" {
            shells[idx] = new_node_shell(node_id);
            let _ = writeln!(stdout);
            let _ = stdout.flush();
            continue;
        }
        let mut echo = [0u8; 16];
        let mut reply = [0u8; CONSOLE_REPLY_CAP];
        for &b in cmd.as_bytes() {
            let _ = shells[idx].feed_byte(b, 1, 0, 0, &mut echo, &mut reply);
        }
        let (_elen, act) = shells[idx].feed_byte(b'\n', 1, 0, 0, &mut echo, &mut reply);
        let n = act.bytes_written().min(reply.len());
        for &b in &reply[..n] {
            let _ = write!(stdout, "{:02x}", b);
        }
        let _ = writeln!(stdout);
        let _ = stdout.flush();
    }
}
