//! Legion Runner eBPF capture agent (userspace).
//!
//! Loads the tracepoint program, then streams one line per outbound connection
//! to stdout in the protocol the action consumes:
//!
//!   LEGIONC <ip> <port> <pid> <comm>
//!
//! Socket-layer capture means it sees the real connect() target regardless of
//! how the name was resolved (nss-resolve, c-ares, hard-coded IP, …).

use std::net::{Ipv4Addr, Ipv6Addr};

use aya::{maps::RingBuf, programs::TracePoint, Ebpf};
use legionr_bpf_common::ConnEvent;

/// Render one event as a protocol line, or `None` to skip (loopback/empty).
fn format_event(e: &ConnEvent) -> Option<String> {
    let comm_end = e.comm.iter().position(|&b| b == 0).unwrap_or(e.comm.len());
    let comm = String::from_utf8_lossy(&e.comm[..comm_end]);
    let comm = if comm.is_empty() { "?".into() } else { comm };

    let ip = match e.family {
        2 => Ipv4Addr::from(u32::from_be(e.addr4)).to_string(),
        10 => Ipv6Addr::from(e.addr6).to_string(),
        _ => return None,
    };
    if ip == "0.0.0.0" || ip == "::" || ip.starts_with("127.") || ip == "::1" {
        return None;
    }
    Some(format!("LEGIONC {ip} {} {} {comm}", e.dport, e.pid))
}

fn main() -> anyhow::Result<()> {
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/legionr-bpf-ebpf"
    )))?;

    let prog: &mut TracePoint = bpf
        .program_mut("legionr_connect")
        .expect("program present")
        .try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_connect")?;

    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").expect("EVENTS map"))?;
    let stdout = std::io::stdout();

    loop {
        let mut emitted = false;
        while let Some(item) = ring.next() {
            if item.len() >= core::mem::size_of::<ConnEvent>() {
                // Safe: the eBPF side writes a ConnEvent (POD) into the ring.
                let event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ConnEvent) };
                if let Some(line) = format_event(&event) {
                    use std::io::Write;
                    let mut h = stdout.lock();
                    let _ = writeln!(h, "{line}");
                    let _ = h.flush();
                    emitted = true;
                }
            }
        }
        if !emitted {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comm(s: &str) -> [u8; 16] {
        let mut c = [0u8; 16];
        c[..s.len()].copy_from_slice(s.as_bytes());
        c
    }

    #[test]
    fn formats_ipv4_line() {
        let e = ConnEvent {
            family: 2,
            dport: 443,
            pid: 1234,
            addr4: u32::to_be(u32::from(Ipv4Addr::new(140, 82, 114, 3))),
            addr6: [0; 16],
            comm: comm("curl"),
        };
        assert_eq!(format_event(&e).unwrap(), "LEGIONC 140.82.114.3 443 1234 curl");
    }

    #[test]
    fn formats_ipv6_line() {
        let e = ConnEvent {
            family: 10,
            dport: 443,
            pid: 7,
            addr4: 0,
            addr6: Ipv6Addr::new(0x2606, 0x50c0, 0, 0, 0, 0, 0, 0x153).octets(),
            comm: comm("git"),
        };
        let line = format_event(&e).unwrap();
        assert!(line.starts_with("LEGIONC 2606:50c0::153 443 7 git"), "{line}");
    }

    #[test]
    fn skips_loopback_and_unknown_family() {
        let lo = ConnEvent {
            family: 2,
            dport: 53,
            pid: 1,
            addr4: u32::to_be(u32::from(Ipv4Addr::new(127, 0, 0, 1))),
            addr6: [0; 16],
            comm: comm("x"),
        };
        assert!(format_event(&lo).is_none());

        let unknown = ConnEvent { family: 99, dport: 1, pid: 1, addr4: 0, addr6: [0; 16], comm: comm("x") };
        assert!(format_event(&unknown).is_none());
    }
}
