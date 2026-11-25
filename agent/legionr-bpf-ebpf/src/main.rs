#![no_std]
#![no_main]

//! Legion Runner eBPF program: tracepoints on outbound socket syscalls that
//! record the destination, PID and comm of each one into a ring buffer.
//!
//! - `sys_enter_connect`: every connect() (TCP, and connected UDP).
//! - `sys_enter_sendto` / `sys_enter_sendmsg`: UDP sent to an explicit address
//!   without connect() (DNS, QUIC). These repeat per packet, so they are
//!   de-duplicated in the kernel per (pid, address, port) for one second.
//!
//! Limits, stated so nobody mistakes this for more than it is: it reads the
//! address from user memory at syscall entry, so a second thread can change it
//! after the read; it does not see io_uring or sendmmsg; and comm is the name a
//! process gives itself. Events that do not fit in the ring buffer are counted
//! in DROPS, not silently lost.
//!
//! We read the userspace `struct sockaddr` directly (ABI-stable layout) instead
//! of kernel `struct sock` fields, so no vmlinux/CO-RE generation is needed.
//!
//! Tracepoint record offsets (after the 16-byte common header + syscall nr):
//!   connect: 24 uservaddr          sendto: 48 addr          sendmsg: 24 msg

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user,
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use legionr_bpf_common::{ConnEvent, PROTO_CONNECT, PROTO_SENDMSG, PROTO_SENDTO};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Events that could not be reserved in EVENTS (ring buffer full).
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Last time (ns) a UDP send to (pid, addr, port) was reported.
#[map]
static SEEN: LruHashMap<[u8; 24], u64> = LruHashMap::with_max_entries(8192, 0);

const DEDUPE_NS: u64 = 1_000_000_000;

#[tracepoint]
pub fn legionr_connect(ctx: TracePointContext) -> u32 {
    if let Ok(addr) = unsafe { ctx.read_at::<u64>(24) } {
        let _ = record(addr, PROTO_CONNECT);
    }
    0
}

#[tracepoint]
pub fn legionr_sendto(ctx: TracePointContext) -> u32 {
    if let Ok(addr) = unsafe { ctx.read_at::<u64>(48) } {
        let _ = record(addr, PROTO_SENDTO);
    }
    0
}

#[tracepoint]
pub fn legionr_sendmsg(ctx: TracePointContext) -> u32 {
    // struct user_msghdr *msg; msg_name (the destination) is its first field.
    if let Ok(msg) = unsafe { ctx.read_at::<u64>(24) } {
        if msg != 0 {
            if let Ok(name) = unsafe { bpf_probe_read_user(msg as *const u64) } {
                let _ = record(name, PROTO_SENDMSG);
            }
        }
    }
    0
}

#[inline(always)]
fn count_drop() {
    if let Some(slot) = DROPS.get_ptr_mut(0) {
        unsafe { *slot += 1 };
    }
}

#[inline(always)]
fn record(uservaddr: u64, proto: u32) -> Result<(), i64> {
    if uservaddr == 0 {
        return Err(0); // connected socket: the destination was seen at connect()
    }
    let family: u16 = unsafe { bpf_probe_read_user(uservaddr as *const u16)? };
    if family != 2 && family != 10 {
        return Err(0); // only AF_INET / AF_INET6
    }
    let be_port: u16 = unsafe { bpf_probe_read_user((uservaddr + 2) as *const u16).unwrap_or(0) };
    let mut addr4: u32 = 0;
    let mut addr6 = [0u8; 16];
    if family == 2 {
        addr4 = unsafe { bpf_probe_read_user((uservaddr + 4) as *const u32).unwrap_or(0) };
    } else {
        addr6 =
            unsafe { bpf_probe_read_user((uservaddr + 8) as *const [u8; 16]).unwrap_or([0u8; 16]) };
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if proto != PROTO_CONNECT {
        let mut key = [0u8; 24];
        key[0..4].copy_from_slice(&pid.to_ne_bytes());
        key[4..6].copy_from_slice(&be_port.to_ne_bytes());
        key[6..8].copy_from_slice(&family.to_ne_bytes());
        if family == 2 {
            key[8..12].copy_from_slice(&addr4.to_ne_bytes());
        } else {
            key[8..24].copy_from_slice(&addr6);
        }
        let now = unsafe { bpf_ktime_get_ns() };
        if let Some(last) = unsafe { SEEN.get(&key) } {
            if now.wrapping_sub(*last) < DEDUPE_NS {
                return Ok(());
            }
        }
        let _ = SEEN.insert(&key, &now, 0);
    }

    let mut entry = match EVENTS.reserve::<ConnEvent>(0) {
        Some(e) => e,
        None => {
            count_drop();
            return Err(0);
        }
    };
    let e = entry.as_mut_ptr();
    unsafe {
        (*e).family = family;
        (*e).dport = u16::from_be(be_port);
        (*e).pid = pid;
        (*e).addr4 = addr4;
        (*e).addr6 = addr6;
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        (*e).proto = proto;
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
