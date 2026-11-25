#![no_std]
#![no_main]

//! Legion Runner eBPF program: a tracepoint on `sys_enter_connect` that records
//! every outbound connect()'s destination + PID + comm into a ring buffer.
//!
//! We read the userspace `struct sockaddr` directly (ABI-stable layout) instead
//! of kernel `struct sock` fields, so no vmlinux/CO-RE generation is needed.
//!
//! syscalls/sys_enter_connect format (offsets):
//!   16: int fd   ·   24: struct sockaddr *uservaddr   ·   32: u64 addrlen

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use legionr_bpf_common::ConnEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn legionr_connect(ctx: TracePointContext) -> u32 {
    let _ = try_connect(&ctx);
    0
}

#[inline(always)]
fn try_connect(ctx: &TracePointContext) -> Result<(), i64> {
    // struct sockaddr *uservaddr lives at offset 24 of the tracepoint record.
    let uservaddr: u64 = unsafe { ctx.read_at::<u64>(24)? };
    if uservaddr == 0 {
        return Err(0);
    }

    let family: u16 = unsafe { bpf_probe_read_user(uservaddr as *const u16)? };
    if family != 2 && family != 10 {
        return Err(0); // only AF_INET / AF_INET6
    }

    let mut entry = match EVENTS.reserve::<ConnEvent>(0) {
        Some(e) => e,
        None => return Err(0),
    };
    let e = entry.as_mut_ptr();

    unsafe {
        // sockaddr: family(2) | be16 port | addr...
        let be_port: u16 = bpf_probe_read_user((uservaddr + 2) as *const u16).unwrap_or(0);
        (*e).family = family;
        (*e).dport = u16::from_be(be_port);
        (*e).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        (*e).addr4 = 0;
        (*e).addr6 = [0u8; 16];
        if family == 2 {
            // sockaddr_in: sin_addr at offset 4
            (*e).addr4 = bpf_probe_read_user((uservaddr + 4) as *const u32).unwrap_or(0);
        } else {
            // sockaddr_in6: sin6_addr at offset 8
            (*e).addr6 = bpf_probe_read_user((uservaddr + 8) as *const [u8; 16]).unwrap_or([0u8; 16]);
        }
        (*e).comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    }

    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
