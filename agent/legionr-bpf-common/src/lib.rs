#![no_std]

//! Event shared between the eBPF program and userspace. `repr(C)` so both sides
//! agree on the byte layout; it is plain-old-data and safe to read from the
//! ring buffer.

/// Captured by `sys_enter_connect` (TCP, connected UDP).
pub const PROTO_CONNECT: u32 = 0;
/// Captured by `sys_enter_sendto` with an explicit destination (UDP).
pub const PROTO_SENDTO: u32 = 1;
/// Captured by `sys_enter_sendmsg` with an explicit destination (UDP).
pub const PROTO_SENDMSG: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnEvent {
    /// Address family: 2 = AF_INET, 10 = AF_INET6.
    pub family: u16,
    /// Destination port, host byte order.
    pub dport: u16,
    /// PID of the process that made the call.
    pub pid: u32,
    /// IPv4 destination, network byte order (valid when family == 2).
    pub addr4: u32,
    /// IPv6 destination bytes (valid when family == 10).
    pub addr6: [u8; 16],
    /// Process name (comm), NUL-padded. Set by the process itself, so it is a
    /// label, not proof of identity.
    pub comm: [u8; 16],
    /// Which syscall produced the event (PROTO_*).
    pub proto: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnEvent {}
