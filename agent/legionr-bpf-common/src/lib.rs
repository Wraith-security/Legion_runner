#![no_std]

//! Event shared between the eBPF program and userspace. `repr(C)` so both sides
//! agree on the byte layout; it is plain-old-data and safe to read from the
//! ring buffer.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnEvent {
    /// Address family: 2 = AF_INET, 10 = AF_INET6.
    pub family: u16,
    /// Destination port, host byte order.
    pub dport: u16,
    /// PID of the connecting process.
    pub pid: u32,
    /// IPv4 destination, network byte order (valid when family == 2).
    pub addr4: u32,
    /// IPv6 destination bytes (valid when family == 10).
    pub addr6: [u8; 16],
    /// Process name (comm), NUL-padded.
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnEvent {}
