//! Sockets -> processes.
//!
//! This is the thing Wireshark structurally cannot do. It sees frames on the
//! wire, and a frame carries no idea which program produced it: by the time
//! bytes reach the network card, the process is gone from the picture. The
//! mapping lives in the kernel's connection table, and only a query to the
//! running system can recover it.
//!
//! The table is a snapshot of this instant, so a connection that has already
//! closed cannot be attributed retroactively. That is a property of the data,
//! not a gap in the implementation, and `live` refreshes on a timer for it.

use std::collections::HashMap;

use anyhow::{Context, Result};

/// One row of the kernel's connection table, with the owning program resolved.
pub struct Connection {
    pub proto: &'static str,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: &'static str,
    pub pid: u32,
    pub process: String,
}

#[cfg(windows)]
mod imp {
    use super::*;

    use std::ffi::c_void;
    use std::mem::size_of;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    /// TCP state numbers as the MIB defines them.
    fn tcp_state(n: u32) -> &'static str {
        match n {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => "?",
        }
    }

    /// The table stores addresses and ports in network byte order.
    fn addr(v: u32) -> String {
        let b = v.to_le_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }

    fn port(v: u32) -> u16 {
        u16::from_be((v & 0xFFFF) as u16)
    }

    /// PID -> executable name, taken in one pass so each connection does not
    /// need to open a process handle (which also fails for processes owned by
    /// other users, and would leave most rows blank).
    pub fn process_names() -> Result<HashMap<u32, String>> {
        let mut map = HashMap::new();
        // SAFETY: the snapshot handle is checked and closed on every path.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap.is_null() || snap as isize == -1 {
                anyhow::bail!("could not enumerate processes");
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    let end = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                    map.insert(entry.th32ProcessID, name);
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        Ok(map)
    }

    /// Read a table twice: once to learn its size, once to fill it. The size
    /// can change between the calls, so the loop retries rather than assuming.
    unsafe fn read_table(
        get: unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, i32, u32) -> u32,
        class: i32,
    ) -> Result<Vec<u8>> {
        let mut size: u32 = 0;
        for _ in 0..4 {
            let err = get(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, class, 0);
            if err != ERROR_INSUFFICIENT_BUFFER && err != NO_ERROR {
                anyhow::bail!("the connection table could not be sized (error {err})");
            }
            let mut buf = vec![0u8; size as usize];
            let err = get(
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
                0,
                AF_INET as u32,
                class,
                0,
            );
            if err == NO_ERROR {
                return Ok(buf);
            }
            if err != ERROR_INSUFFICIENT_BUFFER {
                anyhow::bail!("the connection table could not be read (error {err})");
            }
            // Grew between calls: go round again with the new size.
        }
        anyhow::bail!("the connection table kept changing size")
    }

    pub fn connections() -> Result<Vec<Connection>> {
        let names = process_names().unwrap_or_default();
        let mut out = Vec::new();

        // SAFETY: both buffers are sized by the API itself, and every read
        // below stays inside dwNumEntries as the header reports it.
        unsafe {
            let buf = read_table(GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL)
                .context("reading the TCP connection table")?;
            let head = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(head.table.as_ptr(), head.dwNumEntries as usize);
            for r in rows {
                out.push(Connection {
                    proto: "TCP",
                    local_addr: addr(r.dwLocalAddr),
                    local_port: port(r.dwLocalPort),
                    remote_addr: addr(r.dwRemoteAddr),
                    remote_port: port(r.dwRemotePort),
                    state: tcp_state(r.dwState),
                    pid: r.dwOwningPid,
                    process: names
                        .get(&r.dwOwningPid)
                        .cloned()
                        .unwrap_or_else(|| "?".into()),
                });
            }

            let buf = read_table(GetExtendedUdpTable, UDP_TABLE_OWNER_PID)
                .context("reading the UDP connection table")?;
            let head = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(head.table.as_ptr(), head.dwNumEntries as usize);
            for r in rows {
                // UDP is connectionless: the table knows the local socket only.
                out.push(Connection {
                    proto: "UDP",
                    local_addr: addr(r.dwLocalAddr),
                    local_port: port(r.dwLocalPort),
                    remote_addr: String::new(),
                    remote_port: 0,
                    state: "-",
                    pid: r.dwOwningPid,
                    process: names
                        .get(&r.dwOwningPid)
                        .cloned()
                        .unwrap_or_else(|| "?".into()),
                });
            }
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn connections() -> Result<Vec<Connection>> {
        anyhow::bail!(
            "socket-to-process attribution is implemented for Windows only; \
             on Linux it would read /proc/net plus the fd table"
        )
    }
}

pub use imp::connections;

/// Group the connection table by process, which is how people actually want
/// to read it: one line per program, not one per socket.
pub fn by_process(conns: Vec<Connection>) -> Vec<(String, u32, usize, Vec<Connection>)> {
    let mut groups: HashMap<(String, u32), Vec<Connection>> = HashMap::new();
    for c in conns {
        groups
            .entry((c.process.clone(), c.pid))
            .or_default()
            .push(c);
    }
    let mut out: Vec<_> = groups
        .into_iter()
        .map(|((name, pid), v)| (name, pid, v.len(), v))
        .collect();
    out.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
    out
}
