//! Native adapter discovery; no locale-sensitive parsing of ipconfig output.
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::*;

use crate::network::{AddressState, InterfaceAddress};

struct Entry {
    address: InterfaceAddress,
    gateway: bool,
    metric: u32,
}

fn adapters() -> io::Result<Vec<Entry>> {
    // u64 storage supplies the alignment required by IP_ADAPTER_ADDRESSES_LH.
    let mut length = 16384u32;
    for _ in 0..4 {
        let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
        let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                GAA_FLAG_INCLUDE_GATEWAYS,
                std::ptr::null(),
                head,
                &mut length,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status == ERROR_NO_DATA {
            return Ok(Vec::new());
        }
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut output = Vec::new();
        let mut current = head;
        while !current.is_null() {
            let adapter = unsafe { &*current };
            current = adapter.Next;
            if adapter.OperStatus != IfOperStatusUp || matches!(adapter.IfType, 24 | 131) {
                continue;
            }
            let name = unsafe { text(adapter.FriendlyName) };
            let description = unsafe { text(adapter.Description) }.to_lowercase();
            if [
                "wintun",
                "wireguard",
                "tailscale",
                "tap-windows",
                "virtual",
                "vpn",
            ]
            .iter()
            .any(|part| description.contains(part))
                || name.to_lowercase().starts_with("vethernet")
            {
                continue;
            }
            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                let entry = unsafe { &*unicast };
                unicast = entry.Next;
                let address = entry.Address.lpSockaddr;
                if address.is_null() {
                    continue;
                }
                let (address, index, metric) = match unsafe { (*address).sa_family } {
                    AF_INET => {
                        let address = unsafe { &*address.cast::<SOCKADDR_IN>() };
                        let ip =
                            Ipv4Addr::from(unsafe { address.sin_addr.S_un.S_addr }.to_ne_bytes());
                        (
                            IpAddr::V4(ip),
                            unsafe { adapter.Anonymous1.Anonymous.IfIndex },
                            adapter.Ipv4Metric,
                        )
                    }
                    AF_INET6 => {
                        let address = unsafe { &*address.cast::<SOCKADDR_IN6>() };
                        (
                            IpAddr::V6(Ipv6Addr::from(unsafe { address.sin6_addr.u.Byte })),
                            adapter.Ipv6IfIndex,
                            adapter.Ipv6Metric,
                        )
                    }
                    _ => continue,
                };
                if index == 0 || !crate::network::is_usable_address(&address) {
                    continue;
                }
                output.push(Entry {
                    address: InterfaceAddress {
                        name: name.clone(),
                        index,
                        address,
                        state: AddressState {
                            temporary: entry.SuffixOrigin == IpSuffixOriginRandom,
                            deprecated: entry.DadState == IpDadStateDeprecated,
                            unassignable: entry.DadState != IpDadStatePreferred
                                && entry.DadState != IpDadStateDeprecated,
                        },
                    },
                    gateway: !adapter.FirstGatewayAddress.is_null(),
                    metric,
                });
            }
        }
        return Ok(output);
    }
    Err(io::Error::other(
        "network adapters changed repeatedly during enumeration",
    ))
}

// These NUL-terminated strings and linked lists are owned by the OS-filled buffer.
unsafe fn text(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0;
    unsafe {
        while *pointer.add(length) != 0 {
            length += 1;
        }
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
}

pub(crate) fn addresses() -> io::Result<Vec<InterfaceAddress>> {
    Ok(adapters()?.into_iter().map(|entry| entry.address).collect())
}

pub fn default_interface() -> Option<String> {
    adapters()
        .ok()?
        .into_iter()
        .filter(|entry| entry.gateway)
        .min_by_key(|entry| entry.metric)
        .map(|entry| entry.address.name)
}
