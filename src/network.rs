use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "macos")]
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::Mutex;

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct NetworkMonitor {
    pinned_ip: Option<IpAddr>,
    state: Arc<Mutex<MonitorState>>,
}

struct MonitorState {
    selection: EgressSelection,
    generation: u64,
    checked_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EgressSelection {
    interface_name: Option<String>,
    interface_index: Option<u32>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

#[derive(Clone, Debug)]
pub struct NetworkSnapshot {
    selection: EgressSelection,
    pinned_ip: Option<IpAddr>,
    generation: u64,
}

#[derive(Clone, Debug)]
struct InterfaceAddress {
    name: String,
    index: u32,
    address: IpAddr,
}

impl NetworkMonitor {
    pub fn new(pinned_ip: Option<IpAddr>) -> Self {
        let selection = detect_egress(pinned_ip).unwrap_or_else(|_| EgressSelection::empty());
        Self {
            pinned_ip,
            state: Arc::new(Mutex::new(MonitorState {
                selection,
                generation: 1,
                checked_at: Instant::now(),
            })),
        }
    }

    pub async fn snapshot(&self) -> NetworkSnapshot {
        let mut state = self.state.lock().await;
        if state.checked_at.elapsed() >= REFRESH_INTERVAL {
            let pinned_ip = self.pinned_ip;
            let detected = tokio::task::spawn_blocking(move || detect_egress(pinned_ip)).await;
            state.checked_at = Instant::now();
            if let Ok(Ok(selection)) = detected {
                state.update(selection);
            }
        }
        NetworkSnapshot {
            selection: state.selection.clone(),
            pinned_ip: self.pinned_ip,
            generation: state.generation,
        }
    }
}

impl MonitorState {
    fn update(&mut self, selection: EgressSelection) {
        if self.selection != selection {
            self.selection = selection;
            self.generation = self.generation.wrapping_add(1).max(1);
        }
    }
}

impl EgressSelection {
    fn empty() -> Self {
        Self {
            interface_name: None,
            interface_index: None,
            ipv4: None,
            ipv6: None,
        }
    }

    fn has_address(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }

    #[cfg(target_os = "linux")]
    fn pinned_without_interface(address: IpAddr) -> Self {
        let mut selection = Self::empty();
        match address {
            IpAddr::V4(address) => selection.ipv4 = Some(address),
            IpAddr::V6(address) => selection.ipv6 = Some(address),
        }
        selection
    }
}

impl NetworkSnapshot {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn preferred_source(&self) -> io::Result<Option<IpAddr>> {
        let source = self
            .selection
            .ipv4
            .map(IpAddr::V4)
            .or_else(|| self.selection.ipv6.map(IpAddr::V6));
        if source.is_none() && self.pinned_ip.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "configured outbound IP is not assigned to an active interface",
            ));
        }
        Ok(source)
    }

    pub fn interface_name(&self) -> Option<&str> {
        self.selection.interface_name.as_deref()
    }

    fn source_for(&self, destination: SocketAddr) -> Option<IpAddr> {
        match destination {
            SocketAddr::V4(_) => self.selection.ipv4.map(IpAddr::V4),
            SocketAddr::V6(_) => self.selection.ipv6.map(IpAddr::V6),
        }
    }

    pub fn supports(&self, destination: SocketAddr) -> bool {
        if self.pinned_ip.is_some() {
            return self.source_for(destination).is_some();
        }
        !self.selection.has_address() || self.source_for(destination).is_some()
    }

    pub fn bind_tcp(&self, socket: &TcpSocket, destination: SocketAddr) -> io::Result<()> {
        if let Some(source) = self.source_for(destination) {
            socket.bind(SocketAddr::new(source, 0))?;
        } else if self.pinned_ip.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "configured outbound IP is not assigned to an active interface",
            ));
        }
        self.bind_interface(socket, destination)
    }

    pub fn bind_udp(&self, socket: &UdpSocket, destination: SocketAddr) -> io::Result<()> {
        self.bind_interface(socket, destination)
    }

    #[cfg(target_os = "macos")]
    fn bind_interface<T>(&self, socket: &T, destination: SocketAddr) -> io::Result<()>
    where
        T: std::os::fd::AsFd,
    {
        let Some(index) = self.selection.interface_index.and_then(NonZeroU32::new) else {
            return if self.pinned_ip.is_some() {
                Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "configured outbound interface is unavailable",
                ))
            } else {
                Ok(())
            };
        };
        let socket = socket2::SockRef::from(socket);
        if destination.is_ipv4() {
            socket.bind_device_by_index_v4(Some(index))
        } else {
            socket.bind_device_by_index_v6(Some(index))
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn bind_interface<T>(&self, _socket: &T, _destination: SocketAddr) -> io::Result<()> {
        Ok(())
    }
}

pub async fn bind_udp_socket(
    snapshot: &NetworkSnapshot,
    destination: SocketAddr,
) -> io::Result<UdpSocket> {
    let bind_ip = snapshot.source_for(destination).unwrap_or_else(|| {
        if destination.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        }
    });
    if snapshot.pinned_ip.is_some() && bind_ip.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "configured outbound IP is not assigned to an active interface",
        ));
    }
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    snapshot.bind_udp(&socket, destination)?;
    Ok(socket)
}

fn detect_egress(pinned_ip: Option<IpAddr>) -> io::Result<EgressSelection> {
    detect_egress_from_addresses(interface_addresses(), pinned_ip)
}

fn detect_egress_from_addresses(
    addresses: io::Result<Vec<InterfaceAddress>>,
    pinned_ip: Option<IpAddr>,
) -> io::Result<EgressSelection> {
    let addresses = match addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            #[cfg(target_os = "linux")]
            if let Some(pinned_ip) = pinned_ip {
                return Ok(EgressSelection::pinned_without_interface(pinned_ip));
            }
            return Err(error);
        }
    };
    if let Some(pinned_ip) = pinned_ip {
        let Some(pinned) = addresses.iter().find(|entry| entry.address == pinned_ip) else {
            return Ok(EgressSelection::empty());
        };
        return Ok(selection_for_interface(
            &addresses,
            &pinned.name,
            Some(pinned_ip),
        ));
    }

    let preferred = default_physical_interface();
    let selected = addresses
        .iter()
        .filter(|entry| !is_virtual_interface(&entry.name))
        .max_by_key(|entry| interface_score(&entry.name, preferred.as_deref()))
        .map(|entry| entry.name.as_str());
    Ok(selected
        .map(|name| selection_for_interface(&addresses, name, None))
        .unwrap_or_else(EgressSelection::empty))
}

fn selection_for_interface(
    addresses: &[InterfaceAddress],
    name: &str,
    pinned_ip: Option<IpAddr>,
) -> EgressSelection {
    let mut selection = EgressSelection::empty();
    selection.interface_name = Some(name.to_owned());
    for entry in addresses.iter().filter(|entry| entry.name == name) {
        selection.interface_index = Some(entry.index);
        match entry.address {
            IpAddr::V4(address)
                if pinned_ip.is_none() || pinned_ip == Some(IpAddr::V4(address)) =>
            {
                selection.ipv4.get_or_insert(address);
            }
            IpAddr::V6(address)
                if pinned_ip.is_none() || pinned_ip == Some(IpAddr::V6(address)) =>
            {
                selection.ipv6.get_or_insert(address);
            }
            _ => {}
        }
    }
    selection
}

fn interface_score(name: &str, preferred: Option<&str>) -> u16 {
    let mut score = if Some(name) == preferred { 1000 } else { 0 };
    score += if name == "en0" || name == "br-lan" {
        500
    } else if name.starts_with("en")
        || name.starts_with("eth")
        || name.starts_with("wlan")
        || name.starts_with("wl")
        || name.starts_with("ppp")
    {
        400
    } else {
        100
    };
    score
}

fn is_virtual_interface(name: &str) -> bool {
    [
        "lo",
        "utun",
        "tun",
        "tap",
        "wg",
        "tailscale",
        "docker",
        "veth",
        "vmnet",
        "awdl",
        "llw",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

#[cfg(target_os = "linux")]
fn default_physical_interface() -> Option<String> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8 || fields[1] != "00000000" || is_virtual_interface(fields[0]) {
                return None;
            }
            let flags = u32::from_str_radix(fields[3], 16).ok()?;
            if flags & 1 == 0 {
                return None;
            }
            let metric = fields[6].parse::<u32>().ok()?;
            Some((metric, fields[0].to_owned()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, name)| name)
}

#[cfg(target_os = "macos")]
fn default_physical_interface() -> Option<String> {
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    if output.status.success() {
        if let Some(name) = String::from_utf8_lossy(&output.stdout)
            .lines()
            .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
            .filter(|name| !is_virtual_interface(name))
        {
            return Some(name.to_owned());
        }
    }

    let output = std::process::Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    physical_default_from_netstat(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "macos")]
fn physical_default_from_netstat(routes: &str) -> Option<String> {
    routes
        .lines()
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let name = fields.last().copied()?;
            (fields.first() == Some(&"default") && !is_virtual_interface(name)).then_some(name)
        })
        .map(str::to_owned)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn default_physical_interface() -> Option<String> {
    None
}

fn interface_addresses() -> io::Result<Vec<InterfaceAddress>> {
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut result = Vec::new();
    let mut current = head;
    while !current.is_null() {
        let item = unsafe { &*current };
        if !item.ifa_addr.is_null()
            && item.ifa_flags & libc::IFF_UP as u32 != 0
            && item.ifa_flags & libc::IFF_LOOPBACK as u32 == 0
        {
            let name = unsafe { CStr::from_ptr(item.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let family = unsafe { (*item.ifa_addr).sa_family as i32 };
            let address = if family == libc::AF_INET {
                let address = unsafe { &*(item.ifa_addr.cast::<libc::sockaddr_in>()) };
                Some(IpAddr::V4(Ipv4Addr::from(
                    address.sin_addr.s_addr.to_ne_bytes(),
                )))
            } else if family == libc::AF_INET6 {
                let address = unsafe { &*(item.ifa_addr.cast::<libc::sockaddr_in6>()) };
                Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
            } else {
                None
            };
            if let Some(address) = address.filter(is_usable_address) {
                let index = unsafe { libc::if_nametoindex(item.ifa_name) };
                if index != 0 {
                    result.push(InterfaceAddress {
                        name,
                        index,
                        address,
                    });
                }
            }
        }
        current = item.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    Ok(result)
}

fn is_usable_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_generation_changes_only_with_the_selection() {
        let first = EgressSelection {
            interface_name: Some("en0".to_owned()),
            interface_index: Some(4),
            ipv4: Some("192.0.2.10".parse().unwrap()),
            ipv6: None,
        };
        let second = EgressSelection {
            interface_name: Some("en1".to_owned()),
            interface_index: Some(5),
            ipv4: Some("198.51.100.10".parse().unwrap()),
            ipv6: None,
        };
        let mut state = MonitorState {
            selection: first.clone(),
            generation: 7,
            checked_at: Instant::now(),
        };
        state.update(first);
        assert_eq!(state.generation, 7);
        state.update(second);
        assert_eq!(state.generation, 8);
    }

    #[test]
    fn virtual_interfaces_are_not_selected_as_physical_egress() {
        for name in ["lo0", "utun4", "tun0", "wg0", "docker0", "veth123"] {
            assert!(is_virtual_interface(name), "{name}");
        }
        for name in ["en0", "en7", "eth0", "wlan0", "br-lan", "pppoe-wan"] {
            assert!(!is_virtual_interface(name), "{name}");
        }
    }

    #[test]
    fn unavailable_pinned_address_does_not_fall_back() {
        let snapshot = NetworkSnapshot {
            selection: EgressSelection::empty(),
            pinned_ip: Some("192.0.2.10".parse().unwrap()),
            generation: 2,
        };
        assert!(snapshot.preferred_source().is_err());
        assert!(!snapshot.supports("198.51.100.1:443".parse().unwrap()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restricted_interface_discovery_keeps_pinned_source() {
        let address = "192.0.2.10".parse().unwrap();
        let selection = detect_egress_from_addresses(
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "AF_NETLINK is restricted",
            )),
            Some(address),
        )
        .unwrap();
        assert_eq!(selection.interface_name, None);
        assert_eq!(selection.interface_index, None);
        assert_eq!(selection.ipv4, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(selection.ipv6, None);
    }

    #[test]
    fn default_route_interface_wins_selection_scoring() {
        assert!(interface_score("en7", Some("en7")) > interface_score("en0", Some("en7")));
        assert!(interface_score("en0", None) > interface_score("bridge0", None));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_route_fallback_keeps_routing_table_priority() {
        let routes = concat!(
            "default link#22 UCSIg utun4\n",
            "default 192.0.2.1 UGScg en7\n",
            "default 198.51.100.1 UGScg en0\n",
        );
        assert_eq!(
            physical_default_from_netstat(routes).as_deref(),
            Some("en7")
        );
    }
}
