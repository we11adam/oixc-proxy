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
/// Upper bound on how long a default-route answer is reused while the
/// interface addresses stay the same.
const DEFAULT_ROUTE_RECHECK: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct NetworkMonitor {
    pinned_ip: Option<IpAddr>,
    state: Arc<Mutex<MonitorState>>,
}

struct MonitorState {
    selection: EgressSelection,
    generation: u64,
    checked_at: Instant,
    default_route: DefaultRouteCache,
}

/// Looking up the default route may spawn processes, which is too costly for
/// every refresh. Address changes accompany nearly every route change, so the
/// answer is reused until they change or the recheck interval passes.
#[derive(Default)]
struct DefaultRouteCache {
    addresses: Vec<InterfaceAddress>,
    interface: Option<String>,
    checked_at: Option<Instant>,
}

impl DefaultRouteCache {
    fn interface(
        &mut self,
        addresses: &[InterfaceAddress],
        lookup: impl FnOnce() -> Option<String>,
    ) -> Option<String> {
        let current = self.addresses == addresses
            && self
                .checked_at
                .is_some_and(|checked| checked.elapsed() < DEFAULT_ROUTE_RECHECK);
        if !current {
            self.interface = lookup();
            self.addresses = addresses.to_vec();
            self.checked_at = Some(Instant::now());
        }
        self.interface.clone()
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct InterfaceAddress {
    name: String,
    index: u32,
    address: IpAddr,
    state: AddressState,
}

/// IPv6 address state that matters for source selection. IPv4 addresses,
/// and IPv6 addresses whose state cannot be read, use the default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AddressState {
    /// A privacy address that the host replaces regularly.
    temporary: bool,
    /// Past its preferred lifetime and kept only for existing connections.
    deprecated: bool,
    /// Still in, or failed, duplicate address detection, so it cannot be
    /// bound yet.
    unassignable: bool,
}

impl NetworkMonitor {
    pub fn new(pinned_ip: Option<IpAddr>) -> Self {
        let mut default_route = DefaultRouteCache::default();
        let detected = detect_egress(pinned_ip, &mut default_route);
        let selection = detected
            .as_ref()
            .cloned()
            .unwrap_or_else(|_| EgressSelection::empty());
        let mut fields = selection.diagnostic_fields(1, pinned_ip);
        fields.push((
            "status",
            if detected.is_ok() { "ok" } else { "error" }.to_owned(),
        ));
        if let Err(error) = &detected {
            fields.push(("error", error.to_string()));
        }
        crate::perftrace::diagnostic("network.initial", &fields);
        Self {
            pinned_ip,
            state: Arc::new(Mutex::new(MonitorState {
                selection,
                generation: 1,
                checked_at: Instant::now(),
                default_route,
            })),
        }
    }

    pub async fn snapshot(&self) -> NetworkSnapshot {
        let mut state = self.state.lock().await;
        if state.checked_at.elapsed() >= REFRESH_INTERVAL {
            let pinned_ip = self.pinned_ip;
            let mut default_route = std::mem::take(&mut state.default_route);
            let detected = tokio::task::spawn_blocking(move || {
                let detected = detect_egress(pinned_ip, &mut default_route);
                (detected, default_route)
            })
            .await
            .map(|(detected, default_route)| {
                state.default_route = default_route;
                detected
            });
            state.checked_at = Instant::now();
            match detected {
                Ok(Ok(selection)) => {
                    if state.update(selection) {
                        crate::perftrace::diagnostic(
                            "network.changed",
                            &state
                                .selection
                                .diagnostic_fields(state.generation, self.pinned_ip),
                        );
                    }
                }
                Ok(Err(error)) => crate::perftrace::diagnostic(
                    "network.refresh",
                    &[("status", "error".to_owned()), ("error", error.to_string())],
                ),
                Err(error) => crate::perftrace::diagnostic(
                    "network.refresh",
                    &[
                        ("status", "join_error".to_owned()),
                        ("error", error.to_string()),
                    ],
                ),
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
    fn update(&mut self, selection: EgressSelection) -> bool {
        if self.selection != selection {
            self.selection = selection;
            self.generation = self.generation.wrapping_add(1).max(1);
            return true;
        }
        false
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

    fn diagnostic_fields(
        &self,
        generation: u64,
        pinned_ip: Option<IpAddr>,
    ) -> Vec<(&'static str, String)> {
        vec![
            ("generation", generation.to_string()),
            (
                "mode",
                if pinned_ip.is_some() {
                    "pinned"
                } else {
                    "automatic"
                }
                .to_owned(),
            ),
            (
                "interface",
                self.interface_name.as_deref().unwrap_or("none").to_owned(),
            ),
            (
                "interface_index",
                self.interface_index
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
            ),
            (
                "ipv4",
                self.ipv4
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
            ),
            (
                "ipv6",
                self.ipv6
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
            ),
        ]
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

    pub fn diagnostic_fields(&self) -> Vec<(&'static str, String)> {
        self.selection
            .diagnostic_fields(self.generation, self.pinned_ip)
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

fn detect_egress(
    pinned_ip: Option<IpAddr>,
    default_route: &mut DefaultRouteCache,
) -> io::Result<EgressSelection> {
    detect_egress_from_addresses(interface_addresses(), pinned_ip, |addresses| {
        default_route.interface(addresses, default_physical_interface)
    })
}

fn detect_egress_from_addresses(
    addresses: io::Result<Vec<InterfaceAddress>>,
    pinned_ip: Option<IpAddr>,
    default_interface: impl FnOnce(&[InterfaceAddress]) -> Option<String>,
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

    let preferred = default_interface(&addresses);
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
    let mut best_ipv6 = None;
    for entry in addresses.iter().filter(|entry| entry.name == name) {
        selection.interface_index = Some(entry.index);
        if pinned_ip.is_some_and(|pinned| pinned != entry.address) {
            continue;
        }
        match entry.address {
            IpAddr::V4(address) => {
                selection.ipv4.get_or_insert(address);
            }
            // A pinned address is used as configured. Otherwise prefer an
            // address that lasts: a unique local address only reaches the
            // site, a deprecated one is going away, and a temporary one is
            // replaced regularly, which would keep moving the egress.
            IpAddr::V6(address) if pinned_ip.is_some() || !entry.state.unassignable => {
                let rank = (
                    address.is_unique_local(),
                    entry.state.deprecated,
                    entry.state.temporary,
                );
                if best_ipv6.is_none_or(|(best, _)| rank < best) {
                    best_ipv6 = Some((rank, address));
                }
            }
            IpAddr::V6(_) => {}
        }
    }
    selection.ipv6 = best_ipv6.map(|(_, address)| address);
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
    let states = Ipv6States::load();
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
                    let state = match address {
                        IpAddr::V6(address) => states.get(&name, address),
                        IpAddr::V4(_) => AddressState::default(),
                    };
                    result.push(InterfaceAddress {
                        name,
                        index,
                        address,
                        state,
                    });
                }
            }
        }
        current = item.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    Ok(result)
}

/// Reads IPv6 address flags with `SIOCGIFAFLAG_IN6`.
#[cfg(target_os = "macos")]
struct Ipv6States(Option<std::os::fd::OwnedFd>);

#[cfg(target_os = "macos")]
impl Ipv6States {
    fn load() -> Self {
        use std::os::fd::FromRawFd;

        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        Self((fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }))
    }

    fn get(&self, name: &str, address: Ipv6Addr) -> AddressState {
        use std::os::fd::AsRawFd;

        let Some(socket) = &self.0 else {
            return AddressState::default();
        };
        let mut request: libc::in6_ifreq = unsafe { std::mem::zeroed() };
        if name.len() >= request.ifr_name.len() {
            return AddressState::default();
        }
        for (target, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *target = byte as libc::c_char;
        }
        let mut socket_address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        socket_address.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        socket_address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        socket_address.sin6_addr.s6_addr = address.octets();
        request.ifr_ifru.ifru_addr = socket_address;
        if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFAFLAG_IN6, &mut request) } != 0 {
            return AddressState::default();
        }
        let flags = unsafe { request.ifr_ifru.ifru_flags6 };
        AddressState {
            temporary: flags & libc::IN6_IFF_TEMPORARY != 0,
            deprecated: flags & libc::IN6_IFF_DEPRECATED != 0,
            unassignable: flags & libc::IN6_IFF_OPTIMISTIC == 0
                && flags
                    & (libc::IN6_IFF_TENTATIVE | libc::IN6_IFF_DUPLICATED | libc::IN6_IFF_DETACHED)
                    != 0,
        }
    }
}

/// Reads IPv6 address flags from `/proc/net/if_inet6`.
#[cfg(target_os = "linux")]
struct Ipv6States(Vec<(String, Ipv6Addr, AddressState)>);

#[cfg(target_os = "linux")]
impl Ipv6States {
    fn load() -> Self {
        Self(
            std::fs::read_to_string("/proc/net/if_inet6")
                .map(|content| parse_if_inet6(&content))
                .unwrap_or_default(),
        )
    }

    fn get(&self, name: &str, address: Ipv6Addr) -> AddressState {
        self.0
            .iter()
            .find(|(entry_name, entry_address, _)| entry_name == name && *entry_address == address)
            .map(|(_, _, state)| *state)
            .unwrap_or_default()
    }
}

/// Parses lines of `address index prefix scope flags name`, where flags are
/// the low byte of the kernel `IFA_F_*` address flags.
#[cfg(any(target_os = "linux", test))]
fn parse_if_inet6(content: &str) -> Vec<(String, Ipv6Addr, AddressState)> {
    const TEMPORARY: u8 = 0x01;
    const OPTIMISTIC: u8 = 0x04;
    const DAD_FAILED: u8 = 0x08;
    const DEPRECATED: u8 = 0x20;
    const TENTATIVE: u8 = 0x40;

    content
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [address, _, _, _, flags, name] = fields[..] else {
                return None;
            };
            let address = u128::from_str_radix(address, 16).ok()?;
            let flags = u8::from_str_radix(flags, 16).ok()?;
            let state = AddressState {
                temporary: flags & TEMPORARY != 0,
                deprecated: flags & DEPRECATED != 0,
                unassignable: flags & DAD_FAILED != 0
                    || (flags & TENTATIVE != 0 && flags & OPTIMISTIC == 0),
            };
            Some((name.to_owned(), Ipv6Addr::from(address), state))
        })
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct Ipv6States;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Ipv6States {
    fn load() -> Self {
        Self
    }

    fn get(&self, _name: &str, _address: Ipv6Addr) -> AddressState {
        AddressState::default()
    }
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
            default_route: DefaultRouteCache::default(),
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
            |_| None,
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

    #[test]
    fn default_route_lookup_is_reused_until_addresses_change() {
        let wifi = InterfaceAddress {
            name: "en0".to_owned(),
            index: 4,
            address: "192.0.2.10".parse().unwrap(),
            state: AddressState::default(),
        };
        let mut cache = DefaultRouteCache::default();
        let mut lookups = 0;
        let mut lookup = |addresses: &[InterfaceAddress]| {
            cache.interface(addresses, || {
                lookups += 1;
                Some("en0".to_owned())
            })
        };
        assert_eq!(lookup(std::slice::from_ref(&wifi)).as_deref(), Some("en0"));
        assert_eq!(lookup(std::slice::from_ref(&wifi)).as_deref(), Some("en0"));
        let moved = InterfaceAddress {
            address: "198.51.100.10".parse().unwrap(),
            ..wifi
        };
        lookup(&[moved]);
        assert_eq!(lookups, 2);
    }

    #[test]
    fn global_ipv6_is_preferred_over_unique_local() {
        let entry = |address: &str| InterfaceAddress {
            name: "en0".to_owned(),
            index: 4,
            address: address.parse().unwrap(),
            state: AddressState::default(),
        };
        let addresses = [
            entry("fd00::10"),
            entry("192.0.2.10"),
            entry("2001:db8::10"),
            entry("2001:db8::11"),
        ];
        let selection = selection_for_interface(&addresses, "en0", None);
        assert_eq!(selection.ipv6, Some("2001:db8::10".parse().unwrap()));
        let selection = selection_for_interface(&addresses[..2], "en0", None);
        assert_eq!(selection.ipv6, Some("fd00::10".parse().unwrap()));
    }

    #[test]
    fn stable_ipv6_is_preferred_and_unassignable_is_skipped() {
        let entry = |address: &str, state: AddressState| InterfaceAddress {
            name: "en0".to_owned(),
            index: 4,
            address: address.parse().unwrap(),
            state,
        };
        let temporary = AddressState {
            temporary: true,
            ..AddressState::default()
        };
        let deprecated = AddressState {
            deprecated: true,
            ..AddressState::default()
        };
        let tentative = AddressState {
            unassignable: true,
            ..AddressState::default()
        };
        let addresses = [
            entry("2001:db8::1", tentative),
            entry("2001:db8::2", deprecated),
            entry("2001:db8::3", temporary),
            entry("2001:db8::4", AddressState::default()),
        ];
        let best = |addresses: &[InterfaceAddress]| {
            selection_for_interface(addresses, "en0", None)
                .ipv6
                .map(|address| address.to_string())
        };
        assert_eq!(best(&addresses).as_deref(), Some("2001:db8::4"));
        assert_eq!(best(&addresses[..3]).as_deref(), Some("2001:db8::3"));
        assert_eq!(best(&addresses[..2]).as_deref(), Some("2001:db8::2"));
        assert_eq!(best(&addresses[..1]), None);

        let pinned = "2001:db8::1".parse().unwrap();
        let selection = selection_for_interface(&addresses, "en0", Some(pinned));
        assert_eq!(selection.ipv6.map(IpAddr::V6), Some(pinned));
    }

    #[test]
    fn proc_if_inet6_flags_are_parsed() {
        let content = concat!(
            "20010db8000000000000000000000001 02 40 00 80     eth0\n",
            "20010db8000000000000000000000002 02 40 00 01     eth0\n",
            "20010db8000000000000000000000003 02 40 00 a0     eth0\n",
            "20010db8000000000000000000000004 02 40 00 40     eth0\n",
            "20010db8000000000000000000000005 02 40 00 44     eth0\n",
            "malformed\n",
        );
        let states: Vec<_> = parse_if_inet6(content)
            .into_iter()
            .map(|(name, address, state)| {
                assert_eq!(name, "eth0");
                (address.segments()[7], state)
            })
            .collect();
        let state = |temporary, deprecated, unassignable| AddressState {
            temporary,
            deprecated,
            unassignable,
        };
        assert_eq!(
            states,
            [
                (1, state(false, false, false)),
                (2, state(true, false, false)),
                (3, state(false, true, false)),
                (4, state(false, false, true)),
                (5, state(false, false, false)),
            ]
        );
    }
}
