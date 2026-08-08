use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::OnceLock;

use serde_json::Value;

use crate::routes::lan_cowork_host::LanCoworkHost;

static BOUND_ADDR: OnceLock<SocketAddr> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalDescriptor {
    pub peer_id: String,
    pub name: String,
    pub api_host: String,
    pub api_port: u16,
    pub version: String,
    pub bridges: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DescriptorError {
    BoundPortUnavailable,
    LanAddressUnavailable,
    IdentityUnavailable,
    InvalidAddress,
}

pub fn set_bound_addr(addr: SocketAddr) {
    BOUND_ADDR
        .set(addr)
        .expect("bound address must be set once");
}

pub(crate) fn bound_addr() -> Option<SocketAddr> {
    BOUND_ADDR.get().copied()
}

pub(crate) fn is_reachable_peer_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        #[cfg(any(test, feature = "test-seams"))]
        if TEST_ALLOW_LOOPBACK.load(std::sync::atomic::Ordering::Relaxed) {
            return true;
        }
        return false;
    }
    match ip {
        IpAddr::V4(ip) => ip.is_private() && !ip.is_link_local() && !ip.is_unspecified(),
        IpAddr::V6(ip) => {
            (ip.segments()[0] & 0xfe00) == 0xfc00
                && !ip.is_unicast_link_local()
                && !ip.is_unspecified()
        }
    }
}

pub(crate) fn is_valid_peer_port(port: i64) -> bool {
    (1..=65_535).contains(&port)
}

fn configured_peer_name(state: &dyn LanCoworkHost) -> String {
    let configured = state
        .config_json()
        .get("extensions")
        .and_then(|extensions| extensions.get("builtin-lan-cowork"))
        .and_then(|cowork| cowork.get("peer_name"))
        .and_then(Value::as_str)
        .unwrap_or("auto");
    if configured == "auto" {
        std::env::var("HOSTNAME")
            .ok()
            .filter(|name| !name.is_empty())
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty())
            })
            .unwrap_or_else(|| "localhost".to_string())
    } else {
        configured.to_string()
    }
}

fn resolve_lan_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(addr.ip().to_string()),
        SocketAddr::V6(_) => None,
    }
}

fn advertise_host(bound: Option<SocketAddr>) -> Option<String> {
    let bound = bound?;
    if bound.ip().is_unspecified() {
        resolve_lan_ip()
    } else if bound.ip().is_loopback() {
        None
    } else {
        Some(bound.ip().to_string())
    }
}

pub(crate) fn build_descriptor(
    peer_id: &str,
    name: &str,
    host: Option<&str>,
    port: Option<u16>,
    version: &str,
    bridges: &[String],
) -> Result<LocalDescriptor, DescriptorError> {
    let port = port.ok_or(DescriptorError::BoundPortUnavailable)?;
    let host = host.ok_or(DescriptorError::LanAddressUnavailable)?;
    let ip = host.parse().map_err(|_| DescriptorError::InvalidAddress)?;
    if !is_reachable_peer_ip(ip) || !is_valid_peer_port(i64::from(port)) {
        return Err(DescriptorError::InvalidAddress);
    }
    Ok(LocalDescriptor {
        peer_id: peer_id.to_string(),
        name: name.to_string(),
        api_host: host.to_string(),
        api_port: port,
        version: version.to_string(),
        bridges: bridges.to_vec(),
    })
}

pub(crate) async fn local_descriptor(
    state: &dyn LanCoworkHost,
) -> Result<LocalDescriptor, DescriptorError> {
    let peer_id = crate::routes::peer_identity::local_peer_id(state)
        .await
        .ok_or(DescriptorError::IdentityUnavailable)?;
    let bound = bound_addr();
    let host = advertise_host(bound);
    build_descriptor(
        &peer_id,
        &configured_peer_name(state),
        host.as_deref(),
        bound.map(|addr| addr.port()),
        state.version(),
        &[],
    )
}

#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
pub static TEST_ALLOW_LOOPBACK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
pub static TEST_DESCRIPTOR: std::sync::Mutex<Option<Result<LocalDescriptor, DescriptorError>>> =
    std::sync::Mutex::new(None);

#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
pub fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(any(test, feature = "test-seams"))]
#[doc(hidden)]
pub fn reset_client_state() {
    TEST_ALLOW_LOOPBACK.store(false, std::sync::atomic::Ordering::Relaxed);
    *TEST_DESCRIPTOR.lock().unwrap_or_else(|e| e.into_inner()) = None;
    crate::routes::lan_cowork_client::clear_client_state();
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::*;

    fn descriptor(
        host: Option<&str>,
        port: Option<u16>,
    ) -> Result<LocalDescriptor, DescriptorError> {
        build_descriptor(
            "peer-id",
            "node",
            host,
            port,
            "1.0.0",
            &["tagger".to_string()],
        )
    }

    #[test]
    fn reachable_peer_addresses_follow_the_lan_policy() {
        let _guard = test_guard();
        reset_client_state();

        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1"] {
            assert!(is_reachable_peer_ip(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "2001:4860::1",
            "127.0.0.1",
            "::1",
            "169.254.1.1",
            "fe80::1",
            "fe90::1",
            "febf::1",
            "0.0.0.0",
            "::",
        ] {
            assert!(!is_reachable_peer_ip(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
        assert!(is_valid_peer_port(1));
        assert!(is_valid_peer_port(65_535));
        assert!(!is_valid_peer_port(0));
        assert!(!is_valid_peer_port(65_536));
    }

    #[test]
    fn loopback_escape_hatch_is_closed_by_default_and_narrow_when_open() {
        let _guard = test_guard();
        reset_client_state();

        assert!(!TEST_ALLOW_LOOPBACK.load(std::sync::atomic::Ordering::Relaxed));
        TEST_ALLOW_LOOPBACK.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(is_reachable_peer_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_reachable_peer_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_reachable_peer_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn descriptor_rejects_missing_or_unreachable_bind_details() {
        let _guard = test_guard();
        reset_client_state();

        assert_eq!(
            descriptor(Some("10.0.0.1"), None),
            Err(DescriptorError::BoundPortUnavailable)
        );
        assert_eq!(
            descriptor(None, Some(5000)),
            Err(DescriptorError::LanAddressUnavailable)
        );
        for host in ["127.0.0.1", "169.254.1.1", "0.0.0.0"] {
            assert_eq!(
                descriptor(Some(host), Some(5000)),
                Err(DescriptorError::InvalidAddress)
            );
        }
    }

    #[test]
    fn descriptor_contains_the_six_wire_fields() {
        let _guard = test_guard();
        reset_client_state();

        assert_eq!(
            descriptor(Some("10.0.0.1"), Some(5000)).unwrap(),
            LocalDescriptor {
                peer_id: "peer-id".to_string(),
                name: "node".to_string(),
                api_host: "10.0.0.1".to_string(),
                api_port: 5000,
                version: "1.0.0".to_string(),
                bridges: vec!["tagger".to_string()],
            }
        );
    }

    #[test]
    fn advertise_host_returns_none_before_binding() {
        assert_eq!(advertise_host(None), None);
    }

    #[test]
    fn advertise_host_uses_route_for_unspecified_bind() {
        let actual = resolve_lan_ip();
        assert_eq!(
            advertise_host(Some("0.0.0.0:5000".parse::<SocketAddr>().unwrap())),
            actual
        );
    }

    #[test]
    fn advertise_host_rejects_loopback_bind() {
        assert_eq!(
            advertise_host(Some("127.0.0.1:5000".parse::<SocketAddr>().unwrap())),
            None
        );
    }

    #[test]
    fn advertise_host_uses_concrete_bind_address() {
        assert_eq!(
            advertise_host(Some("192.168.1.10:5000".parse::<SocketAddr>().unwrap())),
            Some("192.168.1.10".to_string())
        );
    }

    #[tokio::test]
    async fn local_descriptor_uses_the_bound_address() {
        let _guard = test_guard();
        reset_client_state();
        set_bound_addr("10.0.0.1:5000".parse().unwrap());
        let state = crate::state::semantic_test_state(false).await;
        sqlx::raw_sql(
            "CREATE TABLE lan_cowork_identity (key TEXT PRIMARY KEY, value BLOB);
             INSERT INTO lan_cowork_identity VALUES ('ed25519_seed', zeroblob(32));",
        )
        .execute(&state.db)
        .await
        .unwrap();

        let descriptor = local_descriptor(&*state).await.unwrap();
        assert_eq!(descriptor.api_host, "10.0.0.1");
        assert_eq!(descriptor.api_port, 5000);
    }
}
