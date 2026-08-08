//! LAN Cowork UDP discovery TOFU logic (Increment B-d4).
//!
//! Port of extensions/builtin_lan_cowork/manager.py::_on_peer_found. Verifies a
//! received HELLO and upserts the peer into the registry. Dead-code until B-d5
//! wires the UDP recv loop; the socket / self-exclusion / broadcast are B-d5.
//! `generating` and `queue_depth` are HTTP-heartbeat fields, not UDP-HELLO fields.
//! recv_loop backs off and retries on recv error (non-terminating under fire-and-forget) — NH-1.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use socket2::{Domain, Protocol, Socket, Type};

use crate::auth::peer_hello::{
    build_hello_packet, parse_hello_packet, verify_hello, ParsedHello, PeerHelloInfo,
};
use crate::routes::lan_cowork_host::LanCoworkState;

use super::lan_cowork_inbound_read::assemble_local_peer_info;
use super::lan_cowork_peer_api::validate_register_host;
use super::lan_cowork_registry::{PeerInfo, PeerRegistry};
use super::peer_identity::derive_peer_id;

const UDP_DISCOVERY_PORT: u16 = 19850;
const HELLO_TICK_SECS: u64 = 10;
const REPLAY_WINDOW_SEC: u64 = 60;
const RECV_BUF_LEN: usize = 4096;
/// Fixed back-off after a UDP recv error before retrying the read, so a persistent
/// error cannot busy-spin the fire-and-forget receive task. 500 ms bounds it to <=2 Hz.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// SF-5: suppress replayed HELLOs before they reach handle_hello.
struct ReplayGuard {
    seen: HashMap<(String, u64), u64>,
}

/// Bind the IPv4 UDP discovery socket with reuse and broadcast enabled.
fn bind_discovery_socket(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// Map a bind result to a shared socket, warning + skipping on any bind error
/// (EADDRINUSE included). Pure decision point so the graceful-skip branch is unit-testable
/// without creating a socket.
fn discovery_socket_or_skip(
    bind: std::io::Result<tokio::net::UdpSocket>,
) -> Option<Arc<tokio::net::UdpSocket>> {
    match bind {
        Ok(sock) => Some(Arc::new(sock)),
        Err(error) => {
            tracing::warn!(%error, "LAN Cowork discovery disabled (UDP bind failed)");
            None
        }
    }
}

/// Discovery daemon must not run in safe_mode (parent decomposition near-B3).
fn should_start_discovery(safe_mode: bool) -> bool {
    !safe_mode
}

/// Project the local PeerInfo onto the HELLO codec input; keys stay None because signing derives
/// them from the seed.
fn hello_info_from_peer(peer: &PeerInfo) -> PeerHelloInfo {
    PeerHelloInfo {
        peer_id: peer.peer_id.clone(),
        name: peer.name.clone(),
        api_host: peer.api_host.clone(),
        api_port: peer.api_port,
        version: peer.version.clone(),
        bridges: peer.bridges.clone(),
        inference_types: peer.inference_types.clone(),
        pubkey: None,
        x25519_pk: None,
    }
}

/// Production broadcast destination(s).
fn broadcast_targets() -> Vec<SocketAddr> {
    vec![SocketAddr::from(([255, 255, 255, 255], UDP_DISCOVERY_PORT))]
}

/// Build one signed HELLO and send it to every broadcast target.
async fn send_hello_tick(
    socket: &tokio::net::UdpSocket,
    peer: &PeerInfo,
    seed: &[u8],
    targets: &[SocketAddr],
    now: u64,
) -> Option<usize> {
    // Peer identity and seed share the lan_cowork_identity row; a mismatch is self-rejected.
    let packet = build_hello_packet(&hello_info_from_peer(peer), Some(seed), now)?;
    let mut sent = 0;
    for target in targets {
        match socket.send_to(&packet, target).await {
            Ok(_) => sent += 1,
            Err(_) => tracing::warn!(%target, "failed to send LAN Cowork HELLO"),
        }
    }
    Some(sent)
}

/// Process one received datagram, returning None for dropped input.
async fn process_datagram(
    buf: &[u8],
    src_ip: &str,
    registry: &PeerRegistry,
    local_peer_id: &str,
    replay: &mut ReplayGuard,
    now: u64,
) -> Option<HelloOutcome> {
    let parsed = parse_hello_packet(buf)?;
    let peer_id = derive_peer_id(&parsed.pubkey);
    if peer_id == local_peer_id {
        return None;
    }
    if let Some(port) = parsed.peer_dict.get("api_port").and_then(Value::as_u64) {
        if !(1..=65535).contains(&port) {
            return None;
        }
    }
    if !replay.check_and_record(&peer_id, parsed.timestamp, now) {
        return None;
    }
    Some(handle_hello(registry, &parsed, src_ip, now).await)
}

/// Decide whether to emit the recv-error warning and how long to back off.
/// Warn once per run of consecutive errors: the first error after a success warns,
/// repeats stay silent until the caller resets `warned` on the next successful recv.
/// Pure (no logging side effect) so the transition is unit-testable.
fn note_recv_error(warned: &mut bool) -> (bool, Duration) {
    let should_warn = !*warned;
    *warned = true;
    (should_warn, RECV_ERROR_BACKOFF)
}

/// Decide whether a loopback-only server needs its one discovery warning.
fn note_loopback_only(bound: Option<SocketAddr>, warned: &mut bool) -> bool {
    let should_warn = bound.is_some_and(|addr| addr.ip().is_loopback()) && !*warned;
    *warned |= should_warn;
    should_warn
}

/// Owns the UDP receive buffer and replay state; survives transient recv errors.
async fn recv_loop(
    socket: Arc<tokio::net::UdpSocket>,
    registry: Arc<PeerRegistry>,
    local_peer_id: String,
) {
    let mut buf = [0u8; RECV_BUF_LEN];
    let mut replay = ReplayGuard::new();
    let mut recv_error_warned = false;
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src)) => {
                recv_error_warned = false;
                let outcome = process_datagram(
                    &buf[..n],
                    &src.ip().to_string(),
                    &registry,
                    &local_peer_id,
                    &mut replay,
                    unix_now(),
                )
                .await;
                tracing::debug!(?outcome, "processed LAN Cowork HELLO datagram");
            }
            Err(error) => {
                // Fire-and-forget: no supervisor. A transient recv error (e.g. an
                // ICMP-port-unreachable-induced ECONNRESET) must not permanently kill
                // discovery, so back off and retry instead of breaking. This matches the
                // asyncio DatagramProtocol primary path (transport survives recv errors),
                // not the Windows _listen_thread fallback (which break()s but pairs that
                // with a _running flag + socket timeout this loop deliberately lacks).
                let (should_warn, backoff) = note_recv_error(&mut recv_error_warned);
                if should_warn {
                    tracing::warn!(%error, "LAN Cowork UDP recv error; backing off and retrying");
                }
                tokio::time::sleep(backoff).await;
            }
        }
    }
    // ponytail: recv_loop never returns under normal operation — it backs off and retries on
    // recv errors rather than breaking; B-d5e's spawn test covers the live wiring, and
    // note_recv_error's unit test covers the warn-throttle transition.
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Load the raw ed25519 seed used to sign the local HELLO.
/// This private seed is never logged/returned/interpolated into a response or error message.
pub async fn load_identity_seed(pool: &sqlx::SqlitePool) -> Option<Vec<u8>> {
    sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

/// Periodically assemble and broadcast the local HELLO.
async fn tick_loop(state: LanCoworkState, socket: Arc<tokio::net::UdpSocket>) {
    let targets = broadcast_targets();
    let mut loopback_warning_emitted = false;
    loop {
        if note_loopback_only(
            super::lan_cowork_descriptor::bound_addr(),
            &mut loopback_warning_emitted,
        ) {
            tracing::warn!(
                "LAN Cowork discovery inactive: server listens on loopback only; bind a LAN address or use --lan"
            );
        }
        let Some(peer) = assemble_local_peer_info(&*state).await else {
            tokio::time::sleep(Duration::from_secs(HELLO_TICK_SECS)).await;
            continue;
        };
        let Some(seed) = load_identity_seed(state.db_read()).await else {
            tokio::time::sleep(Duration::from_secs(HELLO_TICK_SECS)).await;
            continue;
        };
        if let Some(sent) = send_hello_tick(&socket, &peer, &seed, &targets, unix_now()).await {
            tracing::trace!(sent, "LAN Cowork HELLO broadcast tick");
        }
        tokio::time::sleep(Duration::from_secs(HELLO_TICK_SECS)).await;
    }
    // ponytail: tick_loop is a thin sleep-loop over the tested send_hello_tick;
    // B-d5e's spawn test covers the live wiring (bound_port + real socket).
}

/// Spawn the LAN Cowork discovery daemon: UDP recv loop + HELLO broadcast tick + peer
/// timeout sweep, sharing one Arc<UdpSocket> on the fixed discovery port. Fire-and-forget
/// (no JoinHandle/shutdown channel): startup-gated, no runtime toggle, OS reaps tasks and
/// the port at process exit — same lifecycle shape as scheduler::start_scheduler.
/// Caller must ensure native_daemon (⊂ standalone) already holds; this fn additionally
/// suppresses discovery in safe_mode. Never panics: any bind error degrades to no discovery.
pub async fn start_discovery_daemon(state: LanCoworkState, registry: Arc<PeerRegistry>) {
    if !should_start_discovery(state.safe_mode()) {
        return;
    }
    let Some(socket) = discovery_socket_or_skip(bind_discovery_socket(UDP_DISCOVERY_PORT)) else {
        return;
    };

    let recv_registry = registry.clone();
    let local_peer_id = registry.local_peer_id();
    let recv_socket = socket.clone();
    tokio::spawn(recv_loop(recv_socket, recv_registry, local_peer_id));

    tokio::spawn(tick_loop(state.clone(), socket.clone()));

    // Sweep is a separate task, not folded into tick: tick keeps its B-d5d contract of
    // depending only on (state, socket) with no registry handle; the registry dependency
    // lives here. check_timeouts is sync + in-memory only (no DB persist, no event emit —
    // status is not persisted; peer.offline events are deferred to a later increment).
    let sweep_registry = registry;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(HELLO_TICK_SECS)).await;
            let gone_offline = sweep_registry.check_timeouts(unix_now() as f64);
            if !gone_offline.is_empty() {
                tracing::debug!(?gone_offline, "LAN Cowork peers marked offline");
            }
        }
    });
}

impl ReplayGuard {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// true = fresh and recorded; false = duplicate within the replay window.
    fn check_and_record(&mut self, peer_id: &str, ts: u64, now: u64) -> bool {
        // ponytail: prune-on-insert HashMap scan; discovery is low-volume (one broadcast per
        // peer per ~tick). Swap to a time-bucketed ring if peer count ever makes the scan hot.
        self.seen
            .retain(|_, recorded| now.saturating_sub(*recorded) <= REPLAY_WINDOW_SEC);
        let key = (peer_id.to_string(), ts);
        if self.seen.contains_key(&key) {
            return false;
        }
        self.seen.insert(key, now);
        true
    }
}

/// Outcome of processing one received HELLO. B-d5 uses this only for logging/metrics.
#[derive(Debug, PartialEq, Eq)]
pub enum HelloOutcome {
    /// Source address is not an acceptable LAN peer address (reused register gate).
    IgnoredAddr,
    /// Signature or timestamp verification failed; the packet is dropped.
    VerifyFailed,
    /// An already-known peer (by pubkey) was refreshed (and possibly IP-rotated).
    KnownUpdated,
    /// A previously-unknown peer passed self-signature verification and was registered.
    NewRegistered,
}

fn dict_str(dict: &Value, key: &str) -> String {
    dict.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn dict_strings(dict: &Value, key: &str) -> Vec<String> {
    dict.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// TOFU-process one received HELLO. See the module/plan MF-11 notes.
pub async fn handle_hello(
    registry: &PeerRegistry,
    parsed: &ParsedHello,
    addr: &str,
    now: u64,
) -> HelloOutcome {
    // addr gate: reuse the single register/outbound SSRF gate (rejects link-local /
    // metadata / non-LAN). Deliberate tightening of Python's TOFU accept-set.
    if validate_register_host(addr).is_err() {
        return HelloOutcome::IgnoredAddr;
    }

    if let Some(existing) = registry.get_by_pubkey(&parsed.pubkey) {
        // Known peer: verify against the STORED pubkey (MF-11), never the packet's.
        let verified = existing
            .pubkey
            .is_some_and(|pk| verify_hello(parsed, &pk, now));
        if !verified {
            return HelloOutcome::VerifyFailed;
        }
        registry.update_runtime(
            &existing.peer_id,
            None,
            None,
            None,
            None,
            Some(now as f64),
            Some("online".to_string()),
        );
        // IP rotation / x25519 change -> persist the moved endpoint.
        if existing.api_host != addr || existing.x25519_pk != Some(parsed.x25519_pk) {
            // `existing` is a pre-update clone (get_by_pubkey returns .cloned()), so it
            // still holds the STALE runtime. update_runtime already wrote status=online
            // / last_seen=now to the live entry; carry those into the upsert clone too,
            // or the peers.insert() inside upsert would roll them back (MF-8, offline flap).
            let mut updated = existing.clone();
            updated.api_host = addr.to_string();
            updated.x25519_pk = Some(parsed.x25519_pk);
            updated.last_seen = now as f64;
            updated.status = "online".to_string();
            let _ = registry.upsert(updated).await;
        }
        return HelloOutcome::KnownUpdated;
    }

    // Unknown peer: MF-11 deviation — require a valid self-signature + fresh timestamp.
    if !verify_hello(parsed, &parsed.pubkey, now) {
        return HelloOutcome::VerifyFailed;
    }

    let dict = &parsed.peer_dict;
    let peer_id = dict_str(dict, "peer_id");
    let mut new_peer = PeerInfo {
        peer_id: peer_id.clone(),
        name: dict_str(dict, "name"),
        api_host: addr.to_string(),
        api_port: dict.get("api_port").and_then(Value::as_u64).unwrap_or(0) as u16,
        token: None,
        token_expires_at: None,
        token_issued_at: None,
        pubkey: Some(parsed.pubkey),
        x25519_pk: Some(parsed.x25519_pk),
        version: dict_str(dict, "version"),
        bridges: dict_strings(dict, "bridges"),
        inference_types: dict_strings(dict, "inference_types"),
        gpu: String::new(),
        generating: false,
        queue_depth: 0,
        status: "online".to_string(),
        last_seen: now as f64,
        session_id: String::new(),
        roles: vec![],
        last_reached_at: None,
        last_attempted_at: None,
    };
    // Token preservation: keep an existing token if the peer_id row already has one
    // and its stored pubkey is absent or matches (Python manager.py:224-232).
    if let Some(prev) = registry.get(&peer_id) {
        // Python truthiness: an empty-string token is falsy (NH1).
        let has_token = prev.token.as_deref().is_some_and(|token| !token.is_empty());
        if has_token && (prev.pubkey.is_none() || prev.pubkey == Some(parsed.pubkey)) {
            new_peer.token = prev.token;
            new_peer.token_expires_at = prev.token_expires_at;
            new_peer.token_issued_at = prev.token_issued_at;
        }
    }
    let _ = registry.upsert(new_peer).await;
    HelloOutcome::NewRegistered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::peer_hello::{build_hello_packet, parse_hello_packet, PeerHelloInfo};
    use crate::auth::peer_pairing_crypto::x25519_pubkey_from_ed25519_seed;
    use crate::routes::lan_cowork_descriptor::{test_guard, TEST_ALLOW_LOOPBACK};
    use base64::Engine as _;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    const NOW: u64 = 1_700_000_000;
    const SEED_A: &[u8] = &[1u8; 32];
    const SEED_B: &[u8] = &[2u8; 32];

    #[test]
    fn discovery_socket_or_skip_warns_and_skips_on_bind_error() {
        let bind = Err(std::io::Error::from(std::io::ErrorKind::AddrInUse));
        assert!(discovery_socket_or_skip(bind).is_none());
    }

    #[test]
    fn should_start_discovery_suppressed_in_safe_mode() {
        assert!(!should_start_discovery(true));
        assert!(should_start_discovery(false));
    }

    #[test]
    fn note_recv_error_warns_once_until_reset() {
        let mut warned = false;
        // First error of a run warns and returns the fixed backoff.
        let (w1, d1) = note_recv_error(&mut warned);
        assert!(w1);
        assert_eq!(d1, RECV_ERROR_BACKOFF);
        // A consecutive error stays silent (throttled) but still backs off.
        let (w2, d2) = note_recv_error(&mut warned);
        assert!(!w2);
        assert_eq!(d2, RECV_ERROR_BACKOFF);
        // A successful recv resets the flag; the next error warns again.
        warned = false;
        let (w3, _) = note_recv_error(&mut warned);
        assert!(w3);
    }

    #[test]
    fn note_loopback_only_warns_once() {
        let mut warned = false;
        assert!(!note_loopback_only(None, &mut warned));
        assert!(note_loopback_only(
            Some("127.0.0.1:5000".parse().unwrap()),
            &mut warned
        ));
        assert!(!note_loopback_only(
            Some("127.0.0.1:5000".parse().unwrap()),
            &mut warned
        ));
    }

    fn ed25519_pub(seed: &[u8]) -> Vec<u8> {
        openssl::pkey::PKey::private_key_from_raw_bytes(seed, openssl::pkey::Id::ED25519)
            .unwrap()
            .raw_public_key()
            .unwrap()
    }

    fn seed_peer_id(seed: &[u8]) -> String {
        super::super::peer_identity::derive_peer_id(&ed25519_pub(seed))
    }

    fn peer_info(seed: &[u8], api_port: u16) -> PeerHelloInfo {
        PeerHelloInfo {
            peer_id: seed_peer_id(seed),
            name: "node".into(),
            api_host: "ignored".into(),
            api_port,
            version: "4.517.0".into(),
            bridges: vec![],
            inference_types: vec![],
            pubkey: None, // derived from seed when signed
            x25519_pk: None,
        }
    }

    fn local_peer_info(seed: &[u8], api_port: u16) -> PeerInfo {
        PeerInfo {
            peer_id: seed_peer_id(seed),
            name: "node".into(),
            api_host: "127.0.0.1".into(),
            api_port,
            token: None,
            token_expires_at: None,
            token_issued_at: None,
            pubkey: None,
            x25519_pk: None,
            version: "4.517.0".into(),
            bridges: vec!["comfyui".into()],
            inference_types: vec!["text".into()],
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: "online".into(),
            last_seen: NOW as f64,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        }
    }

    /// Build a signed HELLO for `seed` and parse it back into a ParsedHello.
    fn signed(seed: &[u8], api_port: u16, ts: u64) -> ParsedHello {
        let bytes = build_hello_packet(&peer_info(seed, api_port), Some(seed), ts).unwrap();
        parse_hello_packet(&bytes).unwrap()
    }

    /// Build an UNSIGNED HELLO (valid structure, no signature).
    fn unsigned(seed: &[u8], api_port: u16, ts: u64) -> ParsedHello {
        let mut info = peer_info(seed, api_port);
        info.pubkey = Some(ed25519_pub(seed));
        info.x25519_pk = Some(x25519_pubkey_from_ed25519_seed(seed).unwrap());
        let bytes = build_hello_packet(&info, None, ts).unwrap();
        parse_hello_packet(&bytes).unwrap()
    }

    async fn registry() -> PeerRegistry {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        // real peers schema so upsert's DB write succeeds.
        sqlx::query(
            "CREATE TABLE peers (peer_id TEXT PRIMARY KEY, name TEXT, api_host TEXT, \
             api_port INTEGER, token TEXT, token_expires_at INTEGER, token_issued_at INTEGER, \
             pubkey BLOB, x25519_pk BLOB, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, \
             last_reached_at INTEGER, last_attempted_at INTEGER)",
        )
        .execute(&pool)
        .await
        .unwrap();
        PeerRegistry::new(pool, Duration::from_secs(30), "self0".into())
    }

    #[test]
    fn replay_guard_dedups_within_window() {
        let mut replay = ReplayGuard::new();
        assert!(replay.check_and_record("peer", NOW, NOW));
        assert!(!replay.check_and_record("peer", NOW, NOW));
        assert!(replay.check_and_record("peer", NOW + 1, NOW));
        assert!(replay.check_and_record("peer", NOW, NOW + REPLAY_WINDOW_SEC + 1));
    }

    #[test]
    fn hello_info_from_peer_maps_advertised_fields() {
        let peer = local_peer_info(SEED_B, 8188);
        let hello = hello_info_from_peer(&peer);
        assert_eq!(hello.peer_id, peer.peer_id);
        assert_eq!(hello.name, peer.name);
        assert_eq!(hello.api_host, peer.api_host);
        assert_eq!(hello.api_port, peer.api_port);
        assert_eq!(hello.version, peer.version);
        assert_eq!(hello.bridges, peer.bridges);
        assert_eq!(hello.inference_types, peer.inference_types);
        assert_eq!(hello.pubkey, None);
        assert_eq!(hello.x25519_pk, None);
    }

    #[test]
    fn broadcast_targets_is_limited_broadcast() {
        let targets = broadcast_targets();
        assert_eq!(
            targets,
            vec![SocketAddr::from(([255, 255, 255, 255], UDP_DISCOVERY_PORT))]
        );
        assert_eq!(targets[0].port(), UDP_DISCOVERY_PORT);
    }

    #[tokio::test]
    async fn send_hello_tick_broadcast_roundtrips_over_socketpair() {
        let recv = bind_discovery_socket(0).expect("bind");
        let target = SocketAddr::from(([127, 0, 0, 1], recv.local_addr().unwrap().port()));
        let send = bind_discovery_socket(0).expect("bind");
        let peer = local_peer_info(SEED_B, 8188);

        assert_eq!(
            send_hello_tick(&send, &peer, SEED_B, &[target], NOW).await,
            Some(1)
        );

        let mut buf = [0u8; RECV_BUF_LEN];
        let (n, _) = recv.recv_from(&mut buf).await.unwrap();
        let parsed = parse_hello_packet(&buf[..n]).unwrap();
        assert!(verify_hello(&parsed, &ed25519_pub(SEED_B), NOW));
        assert_eq!(derive_peer_id(&parsed.pubkey), seed_peer_id(SEED_B));
        assert_eq!(parsed.peer_dict["api_port"], 8188);
    }

    #[tokio::test]
    async fn send_hello_tick_sends_to_every_target() {
        let recv_a = bind_discovery_socket(0).expect("bind");
        let recv_b = bind_discovery_socket(0).expect("bind");
        let targets = [
            SocketAddr::from(([127, 0, 0, 1], recv_a.local_addr().unwrap().port())),
            SocketAddr::from(([127, 0, 0, 1], recv_b.local_addr().unwrap().port())),
        ];
        let send = bind_discovery_socket(0).expect("bind");
        let peer = local_peer_info(SEED_B, 8188);

        assert_eq!(
            send_hello_tick(&send, &peer, SEED_B, &targets, NOW).await,
            Some(2)
        );

        for recv in [&recv_a, &recv_b] {
            let mut buf = [0u8; RECV_BUF_LEN];
            let (n, _) = recv.recv_from(&mut buf).await.unwrap();
            assert!(parse_hello_packet(&buf[..n]).is_some());
        }
    }

    #[tokio::test]
    async fn send_hello_tick_empty_state_still_verifies() {
        let recv = bind_discovery_socket(0).expect("bind");
        let target = SocketAddr::from(([127, 0, 0, 1], recv.local_addr().unwrap().port()));
        let send = bind_discovery_socket(0).expect("bind");
        let mut peer = local_peer_info(SEED_B, 8188);
        peer.bridges.clear();
        peer.inference_types.clear();

        assert_eq!(
            send_hello_tick(&send, &peer, SEED_B, &[target], NOW).await,
            Some(1)
        );

        let mut buf = [0u8; RECV_BUF_LEN];
        let (n, _) = recv.recv_from(&mut buf).await.unwrap();
        let parsed = parse_hello_packet(&buf[..n]).unwrap();
        assert!(verify_hello(&parsed, &ed25519_pub(SEED_B), NOW));
        assert_eq!(parsed.peer_dict["bridges"], serde_json::json!([]));
        assert_eq!(parsed.peer_dict["inference_types"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn send_hello_tick_returns_none_on_unusable_seed() {
        let send = bind_discovery_socket(0).expect("bind");
        let peer = local_peer_info(SEED_B, 8188);
        let target = SocketAddr::from(([127, 0, 0, 1], UDP_DISCOVERY_PORT));

        assert_eq!(
            send_hello_tick(&send, &peer, &[0u8; 10], &[target], NOW).await,
            None
        );
    }

    #[tokio::test]
    async fn bind_discovery_socket_binds_ephemeral() {
        let socket = bind_discovery_socket(0).expect("bind");
        let addr = socket.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
        assert!(addr.is_ipv4());
    }

    #[tokio::test]
    async fn process_datagram_registers_peer_over_real_socket() {
        let _g = test_guard();
        TEST_ALLOW_LOOPBACK.store(true, Ordering::Relaxed);
        let reg = registry().await;
        let recv = bind_discovery_socket(0).expect("bind");
        let dst = format!("127.0.0.1:{}", recv.local_addr().unwrap().port());
        let send = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pkt = build_hello_packet(&peer_info(SEED_B, 8188), Some(SEED_B), NOW).unwrap();
        send.send_to(&pkt, &dst).await.unwrap();
        let mut buf = [0u8; RECV_BUF_LEN];
        let (n, src) = recv.recv_from(&mut buf).await.unwrap();
        let mut replay = ReplayGuard::new();
        let out = process_datagram(
            &buf[..n],
            &src.ip().to_string(),
            &reg,
            "self0",
            &mut replay,
            NOW,
        )
        .await;
        assert_eq!(out, Some(HelloOutcome::NewRegistered));
        assert!(reg.get(&seed_peer_id(SEED_B)).is_some());
        TEST_ALLOW_LOOPBACK.store(false, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn process_datagram_excludes_self() {
        let reg = registry().await;
        let pkt = build_hello_packet(&peer_info(SEED_A, 8188), Some(SEED_A), NOW).unwrap();
        let mut replay = ReplayGuard::new();
        assert_eq!(
            process_datagram(
                &pkt,
                "10.0.0.5",
                &reg,
                &seed_peer_id(SEED_A),
                &mut replay,
                NOW,
            )
            .await,
            None
        );
        assert!(reg.get(&seed_peer_id(SEED_A)).is_none());
    }

    #[tokio::test]
    async fn process_datagram_drops_replayed() {
        let _g = test_guard();
        let reg = registry().await;
        let pkt = build_hello_packet(&peer_info(SEED_B, 8188), Some(SEED_B), NOW).unwrap();
        let mut replay = ReplayGuard::new();
        assert!(
            process_datagram(&pkt, "10.0.0.5", &reg, "self0", &mut replay, NOW)
                .await
                .is_some()
        );
        assert_eq!(
            process_datagram(&pkt, "10.0.0.5", &reg, "self0", &mut replay, NOW).await,
            None
        );
    }

    #[tokio::test]
    async fn process_datagram_drops_out_of_range_api_port() {
        let reg = registry().await;
        let pubkey = ed25519_pub(SEED_B);
        let x25519_pk = x25519_pubkey_from_ed25519_seed(SEED_B).unwrap();
        let json = serde_json::json!({
            "peer_id": derive_peer_id(&pubkey),
            "pubkey": base64::engine::general_purpose::STANDARD.encode(pubkey),
            "x25519_pk": base64::engine::general_purpose::STANDARD.encode(x25519_pk),
            "api_port": 70000u64,
        });
        let json = serde_json::to_vec(&json).unwrap();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(b"YUAI");
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&(json.len() as u32).to_be_bytes());
        pkt.extend_from_slice(&json);
        pkt.extend_from_slice(&NOW.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 64]);
        let mut replay = ReplayGuard::new();
        assert_eq!(
            process_datagram(&pkt, "10.0.0.5", &reg, "self0", &mut replay, NOW).await,
            None
        );
        assert!(reg.get(&seed_peer_id(SEED_B)).is_none());
    }

    #[tokio::test]
    async fn unknown_signed_peer_is_registered() {
        let reg = registry().await;
        let p = signed(SEED_A, 8188, NOW);
        assert!(matches!(
            handle_hello(&reg, &p, "10.0.0.5", NOW).await,
            HelloOutcome::NewRegistered
        ));
        let stored = reg.get(&seed_peer_id(SEED_A)).unwrap();
        assert_eq!(stored.api_host, "10.0.0.5"); // from src addr, not payload
        assert_eq!(stored.api_port, 8188);
        assert_eq!(stored.status, "online");
        assert!(stored.pubkey.is_some());
    }

    #[tokio::test]
    async fn unknown_unsigned_peer_is_rejected_mf11() {
        // MF-11 deviation from Python: unknown peers must carry a valid self-signature.
        let reg = registry().await;
        let p = unsigned(SEED_A, 8188, NOW);
        assert!(matches!(
            handle_hello(&reg, &p, "10.0.0.5", NOW).await,
            HelloOutcome::VerifyFailed
        ));
        assert!(reg.get(&seed_peer_id(SEED_A)).is_none());
    }

    #[tokio::test]
    async fn stale_timestamp_is_rejected() {
        let reg = registry().await;
        let p = signed(SEED_A, 8188, NOW - 120); // >60s skew
        assert!(matches!(
            handle_hello(&reg, &p, "10.0.0.5", NOW).await,
            HelloOutcome::VerifyFailed
        ));
        assert!(reg.get(&seed_peer_id(SEED_A)).is_none());
    }

    #[tokio::test]
    async fn non_lan_addr_is_ignored() {
        let reg = registry().await;
        let p = signed(SEED_A, 8188, NOW);
        // Loopback (127.0.0.1/::1) is intentionally omitted: is_reachable_peer_ip reads
        // the process-global TEST_ALLOW_LOOPBACK that a sibling test flips, so asserting
        // loopback here would race under a full `cargo test` (MF2). Loopback rejection is
        // covered by the guarded test in lan_cowork_peer_api. These 4 are loopback-free.
        for bad in ["8.8.8.8", "169.254.1.1", "169.254.169.254", "0.0.0.0"] {
            assert!(matches!(
                handle_hello(&reg, &p, bad, NOW).await,
                HelloOutcome::IgnoredAddr
            ));
        }
        assert!(reg.get(&seed_peer_id(SEED_A)).is_none());
    }

    #[tokio::test]
    async fn known_peer_refreshes_and_rotates_ip() {
        let reg = registry().await;
        // first sighting registers.
        handle_hello(&reg, &signed(SEED_A, 8188, NOW), "10.0.0.5", NOW).await;
        // force offline to prove the rotation upsert does NOT roll runtime back (MF-8/MF1).
        reg.update_runtime(
            &seed_peer_id(SEED_A),
            None,
            None,
            None,
            None,
            None,
            Some("offline".to_string()),
        );
        // second sighting from a new addr -> KnownUpdated + api_host rotated + back online.
        let p2 = signed(SEED_A, 8188, NOW + 1);
        assert!(matches!(
            handle_hello(&reg, &p2, "10.0.0.9", NOW + 1).await,
            HelloOutcome::KnownUpdated
        ));
        let stored = reg.get(&seed_peer_id(SEED_A)).unwrap();
        assert_eq!(stored.api_host, "10.0.0.9");
        assert_eq!(stored.status, "online"); // not rolled back to the stale offline clone
        assert_eq!(stored.last_seen, (NOW + 1) as f64);
    }

    #[tokio::test]
    async fn known_peer_tampered_signature_is_rejected() {
        let reg = registry().await;
        handle_hello(&reg, &signed(SEED_A, 8188, NOW), "10.0.0.5", NOW).await;
        // craft a ParsedHello whose signature belongs to a DIFFERENT seed (SEED_B),
        // but carries SEED_A's identity — verify against stored pubkey must fail.
        let mut forged = signed(SEED_A, 8188, NOW + 1);
        forged.signature = signed(SEED_B, 8188, NOW + 1).signature; // wrong signer
        assert!(matches!(
            handle_hello(&reg, &forged, "10.0.0.5", NOW + 1).await,
            HelloOutcome::VerifyFailed
        ));
    }

    #[tokio::test]
    async fn token_is_preserved_on_first_hello_after_pairing() {
        // Unknown-pubkey path (manager.py:224-232): a peer_id row already holds a
        // token but NO stored pubkey (paired, never HELLO'd). The first signed HELLO
        // carrying that pubkey must go through the *unknown* path (get_by_pubkey miss)
        // and inherit the token via get(peer_id).
        let reg = registry().await;
        let pid = seed_peer_id(SEED_A);
        let seeded = PeerInfo {
            peer_id: pid.clone(),
            name: "n".into(),
            api_host: "10.0.0.5".into(),
            api_port: 8188,
            token: Some("tok".into()),
            token_expires_at: Some(NOW as i64 + 600),
            token_issued_at: Some(NOW as i64),
            pubkey: None,
            x25519_pk: None, // no stored key -> get_by_pubkey will miss
            version: String::new(),
            bridges: vec![],
            inference_types: vec![],
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: "offline".into(),
            last_seen: 0.0,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        };
        reg.upsert(seeded).await.unwrap();
        assert!(matches!(
            handle_hello(&reg, &signed(SEED_A, 8188, NOW + 1), "10.0.0.5", NOW + 1).await,
            HelloOutcome::NewRegistered
        ));
        let stored = reg.get(&pid).unwrap();
        assert_eq!(stored.token.as_deref(), Some("tok")); // token inherited
        assert!(stored.pubkey.is_some()); // pubkey now filled from the HELLO
    }
}
