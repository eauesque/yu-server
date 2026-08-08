//! LAN Cowork inbound read/write handler logic (Increments B-d2/B-d3).
//!
//! Pure serialization + response builders for GET discover / GET status, ported
//! from extensions/builtin_lan_cowork/routes/peer_api.py + core_impl/models.py.
//! Dead-code until B-d5 wires the Axum routes; DB (has_inbound_token), session
//! detection, and local-peer construction are the caller's responsibility here.

use base64::Engine;
use serde_json::{json, Value};
use std::net::IpAddr;

use super::lan_cowork_descriptor::is_reachable_peer_ip;
use super::lan_cowork_registry::PeerInfo;

fn b64(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Full serialization (session-authorized view). Mirrors Python `PeerInfo.to_dict()`.
pub fn to_dict(peer: &PeerInfo) -> Value {
    json!({
        "peer_id": peer.peer_id,
        "name": peer.name,
        "api_host": peer.api_host,
        "api_port": peer.api_port,
        "version": peer.version,
        "bridges": peer.bridges,
        "inference_types": peer.inference_types,
        "pubkey": peer.pubkey.map(|key| b64(&key)),
        "x25519_pk": peer.x25519_pk.map(|key| b64(&key)),
        "gpu": peer.gpu,
        "generating": peer.generating,
        "queue_depth": peer.queue_depth,
        "status": peer.status,
        "last_seen": peer.last_seen,
        "token": peer.token,
        "token_expires_at": peer.token_expires_at,
        "token_issued_at": peer.token_issued_at,
        "session_id": peer.session_id,
        "roles": peer.roles,
    })
}

/// Public view (session NOT authorized). Mirrors Python `to_public_dict()`: drops
/// token/token_expires_at/token_issued_at/session_id/roles.
pub fn to_public_dict(peer: &PeerInfo) -> Value {
    let mut value = to_dict(peer);
    if let Value::Object(map) = &mut value {
        for key in [
            "token",
            "token_expires_at",
            "token_issued_at",
            "session_id",
            "roles",
        ] {
            map.remove(key);
        }
    }
    value
}

/// Dispatch on session authorization. Mirrors Python `_serialize_peer()`:
/// authorized -> to_dict() + injected `has_inbound_token`; otherwise public view.
pub fn serialize_peer(peer: &PeerInfo, session_ok: bool, has_inbound_token: bool) -> Value {
    if session_ok {
        let mut value = to_dict(peer);
        if let Value::Object(map) = &mut value {
            map.insert("has_inbound_token".into(), Value::Bool(has_inbound_token));
        }
        value
    } else {
        to_public_dict(peer)
    }
}

/// GET /ext/lan_cowork/api/peer/discover body. Excludes self (local_peer_id).
/// `has_inbound_token` is queried per peer by the caller (B-d5 / token_store).
pub fn discover_response(
    peers: &[PeerInfo],
    local_peer_id: &str,
    session_ok: bool,
    has_inbound_token: impl Fn(&str) -> bool,
) -> Value {
    let serialized: Vec<Value> = peers
        .iter()
        .filter(|peer| peer.peer_id != local_peer_id)
        .map(|peer| {
            // Match Python: has_token is queried only when session_ok (serialize_peer
            // ignores the flag otherwise). Prevents per-peer token_store hits on
            // unauthenticated discover once B-d5 wires the real closure.
            let token = session_ok && has_inbound_token(&peer.peer_id);
            serialize_peer(peer, session_ok, token)
        })
        .collect();
    json!({ "ok": true, "peers": serialized })
}

/// GET /ext/lan_cowork/api/peer/status body. Adds top-level base64 pubkey/x25519_pk.
pub fn status_response(local: &PeerInfo, session_ok: bool, has_inbound_token: bool) -> Value {
    json!({
        "ok": true,
        "peer": serialize_peer(local, session_ok, has_inbound_token),
        "pubkey": local.pubkey.map(|key| b64(&key)),
        "x25519_pk": local.x25519_pk.map(|key| b64(&key)),
    })
}

/// Why a register host was rejected. B-d5 maps these to the 400 response
/// (mirroring peer_api.py's error strings where they apply).
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterHostError {
    /// `host` is not a parseable IP literal (hostnames are rejected — no DNS at
    /// register-validate time, closing register-time DNS rebinding).
    InvalidIp,
    /// Parsed but outside the allowed set (public / CGNAT / link-local /
    /// loopback / unspecified / broadcast / multicast / reserved).
    NotAllowed,
    /// An IPv6 cloud-metadata endpoint reachable inside ULA (fc00::/7).
    CloudMetadata,
}

/// IPv6 cloud-metadata endpoints that fall inside ULA (fc00::/7) and would
/// otherwise pass `is_reachable_peer_ip`. IPv4 metadata (169.254.169.254) is
/// already rejected as link-local. Extend per cloud provider as needed.
const IPV6_METADATA_DENY: &[IpAddr] = &[
    // AWS IMDSv6.
    IpAddr::V6(std::net::Ipv6Addr::new(
        0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254,
    )),
];

/// Validate an untrusted register `host` before the (B-d5) unauthenticated
/// outbound GET to its /api/peer/status. Reuses the single outbound SSRF gate
/// `is_reachable_peer_ip` (RFC1918 v4 + ULA v6, rejecting loopback/link-local/
/// unspecified) so register cannot reach anything the outbound client would
/// itself refuse, then denies IPv6 cloud-metadata inside ULA. This is a
/// deliberate, documented, fail-safe *tightening* of Python's
/// `(is_private or is_link_local)` accept-set (design-advisor 2026-07-22, MF-1/2/3).
pub fn validate_register_host(host: &str) -> Result<IpAddr, RegisterHostError> {
    let ip: IpAddr = host.parse().map_err(|_| RegisterHostError::InvalidIp)?;
    if !is_reachable_peer_ip(ip) {
        return Err(RegisterHostError::NotAllowed);
    }
    if IPV6_METADATA_DENY.contains(&ip) {
        return Err(RegisterHostError::CloudMetadata);
    }
    Ok(ip)
}

fn default_register_port() -> u16 {
    5000
}

/// Trim surrounding whitespace on deserialize, mirroring pydantic ApiModel's
/// `str_strip_whitespace=True` (api_models.py:24) so a padded / whitespace-only
/// host normalizes identically to Python (SF-1).
fn de_trimmed<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(String::deserialize(deserializer)?.trim().to_string())
}

/// POST /ext/lan_cowork/api/peer/register body. Mirrors request_models.py
/// PeerRegisterRequest (host StrictStr min_length=1, port StrictInt default 5000
/// ge 1 le 65535). serde's default integer strictness approximates StrictInt;
/// host is whitespace-trimmed on parse; range/non-empty are enforced by `validate()`.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRegisterRequest {
    #[serde(deserialize_with = "de_trimmed")]
    pub host: String,
    #[serde(default = "default_register_port")]
    pub port: u16,
}

impl PeerRegisterRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.host.is_empty() {
            return Err("host must not be empty");
        }
        if self.port == 0 {
            return Err("port out of range");
        }
        Ok(())
    }
}

/// POST /ext/lan_cowork/api/peer/heartbeat body. Mirrors PeerHeartbeatRequest
/// (all optional; StrictBool/StrictInt). serde rejects integer-for-bool and
/// float-for-int by default, approximating pydantic strict types.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerHeartbeatRequest {
    pub generating: Option<bool>,
    pub queue_depth: Option<i64>,
    pub bridges: Option<Vec<String>>,
    pub inference_types: Option<Vec<String>>,
}

/// Panic-safe 32-byte key from an optional STANDARD-base64 `Value` (matches `b64()`
/// in to_dict / status_response). None on missing/non-string/invalid-base64/wrong-length
/// — never panics (untrusted /status response).
fn key32_from_b64(v: Option<&Value>) -> Option<[u8; 32]> {
    let s = v?.as_str()?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// Parse a peer public-dict (from a remote `/status` response) into `PeerInfo`,
/// **panic-safe** for untrusted input. Returns `None` only when `peer_id` is
/// missing or empty; every other field defaults, and array fields silently skip
/// non-string elements. (The `#[cfg(test)]` `peer_from_json` unwraps and is unsafe
/// here — register is unauthenticated and the response is attacker-influenceable.)
pub fn peer_from_public_dict(input: &Value) -> Option<PeerInfo> {
    let peer_id = input.get("peer_id")?.as_str()?.to_string();
    if peer_id.is_empty() {
        return None;
    }
    let str_vec = |key: &str| -> Vec<String> {
        input
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let api_port = input.get("api_port").and_then(|v| v.as_i64()).unwrap_or(0);
    let api_port = u16::try_from(api_port).unwrap_or(0);
    Some(PeerInfo {
        peer_id,
        name: input
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        api_host: input
            .get("api_host")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        api_port,
        token: input
            .get("token")
            .and_then(|v| v.as_str())
            .map(String::from),
        token_expires_at: input.get("token_expires_at").and_then(|v| v.as_i64()),
        token_issued_at: input.get("token_issued_at").and_then(|v| v.as_i64()),
        pubkey: key32_from_b64(input.get("pubkey")),
        x25519_pk: key32_from_b64(input.get("x25519_pk")),
        version: input
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        bridges: str_vec("bridges"),
        inference_types: str_vec("inference_types"),
        gpu: input
            .get("gpu")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        generating: input
            .get("generating")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        queue_depth: input
            .get("queue_depth")
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        status: input
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("online")
            .to_string(),
        last_seen: input
            .get("last_seen")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        session_id: input
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        roles: str_vec("roles"),
        last_reached_at: input.get("last_reached_at").and_then(|v| v.as_i64()),
        last_attempted_at: input.get("last_attempted_at").and_then(|v| v.as_i64()),
    })
}

/// Peer event types accepted from remote peers (Python `RELAY_TYPES`,
/// peer_event_relay.py). Exactly these 7 — any other type is rejected (M9).
pub const RELAY_TYPES: &[&str] = &[
    "generation.submit",
    "generation.progress",
    "generation.complete",
    "generation.error",
    "generation.cancel",
    "sync.file_changed",
    "peer.status_update",
];

/// True iff `t` is one of the allowlisted relay event types.
pub fn event_type_allowed(t: &str) -> bool {
    RELAY_TYPES.contains(&t)
}

/// Body of `POST /ext/lan_cowork/api/peer/event` (Python `PeerEventRequest`).
/// `event_data` is a free-form JSON OBJECT (Python `dict[str, Any]`, default `{}`);
/// the top level rejects unknown fields. The handler additionally rejects a
/// non-object `event_data` (SF1 — keep the contract as tight as Python's `dict` so a
/// future local consumer never inherits a looser shape).
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEventRequest {
    pub event_type: String,
    #[serde(default = "empty_json_object")]
    pub event_data: serde_json::Value,
    #[serde(default)]
    pub source_peer: String,
}

fn empty_json_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

#[cfg(test)]
mod tests {
    use super::super::lan_cowork_registry::PeerInfo;
    use super::*;

    const VECTORS: &str = include_str!("../../tests/vectors/peer_read_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("peer read vectors parse")
    }

    fn key_from_hex(value: &Value) -> Option<[u8; 32]> {
        value.as_str().map(|hex| {
            let bytes = hex::decode(hex).unwrap();
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        })
    }

    fn peer_from_json(input: &Value) -> PeerInfo {
        PeerInfo {
            peer_id: input["peer_id"].as_str().unwrap().into(),
            name: input["name"].as_str().unwrap_or("").into(),
            api_host: input["api_host"].as_str().unwrap_or("").into(),
            api_port: input["api_port"].as_i64().unwrap_or(0) as u16,
            token: input["token"].as_str().map(Into::into),
            token_expires_at: input["token_expires_at"].as_i64(),
            token_issued_at: input["token_issued_at"].as_i64(),
            pubkey: key_from_hex(&input["pubkey"]),
            x25519_pk: key_from_hex(&input["x25519_pk"]),
            version: input["version"].as_str().unwrap_or("").into(),
            bridges: input["bridges"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect(),
            inference_types: input["inference_types"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect(),
            gpu: input["gpu"].as_str().unwrap_or("").into(),
            generating: input["generating"].as_bool().unwrap_or(false),
            queue_depth: input["queue_depth"].as_i64().unwrap_or(0),
            status: input["status"].as_str().unwrap_or("online").into(),
            last_seen: input["last_seen"].as_f64().unwrap_or(0.0),
            session_id: input["session_id"].as_str().unwrap_or("").into(),
            roles: input["roles"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect(),
            last_reached_at: None,
            last_attempted_at: None,
        }
    }

    #[test]
    fn to_dict_and_public_match_python_golden() {
        for case in vectors()["cases"].as_array().unwrap() {
            let op = case["op"].as_str().unwrap();
            if op != "to_dict" && op != "to_public_dict" {
                continue;
            }
            let peer = peer_from_json(&case["peer"]);
            let got = if op == "to_dict" {
                to_dict(&peer)
            } else {
                to_public_dict(&peer)
            };
            assert_eq!(got, case["expected"], "case {op}");
        }
    }

    #[test]
    fn serialize_peer_matches_python_golden() {
        for case in vectors()["cases"].as_array().unwrap() {
            if case["op"] != "serialize_peer" {
                continue;
            }
            let peer = peer_from_json(&case["peer"]);
            let got = serialize_peer(
                &peer,
                case["session_ok"].as_bool().unwrap(),
                case["has_inbound_token"].as_bool().unwrap(),
            );
            assert_eq!(got, case["expected"], "serialize_peer");
        }
    }

    #[test]
    fn discover_response_matches_python_golden() {
        for case in vectors()["cases"].as_array().unwrap() {
            if case["op"] != "discover" {
                continue;
            }
            let peers: Vec<PeerInfo> = case["peers"]
                .as_array()
                .unwrap()
                .iter()
                .map(peer_from_json)
                .collect();
            let has_ids: Vec<String> = case["has_token_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let got = discover_response(
                &peers,
                case["local_peer_id"].as_str().unwrap(),
                case["session_ok"].as_bool().unwrap(),
                |peer_id| has_ids.iter().any(|id| id == peer_id),
            );
            assert_eq!(got, case["expected"], "discover");
        }
    }

    #[test]
    fn status_response_matches_python_golden() {
        for case in vectors()["cases"].as_array().unwrap() {
            if case["op"] != "status" {
                continue;
            }
            let local = peer_from_json(&case["peer"]);
            let got = status_response(
                &local,
                case["session_ok"].as_bool().unwrap(),
                case["has_inbound_token"].as_bool().unwrap(),
            );
            assert_eq!(got, case["expected"], "status");
        }
    }

    #[test]
    fn validate_register_host_ssrf_policy() {
        use std::net::IpAddr;
        // MF-A: is_reachable_peer_ip reads a process-global TEST_ALLOW_LOOPBACK that a
        // sibling test in lan_cowork_descriptor sets to true. Acquire the shared test
        // guard and reset it so loopback cases observe the production default (reject)
        // under a full `cargo test -p yu-server` run (the path pre_push_check.py uses).
        let _guard = super::super::lan_cowork_descriptor::test_guard();
        super::super::lan_cowork_descriptor::reset_client_state();
        // (host, accepted). Deliberate fail-safe subset of Python: RFC1918 v4 +
        // ULA v6 only; link-local/metadata/public/reserved all rejected.
        let cases: &[(&str, bool)] = &[
            ("10.0.0.5", true),
            ("172.16.0.1", true),
            ("192.168.1.1", true),
            ("fc00::1", true),
            ("fd00:ec2::253", true),
            ("169.254.1.1", false),
            ("169.254.169.254", false),
            ("fd00:ec2::254", false),
            ("127.0.0.1", false),
            ("::1", false),
            ("0.0.0.0", false),
            ("255.255.255.255", false),
            ("224.0.0.1", false),
            ("100.64.0.1", false),
            ("198.18.0.1", false),
            ("240.0.0.1", false),
            ("203.0.113.1", false),
            ("8.8.8.8", false),
            ("fe80::1", false),
            ("example.com", false),
            ("not-an-ip", false),
        ];
        for (host, accepted) in cases {
            let got = validate_register_host(host).is_ok();
            assert_eq!(got, *accepted, "host {host}: expected accepted={accepted}");
            if *accepted {
                assert!(validate_register_host(host).unwrap() == host.parse::<IpAddr>().unwrap());
            }
        }
    }

    #[test]
    fn register_request_parse_and_validate() {
        let r: PeerRegisterRequest = serde_json::from_str(r#"{"host":"10.0.0.1"}"#).unwrap();
        assert_eq!(r.port, 5000);
        assert!(r.validate().is_ok());
        let r: PeerRegisterRequest =
            serde_json::from_str(r#"{"host":"10.0.0.1","port":8188}"#).unwrap();
        assert_eq!(r.port, 8188);
        assert!(r.validate().is_ok());
        let r: PeerRegisterRequest = serde_json::from_str(r#"{"host":""}"#).unwrap();
        assert!(r.validate().is_err());
        let r: PeerRegisterRequest = serde_json::from_str(r#"{"host":"   "}"#).unwrap();
        assert!(r.validate().is_err());
        let r: PeerRegisterRequest =
            serde_json::from_str(r#"{"host":"  10.0.0.1  ","port":8188}"#).unwrap();
        assert_eq!(r.host, "10.0.0.1");
        assert!(r.validate().is_ok());
        assert!(
            serde_json::from_str::<PeerRegisterRequest>(r#"{"host":"10.0.0.1","extra":true}"#)
                .is_err()
        );
        let r: PeerRegisterRequest =
            serde_json::from_str(r#"{"host":"10.0.0.1","port":0}"#).unwrap();
        assert!(r.validate().is_err());
        assert!(
            serde_json::from_str::<PeerRegisterRequest>(r#"{"host":"10.0.0.1","port":70000}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<PeerRegisterRequest>(r#"{}"#).is_err());
    }

    #[test]
    fn heartbeat_request_strict_types() {
        let h: PeerHeartbeatRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert!(h.generating.is_none() && h.queue_depth.is_none());
        let h: PeerHeartbeatRequest = serde_json::from_str(
            r#"{"generating":true,"queue_depth":3,"bridges":["comfyui"],"inference_types":["wd"]}"#,
        )
        .unwrap();
        assert_eq!(h.generating, Some(true));
        assert_eq!(h.queue_depth, Some(3));
        assert!(serde_json::from_str::<PeerHeartbeatRequest>(r#"{"generating":1}"#).is_err());
        assert!(serde_json::from_str::<PeerHeartbeatRequest>(r#"{"queue_depth":1.5}"#).is_err());
    }

    #[test]
    fn peer_from_public_dict_parses_minimal() {
        let v = serde_json::json!({"peer_id": "abc"});
        let p = peer_from_public_dict(&v).expect("peer_id present -> Some");
        assert_eq!(p.peer_id, "abc");
        assert_eq!(p.status, "online"); // default
        assert!(p.token.is_none());
        assert!(p.bridges.is_empty());
    }

    #[test]
    fn peer_from_public_dict_none_without_peer_id() {
        assert!(peer_from_public_dict(&serde_json::json!({"name": "x"})).is_none());
        assert!(peer_from_public_dict(&serde_json::json!({"peer_id": ""})).is_none());
        assert!(peer_from_public_dict(&serde_json::json!("not an object")).is_none());
    }

    #[test]
    fn peer_from_public_dict_decodes_base64_keys_and_rejects_bad_ones() {
        use base64::Engine;
        let good = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let v = serde_json::json!({
            "peer_id": "abc",
            "pubkey": good,        // valid 32-byte base64 -> Some([9;32])
            "x25519_pk": "zzz!!!", // invalid base64 -> None (no panic)
        });
        let p = peer_from_public_dict(&v).unwrap();
        assert_eq!(p.pubkey, Some([9u8; 32]));
        assert_eq!(p.x25519_pk, None);
        // Wrong-length base64 (16 bytes) -> None, not a panic.
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let v2 = serde_json::json!({"peer_id": "abc", "pubkey": short});
        assert_eq!(peer_from_public_dict(&v2).unwrap().pubkey, None);
    }

    #[test]
    fn peer_from_public_dict_skips_malformed_array_elements_without_panic() {
        // Untrusted remote /status: array with non-string elements must not panic.
        let v = serde_json::json!({
            "peer_id": "abc",
            "bridges": ["a", 5, null, "b"],
            "roles": [true, "admin"],
            "api_port": 70000, // out of u16 range -> saturates/wraps to 0-safe default
        });
        let p = peer_from_public_dict(&v).unwrap();
        assert_eq!(p.bridges, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(p.roles, vec!["admin".to_string()]);
    }

    #[test]
    fn relay_types_match_python_and_gate_unknown() {
        // Exactly the 7 Python RELAY_TYPES, no more.
        assert_eq!(RELAY_TYPES.len(), 7);
        for t in [
            "generation.submit",
            "generation.progress",
            "generation.complete",
            "generation.error",
            "generation.cancel",
            "sync.file_changed",
            "peer.status_update",
        ] {
            assert!(event_type_allowed(t), "{t} should be allowed");
        }
        assert!(!event_type_allowed("generation.evil"));
        assert!(!event_type_allowed(""));
        assert!(!event_type_allowed("peer.status_update.extra"));
    }

    #[test]
    fn peer_event_request_deserializes_with_defaults() {
        let req: PeerEventRequest =
            serde_json::from_str(r#"{"event_type":"sync.file_changed"}"#).unwrap();
        assert_eq!(req.event_type, "sync.file_changed");
        assert_eq!(req.source_peer, "");
        assert!(
            req.event_data.is_object(),
            "event_data defaults to {{}} (object), not null"
        ); // SF1
           // Unknown top-level field rejected (deny_unknown_fields), but event_data is free-form.
        let with_data: PeerEventRequest = serde_json::from_str(
            r#"{"event_type":"generation.progress","event_data":{"pct":50},"source_peer":"p2"}"#,
        )
        .unwrap();
        assert_eq!(with_data.event_data["pct"], serde_json::json!(50));
        assert!(
            serde_json::from_str::<PeerEventRequest>(r#"{"event_type":"x","bogus":1}"#).is_err()
        );
    }
}
