use std::io;

use base64::Engine as _;
use openssl::pkey::{Id, PKey};
use openssl::sign::Verifier;
use serde::ser::{SerializeMap, Serializer as _};
use serde_json::ser::Formatter;
use serde_json::Value;

use crate::auth::peer_pairing_crypto::{is_low_order_x25519, x25519_pubkey_from_ed25519_seed};
use crate::routes::peer_identity::derive_peer_id;

const MAGIC: &[u8; 4] = b"YUAI";
const VERSION: u16 = 2;
const FLAG_HAS_SIGNATURE: u16 = 0x0001;
const HELLO_TIMESTAMP_TOLERANCE: u64 = 60;
const HEADER_LEN: usize = 12;
const SIG_LEN: usize = 64;
const TS_LEN: usize = 8;

#[allow(dead_code)]
pub struct PeerHelloInfo {
    pub peer_id: String,
    pub name: String,
    pub api_host: String,
    pub api_port: u16,
    pub version: String,
    pub bridges: Vec<String>,
    pub inference_types: Vec<String>,
    pub pubkey: Option<Vec<u8>>,
    pub x25519_pk: Option<Vec<u8>>,
}

#[allow(dead_code)]
pub struct ParsedHello {
    pub peer_dict: Value,
    pub pubkey: [u8; 32],
    pub x25519_pk: [u8; 32],
    pub timestamp: u64,
    pub signature: Option<[u8; 64]>,
    pub raw_signed: Vec<u8>,
}

fn build_signed_bytes(flags: u16, json_bytes: &[u8], ts: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + json_bytes.len() + TS_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(json_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(json_bytes);
    out.extend_from_slice(&ts.to_be_bytes());
    out
}

#[allow(dead_code)]
fn ed25519_pubkey_from_seed(seed: &[u8]) -> Option<Vec<u8>> {
    PKey::private_key_from_raw_bytes(seed, Id::ED25519)
        .ok()?
        .raw_public_key()
        .ok()
}

#[allow(dead_code)]
fn ed25519_verify_raw(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let key = match PKey::public_key_from_raw_bytes(pubkey, Id::ED25519) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let mut verifier = match Verifier::new_without_digest(&key) {
        Ok(verifier) => verifier,
        Err(_) => return false,
    };
    verifier.verify_oneshot(sig, msg).unwrap_or(false)
}

struct EnsureAsciiFormatter;

impl Formatter for EnsureAsciiFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            if c >= '\u{7f}' {
                writer.write_all(&fragment.as_bytes()[start..i])?;
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    write!(writer, "\\u{:04x}", unit)?;
                }
                start = i + c.len_utf8();
            }
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

#[allow(dead_code)]
fn payload_json(peer: &PeerHelloInfo, seed: Option<&[u8]>) -> Option<Vec<u8>> {
    let mut json = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut json, EnsureAsciiFormatter);
    let mut map = serializer.serialize_map(None).ok()?;
    map.serialize_entry("peer_id", &peer.peer_id).ok()?;
    map.serialize_entry("name", &peer.name).ok()?;
    map.serialize_entry("api_host", &peer.api_host).ok()?;
    map.serialize_entry("api_port", &peer.api_port).ok()?;
    map.serialize_entry("version", &peer.version).ok()?;
    map.serialize_entry("bridges", &peer.bridges).ok()?;
    map.serialize_entry("inference_types", &peer.inference_types)
        .ok()?;
    if let Some(seed) = seed {
        let pubkey = ed25519_pubkey_from_seed(seed)?;
        let x25519_pk = x25519_pubkey_from_ed25519_seed(seed)?;
        map.serialize_entry(
            "pubkey",
            &base64::engine::general_purpose::STANDARD.encode(pubkey),
        )
        .ok()?;
        map.serialize_entry(
            "x25519_pk",
            &base64::engine::general_purpose::STANDARD.encode(x25519_pk),
        )
        .ok()?;
    } else {
        if let Some(pubkey) = peer.pubkey.as_deref().filter(|key| !key.is_empty()) {
            map.serialize_entry(
                "pubkey",
                &base64::engine::general_purpose::STANDARD.encode(pubkey),
            )
            .ok()?;
        }
        if let Some(x25519_pk) = peer.x25519_pk.as_deref().filter(|key| !key.is_empty()) {
            map.serialize_entry(
                "x25519_pk",
                &base64::engine::general_purpose::STANDARD.encode(x25519_pk),
            )
            .ok()?;
        }
    }
    map.end().ok()?;
    Some(json)
}

#[allow(dead_code)]
pub fn build_hello_packet(peer: &PeerHelloInfo, seed: Option<&[u8]>, ts: u64) -> Option<Vec<u8>> {
    let json = payload_json(peer, seed)?;
    u32::try_from(json.len()).ok()?;
    let flags = if seed.is_some() {
        FLAG_HAS_SIGNATURE
    } else {
        0
    };
    let mut signed = build_signed_bytes(flags, &json, ts);
    if let Some(seed) = seed {
        signed.extend_from_slice(&crate::auth::peer_transport::sign_canonical(seed, &signed)?);
    }
    Some(signed)
}

#[allow(dead_code)]
pub fn parse_hello_packet(data: &[u8]) -> Option<ParsedHello> {
    if data.get(..MAGIC.len())? != MAGIC {
        return None;
    }
    if u16::from_be_bytes(data.get(4..6)?.try_into().ok()?) != VERSION {
        return None;
    }
    let flags = u16::from_be_bytes(data.get(6..8)?.try_into().ok()?);
    let json_len = u32::from_be_bytes(data.get(8..HEADER_LEN)?.try_into().ok()?) as usize;
    let json_end = HEADER_LEN.checked_add(json_len)?;
    let ts_end = json_end.checked_add(TS_LEN)?;
    let json = data.get(HEADER_LEN..json_end)?;
    let peer_dict: Value = serde_json::from_slice(json).ok()?;
    if !peer_dict.is_object() {
        return None;
    }
    let timestamp = u64::from_be_bytes(data.get(json_end..ts_end)?.try_into().ok()?);
    let raw_signed = data.get(..ts_end)?.to_vec();
    let signature = if flags & FLAG_HAS_SIGNATURE != 0 {
        let sig_end = ts_end.checked_add(SIG_LEN)?;
        Some(data.get(ts_end..sig_end)?.try_into().ok()?)
    } else {
        None
    };
    let pubkey = base64::engine::general_purpose::STANDARD
        .decode(peer_dict.get("pubkey")?.as_str()?)
        .ok()?;
    let x25519_pk = base64::engine::general_purpose::STANDARD
        .decode(peer_dict.get("x25519_pk")?.as_str()?)
        .ok()?;
    let pubkey: [u8; 32] = pubkey.try_into().ok()?;
    let x25519_pk: [u8; 32] = x25519_pk.try_into().ok()?;
    if is_low_order_x25519(&x25519_pk)
        || peer_dict.get("peer_id")?.as_str()? != derive_peer_id(&pubkey)
    {
        return None;
    }
    Some(ParsedHello {
        peer_dict,
        pubkey,
        x25519_pk,
        timestamp,
        signature,
        raw_signed,
    })
}

#[allow(dead_code)]
pub fn verify_hello(parsed: &ParsedHello, expected_pubkey: &[u8], now: u64) -> bool {
    let Some(signature) = parsed.signature else {
        return false;
    };
    now.abs_diff(parsed.timestamp) <= HELLO_TIMESTAMP_TOLERANCE
        && ed25519_verify_raw(expected_pubkey, &parsed.raw_signed, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../../tests/vectors/hello_packet_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("vectors parse")
    }

    fn sample_peer() -> PeerHelloInfo {
        PeerHelloInfo {
            peer_id: "p".into(),
            name: "n".into(),
            api_host: "10.0.0.2".into(),
            api_port: 8188,
            version: "1".into(),
            bridges: vec![],
            inference_types: vec![],
            pubkey: None,
            x25519_pk: None,
        }
    }

    fn peer_from_case(v: &Value, case: &Value) -> PeerHelloInfo {
        let p = &case["peer"];
        let pubkey = hex::decode(v["pubkey_hex"].as_str().unwrap()).unwrap();
        let x = hex::decode(v["x25519_pk_hex"].as_str().unwrap()).unwrap();
        let unsigned = !case["signed"].as_bool().unwrap();
        PeerHelloInfo {
            peer_id: p["peer_id"].as_str().unwrap().into(),
            name: p["name"].as_str().unwrap().into(),
            api_host: p["api_host"].as_str().unwrap_or("10.0.0.2").into(),
            api_port: p["api_port"].as_u64().unwrap_or(8188) as u16,
            version: p["version"].as_str().unwrap_or("1").into(),
            bridges: p["bridges"]
                .as_array()
                .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
                .unwrap_or_default(),
            inference_types: p["inference_types"]
                .as_array()
                .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
                .unwrap_or_default(),
            pubkey: if unsigned { Some(pubkey) } else { None },
            x25519_pk: if unsigned { Some(x) } else { None },
        }
    }

    #[test]
    fn signed_bytes_layout_is_magic_version_flags_len_json_ts() {
        let json = br#"{"k":1}"#;
        let out = build_signed_bytes(FLAG_HAS_SIGNATURE, json, 0x0102030405060708);
        assert_eq!(&out[0..4], b"YUAI");
        assert_eq!(&out[4..6], &[0x00, 0x02]);
        assert_eq!(&out[6..8], &[0x00, 0x01]);
        assert_eq!(&out[8..12], &(json.len() as u32).to_be_bytes());
        assert_eq!(&out[12..12 + json.len()], json);
        assert_eq!(
            &out[12 + json.len()..],
            &0x0102030405060708u64.to_be_bytes()
        );
    }

    #[test]
    fn sign_canonical_then_ed25519_verify_raw_roundtrips() {
        let seed: Vec<u8> = (1u8..=32).collect();
        let pubkey = ed25519_pubkey_from_seed(&seed).unwrap();
        let msg = b"hello-codec-roundtrip";
        let sig = crate::auth::peer_transport::sign_canonical(&seed, msg).unwrap();
        assert!(ed25519_verify_raw(&pubkey, msg, &sig));
        assert!(!ed25519_verify_raw(&pubkey, b"tampered", &sig));
        assert!(!ed25519_verify_raw(&pubkey, msg, &[0u8; 64]));
        assert!(!ed25519_verify_raw(b"short", msg, &sig));
    }

    #[test]
    fn payload_keeps_declaration_order_and_compact_separators() {
        let mut p = sample_peer();
        p.bridges = vec!["a".into()];
        let seed: Vec<u8> = (1u8..=32).collect();
        let json = payload_json(&p, Some(&seed)).unwrap();
        let s = std::str::from_utf8(&json).unwrap();
        assert!(s.starts_with(r#"{"peer_id":"p","name":"n","api_host":"10.0.0.2","api_port":8188,"version":"1","bridges":["a"],"inference_types":[],"pubkey":"#));
        assert!(!s.contains(", "));
    }

    #[test]
    fn ensure_ascii_escapes_del_bmp_and_supplementary() {
        let mut p = sample_peer();
        p.name = "A\u{7f}\u{65e5}\u{1f600}".into();
        let json = payload_json(&p, None).unwrap();
        let s = std::str::from_utf8(&json).unwrap();
        assert!(
            s.contains(r#""name":"A\u007f\u65e5\ud83d\ude00""#),
            "got: {s}"
        );
    }

    #[test]
    fn build_matches_python_golden_vectors() {
        let v = vectors();
        let seed = hex::decode(v["seed_hex"].as_str().unwrap()).unwrap();
        for case in v["build_cases"].as_array().unwrap() {
            let peer = peer_from_case(&v, case);
            let ts = case["ts"].as_u64().unwrap();
            let seed_arg = if case["signed"].as_bool().unwrap() {
                Some(seed.as_slice())
            } else {
                None
            };
            let out = build_hello_packet(&peer, seed_arg, ts).unwrap();
            assert_eq!(
                hex::encode(&out),
                case["packet_hex"].as_str().unwrap(),
                "build mismatch for {}",
                case["label"]
            );
        }
    }

    #[test]
    fn parse_roundtrips_python_signed_packets() {
        let v = vectors();
        for case in v["build_cases"].as_array().unwrap() {
            if !case["signed"].as_bool().unwrap() {
                continue;
            }
            let data = hex::decode(case["packet_hex"].as_str().unwrap()).unwrap();
            let parsed =
                parse_hello_packet(&data).unwrap_or_else(|| panic!("parse {}", case["label"]));
            assert_eq!(
                hex::encode(parsed.pubkey),
                v["pubkey_hex"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(parsed.x25519_pk),
                v["x25519_pk_hex"].as_str().unwrap()
            );
            assert_eq!(parsed.timestamp, case["ts"].as_u64().unwrap());
            assert!(parsed.signature.is_some());
        }
    }

    #[test]
    fn parse_ignores_trailing_bytes() {
        let v = vectors();
        let case = &v["build_cases"][0];
        let mut data = hex::decode(case["packet_hex"].as_str().unwrap()).unwrap();
        data.extend_from_slice(&[0xAA, 0xBB]);
        assert!(parse_hello_packet(&data).is_some());
    }

    #[test]
    fn verify_hello_matches_expected_over_hostile_packet_ts() {
        let v = vectors();
        let pubkey = hex::decode(v["pubkey_hex"].as_str().unwrap()).unwrap();
        let now_ref = v["now_ref"].as_u64().unwrap();
        for case in v["verify_cases"].as_array().unwrap() {
            let data = hex::decode(case["packet_hex"].as_str().unwrap()).unwrap();
            let parsed =
                parse_hello_packet(&data).unwrap_or_else(|| panic!("parse {}", case["label"]));
            assert_eq!(
                verify_hello(&parsed, &pubkey, now_ref),
                case["expect"].as_bool().unwrap(),
                "verify {}",
                case["label"]
            );
        }
    }

    #[test]
    fn verify_hello_rejects_tampered_signature_and_missing_sig() {
        let v = vectors();
        let pubkey = hex::decode(v["pubkey_hex"].as_str().unwrap()).unwrap();
        let now_ref = v["now_ref"].as_u64().unwrap();
        let ok = &v["verify_cases"][0];
        let mut data = hex::decode(ok["packet_hex"].as_str().unwrap()).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        let parsed = parse_hello_packet(&data).unwrap();
        assert!(!verify_hello(&parsed, &pubkey, now_ref));
        let mut d_ts = hex::decode(ok["packet_hex"].as_str().unwrap()).unwrap();
        let ts_low = d_ts.len() - SIG_LEN - 1;
        d_ts[ts_low] ^= 0x01;
        let parsed_ts = parse_hello_packet(&d_ts).unwrap();
        assert!(!verify_hello(&parsed_ts, &pubkey, now_ref));
        let none_sig = ParsedHello {
            signature: None,
            ..parsed_ts
        };
        assert!(!verify_hello(&none_sig, &pubkey, now_ref));
    }

    #[test]
    fn no_signed_byte_can_be_tampered_while_still_verifying() {
        // Every byte the signature covers (raw_signed = data[..ts_end], i.e. the
        // JSON payload and the 8-byte timestamp) plus the 64-byte signature itself
        // must be integrity-protected: flipping any single byte must make verify
        // fail (parse rejects, or verify returns false). This covers the exact
        // off-by-one offsets a bad raw_signed slice would hide (last JSON byte,
        // first/last timestamp byte) without depending on their positions.
        let v = vectors();
        let pubkey = hex::decode(v["pubkey_hex"].as_str().unwrap()).unwrap();
        let now_ref = v["now_ref"].as_u64().unwrap();
        let good = hex::decode(v["build_cases"][0]["packet_hex"].as_str().unwrap()).unwrap();
        for off in HEADER_LEN..good.len() {
            let mut d = good.clone();
            d[off] ^= 0x01;
            let verified = parse_hello_packet(&d)
                .map(|p| verify_hello(&p, &pubkey, now_ref))
                .unwrap_or(false);
            assert!(!verified, "tampering byte {off} still verified");
        }
    }

    #[test]
    fn parse_rejects_malformed_without_panic() {
        let v = vectors();
        let base = hex::decode(v["build_cases"][0]["packet_hex"].as_str().unwrap()).unwrap();
        assert!(parse_hello_packet(&[]).is_none());
        assert!(parse_hello_packet(&base[..8]).is_none());
        let mut bad_magic = base.clone();
        bad_magic[0] = b'X';
        assert!(parse_hello_packet(&bad_magic).is_none());
        let mut bad_ver = base.clone();
        bad_ver[5] = 1;
        assert!(parse_hello_packet(&bad_ver).is_none());
        let mut huge_len = base.clone();
        huge_len[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_hello_packet(&huge_len).is_none());
        assert!(parse_hello_packet(&base[..base.len() - 1]).is_none());
    }

    #[test]
    fn parse_rejects_python_reject_vectors() {
        let v = vectors();
        for case in v["reject_cases"].as_array().unwrap() {
            let data = hex::decode(case["packet_hex"].as_str().unwrap()).unwrap();
            assert!(
                parse_hello_packet(&data).is_none(),
                "should reject {}",
                case["label"]
            );
        }
    }
}
