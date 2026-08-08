//! Pairing crypto primitives — Rust port of `core/crypto_identity/pairing.py`,
//! the X25519 derivation in `keypair.py`, the low-order deny-list in
//! `hello_packet.py`, and `pairing_service_store.hash_pin`.
//!
//! Increment E1: primitives only — no routes, no DB, no state machine. Every
//! value here is pinned byte-for-byte by `tests/vectors/peer_pairing_vectors.json`
//! (design 2026-07-19 Increment E1, MF-E1..MF-E7).
//!
//! Zero new dependencies (MF-E2): HKDF is 8 lines over the existing `hmac`+`sha2`
//! (salt is empty and L == HashLen, so expand is a single round), X25519 and
//! AES-256-GCM come from openssl, and the KDFs reuse the existing `scrypt` crate.
//!
//! Three scrypt uses appear here and their OUTPUT LENGTHS DIFFER — the source
//! inventory got this wrong twice, so each is pinned separately (MF-E1):
//!   - token hash  n=2^14, salt "yu-ai-peer-token",   64 bytes (in peer_transport)
//!   - PIN hash    n=2^14, salt "yu-ai-pairing-pin",  64 bytes
//!   - PIN AES key n=2^17, salt = request_id,         32 bytes

use hmac::{Hmac, Mac};
use openssl::pkey::{Id, PKey};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const X25519_HKDF_INFO: &[u8] = b"yu-ai-lan-cowork-x25519-v1";
const PIN_HASH_SALT: &[u8] = b"yu-ai-pairing-pin";
const PIN_HASH_LOG_N: u8 = 14;
const PIN_KDF_LOG_N: u8 = 17; // ~128 MiB, ~1s — must not run on an async worker
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const PIN_HASH_DKLEN: usize = 64; // dklen unset in Python -> CPython default 64
const PIN_KDF_DKLEN: usize = 32; // Scrypt(length=32), explicit
const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// Canonical X25519 low-order points, mirroring
/// `hello_packet._X25519_LOW_ORDER_POINTS`. Kept in sync mechanically: the
/// vector generator emits the Python set and a test asserts set equality (MF-E5).
const LOW_ORDER_POINTS_HEX: &[&str] = &[
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
    "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
    "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

/// HKDF-SHA256 with an empty salt, producing exactly 32 bytes.
///
/// L == HashLen, so expand needs only T(1) = HMAC(PRK, info ‖ 0x01). An empty
/// salt means the extract key is HashLen zero bytes (RFC 5869 §2.2).
fn hkdf_sha256_32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract = HmacSha256::new_from_slice(&[0u8; 32]).expect("hmac accepts any key length");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut expand = HmacSha256::new_from_slice(&prk).expect("hmac accepts any key length");
    expand.update(info);
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&okm[..32]);
    out
}

/// Derive the independent X25519 seed from an Ed25519 seed (`keypair.derive_x25519_seed`).
pub fn derive_x25519_seed(ed25519_seed: &[u8]) -> [u8; 32] {
    hkdf_sha256_32(ed25519_seed, X25519_HKDF_INFO)
}

/// Derive the X25519 public key from an Ed25519 seed (`keypair.x25519_pubkey_bytes`).
pub fn x25519_pubkey_from_ed25519_seed(ed25519_seed: &[u8]) -> Option<Vec<u8>> {
    let x_seed = derive_x25519_seed(ed25519_seed);
    let key = PKey::private_key_from_raw_bytes(&x_seed, Id::X25519).ok()?;
    key.raw_public_key().ok()
}

/// Reject known small-order X25519 points (`hello_packet.probe_x25519_low_order`).
pub fn is_low_order_x25519(x25519_pk: &[u8]) -> bool {
    static SET: std::sync::OnceLock<std::collections::HashSet<Vec<u8>>> =
        std::sync::OnceLock::new();
    let set = SET.get_or_init(|| {
        LOW_ORDER_POINTS_HEX
            .iter()
            .map(|h| hex::decode(h).expect("static deny-list hex is valid"))
            .collect()
    });
    set.contains(x25519_pk)
}

/// scrypt hash of a pairing PIN for storage (`pairing_service_store.hash_pin`).
/// n=2^14, salt "yu-ai-pairing-pin", 64-byte output → 128 hex chars.
///
/// Named distinctly from `hash_pin` (the web-UI session PIN hash in
/// `crate::auth::pin`), which is a different domain entirely (pbkdf2, not
/// scrypt) — the two must never be swapped.
pub fn hash_pairing_pin(pin: &str) -> String {
    let params = scrypt::Params::new(PIN_HASH_LOG_N, SCRYPT_R, SCRYPT_P, PIN_HASH_DKLEN)
        .expect("static scrypt params are valid");
    let mut out = vec![0u8; PIN_HASH_DKLEN];
    scrypt::scrypt(pin.as_bytes(), PIN_HASH_SALT, &params, &mut out).expect("scrypt kdf");
    hex::encode(out)
}

/// Derive the AES-256 key from the PIN (`pairing._pin_kdf`).
///
/// n=2^17 → ~128 MiB and ~1s per call, and the salt is the **request_id**, not a
/// constant. Never call this from an async context directly — use
/// [`pin_kdf_async`], which offloads and bounds concurrency (MF-E6).
pub fn pin_kdf(pin: &str, request_id: &str) -> [u8; PIN_KDF_DKLEN] {
    let params = scrypt::Params::new(PIN_KDF_LOG_N, SCRYPT_R, SCRYPT_P, PIN_KDF_DKLEN)
        .expect("static scrypt params are valid");
    let mut out = [0u8; PIN_KDF_DKLEN];
    scrypt::scrypt(pin.as_bytes(), request_id.as_bytes(), &params, &mut out).expect("scrypt kdf");
    out
}

/// Async-safe [`pin_kdf`]: offloads to a blocking thread and caps concurrency so
/// a burst of pairing verifies cannot allocate N × 128 MiB at once (MF-E6).
#[allow(dead_code)] // first caller lands in Increment E2 (responder routes)
pub async fn pin_kdf_async(pin: String, request_id: String) -> Option<[u8; PIN_KDF_DKLEN]> {
    static PERMITS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    let sem = PERMITS.get_or_init(|| tokio::sync::Semaphore::new(2));
    let _permit = sem.acquire().await.ok()?;
    tokio::task::spawn_blocking(move || pin_kdf(&pin, &request_id))
        .await
        .ok()
}

/// commit = sha256(pubkey ‖ x25519_pk ‖ nonce) — the x25519-bound form.
pub fn make_commit_v2(pubkey: &[u8], x25519_pk: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.update(x25519_pk);
    h.update(nonce);
    h.finalize().into()
}

/// commit = sha256(pubkey ‖ nonce) — the legacy form (no x25519).
pub fn make_commit_legacy(pubkey: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pubkey);
    h.update(nonce);
    h.finalize().into()
}

fn sas_from_digest(digest: &[u8]) -> String {
    digest[..6]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// SAS binding both peers' Ed25519 + X25519 identities (`compute_sas` 5-arg form).
///
/// The Python function carries a positional-argument shim for the legacy shape;
/// that shim is deliberately NOT ported — the two shapes are split into distinct
/// functions and the caller reproduces the 3-way branch (MF-E4).
pub fn compute_sas_v2(
    pubkey_req: &[u8],
    x25519_req: &[u8],
    pubkey_server: &[u8],
    x25519_server: &[u8],
    request_id: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(pubkey_req);
    h.update(x25519_req);
    h.update(pubkey_server);
    h.update(x25519_server);
    h.update(request_id.as_bytes());
    sas_from_digest(&h.finalize())
}

/// SAS over Ed25519 identities only (`compute_sas` legacy 3-arg form).
pub fn compute_sas_legacy(pubkey_req: &[u8], pubkey_server: &[u8], request_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(pubkey_req);
    h.update(pubkey_server);
    h.update(request_id.as_bytes());
    sas_from_digest(&h.finalize())
}

/// Encrypt a pairing bundle with a **caller-supplied** IV. Wire layout is
/// `iv(12) ‖ ciphertext ‖ tag(16)`.
///
/// Python's `AESGCM.encrypt` returns ciphertext with the tag appended, whereas
/// openssl yields the tag separately — this reassembly is the most likely source
/// of a byte-level incompatibility, so it is pinned by fixed-IV vectors (MF-E3).
///
/// # IV invariant
///
/// The caller MUST pass a fresh, cryptographically random 12-byte IV and MUST
/// NEVER reuse one under the same key. AES-GCM nonce reuse is catastrophic: it
/// leaks the XOR of the plaintexts and enables authentication-key recovery,
/// which would let an attacker forge pairing bundles. This low-level form exists
/// so tests can pin deterministic vectors; **production callers should use
/// [`encrypt_bundle_random_iv`]**, which mirrors Python's `encrypt_pairing_bundle`
/// by generating the IV internally.
pub fn encrypt_bundle(key: &[u8], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != GCM_IV_LEN {
        return None;
    }
    let mut tag = [0u8; GCM_TAG_LEN];
    let ct = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(iv),
        aad,
        plaintext,
        &mut tag,
    )
    .ok()?;
    let mut out = Vec::with_capacity(iv.len() + ct.len() + GCM_TAG_LEN);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Some(out)
}

/// Encrypt a pairing bundle, generating a fresh random IV internally.
///
/// This is the production entry point — it mirrors Python's
/// `encrypt_pairing_bundle`, which also generates its own IV (`os.urandom(12)`),
/// and removes any opportunity for a caller to reuse a nonce under the same key.
#[allow(dead_code)] // first caller lands in Increment E3 (initiator)
pub fn encrypt_bundle_random_iv(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let mut iv = [0u8; GCM_IV_LEN];
    openssl::rand::rand_bytes(&mut iv).ok()?;
    encrypt_bundle(key, &iv, plaintext, aad)
}

/// Decrypt a pairing bundle laid out as `iv(12) ‖ ciphertext ‖ tag(16)`.
/// Returns `None` on any authentication failure or malformed length.
pub fn decrypt_bundle(key: &[u8], bundle: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if bundle.len() < GCM_IV_LEN + GCM_TAG_LEN {
        return None;
    }
    let (iv, rest) = bundle.split_at(GCM_IV_LEN);
    let (ct, tag) = rest.split_at(rest.len() - GCM_TAG_LEN);
    decrypt_aead(Cipher::aes_256_gcm(), key, Some(iv), aad, ct, tag).ok()
}

/// Decrypted pairing material: the peer's Ed25519 key and, in the v2 shape, its X25519 key.
#[derive(Debug, PartialEq, Eq)]
pub struct PairingMaterial {
    pub pubkey: Vec<u8>,
    pub x25519_pk: Option<Vec<u8>>,
}

/// Decrypt and commit-verify a pairing bundle (`pairing.verify_pairing_bundle`).
///
/// Dispatches on plaintext length: 96 bytes is `pubkey‖x25519‖nonce`, 64 bytes is
/// the legacy `pubkey‖nonce`. Commit comparison is constant-time. When
/// `expected_x25519_pk` is supplied the legacy shape is rejected outright,
/// matching Python.
pub fn verify_bundle(
    key: &[u8],
    request_id: &str,
    commit: &[u8],
    bundle: &[u8],
    expected_x25519_pk: Option<&[u8]>,
) -> Option<PairingMaterial> {
    let plain = decrypt_bundle(key, bundle, request_id.as_bytes())?;

    if plain.len() == 96 {
        let (pubkey, x25519_pk, nonce) = (&plain[..32], &plain[32..64], &plain[64..96]);
        let expected = make_commit_v2(pubkey, x25519_pk, nonce);
        if !constant_time_eq(&expected, commit) {
            return None;
        }
        if let Some(want) = expected_x25519_pk {
            if !constant_time_eq(x25519_pk, want) {
                return None;
            }
        }
        return Some(PairingMaterial {
            pubkey: pubkey.to_vec(),
            x25519_pk: Some(x25519_pk.to_vec()),
        });
    }

    if plain.len() != 64 || expected_x25519_pk.is_some() {
        return None;
    }
    let (pubkey, nonce) = (&plain[..32], &plain[32..64]);
    if !constant_time_eq(&make_commit_legacy(pubkey, nonce), commit) {
        return None;
    }
    Some(PairingMaterial {
        pubkey: pubkey.to_vec(),
        x25519_pk: None,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // Python-generated ground truth (scripts/gen_peer_pairing_vectors.py).
    const VECTORS: &str = include_str!("../../tests/vectors/peer_pairing_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("vectors json parses")
    }

    fn h(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().expect("hex string")).expect("valid hex")
    }

    // ── MF-E1: the three scrypt uses, including their differing output lengths ──
    #[test]
    fn pin_hash_matches_python_and_is_64_bytes() {
        let v = vectors();
        let t = &v["scrypt"]["pin_hash"];
        let expected = t["hex"].as_str().unwrap();
        assert_eq!(
            expected.len(),
            128,
            "hash_pin is 64 bytes / 128 hex, not 64 hex"
        );
        assert_eq!(hash_pairing_pin(t["pin"].as_str().unwrap()), expected);
    }

    /// The only test that runs the n=2^17 KDF (~128 MiB, ~1s). Every other test
    /// uses the pre-derived key from the vectors, because `cargo test` runs in
    /// parallel and this environment OOMs easily (MF-E7).
    #[test]
    fn pin_kdf_matches_python_and_is_32_bytes() {
        let v = vectors();
        let t = &v["scrypt"]["pin_kdf"];
        let key = pin_kdf(
            t["pin"].as_str().unwrap(),
            t["request_id"].as_str().unwrap(),
        );
        assert_eq!(key.len(), 32, "pin_kdf is an explicit 32-byte key");
        assert_eq!(hex::encode(key), t["key_hex"].as_str().unwrap());
    }

    // ── MF-E2: HKDF-derived X25519, no new crates ──────────────────────────────
    #[test]
    fn x25519_derivation_matches_python() {
        let v = vectors();
        let c = &v["identity"]["client"];
        let seed = h(&c["ed25519_seed_hex"]);
        assert_eq!(
            hex::encode(derive_x25519_seed(&seed)),
            c["x25519_seed_hex"].as_str().unwrap(),
            "HKDF-SHA256 seed derivation diverged"
        );
        assert_eq!(
            hex::encode(x25519_pubkey_from_ed25519_seed(&seed).unwrap()),
            c["x25519_pubkey_hex"].as_str().unwrap(),
            "X25519 public key diverged"
        );
    }

    // ── MF-E5: deny-list must match Python exactly (set equality) ──────────────
    #[test]
    fn low_order_deny_list_matches_python_set() {
        let v = vectors();
        let d = &v["x25519_low_order_deny_list"];
        let python: std::collections::HashSet<String> = d["points_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        let rust: std::collections::HashSet<String> =
            LOW_ORDER_POINTS_HEX.iter().map(|s| s.to_string()).collect();
        assert_eq!(rust, python, "Rust deny-list is out of sync with Python");
        assert_eq!(python.len(), 12, "expected the full canonical 12 points");
        assert!(
            python.iter().all(|p| p.len() == 64),
            "all entries must be 32 bytes"
        );
    }

    #[test]
    fn low_order_probe_rejects_and_accepts() {
        assert!(is_low_order_x25519(&[0u8; 32]));
        let mut two_p = vec![0xd9u8];
        two_p.extend_from_slice(&[0xffu8; 31]);
        assert!(is_low_order_x25519(&two_p), "2p family must be denied");
        let v = vectors();
        let good = h(&v["identity"]["client"]["x25519_pubkey_hex"]);
        assert!(!is_low_order_x25519(&good), "a real key must not be denied");
    }

    // ── MF-E4: commit and SAS, both shapes ─────────────────────────────────────
    #[test]
    fn commit_matches_python_both_shapes() {
        let v = vectors();
        let pubkey = h(&v["identity"]["client"]["ed25519_pubkey_hex"]);
        let x = h(&v["identity"]["client"]["x25519_pubkey_hex"]);
        let nonce = h(&v["commit"]["nonce_hex"]);
        assert_eq!(
            hex::encode(make_commit_v2(&pubkey, &x, &nonce)),
            v["commit"]["v2"]["commit_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(make_commit_legacy(&pubkey, &nonce)),
            v["commit"]["legacy"]["commit_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn sas_matches_python_both_shapes() {
        let v = vectors();
        let cpub = h(&v["identity"]["client"]["ed25519_pubkey_hex"]);
        let cx = h(&v["identity"]["client"]["x25519_pubkey_hex"]);
        let spub = h(&v["identity"]["server"]["ed25519_pubkey_hex"]);
        let sx = h(&v["identity"]["server"]["x25519_pubkey_hex"]);
        let rid = v["sas"]["request_id"].as_str().unwrap();
        assert_eq!(
            compute_sas_v2(&cpub, &cx, &spub, &sx, rid),
            v["sas"]["v2"]["sas"].as_str().unwrap()
        );
        assert_eq!(
            compute_sas_legacy(&cpub, &spub, rid),
            v["sas"]["legacy"]["sas"].as_str().unwrap()
        );
    }

    // ── MF-E3: AES-GCM wire format (iv ‖ ct ‖ tag) ─────────────────────────────
    #[test]
    fn aead_encrypt_matches_python_byte_for_byte() {
        let v = vectors();
        let a = &v["aead"];
        let key = h(&a["key_hex"]);
        let iv = h(&a["iv_hex"]);
        let aad = a["aad_utf8"].as_str().unwrap().as_bytes();
        for shape in ["v2", "legacy"] {
            let plain = h(&a[shape]["plaintext_hex"]);
            let wire = encrypt_bundle(&key, &iv, &plain, aad).unwrap();
            assert_eq!(
                hex::encode(&wire),
                a[shape]["wire_hex"].as_str().unwrap(),
                "AES-GCM wire bytes diverged for {shape} (tag placement?)"
            );
        }
    }

    #[test]
    fn aead_decrypt_roundtrips_and_rejects_tampering() {
        let v = vectors();
        let a = &v["aead"];
        let key = h(&a["key_hex"]);
        let aad = a["aad_utf8"].as_str().unwrap().as_bytes();
        let wire = h(&a["v2"]["wire_hex"]);

        assert_eq!(
            hex::encode(decrypt_bundle(&key, &wire, aad).unwrap()),
            a["v2"]["plaintext_hex"].as_str().unwrap()
        );
        // Wrong AAD (i.e. a different request_id) must fail.
        let wrong_aad = a["negative"]["wrong_aad_utf8"].as_str().unwrap().as_bytes();
        assert!(decrypt_bundle(&key, &wire, wrong_aad).is_none());
        // Tampered tag must fail.
        let mut bad = wire.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(decrypt_bundle(&key, &bad, aad).is_none());
        // Too short to hold iv+tag must be rejected, not panic.
        assert!(decrypt_bundle(&key, &h(&a["negative"]["short_bundle_hex"]), aad).is_none());
        assert!(decrypt_bundle(&key, &[], aad).is_none());
    }

    #[test]
    fn decrypts_real_python_bundle() {
        use base64::Engine as _;
        let v = vectors();
        let a = &v["aead"];
        let key = h(&a["key_hex"]);
        let bundle = base64::engine::general_purpose::STANDARD
            .decode(a["real_bundle_b64"].as_str().unwrap())
            .unwrap();
        // Produced by the real encrypt_pairing_bundle (random IV) — proves we
        // parse Python's on-the-wire output, not just our own re-encryption.
        let plain = decrypt_bundle(&key, &bundle, a["aad_utf8"].as_str().unwrap().as_bytes());
        assert_eq!(
            hex::encode(plain.unwrap()),
            a["v2"]["plaintext_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn verify_bundle_accepts_both_shapes_and_enforces_commit() {
        let v = vectors();
        let a = &v["aead"];
        let key = h(&a["key_hex"]);
        let rid = a["aad_utf8"].as_str().unwrap();
        let pubkey = h(&v["identity"]["client"]["ed25519_pubkey_hex"]);
        let x = h(&v["identity"]["client"]["x25519_pubkey_hex"]);

        let commit_v2 = h(&v["commit"]["v2"]["commit_hex"]);
        let wire_v2 = h(&a["v2"]["wire_hex"]);
        let got = verify_bundle(&key, rid, &commit_v2, &wire_v2, None).unwrap();
        assert_eq!(got.pubkey, pubkey);
        assert_eq!(got.x25519_pk.as_deref(), Some(x.as_slice()));
        // Binding to the expected x25519 key succeeds, a mismatch fails.
        assert!(verify_bundle(&key, rid, &commit_v2, &wire_v2, Some(&x)).is_some());
        assert!(verify_bundle(&key, rid, &commit_v2, &wire_v2, Some(&[0u8; 32])).is_none());
        // A wrong commit must be rejected even though decryption succeeds.
        assert!(verify_bundle(&key, rid, &[0u8; 32], &wire_v2, None).is_none());

        let commit_legacy = h(&v["commit"]["legacy"]["commit_hex"]);
        let wire_legacy = h(&a["legacy"]["wire_hex"]);
        let legacy = verify_bundle(&key, rid, &commit_legacy, &wire_legacy, None).unwrap();
        assert_eq!(legacy.pubkey, pubkey);
        assert_eq!(legacy.x25519_pk, None);
        // Legacy shape must be refused when an x25519 binding is demanded.
        assert!(verify_bundle(&key, rid, &commit_legacy, &wire_legacy, Some(&x)).is_none());
    }

    // ── IV misuse-resistance ───────────────────────────────────────────────────
    #[test]
    fn encrypt_bundle_rejects_wrong_iv_length() {
        let v = vectors();
        let key = h(&v["aead"]["key_hex"]);
        assert!(encrypt_bundle(&key, &[0u8; 11], b"x", b"aad").is_none());
        assert!(encrypt_bundle(&key, &[0u8; 13], b"x", b"aad").is_none());
        assert!(encrypt_bundle(&key, &[], b"x", b"aad").is_none());
    }

    #[test]
    fn encrypt_bundle_random_iv_is_fresh_each_call_and_roundtrips() {
        let v = vectors();
        let a = &v["aead"];
        let key = h(&a["key_hex"]);
        let aad = a["aad_utf8"].as_str().unwrap().as_bytes();
        let plain = h(&a["v2"]["plaintext_hex"]);

        let one = encrypt_bundle_random_iv(&key, &plain, aad).unwrap();
        let two = encrypt_bundle_random_iv(&key, &plain, aad).unwrap();
        // Nonce reuse under a fixed key is catastrophic for AES-GCM, so the two
        // IVs (and therefore the whole bundles) must differ.
        assert_ne!(one[..GCM_IV_LEN], two[..GCM_IV_LEN], "IV was reused");
        assert_ne!(one, two);
        // Both must still decrypt back to the same plaintext.
        assert_eq!(decrypt_bundle(&key, &one, aad).unwrap(), plain);
        assert_eq!(decrypt_bundle(&key, &two, aad).unwrap(), plain);
    }

    // ── MF-E6: the async offload path (Semaphore + spawn_blocking) ─────────────
    /// Runs three concurrent derivations against two permits, so the queueing
    /// path is exercised, and asserts each still matches the Python vector.
    /// Peak memory stays at ~2 x 128 MiB because the semaphore caps concurrency.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pin_kdf_async_matches_sync_and_queues_under_semaphore() {
        let v = vectors();
        let t = &v["scrypt"]["pin_kdf"];
        let pin = t["pin"].as_str().unwrap().to_string();
        let rid = t["request_id"].as_str().unwrap().to_string();
        let expected = t["key_hex"].as_str().unwrap();

        let handles: Vec<_> = (0..3)
            .map(|_| {
                let (p, r) = (pin.clone(), rid.clone());
                tokio::spawn(async move { pin_kdf_async(p, r).await })
            })
            .collect();
        for handle in handles {
            let key = handle.await.unwrap().expect("kdf must not fail");
            assert_eq!(hex::encode(key), expected);
        }
    }
}
