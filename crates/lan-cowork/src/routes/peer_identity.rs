//! Shared LAN Cowork peer-identity derivation.
//!
//! Byte-compatible with the Python `core/crypto_identity/identity.py::derive_peer_id`
//! (`sha256(ed25519_pubkey)[:16]` hex). Extracted from `tagger_servers.rs` so the
//! peer-admin routes in `lan_cowork.rs` can reuse the exact same derivation for
//! self-delete rejection (design 2026-07-19 Phase 0, must-fix M6).

use openssl::pkey::{Id, PKey};
use sha2::{Digest, Sha256};

use crate::routes::lan_cowork_host::LanCoworkHost;

pub async fn local_identity_material(state: &dyn LanCoworkHost) -> Option<(Vec<u8>, Vec<u8>)> {
    let seed = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'",
    )
    .fetch_optional(state.db_read())
    .await
    .ok()
    .flatten()?;
    let ed = PKey::private_key_from_raw_bytes(&seed, Id::ED25519)
        .ok()?
        .raw_public_key()
        .ok()?;
    let x = crate::auth::peer_pairing_crypto::x25519_pubkey_from_ed25519_seed(&seed)?;
    Some((ed, x))
}

/// Derive the peer_id from an Ed25519 **public** key: `sha256(pubkey)[:16]` hex.
///
/// Mirrors Python `identity.derive_peer_id`. Used to verify that a pairing
/// request's claimed `peer_id` really is the fingerprint of the key it presents.
pub fn derive_peer_id(pubkey: &[u8]) -> String {
    hex::encode(&Sha256::digest(pubkey)[..16])
}

/// Derive the peer_id from a 32-byte Ed25519 seed.
///
/// Returns `None` if the seed is not exactly 32 bytes or the key cannot be built.
pub fn derive_peer_id_from_seed(seed: &[u8]) -> Option<String> {
    if seed.len() != 32 {
        return None;
    }
    let key = PKey::private_key_from_raw_bytes(seed, Id::ED25519).ok()?;
    let pubkey = key.raw_public_key().ok()?;
    Some(derive_peer_id(&pubkey))
}

/// Load the local peer_id from the `lan_cowork_identity` table.
///
/// Returns `None` when no identity seed is stored (LAN Cowork never initialized).
pub async fn local_peer_id(state: &dyn LanCoworkHost) -> Option<String> {
    let seed = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'",
    )
    .fetch_optional(state.db_read())
    .await
    .ok()
    .flatten()?;
    derive_peer_id_from_seed(&seed)
}

/// Ensure this node's LAN Cowork identity seed exists, generating it once if absent.
///
/// Mirrors Python `load_or_create_identity_from_con`: read first, generate 32 CSPRNG bytes
/// only when the row is missing, `INSERT OR IGNORE`, then RE-FETCH so that a concurrent
/// writer's seed wins consistently. The seed is **never** rotated — every peer_id and both
/// public keys derive from it, so replacing it would invalidate all existing pairings.
///
/// Standalone only: the caller gates on `standalone` because in hybrid Python owns this
/// table (creating the identity from Rust too would double-own it).
///
/// The seed is a private key: it is never logged, never returned, and never placed in an
/// error message.
pub async fn ensure_local_identity(pool: &sqlx::SqlitePool) -> Result<(), String> {
    const SELECT_SEED: &str = "SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'";

    let existing: Option<Vec<u8>> = sqlx::query_scalar(SELECT_SEED)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("lan_cowork identity read failed: {e}"))?;

    let seed = match existing {
        Some(seed) => seed,
        None => {
            let mut fresh = [0u8; 32];
            openssl::rand::rand_bytes(&mut fresh)
                .map_err(|e| format!("lan_cowork identity CSPRNG failed: {e}"))?;
            sqlx::query(
                "INSERT OR IGNORE INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)",
            )
            .bind(&fresh[..])
            .execute(pool)
            .await
            .map_err(|e| format!("lan_cowork identity write failed: {e}"))?;
            // Re-fetch: if a concurrent writer won, use THEIR seed (Python parity).
            sqlx::query_scalar(SELECT_SEED)
                .fetch_optional(pool)
                .await
                .map_err(|e| format!("lan_cowork identity re-read failed: {e}"))?
                .ok_or_else(|| "lan_cowork identity row missing after insert".to_string())?
        }
    };

    // Sanity: the persisted seed must yield a usable identity (32 bytes, valid ed25519).
    // SF-3 — this is a LOCAL data-corruption condition, not an infrastructure failure, so it
    // must NOT brick the whole server: log loudly with the recovery command and continue in
    // the degraded state the readers already handle (they return None -> LAN Cowork 503).
    // Deliberately do NOT auto-regenerate: silently replacing a stored key is exactly the
    // rotation this function exists to prevent. (Safe to delete manually: an underivable seed
    // cannot have any pairing tied to it, because peer_id is derived from it.)
    // The seed is NEVER included in the message.
    if derive_peer_id_from_seed(&seed).is_none() {
        tracing::error!(
            "lan_cowork: persisted ed25519_seed is unusable (expected 32 bytes); LAN Cowork \
             will stay unavailable. To regenerate, delete the row and restart: \
             DELETE FROM lan_cowork_identity WHERE key='ed25519_seed'"
        );
    }
    Ok(())
}

#[cfg(test)]
mod identity_bootstrap_tests {
    use super::{derive_peer_id_from_seed, ensure_local_identity, local_peer_id};

    async fn identity_test_pool() -> sqlx::SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        crate::schema::apply_standalone_schema(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn ensure_identity_generates_a_32_byte_seed_when_absent() {
        let pool = identity_test_pool().await;
        ensure_local_identity(&pool)
            .await
            .expect("bootstrap should succeed");
        let seed: Vec<u8> =
            sqlx::query_scalar("SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(seed.len(), 32);
        // The persisted seed must yield a usable identity.
        assert!(derive_peer_id_from_seed(&seed).is_some());
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM lan_cowork_identity WHERE key='ed25519_seed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn ensure_identity_is_idempotent_and_never_rotates_the_seed() {
        let pool = identity_test_pool().await;
        ensure_local_identity(&pool).await.unwrap();
        let first: Vec<u8> =
            sqlx::query_scalar("SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        // Re-running must reuse the existing seed — rotating it would invalidate every pairing.
        ensure_local_identity(&pool).await.unwrap();
        let second: Vec<u8> =
            sqlx::query_scalar("SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(first, second);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM lan_cowork_identity")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn ensure_identity_preserves_a_preexisting_seed() {
        let pool = identity_test_pool().await;
        let planted: Vec<u8> = (101u8..=132).collect(); // 32 bytes, same shape as the test fixtures
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind(&planted)
            .execute(&pool)
            .await
            .unwrap();
        ensure_local_identity(&pool).await.unwrap();
        let after: Vec<u8> =
            sqlx::query_scalar("SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after, planted); // untouched
    }

    #[tokio::test]
    async fn ensure_identity_leaves_a_corrupt_seed_untouched_and_does_not_brick_startup() {
        // SF-3: a corrupt seed is a LOCAL data problem — it must not fail startup, and it must
        // NOT be silently regenerated (that would be the rotation this function prevents).
        let pool = identity_test_pool().await;
        let corrupt = vec![1u8, 2, 3]; // not 32 bytes
        sqlx::query("INSERT INTO lan_cowork_identity (key, value) VALUES ('ed25519_seed', ?1)")
            .bind(&corrupt)
            .execute(&pool)
            .await
            .unwrap();
        ensure_local_identity(&pool)
            .await
            .expect("corrupt seed must not be a startup failure");
        let after: Vec<u8> =
            sqlx::query_scalar("SELECT value FROM lan_cowork_identity WHERE key='ed25519_seed'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            after, corrupt,
            "the corrupt seed must be left for the operator, not rotated"
        );
        assert!(derive_peer_id_from_seed(&after).is_none()); // still degraded, as expected
    }

    #[tokio::test]
    async fn ensure_identity_unblocks_local_peer_id_and_registry_build() {
        // A state whose db/db_read share one in-memory pool (b-1b precedent).
        let state = crate::state::semantic_test_state_with(false, String::new()).await;
        crate::schema::apply_standalone_schema(&state.db)
            .await
            .unwrap();

        // Before bootstrap: no identity -> the daemon cannot identify itself.
        assert!(local_peer_id(&*state).await.is_none());

        ensure_local_identity(&state.db).await.unwrap();

        // After bootstrap: identity resolves, so the registry can be built (b-1b) and every
        // inbound handler stops 503-ing on a missing slot.
        let pid = local_peer_id(&*state)
            .await
            .expect("peer_id after bootstrap");
        assert_eq!(pid.len(), 32); // sha256(pubkey)[..16] hex
        assert!(
            crate::routes::lan_cowork_inbound_read::build_peer_registry(&state, true)
                .await
                .is_some(),
            "registry must build once the identity exists"
        );
    }
}
