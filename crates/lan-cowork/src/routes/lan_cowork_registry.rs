//! LAN Cowork in-memory peer registry (Increment B-d1).
//!
//! Port of extensions/builtin_lan_cowork/core_impl/registry.py + the DB layer in
//! core/services_core/peer_registry_service.py. Dead-code until B-d5 wires it
//! behind the `lan_cowork.native_daemon` flag; `new()` performs pure in-memory
//! init and never touches the DB (`load_all()` is separate and test-only).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use sqlx::SqlitePool;

/// Peers not reached within this window (epoch seconds) are hard-deleted by
/// `load_all` (fleet_config `hard_prune_sec` = 7 days).
pub const HARD_PRUNE_SEC: i64 = 604_800;
/// Unpaired peers not reached within this window are soft-pruned by `load_all`
/// (fleet_config `soft_prune_sec` = 1 hour).
pub const SOFT_PRUNE_SEC: i64 = 3_600;
/// Seconds since last_seen after which a peer is marked offline
/// (Python `PeerRegistry` default `offline_timeout = 30.0`).
pub const OFFLINE_TIMEOUT_SEC: u64 = 30;

/// One peer as tracked in memory. Persistent fields map to `peers` columns;
/// runtime fields live only here; telemetry fields are written by fleet only.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub peer_id: String,
    pub name: String,
    pub api_host: String,
    pub api_port: u16,
    pub token: Option<String>,
    pub token_expires_at: Option<i64>,
    pub token_issued_at: Option<i64>,
    pub pubkey: Option<[u8; 32]>,
    pub x25519_pk: Option<[u8; 32]>,
    pub version: String,
    pub bridges: Vec<String>,
    pub inference_types: Vec<String>,
    pub gpu: String,
    pub generating: bool,
    pub queue_depth: i64,
    pub status: String,
    pub last_seen: f64,
    pub session_id: String,
    pub roles: Vec<String>,
    pub last_reached_at: Option<i64>,
    pub last_attempted_at: Option<i64>,
}

struct Inner {
    peers: HashMap<String, PeerInfo>,
    pubkey_index: HashMap<[u8; 32], String>,
}

pub struct PeerRegistry {
    inner: Mutex<Inner>,
    db: SqlitePool,
    offline_timeout: Duration,
    local_peer_id: String,
}

impl PeerRegistry {
    /// Pure in-memory init. Unlike Python `__init__`, it does NOT hydrate;
    /// call `load_all()` separately (B-d5 / tests only).
    pub fn new(db: SqlitePool, offline_timeout: Duration, local_peer_id: String) -> Self {
        Self {
            inner: Mutex::new(Inner {
                peers: HashMap::new(),
                pubkey_index: HashMap::new(),
            }),
            db,
            offline_timeout,
            local_peer_id,
        }
    }

    /// The local node's own peer_id (used to exclude self from `discover`).
    pub fn local_peer_id(&self) -> String {
        self.local_peer_id.clone()
    }

    pub fn get(&self, peer_id: &str) -> Option<PeerInfo> {
        self.inner.lock().unwrap().peers.get(peer_id).cloned()
    }

    pub fn get_by_pubkey(&self, pubkey: &[u8; 32]) -> Option<PeerInfo> {
        let inner = self.inner.lock().unwrap();
        let peer_id = inner.pubkey_index.get(pubkey)?;
        inner.peers.get(peer_id).cloned()
    }

    pub fn list_all(&self) -> Vec<PeerInfo> {
        self.inner.lock().unwrap().peers.values().cloned().collect()
    }

    #[cfg(any(test, feature = "test-seams"))]
    #[doc(hidden)]
    pub fn insert_for_test(&self, peer: PeerInfo) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .peers
            .insert(peer.peer_id.clone(), peer);
    }

    /// Upsert a peer while retaining missing keys like DB `COALESCE`.
    ///
    /// MF-12: an incoming peer that omits pubkey/x25519 has those keys backfilled
    /// from the existing in-memory entry before the persist-diff, matching the DB
    /// COALESCE. One consequence: an update that omits only the keys, with every
    /// other persistent field unchanged, is persist-skipped here. Python issues a
    /// redundant COALESCE no-op UPDATE in that case, so the end DB state is
    /// identical and the skip is safe (pinned by
    /// `upsert_skips_db_write_when_only_key_omitted_and_otherwise_unchanged`).
    pub async fn upsert(&self, peer: PeerInfo) -> Result<(), sqlx::Error> {
        if peer.peer_id == self.local_peer_id {
            return Ok(());
        }
        let to_persist = {
            let mut inner = self.inner.lock().unwrap();
            let mut peer = peer;
            if let Some(existing) = inner.peers.get(&peer.peer_id) {
                if peer.pubkey.is_none() {
                    peer.pubkey = existing.pubkey;
                }
                if peer.x25519_pk.is_none() {
                    peer.x25519_pk = existing.x25519_pk;
                }
            }
            if let Some(old) = inner.peers.get(&peer.peer_id) {
                if let Some(key) = old.pubkey {
                    inner.pubkey_index.remove(&key);
                }
            }
            if let Some(key) = peer.pubkey {
                inner.pubkey_index.insert(key, peer.peer_id.clone());
            }
            let differs = inner
                .peers
                .get(&peer.peer_id)
                .map(|existing| persistent_snapshot(existing) != persistent_snapshot(&peer))
                .unwrap_or(true);
            inner.peers.insert(peer.peer_id.clone(), peer.clone());
            differs.then_some(peer)
        };
        if let Some(peer) = to_persist {
            let now = now_secs();
            sqlx::query(
                "INSERT INTO peers (peer_id,name,api_host,api_port,token,token_expires_at,\
                 token_issued_at,pubkey,x25519_pk,created_at,updated_at) \
                 VALUES (?,?,?,?,?,?,?,?,?,?,?) \
                 ON CONFLICT(peer_id) DO UPDATE SET \
                 name=excluded.name, api_host=excluded.api_host, api_port=excluded.api_port,\
                 token=excluded.token, token_expires_at=excluded.token_expires_at,\
                 token_issued_at=excluded.token_issued_at,\
                 pubkey=COALESCE(excluded.pubkey, pubkey),\
                 x25519_pk=COALESCE(excluded.x25519_pk, x25519_pk),\
                 updated_at=excluded.updated_at",
            )
            .bind(&peer.peer_id)
            .bind(&peer.name)
            .bind(&peer.api_host)
            .bind(peer.api_port as i64)
            .bind(&peer.token)
            .bind(peer.token_expires_at)
            .bind(peer.token_issued_at)
            .bind(peer.pubkey.map(|value| value.to_vec()))
            .bind(peer.x25519_pk.map(|value| value.to_vec()))
            .bind(now)
            .bind(now)
            .execute(&self.db)
            .await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_runtime(
        &self,
        peer_id: &str,
        generating: Option<bool>,
        queue_depth: Option<i64>,
        bridges: Option<Vec<String>>,
        inference_types: Option<Vec<String>>,
        last_seen: Option<f64>,
        status: Option<String>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(peer) = inner.peers.get_mut(peer_id) {
            if let Some(value) = generating {
                peer.generating = value;
            }
            if let Some(value) = queue_depth {
                peer.queue_depth = value;
            }
            if let Some(value) = bridges {
                peer.bridges = value;
            }
            if let Some(value) = inference_types {
                peer.inference_types = value;
            }
            if let Some(value) = last_seen {
                peer.last_seen = value;
            }
            if let Some(value) = status {
                peer.status = value;
            }
        }
    }

    pub fn list_online(&self) -> Vec<PeerInfo> {
        self.inner
            .lock()
            .unwrap()
            .peers
            .values()
            .filter(|peer| peer.status == "online")
            .cloned()
            .collect()
    }

    /// Mark peers offline whose last_seen is older than offline_timeout.
    pub fn check_timeouts(&self, now: f64) -> Vec<String> {
        let timeout = self.offline_timeout.as_secs_f64();
        let mut inner = self.inner.lock().unwrap();
        let mut went_offline = Vec::new();
        for peer in inner.peers.values_mut() {
            if peer.status == "online" && (now - peer.last_seen) > timeout {
                peer.status = "offline".into();
                went_offline.push(peer.peer_id.clone());
            }
        }
        went_offline
    }

    /// Hydrate after dual-prune. Never called by `new()`.
    pub async fn load_all(
        &self,
        hard_cutoff: i64,
        soft_cutoff: i64,
        now: f64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "DELETE FROM peers WHERE (last_reached_at IS NOT NULL AND last_reached_at < ?) \
             OR (last_reached_at IS NULL AND created_at < ?)",
        )
        .bind(hard_cutoff)
        .bind(hard_cutoff)
        .execute(&self.db)
        .await?;
        sqlx::query(
            "DELETE FROM peers WHERE (token IS NULL OR token = '') \
             AND last_reached_at IS NULL AND created_at < ?",
        )
        .bind(soft_cutoff)
        .execute(&self.db)
        .await?;

        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT peer_id,name,api_host,api_port,token,token_expires_at,token_issued_at,\
             pubkey,x25519_pk,last_reached_at,last_attempted_at FROM peers",
        )
        .fetch_all(&self.db)
        .await?;
        let mut stale_self = None;
        {
            let mut inner = self.inner.lock().unwrap();
            inner.peers.clear();
            inner.pubkey_index.clear();
            for row in &rows {
                let peer_id: String = row.get("peer_id");
                if peer_id == self.local_peer_id {
                    stale_self = Some(peer_id);
                    continue;
                }
                let to_32 = |value: Option<Vec<u8>>| {
                    value.and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                };
                let pubkey = to_32(row.get("pubkey"));
                let peer = PeerInfo {
                    peer_id: peer_id.clone(),
                    name: row.get::<Option<String>, _>("name").unwrap_or_default(),
                    api_host: row.get::<Option<String>, _>("api_host").unwrap_or_default(),
                    api_port: row.get::<Option<i64>, _>("api_port").unwrap_or(0) as u16,
                    token: row.get("token"),
                    token_expires_at: row.get("token_expires_at"),
                    token_issued_at: row.get("token_issued_at"),
                    pubkey,
                    x25519_pk: to_32(row.get("x25519_pk")),
                    version: String::new(),
                    bridges: vec![],
                    inference_types: vec![],
                    gpu: String::new(),
                    generating: false,
                    queue_depth: 0,
                    status: "online".into(),
                    last_seen: now,
                    session_id: String::new(),
                    roles: vec![],
                    last_reached_at: row.get("last_reached_at"),
                    last_attempted_at: row.get("last_attempted_at"),
                };
                if let Some(key) = pubkey {
                    inner.pubkey_index.insert(key, peer_id.clone());
                }
                inner.peers.insert(peer_id, peer);
            }
        }
        if let Some(peer_id) = stale_self {
            sqlx::query("DELETE FROM peers WHERE peer_id=?")
                .bind(peer_id)
                .execute(&self.db)
                .await?;
        }
        Ok(())
    }

    pub async fn remove(&self, peer_id: &str) -> Result<(), sqlx::Error> {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(peer) = inner.peers.remove(peer_id) {
                if let Some(key) = peer.pubkey {
                    inner.pubkey_index.remove(&key);
                }
            }
        }
        sqlx::query("DELETE FROM peers WHERE peer_id=?")
            .bind(peer_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    /// Fleet-only telemetry (MF-7). Not wired to heartbeat/discovery.
    ///
    /// Mirrors Python's two entry points: `reached` sets last_reached_at +
    /// last_attempted_at (+ updated_at) to the timestamp; `attempted` sets only
    /// last_attempted_at (+ updated_at). Python callers supply exactly one; if
    /// both are `Some`, `reached` takes precedence and `attempted` is ignored.
    pub async fn update_telemetry(
        &self,
        peer_id: &str,
        reached: Option<i64>,
        attempted: Option<i64>,
    ) -> Result<(), sqlx::Error> {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(peer) = inner.peers.get_mut(peer_id) {
                if let Some(timestamp) = reached {
                    peer.last_reached_at = Some(timestamp);
                    peer.last_attempted_at = Some(timestamp);
                } else if let Some(timestamp) = attempted {
                    peer.last_attempted_at = Some(timestamp);
                }
            }
        }
        if let Some(timestamp) = reached {
            sqlx::query(
                "UPDATE peers SET last_reached_at=?, last_attempted_at=?, updated_at=? WHERE peer_id=?",
            )
            .bind(timestamp)
            .bind(timestamp)
            .bind(timestamp)
            .bind(peer_id)
            .execute(&self.db)
            .await?;
        } else if let Some(timestamp) = attempted {
            sqlx::query("UPDATE peers SET last_attempted_at=?, updated_at=? WHERE peer_id=?")
                .bind(timestamp)
                .bind(timestamp)
                .bind(peer_id)
                .execute(&self.db)
                .await?;
        }
        Ok(())
    }
}

type PersistentSnapshot = (
    String,
    String,
    u16,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<[u8; 32]>,
    Option<[u8; 32]>,
);

fn persistent_snapshot(peer: &PeerInfo) -> PersistentSnapshot {
    (
        peer.name.clone(),
        peer.api_host.clone(),
        peer.api_port,
        peer.token.clone(),
        peer.token_expires_at,
        peer.token_issued_at,
        peer.pubkey,
        peer.x25519_pk,
    )
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::Row;

    const VECTORS: &str = include_str!("../../tests/vectors/registry_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("registry vectors parse")
    }

    async fn empty_pool() -> sqlx::SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    async fn mem_pool(ddl: &str) -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("mem pool");
        sqlx::query(ddl).execute(&pool).await.expect("ddl");
        pool
    }

    async fn insert_rows(pool: &sqlx::SqlitePool, rows: &[Value]) {
        for row in rows {
            sqlx::query(
                "INSERT INTO peers (peer_id,name,api_host,api_port,token,\
                 token_expires_at,token_issued_at,pubkey,x25519_pk,\
                 created_at,updated_at,last_reached_at,last_attempted_at) \
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )
            .bind(row["peer_id"].as_str())
            .bind(row["name"].as_str())
            .bind(row["api_host"].as_str())
            .bind(row["api_port"].as_i64())
            .bind(row["token"].as_str())
            .bind(row["token_expires_at"].as_i64())
            .bind(row["token_issued_at"].as_i64())
            .bind(row["pubkey"].as_str().map(|hex| hex::decode(hex).unwrap()))
            .bind(
                row["x25519_pk"]
                    .as_str()
                    .map(|hex| hex::decode(hex).unwrap()),
            )
            .bind(row["created_at"].as_i64())
            .bind(row["updated_at"].as_i64())
            .bind(row["last_reached_at"].as_i64())
            .bind(row["last_attempted_at"].as_i64())
            .execute(pool)
            .await
            .expect("insert row");
        }
    }

    async fn dump_rows(pool: &sqlx::SqlitePool) -> Vec<Value> {
        sqlx::query("SELECT * FROM peers ORDER BY peer_id")
            .fetch_all(pool)
            .await
            .unwrap()
            .iter()
            .map(|row| {
                serde_json::json!({
                    "peer_id": row.get::<Option<String>, _>("peer_id"),
                    "name": row.get::<Option<String>, _>("name"),
                    "api_host": row.get::<Option<String>, _>("api_host"),
                    "api_port": row.get::<Option<i64>, _>("api_port"),
                    "token": row.get::<Option<String>, _>("token"),
                    "token_expires_at": row.get::<Option<i64>, _>("token_expires_at"),
                    "token_issued_at": row.get::<Option<i64>, _>("token_issued_at"),
                    "pubkey": row.get::<Option<Vec<u8>>, _>("pubkey").map(hex::encode),
                    "x25519_pk": row.get::<Option<Vec<u8>>, _>("x25519_pk").map(hex::encode),
                    "created_at": row.get::<Option<i64>, _>("created_at"),
                    "updated_at": row.get::<Option<i64>, _>("updated_at"),
                    "last_reached_at": row.get::<Option<i64>, _>("last_reached_at"),
                    "last_attempted_at": row.get::<Option<i64>, _>("last_attempted_at"),
                })
            })
            .collect()
    }

    fn peer_from_input(input: &Value, now: f64) -> PeerInfo {
        let decode_key = |key: &str| {
            input[key].as_str().map(|hex| {
                let bytes = hex::decode(hex).unwrap();
                let mut value = [0; 32];
                value.copy_from_slice(&bytes);
                value
            })
        };
        PeerInfo {
            peer_id: input["peer_id"].as_str().unwrap().into(),
            name: input["name"].as_str().unwrap_or("").into(),
            api_host: input["api_host"].as_str().unwrap_or("").into(),
            api_port: input["api_port"].as_i64().unwrap_or(0) as u16,
            token: input["token"].as_str().map(Into::into),
            token_expires_at: input["token_expires_at"].as_i64(),
            token_issued_at: input["token_issued_at"].as_i64(),
            pubkey: decode_key("pubkey"),
            x25519_pk: decode_key("x25519_pk"),
            version: String::new(),
            bridges: vec![],
            inference_types: vec![],
            gpu: String::new(),
            generating: false,
            queue_depth: 0,
            status: "online".into(),
            last_seen: now,
            session_id: String::new(),
            roles: vec![],
            last_reached_at: None,
            last_attempted_at: None,
        }
    }

    fn strip_ts(rows: &[Value]) -> Vec<Value> {
        rows.iter()
            .map(|row| {
                let mut value = row.as_object().unwrap().clone();
                value.remove("created_at");
                value.remove("updated_at");
                Value::Object(value)
            })
            .collect()
    }

    fn find_row<'a>(rows: &'a [Value], peer_id: &str) -> &'a Value {
        rows.iter()
            .find(|row| row["peer_id"].as_str() == Some(peer_id))
            .expect("row present")
    }

    #[tokio::test]
    async fn new_is_pure_in_memory_and_empty() {
        let registry = PeerRegistry::new(
            empty_pool().await,
            std::time::Duration::from_secs(30),
            "self0".into(),
        );
        assert!(registry.list_all().is_empty());
        assert!(registry.get("nope").is_none());
        assert!(registry.get_by_pubkey(&[0; 32]).is_none());
    }

    #[tokio::test]
    async fn upsert_matches_python_golden() {
        let values = vectors();
        let ddl = values["peers_ddl"].as_str().unwrap();
        for case in values["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["op"] == "upsert")
        {
            let pool = mem_pool(ddl).await;
            insert_rows(&pool, case["initial_rows"].as_array().unwrap()).await;
            let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "self0".into());
            let peer_id = case["input"]["peer_id"].as_str().unwrap();
            registry
                .upsert(peer_from_input(
                    &case["input"],
                    case["now"].as_f64().unwrap(),
                ))
                .await
                .unwrap();
            let got = dump_rows(&pool).await;
            let wanted = case["expected_rows"].as_array().unwrap();
            assert_eq!(
                strip_ts(&got),
                strip_ts(wanted),
                "rows(non-ts) case {}",
                case["label"]
            );
            let row = find_row(&got, peer_id);
            let created = row["created_at"].as_i64().unwrap();
            let updated = row["updated_at"].as_i64().unwrap();
            match case["initial_rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["peer_id"].as_str() == Some(peer_id))
            {
                Some(existing) => assert_eq!(created, existing["created_at"].as_i64().unwrap()),
                None => assert_eq!(created, updated),
            }
        }
    }

    #[tokio::test]
    async fn upsert_preserves_in_memory_keys_on_key_missing_update() {
        let pool = mem_pool(vectors()["peers_ddl"].as_str().unwrap()).await;
        let registry = PeerRegistry::new(pool, Duration::from_secs(30), "self0".into());
        let key = [7; 32];
        let peer_id = "ab".repeat(16);
        registry
            .upsert(peer_from_input(
                &serde_json::json!({
                    "peer_id": peer_id, "name": "n", "api_host": "10.0.0.5", "api_port": 8188,
                    "token": null, "token_expires_at": null, "token_issued_at": null,
                    "pubkey": hex::encode(key), "x25519_pk": null
                }),
                1000.0,
            ))
            .await
            .unwrap();
        registry
            .upsert(peer_from_input(
                &serde_json::json!({
                    "peer_id": peer_id, "name": "n2", "api_host": "10.0.0.5", "api_port": 8188,
                    "token": "tok", "token_expires_at": null, "token_issued_at": null,
                    "pubkey": null, "x25519_pk": null
                }),
                1001.0,
            ))
            .await
            .unwrap();
        let got = registry.get(&peer_id).unwrap();
        assert_eq!(got.pubkey, Some(key));
        assert_eq!(got.name, "n2");
        assert!(registry.get_by_pubkey(&key).is_some());
    }

    #[tokio::test]
    async fn upsert_skips_db_write_when_only_key_omitted_and_otherwise_unchanged() {
        // MF-12 consequence: a second upsert that omits only pubkey/x25519, with all
        // other persistent fields identical to the stored peer, is persist-skipped
        // (missing keys are backfilled before the snapshot diff). Python issues a
        // redundant COALESCE no-op UPDATE; the end DB state is identical, so the skip
        // is safe. A sentinel updated_at makes a would-be second write observable.
        let pool = mem_pool(vectors()["peers_ddl"].as_str().unwrap()).await;
        let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "self0".into());
        let key = [9; 32];
        let peer_id = "cd".repeat(16);
        let base = serde_json::json!({
            "peer_id": peer_id, "name": "n", "api_host": "10.0.0.7", "api_port": 8188,
            "token": null, "token_expires_at": null, "token_issued_at": null,
            "pubkey": hex::encode(key), "x25519_pk": null
        });
        registry
            .upsert(peer_from_input(&base, 1000.0))
            .await
            .unwrap();
        sqlx::query("UPDATE peers SET updated_at = 999 WHERE peer_id = ?")
            .bind(&peer_id)
            .execute(&pool)
            .await
            .unwrap();
        // Same persistent fields, but pubkey omitted -> backfilled -> snapshot unchanged.
        let mut omitted = base.clone();
        omitted["pubkey"] = Value::Null;
        registry
            .upsert(peer_from_input(&omitted, 1001.0))
            .await
            .unwrap();
        let rows = dump_rows(&pool).await;
        let row = find_row(&rows, &peer_id);
        assert_eq!(
            row["updated_at"].as_i64(),
            Some(999),
            "persist skipped: no second UPDATE bumped updated_at"
        );
        assert_eq!(
            row["pubkey"].as_str().map(str::to_string),
            Some(hex::encode(key)),
            "existing DB key preserved"
        );
        assert_eq!(
            registry.get(&peer_id).unwrap().pubkey,
            Some(key),
            "in-memory key retained"
        );
    }

    #[tokio::test]
    async fn runtime_and_timeouts_are_in_memory() {
        let pool = mem_pool(vectors()["peers_ddl"].as_str().unwrap()).await;
        let registry = PeerRegistry::new(pool, Duration::from_secs(30), "self0".into());
        let peer = peer_from_input(
            &serde_json::json!({
                "peer_id": "dd".repeat(16), "name": "n", "api_host": "10.0.0.9", "api_port": 8188,
                "token": null, "token_expires_at": null, "token_issued_at": null,
                "pubkey": null, "x25519_pk": null
            }),
            1000.0,
        );
        registry.upsert(peer.clone()).await.unwrap();
        registry.update_runtime(
            &peer.peer_id,
            Some(true),
            Some(3),
            None,
            None,
            Some(1000.0),
            None,
        );
        let got = registry.get(&peer.peer_id).unwrap();
        assert!(got.generating && got.queue_depth == 3 && got.status == "online");
        assert_eq!(registry.list_online().len(), 1);
        assert_eq!(registry.check_timeouts(1031.0), vec![peer.peer_id.clone()]);
        assert_eq!(registry.list_online().len(), 0);
    }

    #[tokio::test]
    async fn load_all_matches_python_golden() {
        let values = vectors();
        let ddl = values["peers_ddl"].as_str().unwrap();
        for case in values["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["op"] == "load_all")
        {
            let pool = mem_pool(ddl).await;
            insert_rows(&pool, case["initial_rows"].as_array().unwrap()).await;
            let registry = PeerRegistry::new(
                pool.clone(),
                Duration::from_secs(30),
                case["local_peer_id"].as_str().unwrap().into(),
            );
            registry
                .load_all(
                    case["hard_cutoff"].as_i64().unwrap(),
                    case["soft_cutoff"].as_i64().unwrap(),
                    case["now"].as_f64().unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                &dump_rows(&pool).await,
                case["expected_rows"].as_array().unwrap()
            );
            let mut memory: Vec<Value> = registry
                .list_all()
                .iter()
                .map(|peer| serde_json::json!({
                    "peer_id": peer.peer_id, "status": peer.status, "has_pubkey": peer.pubkey.is_some()
                }))
                .collect();
            memory.sort_by(|left, right| left["peer_id"].as_str().cmp(&right["peer_id"].as_str()));
            let mut wanted = case["expected_memory"].as_array().unwrap().clone();
            wanted.sort_by(|left, right| left["peer_id"].as_str().cmp(&right["peer_id"].as_str()));
            assert_eq!(memory, wanted);
            for peer in registry.list_all() {
                assert_eq!(peer.last_seen, case["now"].as_f64().unwrap());
            }
        }
    }

    #[tokio::test]
    async fn remove_and_telemetry_match_python_golden() {
        let values = vectors();
        let ddl = values["peers_ddl"].as_str().unwrap();
        for case in values["cases"].as_array().unwrap() {
            let operation = case["op"].as_str().unwrap();
            if operation != "remove" && operation != "telemetry" {
                continue;
            }
            let pool = mem_pool(ddl).await;
            insert_rows(&pool, case["initial_rows"].as_array().unwrap()).await;
            let registry = PeerRegistry::new(pool.clone(), Duration::from_secs(30), "self0".into());
            let peer_id = case["target"].as_str().unwrap();
            if operation == "remove" {
                registry.remove(peer_id).await.unwrap();
            } else {
                registry
                    .update_telemetry(
                        peer_id,
                        case["reached"].as_i64(),
                        case["attempted"].as_i64(),
                    )
                    .await
                    .unwrap();
            }
            assert_eq!(
                &dump_rows(&pool).await,
                case["expected_rows"].as_array().unwrap()
            );
        }
    }
}
