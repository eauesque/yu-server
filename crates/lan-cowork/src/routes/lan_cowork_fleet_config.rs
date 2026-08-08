//! LAN Cowork fleet timing configuration (F1).

use serde_json::{json, Value};

pub const TIMING_DEFAULTS: [(&str, i64); 8] = [
    ("chief_observation_sec", 25),
    ("peers_poll_interval_sec", 30),
    ("heartbeat_timeout_sec", 60),
    ("update_job_timeout_sec", 600),
    ("postcheck_timeout_sec", 180),
    ("consent_timeout_sec", 300),
    ("soft_prune_sec", 3_600),
    ("hard_prune_sec", 604_800),
];

/// Return Python-compatible fleet timings from `config.json` app config.
pub fn get_fleet_timings(app_config: &Value) -> Value {
    let overrides = app_config
        .pointer("/extensions/builtin-lan-cowork/fleet/timings")
        .and_then(Value::as_object);
    let mut timings = serde_json::Map::new();
    for (key, default) in TIMING_DEFAULTS {
        timings.insert(
            key.to_owned(),
            overrides
                .and_then(|value| value.get(key))
                .cloned()
                .unwrap_or_else(|| json!(default)),
        );
    }
    Value::Object(timings)
}

/// Normalize the persisted allowlist union without retaining unsupported roles.
pub fn parse_allowlist(entries: &[Value]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            Value::String(peer_id) => Some(peer_id.clone()),
            Value::Object(entry) => match entry.get("peer_id").and_then(Value::as_str) {
                Some(peer_id) => Some(peer_id.to_owned()),
                None if entry.contains_key("role") => {
                    tracing::warn!("invalid allowlist role entry ignored");
                    None
                }
                None => {
                    tracing::warn!("invalid allowlist entry shape ignored");
                    None
                }
            },
            _ => {
                tracing::warn!("invalid allowlist entry ignored");
                None
            }
        })
        .collect()
}

pub fn peer_id_in_allowlist(peer_id: &str, entries: &[String]) -> bool {
    entries.iter().any(|entry| entry == peer_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_timings_apply_only_known_overrides() {
        let timings = get_fleet_timings(&json!({
            "extensions": {"builtin-lan-cowork": {"fleet": {"timings": {
                "heartbeat_timeout_sec": 12, "unknown": 99
            }}}}
        }));
        assert_eq!(timings.as_object().unwrap().len(), TIMING_DEFAULTS.len());
        assert_eq!(timings["heartbeat_timeout_sec"], 12);
        assert_eq!(timings["chief_observation_sec"], 25);
        assert!(timings.get("unknown").is_none());
    }

    #[test]
    fn allowlist_parser_drops_roles_and_matches_peer_ids() {
        let parsed = parse_allowlist(&[
            json!("peer-a"),
            json!({"peer_id": "peer-b"}),
            json!({"role": "chief"}),
        ]);
        assert_eq!(parsed, ["peer-a", "peer-b"]);
        assert!(peer_id_in_allowlist("peer-b", &parsed));
    }
}
