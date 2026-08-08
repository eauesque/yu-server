//! Shared fleet authorization: master switch, one-time consent, and allowlists.

use axum::http::HeaderMap;
use serde_json::Value;

use crate::routes::lan_cowork_host::LanCoworkState;

use super::{
    lan_cowork::{ext_config, load_config_json},
    lan_cowork_fleet_config::{parse_allowlist, peer_id_in_allowlist},
    lan_cowork_fleet_consent::consume_consent_token,
};

fn fleet(state: &LanCoworkState) -> Value {
    ext_config(&load_config_json(state.config_path()))
        .get("fleet")
        .cloned()
        .unwrap_or_default()
}

/// Master switch false: valid consent consumes and permits; otherwise deny.
/// Master switch true: self, update allowlist, then optional restart allowlist.
pub(crate) fn check_update_allowed(
    state: &LanCoworkState,
    headers: &HeaderMap,
    requester_peer_id: &str,
    allow_consent: bool,
    include_restart_allowlist: bool,
) -> Result<(), &'static str> {
    let fleet = fleet(state);
    let token = headers
        .get("X-Consent-Token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    let local = state
        .peer_registry
        .get()
        .map(|registry| registry.local_peer_id())
        .unwrap_or_default();
    check_fleet_policy(
        &fleet,
        &local,
        requester_peer_id,
        token,
        allow_consent,
        include_restart_allowlist,
        consume_consent_token,
    )
}

fn check_fleet_policy<F>(
    fleet: &Value,
    local: &str,
    requester_peer_id: &str,
    token: &str,
    allow_consent: bool,
    include_restart_allowlist: bool,
    consume: F,
) -> Result<(), &'static str>
where
    F: FnOnce(&str, &str) -> bool,
{
    if !fleet
        .get("allow_remote_update")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return if allow_consent && !token.is_empty() && consume(token, requester_peer_id) {
            Ok(())
        } else if allow_consent && !token.is_empty() {
            Err("consent_token_invalid")
        } else {
            Err("remote_update_disabled")
        };
    }
    if requester_peer_id == local
        || peer_id_in_allowlist(
            requester_peer_id,
            &parse_allowlist(
                fleet
                    .get("allow_update_from")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            ),
        )
    {
        return Ok(());
    }
    if include_restart_allowlist
        && peer_id_in_allowlist(
            requester_peer_id,
            &parse_allowlist(
                fleet
                    .get("allow_restart_from")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            ),
        )
    {
        return Ok(());
    }
    Err("not_in_allowlist")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policy_preserves_consent_and_allowlist_branches() {
        let disabled = json!({"allow_remote_update": false});
        assert_eq!(
            check_fleet_policy(&disabled, "local", "peer", "token", true, false, |_, _| {
                true
            }),
            Ok(())
        );
        assert_eq!(
            check_fleet_policy(&disabled, "local", "peer", "", true, false, |_, _| false),
            Err("remote_update_disabled")
        );
        let enabled = json!({"allow_remote_update": true, "allow_update_from": ["peer"]});
        assert_eq!(
            check_fleet_policy(&enabled, "local", "peer", "", true, false, |_, _| false),
            Ok(())
        );
        let restart = json!({"allow_remote_update": true, "allow_restart_from": ["peer"]});
        assert_eq!(
            check_fleet_policy(&restart, "local", "peer", "", true, true, |_, _| false),
            Ok(())
        );
    }
}
