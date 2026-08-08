#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassMatch {
    Exact,
    SingleSegment,
    Prefix,
}

impl BypassMatch {
    pub fn matches(self, pattern: &str, path: &str) -> bool {
        match self {
            Self::Exact => path == pattern,
            Self::SingleSegment => path
                .strip_prefix(pattern)
                .is_some_and(|tail| !tail.is_empty() && !tail.contains('/')),
            Self::Prefix => path.starts_with(pattern),
        }
    }
}

pub const BYPASS_ROUTES: &[(&str, BypassMatch, &str)] = &[
    (
        "/ext/lan_cowork/api/peer/pair/request",
        BypassMatch::Exact,
        "lan_cowork_pairing",
    ),
    (
        "/ext/lan_cowork/api/peer/pair/verify",
        BypassMatch::Exact,
        "lan_cowork_pairing",
    ),
    (
        "/ext/lan_cowork/api/peer/discover",
        BypassMatch::Exact,
        "lan_cowork_discover_status",
    ),
    (
        "/ext/lan_cowork/api/peer/status",
        BypassMatch::Exact,
        "lan_cowork_discover_status",
    ),
    (
        "/ext/lan_cowork/api/peer/register",
        BypassMatch::Exact,
        "lan_cowork_register",
    ),
    (
        "/ext/lan_cowork/api/peer/token/renew",
        BypassMatch::Exact,
        "lan_cowork_token_renew",
    ),
    (
        "/ext/lan_cowork/api/peer/event",
        BypassMatch::Exact,
        "lan_cowork_event",
    ),
    (
        "/ext/lan_cowork/api/peer/heartbeat",
        BypassMatch::Exact,
        "lan_cowork_heartbeat",
    ),
    (
        "/ext/lan_cowork/fleet/consent/request",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/consent/respond",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/consent/pending",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/consent/relay/request",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/consent/relay/status",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/allowlists/grant",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/allowlists/revoke",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/allowlists/check",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/info",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/logs/stream",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/restart",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/update",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/update/status",
        BypassMatch::Exact,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/fleet/consent/status/",
        BypassMatch::SingleSegment,
        "lan_cowork_fleet_peer",
    ),
    (
        "/ext/lan_cowork/api/peer/import/meta",
        BypassMatch::Exact,
        "lan_cowork_remote_import",
    ),
    (
        "/ext/lan_cowork/api/peer/import/diff",
        BypassMatch::Exact,
        "lan_cowork_remote_import",
    ),
    (
        "/ext/lan_cowork/api/peer/import/zip",
        BypassMatch::Exact,
        "lan_cowork_remote_import",
    ),
    // Never use the broader import prefix because local import session routes
    // must stay gated.
    (
        "/ext/lan_cowork/api/peer/import/file/",
        BypassMatch::Prefix,
        "lan_cowork_remote_import",
    ),
    (
        "/ext/lan_cowork/api/peer/import/stream/",
        BypassMatch::Prefix,
        "lan_cowork_remote_import",
    ),
];

// NOTE: the following BYPASS_ROUTES/BypassMatch tests are self-contained (data-only,
// no dependency on yu-server's auth::chain). Tests that exercise check_static_bypass /
// run_chain, and the include_str! scan of auth/chain.rs, live in yu-server's
// routes/lan_cowork_split_integration_tests.rs -- a #[cfg(test)] item is invisible
// across the crate boundary regardless of pub visibility, and auth::chain is a
// yu-server-only module, so those tests cannot compile inside this crate.
#[cfg(test)]
mod tests {
    use super::{BypassMatch, BYPASS_ROUTES};

    #[test]
    fn route_group_and_match_kind_counts_are_pinned() {
        let mut groups = [0; 3];
        let mut kinds = [0; 3];
        for &(path, kind, _) in BYPASS_ROUTES {
            if path.starts_with("/ext/lan_cowork/fleet/") {
                groups[0] += 1;
            } else if path.starts_with("/ext/lan_cowork/api/peer/import/") {
                groups[1] += 1;
            } else {
                groups[2] += 1;
            }
            match kind {
                BypassMatch::Exact => kinds[0] += 1,
                BypassMatch::SingleSegment => kinds[1] += 1,
                BypassMatch::Prefix => kinds[2] += 1,
            }
        }
        assert_eq!(BYPASS_ROUTES.len(), 27);
        assert_eq!(groups, [14, 5, 8]);
        assert_eq!(kinds, [24, 1, 2]);
    }

    #[test]
    fn no_route_matches_another_route() {
        for (left_index, &(left_path, left_kind, _)) in BYPASS_ROUTES.iter().enumerate() {
            for (right_index, &(right_path, _, _)) in BYPASS_ROUTES.iter().enumerate() {
                if left_index == right_index {
                    continue;
                }
                assert_ne!(
                    left_path, right_path,
                    "duplicate route at {left_index}/{right_index}"
                );
                assert!(
                    !left_kind.matches(left_path, right_path),
                    "route {left_index} matches route {right_index}"
                );
            }
        }
    }
}
