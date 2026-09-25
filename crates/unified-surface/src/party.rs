//! Structural first- vs third-party classification of the hosts an app uses.
//!
//! First-party means "the app's own backend": a host whose registrable domain
//! is declared first-party, carries the app package's own name, or — when
//! neither signal exists — is the one domain that clearly dominates the
//! app's endpoints. Every other host is third-party. There is no tracker
//! allowlist: a host unknown to any list is still third-party when it is not
//! the app's own. When no first-party domain can be established at all, no
//! host is labeled rather than guessing.

use std::collections::BTreeMap;

use apiaxess_api_model::{Endpoint, HostParty, normalize_host};

/// What identifies the analyzed app's own backend.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirstPartyHints {
    /// Android package name (`pro.example.app`), when the target is an APK.
    pub app_package: Option<String>,
    /// Hosts declared as the app's own (for example a web target's host).
    pub first_party_hosts: Vec<String>,
}

/// Package segments too generic to identify an app's own domain.
const GENERIC_PACKAGE_TOKENS: &[&str] = &[
    "com", "org", "net", "app", "apps", "android", "mobile", "www", "io", "co", "the", "api",
    "client", "debug", "release", "main", "free", "lite", "prod", "staging", "internal",
];

/// Two-label public suffixes common enough that the registrable domain needs
/// a third label. Approximate by design; hosts under an unlisted multi-label
/// suffix degrade to their last two labels.
const TWO_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "co.jp", "com.au", "com.br", "co.nz", "co.za",
    "com.cn", "com.mx", "com.sg", "com.hk", "co.kr", "com.tr", "com.tw", "co.id", "com.my",
];

/// The registrable domain (`api.example.co.uk` -> `example.co.uk`). IP
/// literals and single-label hosts are returned unchanged, without a port.
#[must_use]
pub fn registrable_domain(host: &str) -> String {
    let host = strip_port(host).trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return host;
    }
    let labels = host
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.len() <= 2 {
        return labels.join(".");
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let keep = if TWO_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        2
    };
    labels[labels.len() - keep..].join(".")
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map_or(host, |end| &host[..=end]);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
}

/// The owner label of a registrable domain (`example.co.uk` -> `example`).
fn owner_label(domain: &str) -> &str {
    domain.split('.').next().unwrap_or(domain)
}

/// The host an endpoint is on: its identity host, else its selected base URL.
#[must_use]
pub fn endpoint_host(endpoint: &Endpoint) -> Option<String> {
    endpoint.identity.host.clone().or_else(|| {
        endpoint
            .base_url
            .as_ref()
            .and_then(|fact| fact.selected_candidate())
            .and_then(|candidate| normalize_host(&candidate.value))
    })
}

/// Classifies each host. `weights` counts how much of the app's surface each
/// host carries (endpoints, or observed flows); it only matters when no
/// declared or package-affine first-party domain exists. Hosts that cannot be
/// classified are absent from the result.
#[must_use]
pub fn classify_hosts(
    weights: &BTreeMap<String, usize>,
    hints: &FirstPartyHints,
) -> BTreeMap<String, HostParty> {
    let mut domain_weights = BTreeMap::<String, usize>::new();
    for (host, weight) in weights {
        *domain_weights.entry(registrable_domain(host)).or_default() += weight;
    }
    let declared = hints
        .first_party_hosts
        .iter()
        .filter_map(|host| normalize_host(host))
        .map(|host| registrable_domain(&host))
        .collect::<Vec<_>>();
    let package_tokens = hints
        .app_package
        .as_deref()
        .unwrap_or_default()
        .split('.')
        .map(str::to_ascii_lowercase)
        .filter(|token| token.len() >= 4 && !GENERIC_PACKAGE_TOKENS.contains(&token.as_str()))
        .collect::<Vec<_>>();
    let mut first_party = domain_weights
        .keys()
        .filter(|domain| {
            declared.contains(domain)
                || package_tokens
                    .iter()
                    .any(|token| token.as_str() == owner_label(domain))
        })
        .cloned()
        .collect::<Vec<_>>();
    if first_party.is_empty() {
        let mut ranked = domain_weights.iter().collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.1.cmp(left.1));
        match ranked.as_slice() {
            [(domain, _)] => first_party.push((*domain).clone()),
            [(domain, top), (_, next), ..] if top > next => first_party.push((*domain).clone()),
            _ => {}
        }
    }
    if first_party.is_empty() {
        return BTreeMap::new();
    }
    weights
        .keys()
        .map(|host| {
            let party = if first_party.contains(&registrable_domain(host)) {
                HostParty::FirstParty
            } else {
                HostParty::ThirdParty
            };
            (host.clone(), party)
        })
        .collect()
}

/// Classifies each endpoint's host, one entry per endpoint in order.
#[must_use]
pub fn classify_endpoints(
    endpoints: &[Endpoint],
    hints: &FirstPartyHints,
) -> Vec<Option<HostParty>> {
    let hosts = endpoints.iter().map(endpoint_host).collect::<Vec<_>>();
    let mut weights = BTreeMap::<String, usize>::new();
    for host in hosts.iter().flatten() {
        *weights.entry(host.clone()).or_default() += 1;
    }
    let parties = classify_hosts(&weights, hints);
    hosts
        .iter()
        .map(|host| host.as_ref().and_then(|host| parties.get(host).copied()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weights(entries: &[(&str, usize)]) -> BTreeMap<String, usize> {
        entries
            .iter()
            .map(|(host, weight)| ((*host).to_owned(), *weight))
            .collect()
    }

    fn package(name: &str) -> FirstPartyHints {
        FirstPartyHints {
            app_package: Some(name.to_owned()),
            first_party_hosts: Vec::new(),
        }
    }

    #[test]
    fn a_host_named_like_the_package_is_first_party_and_every_other_host_is_third() {
        let parties = classify_hosts(
            &weights(&[
                ("api.shopwise.example", 3),
                ("cdn.shopwise.example", 1),
                ("jsonfeed.unlisted-vendor.test", 5),
            ]),
            &package("io.shopwise.android"),
        );
        assert_eq!(parties["api.shopwise.example"], HostParty::FirstParty);
        assert_eq!(parties["cdn.shopwise.example"], HostParty::FirstParty);
        // Not on any tracker list, and heavier than the app's own host: still
        // third-party, because it is not the app's own domain.
        assert_eq!(
            parties["jsonfeed.unlisted-vendor.test"],
            HostParty::ThirdParty
        );
    }

    #[test]
    fn a_package_token_must_name_the_domain_not_just_any_label() {
        // `reference` is a package token and a subdomain label here, but the
        // domain belongs to someone else.
        let parties = classify_hosts(
            &weights(&[("reference.cdnhost.test", 1), ("api.mailbox.test", 1)]),
            &package("pro.mailbox.reference"),
        );
        assert_eq!(parties["reference.cdnhost.test"], HostParty::ThirdParty);
        assert_eq!(parties["api.mailbox.test"], HostParty::FirstParty);
    }

    #[test]
    fn without_package_affinity_the_dominant_domain_is_first_party() {
        let parties = classify_hosts(
            &weights(&[("api.backend.test", 7), ("metrics.vendor.test", 2)]),
            &package("com.x9.client"),
        );
        assert_eq!(parties["api.backend.test"], HostParty::FirstParty);
        assert_eq!(parties["metrics.vendor.test"], HostParty::ThirdParty);
    }

    #[test]
    fn no_established_first_party_leaves_hosts_unlabeled() {
        let parties = classify_hosts(
            &weights(&[("a.one.test", 2), ("b.two.test", 2)]),
            &FirstPartyHints::default(),
        );
        assert!(parties.is_empty());
    }

    #[test]
    fn declared_first_party_hosts_win() {
        let parties = classify_hosts(
            &weights(&[("shop.site.test", 1), ("api.payments.test", 9)]),
            &FirstPartyHints {
                app_package: None,
                first_party_hosts: vec!["https://www.site.test".to_owned()],
            },
        );
        assert_eq!(parties["shop.site.test"], HostParty::FirstParty);
        assert_eq!(parties["api.payments.test"], HostParty::ThirdParty);
    }

    #[test]
    fn registrable_domain_handles_suffixes_ports_and_addresses() {
        assert_eq!(registrable_domain("api.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("a.b.example.com:8443"), "example.com");
        assert_eq!(registrable_domain("10.0.2.2:8080"), "10.0.2.2");
        assert_eq!(registrable_domain("localhost"), "localhost");
    }
}
