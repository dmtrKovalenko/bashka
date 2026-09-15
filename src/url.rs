/// Yields every `http://` / `https://` URL embedded in `text`.
pub fn urls_in(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        let start = ["https://", "http://"]
            .iter()
            .filter_map(|p| rest.find(p))
            .min()?;
        let tail = &rest[start..];
        let end = tail
            .find(|c: char| c.is_whitespace() || "'\"`|;<>()[]{},".contains(c))
            .unwrap_or(tail.len());
        let url = &tail[..end];
        rest = &tail[end..];
        Some(url)
    })
}

pub fn is_https(url: &str) -> bool {
    url.starts_with("https://")
}

pub fn locate(text: &str, base: usize, needle: &str) -> std::ops::Range<usize> {
    match text.find(needle) {
        Some(off) => base + off..base + off + needle.len(),
        None => base..base + text.len(),
    }
}

/// Host part of a URL, lower-cased, without credentials or port.
pub fn host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    // Bracketed IPv6 (`[::1]` or `[::1]:443`): keep everything up to the closing bracket.
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(h, _)| h)
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// `true` when `host` equals `domain` or is a subdomain of it.
pub fn host_matches(host: &str, domain: &str) -> bool {
    host == domain || host.strip_suffix(domain).is_some_and(|p| p.ends_with('.'))
}

/// Approximate registrable domain: the last two dot-labels (`releases.openai.com` -> `openai.com`).
/// Good enough for same-publisher checks; not a full public-suffix implementation.
pub fn registrable(host: &str) -> &str {
    match host.rmatch_indices('.').nth(1) {
        Some((i, _)) => &host[i + 1..],
        None => host,
    }
}

/// Two hosts belong to the same publisher (share a registrable domain).
pub fn same_site(a: &str, b: &str) -> bool {
    !is_ip_host(a) && registrable(a) == registrable(b)
}

pub fn is_ip_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_multiple_urls() {
        let found: Vec<_> = urls_in(r#"curl "https://a.b/x?y=1" http://1.2.3.4/z | sh"#).collect();
        assert_eq!(found, ["https://a.b/x?y=1", "http://1.2.3.4/z"]);
    }

    #[test]
    fn extracts_host() {
        assert_eq!(
            host("https://user@Raw.GitHubUserContent.com:443/p").as_deref(),
            Some("raw.githubusercontent.com")
        );
        assert!(host_matches(
            "raw.githubusercontent.com",
            "githubusercontent.com"
        ));
        assert!(!host_matches(
            "evilgithubusercontent.com",
            "githubusercontent.com"
        ));
        assert!(is_ip_host("10.0.0.1"));
    }

    #[test]
    fn same_publisher() {
        assert_eq!(registrable("releases.openai.com"), "openai.com");
        assert!(same_site("releases.openai.com", "openai.com"));
        assert!(same_site("cdn.get.volta.sh", "volta.sh"));
        assert!(!same_site("evil.com", "openai.com"));
        assert!(!same_site("10.0.0.1", "10.0.0.1"));
    }
}
