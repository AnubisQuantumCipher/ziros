use crate::types::{AgentWebFetchReportV1, AgentWebFetchRequestV1};
use zkf_command_surface::now_rfc3339;

const WEB_FETCH_SCHEMA: &str = "ziros-agent-web-fetch-v1";
const WEB_POLICY_SCOPE: &str = "official-web-only";
const DEFAULT_MAX_BYTES: usize = 65_536;
const DEFAULT_LINK_LIMIT: usize = 20;
const BROWSER_LIKE_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) ",
    "AppleWebKit/537.36 (KHTML, like Gecko) ",
    "Chrome/124.0.0.0 Safari/537.36 ZirOSAgent/1.0"
);

pub fn web_fetch(request: AgentWebFetchRequestV1) -> Result<AgentWebFetchReportV1, String> {
    let host = extract_host(&request.url)?;
    if !host_allowed(&host) {
        return Err(format!(
            "web fetch is restricted to official allowlisted hosts; '{}' is not permitted",
            host
        ));
    }

    let max_bytes = request.max_bytes.unwrap_or(DEFAULT_MAX_BYTES).max(1);
    let response_result = ureq::AgentBuilder::new()
        .user_agent(BROWSER_LIKE_USER_AGENT)
        .timeout(std::time::Duration::from_secs(20))
        .max_idle_connections(2)
        .build()
        .get(&request.url)
        .set(
            "Accept",
            "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
        )
        .set("Accept-Language", "en-US,en;q=0.8")
        .call();

    let (ok, response) = match response_result {
        Ok(response) => (true, response),
        Err(ureq::Error::Status(_, response)) => (false, response),
        Err(ureq::Error::Transport(error)) => {
            return Err(format!("failed to fetch {}: {}", request.url, error));
        }
    };

    let final_url = response.get_url().to_string();
    let final_host = extract_host(&final_url)?;
    let content_type = response.content_type().trim().to_string();
    let status_code = response.status();
    let status_text = response.status_text().to_string();
    let body_bytes = read_body_excerpt(response, max_bytes)?;
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    let title = looks_like_html(&content_type, &body_text)
        .then(|| extract_title(&body_text))
        .flatten();
    let canonical_url = looks_like_html(&content_type, &body_text)
        .then(|| extract_canonical_url(&body_text))
        .flatten();
    let body_excerpt = if content_type.starts_with("text/")
        || content_type.contains("json")
        || looks_like_html(&content_type, &body_text)
    {
        let text = if looks_like_html(&content_type, &body_text) {
            collapse_whitespace(&strip_html_tags(&body_text))
        } else {
            collapse_whitespace(&body_text)
        };
        (!text.is_empty()).then(|| truncate_chars(&text, 600))
    } else {
        None
    };
    let same_host_links = if looks_like_html(&content_type, &body_text) {
        extract_same_host_links(&body_text, &final_url, &final_host, DEFAULT_LINK_LIMIT)
    } else {
        Vec::new()
    };

    let request_url = request.url;
    let redirected = final_url != request_url;

    Ok(AgentWebFetchReportV1 {
        schema: WEB_FETCH_SCHEMA.to_string(),
        generated_at: now_rfc3339(),
        request_url,
        final_url: final_url.clone(),
        host: final_host,
        policy_scope: WEB_POLICY_SCOPE.to_string(),
        ok,
        status_code,
        status_text,
        redirected,
        content_type: (!content_type.is_empty()).then_some(content_type),
        canonical_url,
        title,
        body_excerpt,
        same_host_links,
    })
}

fn host_allowed(host: &str) -> bool {
    const ALLOWED_HOST_SUFFIXES: &[&str] = &[
        "openai.com",
        "platform.openai.com",
        "cdn.openai.com",
        "modelcontextprotocol.io",
        "hermes-agent.nousresearch.com",
        "nousresearch.com",
        "docs.midnight.network",
        "midnight.network",
        "github.com",
        "raw.githubusercontent.com",
        "api.github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
        "nvlpubs.nist.gov",
        "csrc.nist.gov",
        "rfc-editor.org",
        "www.rfc-editor.org",
        "crypto.stanford.edu",
        "web.cs.ucdavis.edu",
        "cacr.uwaterloo.ca",
        "cr.yp.to",
        "ed25519.cr.yp.to",
        "eprint.iacr.org",
    ];
    ALLOWED_HOST_SUFFIXES.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

fn extract_host(url: &str) -> Result<String, String> {
    let scheme_split = url
        .split_once("://")
        .ok_or_else(|| format!("unsupported URL '{}': expected http:// or https://", url))?;
    let scheme = scheme_split.0;
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported URL scheme '{}'", scheme));
    }
    let authority = scheme_split
        .1
        .split('/')
        .next()
        .ok_or_else(|| format!("invalid URL '{}'", url))?;
    let host = authority
        .split('@')
        .next_back()
        .unwrap_or(authority)
        .split(':')
        .next()
        .unwrap_or(authority)
        .trim()
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(format!("invalid URL '{}': missing host", url));
    }
    Ok(host)
}

fn read_body_excerpt(response: ureq::Response, max_bytes: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let mut reader = response.into_reader().take(max_bytes as u64);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read web response body: {error}"))?;
    Ok(bytes)
}

fn looks_like_html(content_type: &str, body: &str) -> bool {
    content_type.contains("html")
        || body.contains("<html")
        || body.contains("<HTML")
        || body.contains("<title")
}

fn extract_title(html: &str) -> Option<String> {
    extract_tag_contents(html, "title").map(|value| collapse_whitespace(value.trim()))
}

fn extract_canonical_url(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(index) = lower[offset..].find("<link") {
        let start = offset + index;
        let end = lower[start..]
            .find('>')
            .map(|value| start + value)
            .unwrap_or(lower.len());
        let tag = &html[start..end];
        let tag_lower = &lower[start..end];
        if tag_lower.contains("rel=\"canonical\"")
            || tag_lower.contains("rel='canonical'")
            || tag_lower.contains("rel=canonical")
        {
            if let Some(value) = extract_attribute(tag, "href") {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        offset = end;
    }
    None
}

fn extract_same_host_links(
    html: &str,
    final_url: &str,
    final_host: &str,
    limit: usize,
) -> Vec<String> {
    let origin = origin_from_url(final_url);
    let mut links = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut offset = 0;
    while let Some(index) = html[offset..].find("href=") {
        let start = offset + index + "href=".len();
        let rest = &html[start..];
        let Some(first) = rest.chars().next() else {
            break;
        };
        let value = if first == '"' || first == '\'' {
            let quote = first;
            let quoted = &rest[1..];
            quoted
                .find(quote)
                .map(|end| &quoted[..end])
                .unwrap_or(quoted)
        } else {
            rest.split_whitespace().next().unwrap_or(rest)
        };
        let normalized = normalize_link(value.trim(), origin.as_deref(), final_host);
        if let Some(link) = normalized
            && seen.insert(link.clone())
        {
            links.push(link);
            if links.len() >= limit {
                break;
            }
        }
        offset = start + value.len().max(1);
    }
    links
}

fn origin_from_url(url: &str) -> Option<String> {
    let (scheme, remainder) = url.split_once("://")?;
    let authority = remainder.split('/').next()?;
    Some(format!("{scheme}://{authority}"))
}

fn normalize_link(link: &str, origin: Option<&str>, final_host: &str) -> Option<String> {
    if link.is_empty() || link.starts_with('#') || link.starts_with("javascript:") {
        return None;
    }
    if link.starts_with("http://") || link.starts_with("https://") {
        let host = extract_host(link).ok()?;
        return (host == final_host).then(|| link.to_string());
    }
    if link.starts_with('/') {
        return origin.map(|prefix| format!("{prefix}{link}"));
    }
    None
}

fn extract_tag_contents<'a>(html: &'a str, tag: &str) -> Option<&'a str> {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let start = lower.find(&open)?;
    let start = lower[start..].find('>').map(|index| start + index + 1)?;
    let end = lower[start..].find(&close).map(|index| start + index)?;
    Some(&html[start..end])
}

fn extract_attribute(tag: &str, attribute: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{attribute}=");
    let index = lower.find(&needle)?;
    let value_start = index + needle.len();
    let raw = &tag[value_start..];
    let first = raw.chars().next()?;
    if first == '"' || first == '\'' {
        let quote = first;
        let after_quote = &raw[1..];
        let end = after_quote.find(quote)?;
        return Some(after_quote[..end].to_string());
    }
    Some(
        raw.split_whitespace()
            .next()
            .unwrap_or(raw)
            .trim_end_matches('>')
            .to_string(),
    )
}

fn strip_html_tags(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut in_tag = false;
    for ch in value.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => output.push(ch),
            _ => {}
        }
    }
    output
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let truncated = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        format!("{truncated}…")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_canonical_url, extract_same_host_links, extract_title, host_allowed, normalize_link,
    };

    #[test]
    fn host_allowlist_accepts_official_sources_only() {
        assert!(host_allowed("platform.openai.com"));
        assert!(host_allowed("docs.midnight.network"));
        assert!(host_allowed("eprint.iacr.org"));
        assert!(!host_allowed("example.com"));
    }

    #[test]
    fn html_extractors_capture_title_canonical_and_links() {
        let html = r#"
            <html>
              <head>
                <title> Tools Shell Guide </title>
                <link rel="canonical" href="https://platform.openai.com/docs/guides/tools-shell" />
              </head>
              <body>
                <a href="/docs/guides/tools-shell">same host</a>
                <a href="https://platform.openai.com/docs/guides/tools-remote-mcp">remote mcp</a>
                <a href="https://example.com/nope">off host</a>
              </body>
            </html>
        "#;
        assert_eq!(extract_title(html).as_deref(), Some("Tools Shell Guide"));
        assert_eq!(
            extract_canonical_url(html).as_deref(),
            Some("https://platform.openai.com/docs/guides/tools-shell")
        );
        assert_eq!(
            extract_same_host_links(
                html,
                "https://platform.openai.com/docs/guides/tools-shell",
                "platform.openai.com",
                10
            ),
            vec![
                "https://platform.openai.com/docs/guides/tools-shell".to_string(),
                "https://platform.openai.com/docs/guides/tools-remote-mcp".to_string()
            ]
        );
    }

    #[test]
    fn normalize_link_ignores_non_http_targets() {
        assert_eq!(
            normalize_link(
                "/docs/guides/tools-shell",
                Some("https://platform.openai.com"),
                "platform.openai.com"
            )
            .as_deref(),
            Some("https://platform.openai.com/docs/guides/tools-shell")
        );
        assert!(
            normalize_link(
                "#section",
                Some("https://platform.openai.com"),
                "platform.openai.com"
            )
            .is_none()
        );
        assert!(
            normalize_link(
                "javascript:void(0)",
                Some("https://platform.openai.com"),
                "platform.openai.com"
            )
            .is_none()
        );
    }
}
