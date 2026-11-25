//! Result filters and date provenance (WEB-03, WEB-04).
//!
//! [`apply`] narrows a fused [`SearchResponse`] without touching fusion: it
//! keeps the surviving results in their original order and with their original
//! scores. Every surviving result carries a [`Provenance`] record with its age
//! in days and the source of its publish date.
//!
//! All filters are ANDed. A filter list that is empty imposes no restriction,
//! except freshness, which is only active when a window is set. The date rule
//! is fail-closed: when a freshness window is requested, a result whose
//! `published` value is absent or unparseable is dropped.

use serde::{Deserialize, Serialize};

use crate::search::{canonical_url_key, FusedResult, SearchError, SearchResponse};

/// Milliseconds in one day.
pub const DAY_MS: i64 = 86_400_000;

/// Requested freshness window.
///
/// The window is a maximum age in whole days; see [`Freshness::max_age_days`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Freshness {
    Day,
    Week,
    Month,
    Year,
}

impl Freshness {
    /// Largest accepted result age in whole days.
    pub const fn max_age_days(self) -> i64 {
        match self {
            Freshness::Day => 1,
            Freshness::Week => 7,
            Freshness::Month => 30,
            Freshness::Year => 365,
        }
    }
}

/// Where a result's publish date came from.
///
/// Fetch and reader-mode extraction do not exist yet, so every parseable
/// `published` string is attributed to the engine that reported it. `Page` is
/// reserved for a date extracted from the page body by a later task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DateSource {
    Engine,
    Page,
    Unknown,
}

/// The publish date of one result, its age, and where the date came from.
///
/// `published` is the raw engine string, preserved even when it could not be
/// parsed. `age_days` is `None` exactly when no valid date was found; it is
/// never guessed from surrounding text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub published: Option<String>,
    pub age_days: Option<i64>,
    pub source: DateSource,
}

impl Provenance {
    /// Interpret one raw `published` value at `now_ms` (Unix epoch millis).
    ///
    /// A parseable value yields `source: Engine` and a non-negative age; a
    /// timestamp ahead of `now_ms` is clamped to age 0 to absorb clock skew.
    /// An absent or unparseable value yields `age_days: None` and
    /// `source: Unknown`; the raw string is kept either way.
    pub fn from_published(published: Option<&str>, now_ms: i64) -> Self {
        match published.and_then(parse_timestamp_ms) {
            Some(published_ms) => Self {
                published: published.map(str::to_string),
                age_days: Some(now_ms.saturating_sub(published_ms).max(0) / DAY_MS),
                source: DateSource::Engine,
            },
            None => Self {
                published: published.map(str::to_string),
                age_days: None,
                source: DateSource::Unknown,
            },
        }
    }
}

/// Filters applied to a fused response.
///
/// Every list is a restriction: empty means "no restriction". Domain entries
/// match the canonical host or one of its subdomains, so `example.com` matches
/// `example.com`, `docs.example.com`, and `www.example.com` (the leading `www.`
/// is normalized away on both sides). Entries are lowercased, may include a
/// scheme or a leading `*.`, and ignore ports. Exclusions win over inclusions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SearchFilters {
    /// Maximum result age. When set, results without a parseable date are
    /// dropped (fail closed).
    pub freshness: Option<Freshness>,
    /// Keep only these hosts or their subdomains.
    pub include_domains: Vec<String>,
    /// Drop these hosts and their subdomains. Takes precedence over
    /// `include_domains`.
    pub exclude_domains: Vec<String>,
    /// Keep only these [`category_for`] values. Empty keeps every category.
    pub categories: Vec<String>,
    /// Every entry must appear in `title + snippet`, case-insensitively.
    /// Blank entries are ignored.
    pub required_substrings: Vec<String>,
    /// No entry may appear in `title + snippet`, case-insensitively.
    /// Blank entries are ignored.
    pub forbidden_substrings: Vec<String>,
}

/// One surviving result with its category and date provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilteredResult {
    pub result: FusedResult,
    /// Value from [`category_for`] for the result URL.
    pub category: String,
    pub provenance: Provenance,
}

/// The result of applying [`SearchFilters`] to a [`SearchResponse`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilteredResponse {
    pub query: String,
    /// Surviving results in their original fusion order, scores unchanged.
    pub results: Vec<FilteredResult>,
    /// Engine failures carried over from the fused response.
    pub failed: Vec<SearchError>,
    /// How many results the filters removed.
    pub dropped: usize,
}

/// Filter `response` with `filters`, interpreting dates at `now_ms`.
///
/// Fusion scores, source ranks, and result order are untouched; filtering only
/// removes entries.
pub fn apply(filters: &SearchFilters, response: &SearchResponse, now_ms: i64) -> FilteredResponse {
    let mut results = Vec::with_capacity(response.results.len());
    for result in &response.results {
        if !domain_allowed(&result.url, filters) {
            continue;
        }
        if !substrings_allowed(result, filters) {
            continue;
        }
        let category = category_for(&result.url).to_string();
        if !category_allowed(&category, filters) {
            continue;
        }
        let provenance = Provenance::from_published(result.published.as_deref(), now_ms);
        if !fresh_enough(&provenance, filters.freshness) {
            continue;
        }
        results.push(FilteredResult {
            result: result.clone(),
            category,
            provenance,
        });
    }

    FilteredResponse {
        query: response.query.clone(),
        dropped: response.results.len() - results.len(),
        results,
        failed: response.failed.clone(),
    }
}

impl SearchResponse {
    /// Convenience wrapper around the free [`apply`] function.
    pub fn apply(&self, filters: &SearchFilters, now_ms: i64) -> FilteredResponse {
        apply(filters, self, now_ms)
    }
}

/// Classify a result URL into one of `docs`, `code`, `news`, or `general`.
///
/// The rule is deliberately small and applies the first matching row:
///
/// | Category  | Matches when                                                       |
/// |-----------|--------------------------------------------------------------------|
/// | `docs`    | host starts with `docs.` or `developer.`, or the first path        |
/// |           | segment is `docs` or `documentation`                               |
/// | `code`    | host is `github.com`, `gitlab.com`, or `bitbucket.org`, or the     |
/// |           | first path segment is `src`                                        |
/// | `news`    | host starts with `news.` or `blog.`, or the first path segment is  |
/// |           | `news`, `blog`, or `press`                                         |
/// | `general` | everything else, including URLs without a host                     |
///
/// Matching is case-insensitive through [`canonical_url_key`], which lowercases
/// the host and keeps path case; the comparison lowercases the first segment.
pub fn category_for(url: &str) -> &'static str {
    let Some(host) = canonical_host(url) else {
        return "general";
    };
    let key = canonical_url_key(url);
    let first_segment = key
        .split_once('/')
        .map(|(_, path)| path.split('/').next().unwrap_or(""))
        .unwrap_or("")
        .to_ascii_lowercase();

    if host.starts_with("docs.")
        || host.starts_with("developer.")
        || matches!(first_segment.as_str(), "docs" | "documentation")
    {
        return "docs";
    }
    if matches!(host.as_str(), "github.com" | "gitlab.com" | "bitbucket.org")
        || first_segment == "src"
    {
        return "code";
    }
    if host.starts_with("news.")
        || host.starts_with("blog.")
        || matches!(first_segment.as_str(), "news" | "blog" | "press")
    {
        return "news";
    }
    "general"
}

/// Canonical host of a URL, or `None` when it has no host.
///
/// Built on [`canonical_url_key`]: the host is lowercased, a leading `www.` is
/// stripped, and any port is dropped.
pub fn canonical_host(url: &str) -> Option<String> {
    let key = canonical_url_key(url);
    let host = key.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    let host = host.trim_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Parse `YYYY-MM-DD` or an RFC 3339 timestamp into Unix epoch milliseconds.
///
/// Accepted forms:
///
/// - `YYYY-MM-DD` (midnight UTC),
/// - `YYYY-MM-DDTHH:MM:SS` followed by `Z` or a `+HH:MM` / `-HH:MM` offset,
///   with optional fractional seconds (truncated).
///
/// Anything else — a space separator, a missing offset, an out-of-range field,
/// a non-leap February 29 — returns `None`. No timezone is assumed for a
/// timestamp without an offset.
pub fn parse_timestamp_ms(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();

    let year = i64::from(number(bytes, 0, 4)?);
    if bytes.get(4) != Some(&b'-') {
        return None;
    }
    let month = number(bytes, 5, 2)?;
    if bytes.get(7) != Some(&b'-') {
        return None;
    }
    let day = number(bytes, 8, 2)?;
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }

    let mut hour = 0;
    let mut minute = 0;
    let mut second = 0;
    let mut offset_seconds = 0i64;

    if bytes.len() > 10 {
        if bytes.get(10) != Some(&b'T') {
            return None;
        }
        hour = number(bytes, 11, 2)?;
        if bytes.get(13) != Some(&b':') {
            return None;
        }
        minute = number(bytes, 14, 2)?;
        if bytes.get(16) != Some(&b':') {
            return None;
        }
        second = number(bytes, 17, 2)?;
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }

        let mut index = 19;
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            let start = index;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if index == start {
                return None;
            }
        }

        match bytes.get(index) {
            Some(b'Z') => index += 1,
            Some(b'+') | Some(b'-') => {
                let sign = if bytes[index] == b'-' { -1 } else { 1 };
                let offset_hour = number(bytes, index + 1, 2)?;
                if bytes.get(index + 3) != Some(&b':') {
                    return None;
                }
                let offset_minute = number(bytes, index + 4, 2)?;
                if offset_hour > 23 || offset_minute > 59 {
                    return None;
                }
                offset_seconds =
                    sign * (i64::from(offset_hour) * 3600 + i64::from(offset_minute) * 60);
                index += 6;
            }
            _ => return None,
        }

        if index != bytes.len() {
            return None;
        }
    } else if bytes.len() != 10 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))?
        .checked_sub(offset_seconds)?;
    seconds.checked_mul(1000)
}

/// Read `len` ASCII digits starting at `start`.
fn number(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    let slice = bytes.get(start..start.checked_add(len)?)?;
    let mut value = 0u32;
    for &byte in slice {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
///
/// Howard Hinnant's `days_from_civil` algorithm; no date dependency.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn domain_allowed(url: &str, filters: &SearchFilters) -> bool {
    let Some(host) = canonical_host(url) else {
        // A host-less URL cannot match an inclusion list, and cannot match an
        // exclusion entry either. With no inclusions requested it survives.
        return filters.include_domains.is_empty();
    };
    if filters
        .exclude_domains
        .iter()
        .any(|entry| domain_matches(&host, entry))
    {
        return false;
    }
    filters.include_domains.is_empty()
        || filters
            .include_domains
            .iter()
            .any(|entry| domain_matches(&host, entry))
}

fn normalize_domain(value: &str) -> Option<String> {
    let mut value = value.trim().to_ascii_lowercase();
    if let Some((_, rest)) = value.split_once("://") {
        value = rest.to_string();
    }
    let value = value.split('/').next().unwrap_or("");
    let value = value.rsplit('@').next().unwrap_or(value);
    let value = value.split(':').next().unwrap_or(value);
    let value = value.trim_matches('.');
    let value = value.strip_prefix("*.").unwrap_or(value);
    let value = value.strip_prefix("www.").unwrap_or(value);
    let value = value.trim_matches('.');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn domain_matches(host: &str, entry: &str) -> bool {
    let Some(domain) = normalize_domain(entry) else {
        return false;
    };
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn substrings_allowed(result: &FusedResult, filters: &SearchFilters) -> bool {
    if filters.required_substrings.is_empty() && filters.forbidden_substrings.is_empty() {
        return true;
    }
    let haystack = format!("{} {}", result.title, result.snippet).to_lowercase();
    let required = filters
        .required_substrings
        .iter()
        .filter(|needle| !needle.trim().is_empty())
        .all(|needle| needle_matches(&haystack, needle));
    required
        && !filters
            .forbidden_substrings
            .iter()
            .any(|needle| needle_matches(&haystack, needle))
}

fn needle_matches(haystack: &str, needle: &str) -> bool {
    let needle = needle.trim().to_lowercase();
    !needle.is_empty() && haystack.contains(&needle)
}

fn category_allowed(category: &str, filters: &SearchFilters) -> bool {
    filters.categories.is_empty()
        || filters
            .categories
            .iter()
            .any(|wanted| wanted.trim().eq_ignore_ascii_case(category))
}

fn fresh_enough(provenance: &Provenance, freshness: Option<Freshness>) -> bool {
    match freshness {
        None => true,
        Some(window) => match provenance.age_days {
            Some(age) => age <= window.max_age_days(),
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::EngineRank;

    /// 2026-11-25T00:00:00Z.
    const NOW_MS: i64 = 1_795_564_800_000;

    const NEWS: &str = "https://news.example.com/story";
    const DOCS: &str = "https://docs.example.com/guide";
    const CODE: &str = "https://github.com/rust-lang/rust";
    const BLOG: &str = "https://blog.example.org/post";
    const ABOUT: &str = "https://example.com/about";

    fn fused(
        rank: usize,
        title: &str,
        url: &str,
        snippet: &str,
        published: Option<&str>,
    ) -> FusedResult {
        FusedResult {
            title: title.to_string(),
            url: url.to_string(),
            snippet: snippet.to_string(),
            published: published.map(str::to_string),
            score: 1.0 / (60.0 + rank as f64),
            sources: vec![EngineRank {
                engine: "fixture".to_string(),
                rank,
            }],
        }
    }

    /// Five results covering every filter dimension:
    ///
    /// | # | URL      | Category | Published            | Age  |
    /// |---|----------|----------|----------------------|------|
    /// | 0 | news     | news     | 2026-11-24T00:00:00Z | 1    |
    /// | 1 | docs     | docs     | 2026-11-18           | 7    |
    /// | 2 | github   | code     | 2026-06-01           | 177  |
    /// | 3 | blog     | news     | not-a-date           | none |
    /// | 4 | about    | general  | absent               | none |
    fn fixture() -> SearchResponse {
        SearchResponse {
            query: "rust".to_string(),
            results: vec![
                fused(
                    1,
                    "Rust 1.90 Released",
                    NEWS,
                    "release notes",
                    Some("2026-11-24T00:00:00Z"),
                ),
                fused(2, "Rust Guide", DOCS, "how to install", Some("2026-11-18")),
                fused(3, "rust-lang/rust", CODE, "source code", Some("2026-06-01")),
                fused(4, "A Blog Post", BLOG, "opinion piece", Some("not-a-date")),
                fused(5, "About Us", ABOUT, "contact page", None),
            ],
            failed: Vec::new(),
        }
    }

    struct Case {
        name: &'static str,
        filters: SearchFilters,
        expected: Vec<&'static str>,
    }

    #[test]
    fn filter_matrix_keeps_exactly_the_expected_urls() {
        let cases = vec![
            Case {
                name: "no filters keeps every result",
                filters: SearchFilters::default(),
                expected: vec![NEWS, DOCS, CODE, BLOG, ABOUT],
            },
            Case {
                name: "freshness day keeps one-day-old results",
                filters: SearchFilters {
                    freshness: Some(Freshness::Day),
                    ..SearchFilters::default()
                },
                expected: vec![NEWS],
            },
            Case {
                name: "freshness week keeps results at or under seven days",
                filters: SearchFilters {
                    freshness: Some(Freshness::Week),
                    ..SearchFilters::default()
                },
                expected: vec![NEWS, DOCS],
            },
            Case {
                name: "freshness year keeps results at or under 365 days",
                filters: SearchFilters {
                    freshness: Some(Freshness::Year),
                    ..SearchFilters::default()
                },
                expected: vec![NEWS, DOCS, CODE],
            },
            Case {
                name: "include domain matches host and subdomains",
                filters: SearchFilters {
                    include_domains: vec!["example.com".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![NEWS, DOCS, ABOUT],
            },
            Case {
                name: "include domain as an exact subdomain",
                filters: SearchFilters {
                    include_domains: vec!["docs.example.com".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![DOCS],
            },
            Case {
                name: "exclude domain matches host and subdomains",
                filters: SearchFilters {
                    exclude_domains: vec!["example.com".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![CODE, BLOG],
            },
            Case {
                name: "exclude wins over include",
                filters: SearchFilters {
                    include_domains: vec!["example.com".to_string()],
                    exclude_domains: vec!["news.example.com".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![DOCS, ABOUT],
            },
            Case {
                name: "exclude entry accepts a scheme and port",
                filters: SearchFilters {
                    exclude_domains: vec!["https://example.com:8443".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![CODE, BLOG],
            },
            Case {
                name: "required substrings are case-insensitive",
                filters: SearchFilters {
                    required_substrings: vec!["RUST".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![NEWS, DOCS, CODE],
            },
            Case {
                name: "every required substring must appear in title or snippet",
                filters: SearchFilters {
                    required_substrings: vec!["rust".to_string(), "INSTALL".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![DOCS],
            },
            Case {
                name: "forbidden substring removes matching results",
                filters: SearchFilters {
                    forbidden_substrings: vec!["install".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![NEWS, CODE, BLOG, ABOUT],
            },
            Case {
                name: "blank needles are ignored",
                filters: SearchFilters {
                    required_substrings: vec!["  ".to_string()],
                    forbidden_substrings: vec!["".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![NEWS, DOCS, CODE, BLOG, ABOUT],
            },
            Case {
                name: "category docs",
                filters: SearchFilters {
                    categories: vec!["docs".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![DOCS],
            },
            Case {
                name: "category list unions docs and code",
                filters: SearchFilters {
                    categories: vec!["docs".to_string(), "code".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![DOCS, CODE],
            },
            Case {
                name: "category general keeps only unclassified results",
                filters: SearchFilters {
                    categories: vec!["general".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![ABOUT],
            },
            Case {
                name: "unparseable date is dropped under freshness",
                filters: SearchFilters {
                    freshness: Some(Freshness::Year),
                    exclude_domains: vec!["github.com".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![NEWS, DOCS],
            },
            Case {
                name: "freshness combines with include and substring",
                filters: SearchFilters {
                    freshness: Some(Freshness::Year),
                    include_domains: vec!["example.com".to_string()],
                    required_substrings: vec!["rust".to_string()],
                    ..SearchFilters::default()
                },
                expected: vec![NEWS, DOCS],
            },
            Case {
                name: "category and exclude can empty the result list",
                filters: SearchFilters {
                    categories: vec!["code".to_string()],
                    exclude_domains: vec!["github.com".to_string()],
                    ..SearchFilters::default()
                },
                expected: Vec::new(),
            },
        ];

        for case in cases {
            let response = fixture();
            let filtered = apply(&case.filters, &response, NOW_MS);
            let urls: Vec<&str> = filtered
                .results
                .iter()
                .map(|entry| entry.result.url.as_str())
                .collect();
            assert_eq!(urls, case.expected, "case: {}", case.name);
            assert_eq!(
                filtered.dropped + filtered.results.len(),
                response.results.len(),
                "case: {}",
                case.name
            );
            assert!(filtered.failed.is_empty(), "case: {}", case.name);
        }
    }

    #[test]
    fn filtering_preserves_scores_and_order() {
        let response = fixture();
        let filtered = response.apply(&SearchFilters::default(), NOW_MS);

        assert_eq!(filtered.results.len(), response.results.len());
        assert_eq!(filtered.dropped, 0);
        for (kept, original) in filtered.results.iter().zip(&response.results) {
            assert_eq!(&kept.result, original);
        }
        // The narrow case keeps the original relative order.
        let narrowed = apply(
            &SearchFilters {
                include_domains: vec!["example.com".to_string()],
                ..SearchFilters::default()
            },
            &response,
            NOW_MS,
        );
        let urls: Vec<&str> = narrowed
            .results
            .iter()
            .map(|entry| entry.result.url.as_str())
            .collect();
        assert_eq!(urls, vec![NEWS, DOCS, ABOUT]);
        assert_eq!(narrowed.dropped, 2);
    }

    #[test]
    fn provenance_records_age_and_date_source() {
        let filtered = fixture().apply(&SearchFilters::default(), NOW_MS);

        let news = &filtered.results[0].provenance;
        assert_eq!(news.published.as_deref(), Some("2026-11-24T00:00:00Z"));
        assert_eq!(news.age_days, Some(1));
        assert_eq!(news.source, DateSource::Engine);

        let docs = &filtered.results[1].provenance;
        assert_eq!(docs.age_days, Some(7));
        assert_eq!(docs.source, DateSource::Engine);

        let code = &filtered.results[2].provenance;
        assert_eq!(code.age_days, Some(177));

        // An unparseable value is kept raw but never guessed at.
        let blog = &filtered.results[3].provenance;
        assert_eq!(blog.published.as_deref(), Some("not-a-date"));
        assert_eq!(blog.age_days, None);
        assert_eq!(blog.source, DateSource::Unknown);

        // An absent value has no date and no source.
        let about = &filtered.results[4].provenance;
        assert_eq!(about.published, None);
        assert_eq!(about.age_days, None);
        assert_eq!(about.source, DateSource::Unknown);
    }

    #[test]
    fn future_dates_clamp_to_age_zero() {
        let provenance = Provenance::from_published(Some("2027-01-01"), NOW_MS);
        assert_eq!(provenance.age_days, Some(0));
        assert_eq!(provenance.source, DateSource::Engine);
        assert!(fresh_enough(&provenance, Some(Freshness::Day)));
    }

    #[test]
    fn timestamp_parser_accepts_only_documented_forms() {
        assert_eq!(parse_timestamp_ms("2026-11-25"), Some(NOW_MS));
        assert_eq!(parse_timestamp_ms("2026-11-25T00:00:00Z"), Some(NOW_MS));
        assert_eq!(
            parse_timestamp_ms("2026-11-25T02:00:00+02:00"),
            Some(NOW_MS)
        );
        assert_eq!(
            parse_timestamp_ms("2026-11-24T22:00:00-02:00"),
            Some(NOW_MS)
        );
        // Fractional seconds are accepted and truncated.
        assert_eq!(parse_timestamp_ms("2026-11-25T00:00:00.987Z"), Some(NOW_MS));
        assert_eq!(parse_timestamp_ms("2024-02-29"), Some(1_709_164_800_000));

        for bad in [
            "",
            "2026-11",
            "2026-11-25x",
            "2026-13-01",
            "2026-00-01",
            "2026-02-30",
            "2025-02-29",
            "2026-11-25 00:00:00Z",
            "2026-11-25T00:00:00",
            "2026-11-25T24:00:00Z",
            "2026-11-25T00:60:00Z",
            "2026-11-25T00:00:60Z",
            "2026-11-25T00:00:00z",
            "2026-11-25T00:00:00.Z",
            "2026-11-25T00:00:00+2:00",
            "2026-11-25T00:00:00+02:60",
            "25-11-2026",
            "not-a-date",
            " 2026-11-25",
        ] {
            assert_eq!(parse_timestamp_ms(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn category_classification_follows_documented_rule() {
        assert_eq!(category_for(NEWS), "news");
        assert_eq!(category_for(DOCS), "docs");
        assert_eq!(category_for(CODE), "code");
        assert_eq!(category_for(BLOG), "news");
        assert_eq!(category_for(ABOUT), "general");
        assert_eq!(
            category_for("https://developer.mozilla.org/docs/Web"),
            "docs"
        );
        assert_eq!(category_for("https://example.com/documentation/x"), "docs");
        assert_eq!(category_for("https://gitlab.com/group/repo"), "code");
        assert_eq!(category_for("https://example.com/src/lib"), "code");
        assert_eq!(category_for("https://example.com/news/x"), "news");
        assert_eq!(category_for("https://example.com/press/x"), "news");
        assert_eq!(category_for(""), "general");
    }

    #[test]
    fn canonical_host_normalizes_www_and_ports() {
        assert_eq!(canonical_host(NEWS).as_deref(), Some("news.example.com"));
        assert_eq!(
            canonical_host("https://WWW.Example.com:8443/a").as_deref(),
            Some("example.com")
        );
        assert_eq!(canonical_host("/relative/path"), None);
        assert_eq!(canonical_host(""), None);
    }

    #[test]
    fn freshness_windows_are_documented_days() {
        assert_eq!(Freshness::Day.max_age_days(), 1);
        assert_eq!(Freshness::Week.max_age_days(), 7);
        assert_eq!(Freshness::Month.max_age_days(), 30);
        assert_eq!(Freshness::Year.max_age_days(), 365);
    }
}
