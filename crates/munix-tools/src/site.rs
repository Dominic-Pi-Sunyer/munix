//! Site templates: how the trusted side splits one known site's page into fields the `web.open` manifest labels
//! by region (product listing, editorial, user reviews), so the Gate can score each part by what it is.
//!
//! A template is a YAML file naming one exact host (`host[:port]`), the path prefixes it covers, and the fields
//! to build from the page map Web Speed returns. Each field picks parts of the map; parts nobody picks are
//! dropped, so a new or odd region of a page never gets a label it did not earn.
//!
//! ```yaml
//! host: pixelmart.test:8080
//! paths: ["/reviews/"]
//! fields:
//!   listing:   {picks: [title, headings, tables, li]}
//!   editorial: {picks: [blockquote]}
//!   reviews:   {picks: [p], each: true}
//! ```
//!
//! Picks are `title`, `headings`, `tables` and the text-block tags `p`, `li` and `blockquote`. A field without
//! `each` is one text: the picked parts in page-map order (title, headings, text blocks, then table rows as
//! `a | b`), one per line. With `each: true` it is a list with one text per picked part. A pick belongs to one
//! field only, so no part of a page can be handed to two regions. Field names follow the manifest's output-name
//! rule and can't be `page` or `links`, which the tool itself owns.
//!
//! Matching is deliberately strict: http or https only, no userinfo, the host and port compared exactly after
//! lowercasing, and the prefix compared with the path alone. Anything odd about a URL means no match, and a page
//! with no matching template gets the plain, unclassified `page` text.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use munix_core::manifest::ToolManifest;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ToolConfigError;
use crate::webspeed::{array, field_text, table_rows};

/// Field names the tool fills itself.
const RESERVED_FIELDS: [&str; 2] = ["page", "links"];

/// A part of the page map a field can pick.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Pick {
    Title,
    Headings,
    Tables,
    P,
    Li,
    Blockquote,
}

impl Pick {
    /// The pick for a text block's `tag`, if any.
    fn from_tag(tag: &str) -> Option<Self> {
        match tag.to_ascii_lowercase().as_str() {
            "p" => Some(Self::P),
            "li" => Some(Self::Li),
            "blockquote" => Some(Self::Blockquote),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawField {
    picks: Vec<Pick>,
    #[serde(default)]
    each: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTemplate {
    host: String,
    paths: Vec<String>,
    fields: BTreeMap<String, RawField>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Field {
    picks: BTreeSet<Pick>,
    each: bool,
}

/// One site's template. Built only by [`SiteTemplate::from_yaml`], so every value in it has been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteTemplate {
    host: String,
    paths: Vec<String>,
    fields: BTreeMap<String, Field>,
}

fn invalid(message: impl std::fmt::Display) -> ToolConfigError {
    ToolConfigError::Invalid(format!("site template: {message}"))
}

impl SiteTemplate {
    /// Parses and checks a template. Unknown keys, an unknown pick, no paths, a bad host or path, a bad or
    /// reserved field name, a field with no picks, and a pick used by two fields are all refused.
    pub fn from_yaml(text: &str) -> Result<Self, ToolConfigError> {
        let raw: RawTemplate = serde_yaml_ng::from_str(text).map_err(invalid)?;
        if raw.host != raw.host.to_ascii_lowercase() || !is_host_port(&raw.host) {
            return Err(invalid("host must be a lowercase host or host:port"));
        }
        if raw.paths.is_empty() {
            return Err(invalid("at least one path prefix is required"));
        }
        for path in &raw.paths {
            if !is_path_prefix(path) {
                return Err(invalid(
                    "a path prefix starts with / and has no query, fragment, dot segments or escapes",
                ));
            }
        }
        if raw.fields.is_empty() {
            return Err(invalid("at least one field is required"));
        }
        let mut used: BTreeSet<Pick> = BTreeSet::new();
        let mut fields = BTreeMap::new();
        for (name, field) in raw.fields {
            check_field_name(&name)?;
            if field.picks.is_empty() {
                return Err(invalid("a field needs at least one pick"));
            }
            let picks: BTreeSet<Pick> = field.picks.into_iter().collect();
            for pick in &picks {
                if !used.insert(*pick) {
                    return Err(invalid("a pick may belong to one field only"));
                }
            }
            fields.insert(
                name,
                Field {
                    picks,
                    each: field.each,
                },
            );
        }
        Ok(Self {
            host: raw.host,
            paths: raw.paths,
            fields,
        })
    }

    /// The `host[:port]` this template covers.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether `url` is on this template's host and under one of its path prefixes.
    pub fn matches(&self, url: &str) -> bool {
        let Some((host, path)) = split_url(url) else {
            return false;
        };
        host == self.host && self.paths.iter().any(|prefix| path.starts_with(prefix))
    }

    /// Builds the template's fields from a page map shaped like Web Speed's. Fields with nothing in them are
    /// left out. The texts are raw: the caller cleans them before they leave the tool.
    pub fn apply(&self, map: &Value) -> BTreeMap<String, Value> {
        let mut out = BTreeMap::new();
        for (name, field) in &self.fields {
            let parts: Vec<String> = parts(map, &field.picks)
                .into_iter()
                .filter(|part| !part.trim().is_empty())
                .collect();
            if parts.is_empty() {
                continue;
            }
            let value = if field.each {
                Value::Array(parts.into_iter().map(Value::String).collect())
            } else {
                Value::String(parts.join("\n"))
            };
            out.insert(name.clone(), value);
        }
        out
    }
}

/// The picked parts of a page map, in page-map order: title, headings, text blocks, table rows.
fn parts(map: &Value, picks: &BTreeSet<Pick>) -> Vec<String> {
    let mut out = Vec::new();
    if picks.contains(&Pick::Title) {
        out.extend(field_text(map, "title"));
    }
    if picks.contains(&Pick::Headings) {
        for heading in array(map, "headings") {
            out.extend(field_text(heading, "text"));
        }
    }
    for block in array(map, "text_blocks") {
        let picked = block
            .get("tag")
            .and_then(Value::as_str)
            .and_then(Pick::from_tag)
            .is_some_and(|pick| picks.contains(&pick));
        if picked {
            out.extend(field_text(block, "text"));
        }
    }
    if picks.contains(&Pick::Tables) {
        for table in array(map, "tables") {
            out.extend(table_rows(table));
        }
    }
    out
}

/// Field names follow the manifest's own output-name rule. That rule is core's, so it is asked of core rather
/// than copied: a throwaway manifest with this one output is validated.
fn check_field_name(name: &str) -> Result<(), ToolConfigError> {
    if RESERVED_FIELDS.contains(&name) {
        return Err(invalid("page and links are reserved field names"));
    }
    let manifest = json!({
        "tool": "site.check",
        "description": "field name check",
        "tier": 0,
        "output": {name: {"type": "text", "region": "unclassified"}},
    });
    serde_json::from_value::<ToolManifest>(manifest)
        .ok()
        .filter(|m| m.validate().is_ok())
        .map(|_| ())
        .ok_or_else(|| invalid("field names are 1-32 of [a-z_]"))
}

// ---------------------------------------------------------------------------------------------
// URL matching
// ---------------------------------------------------------------------------------------------

/// `host` or `host:port`, lowercase letters, digits, hyphens and dots only, no empty labels.
fn is_host_port(s: &str) -> bool {
    let (host, port) = match s.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (s, None),
    };
    let host_ok = !host.is_empty()
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    let port_ok = port.is_none_or(|p| {
        (1..=5).contains(&p.len())
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    });
    host_ok && port_ok
}

/// A path with no dot segments and no escaped dots, slashes or backslashes: the page the template sees is the
/// page the prefix names, however the fetcher would normalize the URL.
fn is_plain_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    !path.contains('\\')
        && !["%2e", "%2f", "%5c"].iter().any(|esc| lower.contains(esc))
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

fn is_path_prefix(path: &str) -> bool {
    path.starts_with('/')
        && path.bytes().all(|b| (0x21..=0x7e).contains(&b))
        && !path.contains(['?', '#'])
        && is_plain_path(path)
}

/// Splits an http(s) URL into its lowercased `host[:port]` and its path (`/` when empty). `None` for any other
/// scheme, userinfo, odd characters, a host that is not plain, or a path with dot segments or escapes.
fn split_url(url: &str) -> Option<(String, &str)> {
    if url
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'\\')
    {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let host = authority.to_ascii_lowercase();
    if !is_host_port(&host) {
        return None;
    }
    let path = &tail[..tail.find(['?', '#']).unwrap_or(tail.len())];
    let path = if path.is_empty() { "/" } else { path };
    is_plain_path(path).then_some((host, path))
}

// ---------------------------------------------------------------------------------------------
// A set of templates
// ---------------------------------------------------------------------------------------------

/// The templates in force, at most one per host.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SiteTemplates(Vec<SiteTemplate>);

impl SiteTemplates {
    /// A set from templates already built; two for the same host are refused.
    pub fn new(templates: Vec<SiteTemplate>) -> Result<Self, ToolConfigError> {
        let mut hosts = BTreeSet::new();
        for template in &templates {
            if !hosts.insert(template.host.as_str()) {
                return Err(invalid("two templates for the same host"));
            }
        }
        Ok(Self(templates))
    }

    /// Reads every `*.yaml` file directly in `dir` (in name order). A bad file, or two templates for one host,
    /// is an error naming the file, never its contents.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Self, ToolConfigError> {
        let dir = dir.as_ref();
        let entries = std::fs::read_dir(dir)
            .map_err(|_| invalid(format!("cannot read {}", dir.display())))?;
        let mut files: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "yaml") && path.is_file())
            .collect();
        files.sort();
        let mut templates = Vec::new();
        for path in files {
            let text = std::fs::read_to_string(&path)
                .map_err(|_| invalid(format!("cannot read {}", path.display())))?;
            let template = SiteTemplate::from_yaml(&text).map_err(|e| match e {
                ToolConfigError::Invalid(message) => {
                    ToolConfigError::Invalid(format!("{}: {message}", path.display()))
                }
            })?;
            templates.push(template);
        }
        Self::new(templates)
    }

    /// The template whose host and paths cover `url`, if any.
    pub fn find(&self, url: &str) -> Option<&SiteTemplate> {
        self.0.iter().find(|template| template.matches(url))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const PIXELMART: &str = r#"
host: pixelmart.test:8080
paths: ["/reviews/"]
fields:
  listing:   {picks: [title, headings, tables, li]}
  editorial: {picks: [blockquote]}
  reviews:   {picks: [p], each: true}
"#;

    fn template() -> SiteTemplate {
        SiteTemplate::from_yaml(PIXELMART).unwrap()
    }

    fn err(yaml: &str) -> String {
        match SiteTemplate::from_yaml(yaml) {
            Ok(_) => panic!("accepted: {yaml}"),
            Err(ToolConfigError::Invalid(message)) => message,
        }
    }

    #[test]
    fn parses_the_documented_shape() {
        let t = template();
        assert_eq!(t.host(), "pixelmart.test:8080");
        assert_eq!(t.fields.len(), 3);
        assert!(t.fields["reviews"].each);
        assert!(!t.fields["listing"].each);
        assert_eq!(t.fields["listing"].picks.len(), 4);
    }

    #[test]
    fn unknown_keys_are_rejected_everywhere() {
        err(&format!("{PIXELMART}extra: 1\n"));
        err(&PIXELMART.replace("paths:", "pathz:"));
        err(&PIXELMART.replace("each: true", "each: true, loud: true"));
        err(&PIXELMART.replace("picks: [blockquote]", "picks: [blockquote], extra: 1"));
    }

    #[test]
    fn bad_picks_are_rejected() {
        err(&PIXELMART.replace("blockquote", "div"));
        err(&PIXELMART.replace("[blockquote]", "[]"));
        err(&PIXELMART.replace("[blockquote]", "[Blockquote]"));
        err(&PIXELMART.replace("[blockquote]", "blockquote"));
    }

    #[test]
    fn a_pick_may_belong_to_one_field_only() {
        err(&PIXELMART.replace("[blockquote]", "[p]"));
        // The same pick twice inside one field is harmless.
        SiteTemplate::from_yaml(
            "host: a.test\npaths: [\"/\"]\nfields: {x: {picks: [p, p]}, y: {picks: [li]}}\n",
        )
        .unwrap();
    }

    #[test]
    fn missing_or_bad_paths_are_rejected() {
        err(&PIXELMART.replace("paths: [\"/reviews/\"]", "paths: []"));
        err(&PIXELMART.replace("paths: [\"/reviews/\"]\n", ""));
        for bad in [
            "reviews/", "/a?b", "/a#b", "/a/../b", "/a/./b", "/a%2fb", "/a\\\\b", "/a b", "",
        ] {
            err(&PIXELMART.replace("/reviews/", bad));
        }
    }

    #[test]
    fn bad_hosts_are_rejected() {
        for bad in [
            "PixelMart.test",
            "pixelmart.test:",
            "pixelmart.test:0",
            "pixelmart.test:99999",
            "user@pixelmart.test",
            "pixelmart..test",
            "-a.test",
            "",
            "http://pixelmart.test",
            "pixelmart.test/",
        ] {
            err(&PIXELMART.replace("pixelmart.test:8080", &format!("{bad:?}")));
        }
    }

    #[test]
    fn bad_field_names_are_rejected() {
        for bad in [
            "Listing",
            "list-ing",
            "page",
            "links",
            "a1",
            "",
            &"x".repeat(33),
        ] {
            let yaml = PIXELMART.replace("listing:  ", &format!("{bad:?}:"));
            err(&yaml);
        }
        err("host: a.test\npaths: [\"/\"]\nfields: {}\n");
    }

    #[test]
    fn host_must_match_exactly_after_lowercasing() {
        let t = template();
        assert!(t.matches("http://pixelmart.test:8080/reviews/gaming-monitor"));
        assert!(t.matches("HTTP://PixelMart.TEST:8080/reviews/x"));
        assert!(t.matches("https://pixelmart.test:8080/reviews/x"));
        assert!(!t.matches("http://pixelmart.test/reviews/x"));
        assert!(!t.matches("http://pixelmart.test:8081/reviews/x"));
        assert!(!t.matches("http://other.test:8080/reviews/x"));
        assert!(!t.matches("http://sub.pixelmart.test:8080/reviews/x"));
        assert!(!t.matches("http://pixelmart.test:8080.evil.test/reviews/x"));
        assert!(!t.matches("http://pixelmart.test.:8080/reviews/x"));
    }

    #[test]
    fn a_template_without_a_port_does_not_match_a_url_with_one() {
        let t = SiteTemplate::from_yaml(&PIXELMART.replace(":8080", "")).unwrap();
        assert!(t.matches("http://pixelmart.test/reviews/x"));
        assert!(!t.matches("http://pixelmart.test:8080/reviews/x"));
        assert!(!t.matches("http://pixelmart.test:80/reviews/x"));
    }

    #[test]
    fn the_path_is_a_prefix_on_the_path_only() {
        let t = template();
        assert!(t.matches("http://pixelmart.test:8080/reviews/"));
        assert!(t.matches("http://pixelmart.test:8080/reviews/a/b?x=1#f"));
        assert!(!t.matches("http://pixelmart.test:8080/reviews"));
        assert!(!t.matches("http://pixelmart.test:8080/other/reviews/"));
        assert!(!t.matches("http://pixelmart.test:8080/?next=/reviews/"));
        assert!(!t.matches("http://pixelmart.test:8080/#/reviews/"));
        assert!(!t.matches("http://pixelmart.test:8080"));
        // Dot segments and escapes that could reach another page are no match.
        assert!(!t.matches("http://pixelmart.test:8080/reviews/../admin"));
        assert!(!t.matches("http://pixelmart.test:8080/reviews/%2e%2e/admin"));
        assert!(!t.matches("http://pixelmart.test:8080/reviews/..%2fadmin"));
        assert!(!t.matches("http://pixelmart.test:8080/reviews/a\\b"));
    }

    #[test]
    fn only_http_and_https_match() {
        let t = template();
        for url in [
            "ftp://pixelmart.test:8080/reviews/x",
            "file://pixelmart.test:8080/reviews/x",
            "javascript://pixelmart.test:8080/reviews/x",
            "//pixelmart.test:8080/reviews/x",
            "pixelmart.test:8080/reviews/x",
            "httpx://pixelmart.test:8080/reviews/x",
            "",
        ] {
            assert!(!t.matches(url), "{url}");
        }
    }

    #[test]
    fn userinfo_and_odd_urls_never_match() {
        let t = template();
        for url in [
            "http://user@pixelmart.test:8080/reviews/x",
            "http://pixelmart.test:8080@evil.test/reviews/x",
            "http://evil.test@pixelmart.test:8080/reviews/x",
            "http://user:pw@pixelmart.test:8080/reviews/x",
            "http://pixelmart.test:8080 /reviews/x",
            "http://pixelmart.test:8080\t/reviews/x",
            "http://pixelmart.test:8080\\@evil.test/reviews/x",
            "http://pixelmart.test:8080/reviews/\u{e9}",
            "http://[::1]:8080/reviews/x",
        ] {
            assert!(!t.matches(url), "{url}");
        }
    }

    fn map() -> Value {
        json!({
            "url": "http://pixelmart.test:8080/reviews/gaming-monitor",
            "title": "Aurora G27Q | PixelMart",
            "description": "ignored",
            "headings": [
                {"level": 1, "text": "Aurora G27Q"},
                {"level": 2, "text": "Our take"},
                {"level": 2, "text": "Customer reviews"},
            ],
            "text_blocks": [
                {"tag": "li", "text": "Price: $329.99"},
                {"tag": "blockquote", "text": "Good value. Sharp panel."},
                {"tag": "p", "text": "Review one."},
                {"tag": "div", "text": "Unpicked div text"},
                {"tag": "p", "text": "   "},
                {"tag": "P", "text": "Review two."},
                {"text": "no tag"},
            ],
            "tables": [{"headers": ["Spec", "Value"], "rows": [["Panel", "IPS"], ["HDR", 400]]}],
            "article": {"intro": "ignored"},
            "content_links": {"items": []},
        })
    }

    #[test]
    fn apply_splits_a_page_map_by_pick() {
        let out = template().apply(&map());
        assert_eq!(
            out["listing"],
            json!(
                "Aurora G27Q | PixelMart\nAurora G27Q\nOur take\nCustomer reviews\nPrice: $329.99\n\
                 Spec | Value\nPanel | IPS\nHDR | 400"
            )
        );
        assert_eq!(out["editorial"], json!("Good value. Sharp panel."));
        assert_eq!(out["reviews"], json!(["Review one.", "Review two."]));
        assert_eq!(out.len(), 3);
        let all = serde_json::to_string(&out).unwrap();
        assert!(!all.contains("ignored") && !all.contains("Unpicked") && !all.contains("no tag"));
    }

    #[test]
    fn empty_fields_are_left_out() {
        let out =
            template().apply(&json!({"title": "T", "text_blocks": [{"tag": "p", "text": " "}]}));
        assert_eq!(out.keys().collect::<Vec<_>>(), ["listing"]);
        assert!(template().apply(&json!({})).is_empty());
        assert!(template().apply(&json!("not a map")).is_empty());
    }

    #[test]
    fn each_gives_one_entry_per_part() {
        let t = SiteTemplate::from_yaml(
            "host: a.test\npaths: [\"/\"]\nfields:\n  all: {picks: [headings, li], each: true}\n",
        )
        .unwrap();
        let out = t.apply(&map());
        assert_eq!(
            out["all"],
            json!([
                "Aurora G27Q",
                "Our take",
                "Customer reviews",
                "Price: $329.99"
            ])
        );
    }

    #[test]
    fn templates_reject_two_for_one_host_and_find_by_url() {
        let a = template();
        let b = SiteTemplate::from_yaml(&PIXELMART.replace("/reviews/", "/other/")).unwrap();
        assert!(SiteTemplates::new(vec![a.clone(), b]).is_err());
        let set = SiteTemplates::new(vec![a]).unwrap();
        assert!(set.find("http://pixelmart.test:8080/reviews/x").is_some());
        assert!(set.find("http://pixelmart.test:8080/x").is_none());
        assert!(SiteTemplates::default().is_empty());
    }

    #[test]
    fn load_dir_reads_yaml_files_and_refuses_duplicates_and_bad_files() {
        let dir = std::env::temp_dir().join(format!("munix-site-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.yaml"), PIXELMART).unwrap();
        std::fs::write(dir.join("b.yaml"), PIXELMART.replace("pixelmart", "other")).unwrap();
        std::fs::write(dir.join("notes.txt"), "not yaml: [").unwrap();
        let set = SiteTemplates::load_dir(&dir).unwrap();
        assert_eq!(set.len(), 2);

        std::fs::write(dir.join("c.yaml"), PIXELMART).unwrap();
        assert!(SiteTemplates::load_dir(&dir).is_err());
        std::fs::remove_file(dir.join("c.yaml")).unwrap();
        std::fs::write(dir.join("c.yaml"), "host: [").unwrap();
        assert!(SiteTemplates::load_dir(&dir).is_err());
        assert!(SiteTemplates::load_dir(dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
