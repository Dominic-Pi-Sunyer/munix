//! The metadata view: what the Supervisor's model sees about a parked request (design spec 4.5).
//!
//! Invariant 3: the Supervisor's model never sees an attacker-chosen string. The view holds no argument values, no
//! URLs, domains, names or page text. It holds only:
//! - ref ids;
//! - type names and lengths;
//! - opaque domain numbers, region types and trust numbers;
//! - names that come from the operator: the tool, its argument and output names in the manifest, and the store
//!   names in the plan;
//! - Stage 1's fixed check strings.

use munix_core::context::Band;
use munix_core::ids::{RefId, ToolName};
use munix_core::label::{Confidential, RegionType, Trust};
use munix_core::manifest::ArgRole;
use serde::Serialize;

/// Where one value came from, in terms the Supervisor may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceView {
    Prompt {
        trust: Trust,
    },
    UserData {
        trust: Trust,
    },
    /// An operator store; `name` and `key` come from the plan.
    Store {
        name: String,
        key: String,
        trust: Trust,
    },
    /// An output field of an earlier step; `field` is a manifest output name, `domain` an opaque number.
    Step {
        step: u32,
        field: String,
        region: RegionType,
        domain: Option<u32>,
        trust: Trust,
    },
    /// The Gate can't say where it came from (trust 0).
    Untraced,
}

/// One destination or selector value, or one value embedded in content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValueView {
    /// The ref the agent used, or the ref a raw value matched; `None` when untraced.
    #[serde(rename = "ref")]
    pub ref_id: Option<RefId>,
    /// The entry's scalar type name when traced; `None` when untraced.
    pub ty: Option<String>,
    /// Every source the value traces to (one per match), or `[Untraced]`.
    pub sources: Vec<SourceView>,
}

/// One argument of the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArgView {
    /// The manifest's argument name.
    pub name: String,
    /// The manifest's type, such as `email[]` or `text`.
    pub ty: String,
    pub role: ArgRole,
    /// Destinations and selectors: one entry per value.
    pub values: Vec<ValueView>,
    /// Content text: the length in characters (never the text).
    pub chars: Option<usize>,
    /// Content text: what it embeds (refs, and raw links or addresses the Gate traced).
    pub embeds: Vec<ValueView>,
    /// Content text: raw links or addresses the Gate could not trace (counted, never shown).
    pub raw_destinations: u32,
    /// The most confidential data found in the argument.
    pub confidential: Confidential,
    /// True when the argument is a number, bool or enum; the value is not shown either way.
    pub control: bool,
}

/// The whole view of one parked request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewView {
    pub tool: ToolName,
    pub tier: u8,
    pub step: u32,
    pub steps_in_plan: usize,
    /// Calls already executed on this step, and the step's budget.
    pub calls_made: u32,
    pub budget: u32,
    pub context_trust: Trust,
    pub band: Band,
    /// The lowest-trust thing this agent instance has read, if any.
    pub lowest_read: Option<SourceView>,
    pub args: Vec<ArgView>,
    /// Stage 1's reasons for this request, as recorded when it was parked.
    pub checks: Vec<String>,
}

impl ReviewView {
    /// The text the reviewer model reads, in the shape of design spec 4.5:
    ///
    /// ```text
    /// REQUEST   step 2/2 · email.send (tier 3) · call 1 of max 1
    /// ARG to[0] ref:e2  email  source=store contacts.boss  trust=100
    /// ARG body  text 412 chars · embeds 1 · raw destinations 0 · confidential=public
    ///           ref:u3  url  source=step 1 links (product_listing, domain#1)  trust=80
    /// CONTEXT   trust=15 · band 0-19 · lowest=domain#1/ugc_review
    /// CHECKS    plan.step2 · budget.ok · to.trace_ok · band.lockdown
    /// ```
    ///
    /// Built only from the fields above, so it can't contain anything else.
    pub fn render(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "REQUEST   step {}/{} · {} (tier {}) · call {} of max {}",
            self.step,
            self.steps_in_plan,
            self.tool,
            self.tier,
            self.calls_made.saturating_add(1),
            self.budget,
        ));
        for arg in &self.args {
            let base_ty = arg.ty.trim_end_matches("[]");
            if !arg.values.is_empty() {
                for (i, value) in arg.values.iter().enumerate() {
                    let slot = format!("{}[{i}]", arg.name);
                    let ty = value.ty.as_deref().unwrap_or(base_ty);
                    lines.push(format!("ARG {slot:<5} {}", render_value(value, ty)));
                }
            } else if let Some(chars) = arg.chars {
                lines.push(format!(
                    "ARG {:<5} {} {chars} chars · embeds {} · raw destinations {} · confidential={}",
                    arg.name,
                    arg.ty,
                    arg.embeds.len(),
                    arg.raw_destinations,
                    confidential_name(arg.confidential),
                ));
                for embed in &arg.embeds {
                    let ty = embed.ty.as_deref().unwrap_or(base_ty);
                    lines.push(format!("          {}", render_value(embed, ty)));
                }
            } else if !arg.embeds.is_empty() {
                lines.push(format!(
                    "ARG {:<5} {} · embeds {} · confidential={}",
                    arg.name,
                    arg.ty,
                    arg.embeds.len(),
                    confidential_name(arg.confidential),
                ));
                for embed in &arg.embeds {
                    let ty = embed.ty.as_deref().unwrap_or(base_ty);
                    lines.push(format!("          {}", render_value(embed, ty)));
                }
            } else {
                lines.push(format!(
                    "ARG {:<5} {} · confidential={}",
                    arg.name,
                    arg.ty,
                    confidential_name(arg.confidential),
                ));
            }
        }
        lines.push(format!(
            "CONTEXT   trust={} · band {} · lowest={}",
            self.context_trust.value(),
            band_name(self.band),
            render_lowest(self.lowest_read.as_ref()),
        ));
        lines.push(format!("CHECKS    {}", self.checks.join(" · ")));
        lines.join("\n")
    }
}

fn render_value(value: &ValueView, scalar_ty: &str) -> String {
    // A word typed in the prompt traces without a ref.
    let no_ref = if value.sources.is_empty() {
        "untraced"
    } else {
        "no-ref"
    };
    let ref_text = value.ref_id.as_ref().map_or(no_ref, RefId::as_str);
    let (source, trust) = render_sources(&value.sources);
    format!("{ref_text}  {scalar_ty}  source={source}  trust={trust}")
}

fn render_sources(sources: &[SourceView]) -> (String, u8) {
    if sources.is_empty() {
        return ("untraced".to_owned(), 0);
    }
    let mut parts = Vec::with_capacity(sources.len());
    let mut best_trust = 0u8;
    for source in sources {
        let (text, trust) = render_source(source);
        parts.push(text);
        best_trust = best_trust.max(trust);
    }
    (parts.join(", "), best_trust)
}

fn render_source(source: &SourceView) -> (String, u8) {
    match source {
        SourceView::Prompt { trust } => ("prompt".to_owned(), trust.value()),
        SourceView::UserData { trust } => ("user_data".to_owned(), trust.value()),
        SourceView::Store { name, key, trust } => (format!("store {name}.{key}"), trust.value()),
        SourceView::Step {
            step,
            field,
            region,
            domain,
            trust,
        } => {
            let region = region_name(*region);
            let detail = match domain {
                Some(d) => format!("{region}, domain#{d}"),
                None => region.to_owned(),
            };
            (format!("step {step} {field} ({detail})"), trust.value())
        }
        SourceView::Untraced => ("untraced".to_owned(), 0),
    }
}

fn render_lowest(lowest: Option<&SourceView>) -> String {
    match lowest {
        None => "none".to_owned(),
        Some(SourceView::Step {
            region,
            domain: Some(d),
            ..
        }) => format!("domain#{d}/{}", region_name(*region)),
        Some(SourceView::Step {
            step,
            field,
            region,
            domain: None,
            ..
        }) => format!("step {step} {field}/{}", region_name(*region)),
        Some(SourceView::Prompt { .. }) => "prompt".to_owned(),
        Some(SourceView::UserData { .. }) => "user_data".to_owned(),
        Some(SourceView::Store { name, key, .. }) => format!("store {name}.{key}"),
        Some(SourceView::Untraced) => "untraced".to_owned(),
    }
}

fn band_name(band: Band) -> &'static str {
    match band {
        Band::Clean => "80-100",
        Band::Elevated => "50-79",
        Band::Restricted => "20-49",
        Band::Lockdown => "0-19",
    }
}

fn confidential_name(confidential: Confidential) -> &'static str {
    match confidential {
        Confidential::Public => "public",
        Confidential::Internal => "internal",
        Confidential::Private => "private",
        Confidential::Secret => "secret",
    }
}

fn region_name(region: RegionType) -> &'static str {
    match region {
        RegionType::OperatorLegal => "operator_legal",
        RegionType::OperatorContent => "operator_content",
        RegionType::OperatorUi => "operator_ui",
        RegionType::ProductListing => "product_listing",
        RegionType::Editorial => "editorial",
        RegionType::SearchSnippet => "search_snippet",
        RegionType::UgcPost => "ugc_post",
        RegionType::UgcReview => "ugc_review",
        RegionType::Profile => "profile",
        RegionType::UgcComment => "ugc_comment",
        RegionType::Ad => "ad",
        RegionType::EmbeddedThirdParty => "embedded_third_party",
        RegionType::UserContent => "user_content",
        RegionType::Message => "message",
        RegionType::Unclassified => "unclassified",
        RegionType::Hidden => "hidden",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn render_matches_the_spec_doc_example_exactly() {
        let view = ReviewView {
            tool: "email.send".parse().unwrap(),
            tier: 3,
            step: 2,
            steps_in_plan: 2,
            calls_made: 0,
            budget: 1,
            context_trust: Trust::new(15),
            band: Band::Lockdown,
            lowest_read: Some(SourceView::Step {
                step: 1,
                field: "reviews".to_owned(),
                region: RegionType::UgcReview,
                domain: Some(1),
                trust: Trust::new(15),
            }),
            args: vec![
                ArgView {
                    name: "to".to_owned(),
                    ty: "email[]".to_owned(),
                    role: ArgRole::Destination,
                    values: vec![ValueView {
                        ref_id: Some("ref:e2".parse().unwrap()),
                        ty: Some("email".to_owned()),
                        sources: vec![SourceView::Store {
                            name: "contacts".to_owned(),
                            key: "boss".to_owned(),
                            trust: Trust::FULL,
                        }],
                    }],
                    chars: None,
                    embeds: Vec::new(),
                    raw_destinations: 0,
                    confidential: Confidential::Private,
                    control: false,
                },
                ArgView {
                    name: "body".to_owned(),
                    ty: "text".to_owned(),
                    role: ArgRole::Content,
                    values: Vec::new(),
                    chars: Some(412),
                    embeds: vec![ValueView {
                        ref_id: Some("ref:u3".parse().unwrap()),
                        ty: Some("url".to_owned()),
                        sources: vec![SourceView::Step {
                            step: 1,
                            field: "links".to_owned(),
                            region: RegionType::ProductListing,
                            domain: Some(1),
                            trust: Trust::new(80),
                        }],
                    }],
                    raw_destinations: 0,
                    confidential: Confidential::Public,
                    control: false,
                },
            ],
            checks: vec![
                "plan.step2".to_owned(),
                "budget.ok".to_owned(),
                "to.trace_ok".to_owned(),
                "band.lockdown".to_owned(),
            ],
        };
        let expected = "\
REQUEST   step 2/2 · email.send (tier 3) · call 1 of max 1
ARG to[0] ref:e2  email  source=store contacts.boss  trust=100
ARG body  text 412 chars · embeds 1 · raw destinations 0 · confidential=public
          ref:u3  url  source=step 1 links (product_listing, domain#1)  trust=80
CONTEXT   trust=15 · band 0-19 · lowest=domain#1/ugc_review
CHECKS    plan.step2 · budget.ok · to.trace_ok · band.lockdown";
        assert_eq!(view.render(), expected);
    }

    #[test]
    fn a_prompt_word_renders_as_the_prompt_without_a_ref() {
        let word = ValueView {
            ref_id: None,
            ty: None,
            sources: vec![SourceView::Prompt { trust: Trust::FULL }],
        };
        assert_eq!(
            render_value(&word, "id"),
            "no-ref  id  source=prompt  trust=100"
        );
        let untraced = ValueView {
            ref_id: None,
            ty: None,
            sources: Vec::new(),
        };
        assert_eq!(
            render_value(&untraced, "id"),
            "untraced  id  source=untraced  trust=0"
        );
    }
}
