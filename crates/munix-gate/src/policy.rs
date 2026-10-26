//! The Policy Engine: Stage 1, the deterministic ruling on every request (design spec 7.1 and 7.2).
//!
//! A pure function of the facts. It never calls a model, and nothing later can turn its `Deny` into anything
//! else (invariant 6).

use std::collections::BTreeMap;

use munix_core::context::Band;
use munix_core::ids::ToolName;
use munix_core::label::{Confidential, Trust};
use munix_core::manifest::{ArgRole, ToolManifest};
use munix_core::plan::{ArgRule, Dlp, Plan};
use serde::{Deserialize, Serialize};

use crate::facts::{ArgFacts, Traced};

/// A coarse denial reason, the only thing the agent learns about a denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyCode {
    /// The step is not in the plan, or the tool is not that step's tool.
    OffPlan,
    /// The step has used its budget.
    BudgetExhausted,
    /// The plan forbids this argument.
    ForbiddenArg,
    /// A destination, selector or embedded ref does not trace to a source the plan allows, with enough trust.
    UntrustedDestination,
    /// A raw link or address was written into content text for an egress tool.
    RawDestination,
    /// Content carries data more confidential than the plan's DLP rule allows, or a credential.
    ConfidentialData,
    /// A `ref:` the Gate never issued for this task.
    UnknownRef,
    /// The current band never allows this request (destinations outside the plan at 0-19).
    BandLimit,
    /// The Supervisor's review or the user said no.
    Reviewer,
}

impl DenyCode {
    /// Takeover signals go to recovery instead of back to the agent (design spec 6, "Recovery").
    pub fn is_takeover(self) -> bool {
        matches!(
            self,
            DenyCode::OffPlan | DenyCode::UntrustedDestination | DenyCode::RawDestination
        )
    }
}

/// What Stage 1 decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "code")]
pub enum Outcome {
    /// Code checks are enough: execute.
    Allow,
    /// Code checks passed, but the band sends this to the Supervisor's review (Stage 2).
    Gray,
    /// Code checks passed, but the band needs the user's confirmation at the Console.
    ConfirmUser,
    Deny(DenyCode),
}

/// Stage 1's ruling with its reasons for the ledger. Reasons are short fixed strings such as `plan.step2`,
/// `budget.ok`, `to.trace=store.contacts`, `body.raw_destination`; they never contain argument values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ruling {
    pub outcome: Outcome,
    pub reasons: Vec<String>,
}

/// Everything Stage 1 looks at. The request has already passed `Request::check_shape` against `manifest`, and
/// `args` holds the tracer's facts for every argument present in the request.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub plan: &'a Plan,
    pub step: u32,
    pub tool: &'a ToolName,
    pub manifest: &'a ToolManifest,
    /// Calls already executed for this step.
    pub calls_so_far: u32,
    pub band: Band,
    pub args: &'a BTreeMap<String, ArgFacts>,
}

/// Rules on one request. Checks run in this order and the first failure decides:
///
/// 1. **Plan:** the step exists and its tool is `tool` (else `OffPlan`); `calls_so_far < budget` (else
///    `BudgetExhausted`).
/// 2. **Per argument**, in name order, using the step's rule for it (an argument with no rule has no constraint
///    beyond the ones below):
///    - forbidden and present: `ForbiddenArg`;
///    - any unknown ref: `UnknownRef`;
///    - `from`: every entry of `values` must satisfy it with `min_trust` (else `UntrustedDestination`);
///    - a destination argument of a tier 1+ tool with no `from` rule: `UntrustedDestination`;
///    - content of an egress tool with `raw_destinations > 0`: `RawDestination`;
///    - `embedded` refs: each must satisfy `may_embed.from` with `may_embed.min_trust`; any embedded ref without
///      a `may_embed` rule is `UntrustedDestination`;
///    - `contains_credential`, or `confidential` above the `dlp` rule (`no_secret`: secret is too much;
///      `no_private`: private or more; `public_only`: anything above public): `ConfidentialData`. A content
///      argument with no `dlp` rule gets `no_secret`.
/// 3. **Band** (design spec 7.2), only when everything above passed. "Clean-side destinations" means every
///    destination value has a match whose origin `is_clean_side()`. "High trust" means every destination
///    value's `best_trust()` is at least 90.
///
///    | band | tier 0 | tier 1 | tier 2 | tier 3 |
///    |---|---|---|---|---|
///    | Clean | Allow | Allow | Allow | Allow |
///    | Elevated | Allow | Allow | Gray | Gray |
///    | Restricted | Allow | clean-side: Allow, else Gray | Gray | high trust: Gray, else ConfirmUser |
///    | Lockdown | Allow | clean-side: Allow, else `Deny(BandLimit)` | ConfirmUser | ConfirmUser |
pub fn evaluate(facts: &Facts<'_>) -> Ruling {
    let mut reasons: Vec<String> = Vec::new();
    match check_request(facts, &mut reasons) {
        Err(code) => ruling(Outcome::Deny(code), reasons),
        Ok(()) => {
            let outcome = band_outcome(facts, &mut reasons);
            ruling(outcome, reasons)
        }
    }
}

fn ruling(outcome: Outcome, reasons: Vec<String>) -> Ruling {
    Ruling { outcome, reasons }
}

/// Fixed reason for a band, never built from request data.
fn band_reason(band: Band) -> &'static str {
    match band {
        Band::Clean => "band.clean",
        Band::Elevated => "band.elevated",
        Band::Restricted => "band.restricted",
        Band::Lockdown => "band.lockdown",
    }
}

/// Steps 1 and 2: the plan and every argument. The first failure decides.
fn check_request(facts: &Facts<'_>, reasons: &mut Vec<String>) -> Result<(), DenyCode> {
    // 1. Plan.
    let Some(step) = facts.plan.steps.iter().find(|s| s.id == facts.step) else {
        reasons.push("plan.no_step".to_owned());
        return Err(DenyCode::OffPlan);
    };
    if step.tool != *facts.tool || facts.manifest.tool != *facts.tool {
        reasons.push("plan.tool_mismatch".to_owned());
        return Err(DenyCode::OffPlan);
    }
    reasons.push(format!("plan.step{}", step.id));
    if facts.calls_so_far >= step.budget {
        reasons.push("budget.exhausted".to_owned());
        return Err(DenyCode::BudgetExhausted);
    }
    reasons.push("budget.ok".to_owned());

    // 2. Per argument, in name order (`BTreeMap`).
    for (name, arg) in facts.args {
        let rule = step.args.get(name);

        if rule.is_some_and(ArgRule::is_forbidden) {
            reasons.push(format!("{name}.forbidden"));
            return Err(DenyCode::ForbiddenArg);
        }

        // An argument the manifest does not have cannot have passed the shape check; refuse it.
        let Some(spec) = facts.manifest.args.get(name) else {
            reasons.push(format!("{name}.not_in_manifest"));
            return Err(DenyCode::ForbiddenArg);
        };

        if arg.unknown_refs > 0 {
            reasons.push(format!("{name}.unknown_ref"));
            return Err(DenyCode::UnknownRef);
        }

        let from = rule.and_then(|r| r.from.as_deref());
        if let Some(from) = from {
            let min_trust = rule.and_then(|r| r.min_trust);
            if !arg.values.iter().all(|v| v.satisfies(from, min_trust)) {
                reasons.push(format!("{name}.trace_untrusted"));
                return Err(DenyCode::UntrustedDestination);
            }
            reasons.push(format!("{name}.trace_ok"));
        } else if spec.role == ArgRole::Destination && facts.manifest.tier >= 1 {
            reasons.push(format!("{name}.no_from_rule"));
            return Err(DenyCode::UntrustedDestination);
        }

        if spec.role == ArgRole::Content && facts.manifest.egress && arg.raw_destinations > 0 {
            reasons.push(format!("{name}.raw_destination"));
            return Err(DenyCode::RawDestination);
        }

        if !arg.embedded.is_empty() {
            let embed = rule.and_then(|r| r.may_embed.as_ref());
            let allowed = embed.is_some_and(|e| {
                arg.embedded
                    .iter()
                    .all(|t| t.satisfies(&e.from, e.min_trust))
            });
            if !allowed {
                reasons.push(format!("{name}.embed_untrusted"));
                return Err(DenyCode::UntrustedDestination);
            }
            reasons.push(format!("{name}.embed_ok"));
        }

        if arg.contains_credential {
            reasons.push(format!("{name}.credential"));
            return Err(DenyCode::ConfidentialData);
        }
        // Content with no DLP rule still never carries secrets.
        let dlp = rule
            .and_then(|r| r.dlp)
            .or((spec.role == ArgRole::Content).then_some(Dlp::NoSecret));
        if let Some(dlp) = dlp {
            let too_much = match dlp {
                Dlp::NoSecret => arg.confidential >= Confidential::Secret,
                Dlp::NoPrivate => arg.confidential >= Confidential::Private,
                Dlp::PublicOnly => arg.confidential > Confidential::Public,
            };
            if too_much {
                reasons.push(format!("{name}.confidential"));
                return Err(DenyCode::ConfidentialData);
            }
            reasons.push(format!("{name}.dlp_ok"));
        }
    }
    Ok(())
}

/// Step 3: the band table. Only reached when the plan and argument checks passed.
fn band_outcome(facts: &Facts<'_>, reasons: &mut Vec<String>) -> Outcome {
    let tier = facts.manifest.tier;
    let band = facts.band;
    reasons.push(band_reason(band).to_owned());

    // Every value of every destination argument present in the request.
    let destinations: Vec<&Traced> = facts
        .args
        .iter()
        .filter(|(name, _)| {
            facts
                .manifest
                .args
                .get(*name)
                .is_some_and(|s| s.role == ArgRole::Destination)
        })
        .flat_map(|(_, a)| a.values.iter())
        .collect();
    let clean_side = destinations
        .iter()
        .all(|t| t.matches.iter().any(|m| m.origin.is_clean_side()));
    let high_trust = destinations
        .iter()
        .all(|t| t.best_trust() >= Trust::new(90));

    match (band, tier) {
        (Band::Clean, _) | (_, 0) => Outcome::Allow,
        (Band::Elevated, 1) => Outcome::Allow,
        (Band::Elevated, _) => Outcome::Gray,
        (Band::Restricted, 1) => {
            if clean_side {
                Outcome::Allow
            } else {
                Outcome::Gray
            }
        }
        (Band::Restricted, 2) => Outcome::Gray,
        (Band::Restricted, _) => {
            if high_trust {
                Outcome::Gray
            } else {
                Outcome::ConfirmUser
            }
        }
        (Band::Lockdown, 1) => {
            if clean_side {
                Outcome::Allow
            } else {
                reasons.push("band.limit".to_owned());
                Outcome::Deny(DenyCode::BandLimit)
            }
        }
        (Band::Lockdown, _) => Outcome::ConfirmUser,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::facts::{Match, Origin};

    const WEB_OPEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/web.open.yaml"
    ));
    const EMAIL_SEND: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/email.send.yaml"
    ));
    const DEMO_PLAN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/demo-plan.yaml"
    ));

    const NOTES_READ: &str = "
tool: notes.read
description: Read a note.
tier: 0
args:
  title: {type: text, role: selector, max_len: 50}
";
    const NOTES_WRITE: &str = "
tool: notes.write
description: Write a note to a shared place.
tier: 2
args:
  target: {type: text, role: destination, max_len: 50}
  body:   {type: text, role: content, max_len: 500}
";

    /// Steps 1 and 2 of the demo plan, plus a tier 0 step 3 and a tier 2 step 4 for the band tests.
    fn band_plan() -> Plan {
        let mut plan = Plan::from_yaml(DEMO_PLAN).unwrap();
        let extra = Plan::from_yaml(&DEMO_PLAN.replace(
            "steps:\n  - id: 1\n    tool: web.open\n    args:\n      url: {from: [prompt]}\n    budget: 3\n  - id: 2\n    tool: email.send",
            "steps:\n  - id: 3\n    tool: notes.read\n    args: {}\n    budget: 5\n  - id: 4\n    tool: notes.write\n    args:\n      target: {from: [prompt]}\n    budget: 5\n  - id: 2\n    tool: email.send",
        ))
        .unwrap();
        plan.steps
            .extend(extra.steps.into_iter().filter(|s| s.id == 3 || s.id == 4));
        plan
    }

    fn manifest(text: &str) -> ToolManifest {
        ToolManifest::from_yaml(text).unwrap()
    }

    fn tool(name: &str) -> ToolName {
        name.parse().unwrap()
    }

    fn matched(origin: Origin, trust: u8, confidential: Confidential) -> Match {
        Match {
            origin,
            trust: Trust::new(trust),
            confidential,
        }
    }

    fn traced(origin: Origin, trust: u8) -> Traced {
        Traced {
            matches: vec![matched(origin, trust, Confidential::Public)],
        }
    }

    fn boss() -> Traced {
        traced(
            Origin::Store {
                name: "contacts".into(),
                key: "boss".into(),
            },
            100,
        )
    }

    fn from_step(trust: u8) -> Traced {
        traced(
            Origin::Step {
                step: 1,
                field: "links".into(),
            },
            trust,
        )
    }

    fn with_values(values: Vec<Traced>) -> ArgFacts {
        ArgFacts {
            values,
            ..ArgFacts::default()
        }
    }

    fn args(items: Vec<(&str, ArgFacts)>) -> BTreeMap<String, ArgFacts> {
        items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
    }

    /// The honest demo request: mail to the boss, body without links.
    fn honest_email() -> BTreeMap<String, ArgFacts> {
        args(vec![
            ("to", with_values(vec![boss()])),
            ("subject", ArgFacts::default()),
            ("body", ArgFacts::default()),
        ])
    }

    fn email_with(
        edit: impl FnOnce(&mut BTreeMap<String, ArgFacts>),
    ) -> BTreeMap<String, ArgFacts> {
        let mut a = honest_email();
        edit(&mut a);
        a
    }

    fn run_with(
        plan: &Plan,
        step: u32,
        tool_name: &str,
        manifest: &ToolManifest,
        calls: u32,
        band: Band,
        args: &BTreeMap<String, ArgFacts>,
    ) -> Ruling {
        let tool = tool(tool_name);
        evaluate(&Facts {
            plan,
            step,
            tool: &tool,
            manifest,
            calls_so_far: calls,
            band,
            args,
        })
    }

    fn email(band: Band, args: &BTreeMap<String, ArgFacts>) -> Ruling {
        run_with(
            &band_plan(),
            2,
            "email.send",
            &manifest(EMAIL_SEND),
            0,
            band,
            args,
        )
    }

    fn web(band: Band, calls: u32, args: &BTreeMap<String, ArgFacts>) -> Ruling {
        run_with(
            &band_plan(),
            1,
            "web.open",
            &manifest(WEB_OPEN),
            calls,
            band,
            args,
        )
    }

    fn denied(r: &Ruling) -> DenyCode {
        match r.outcome {
            Outcome::Deny(code) => code,
            other => panic!("expected a denial, got {other:?} ({:?})", r.reasons),
        }
    }

    fn has_reason(r: &Ruling, reason: &str) -> bool {
        r.reasons.iter().any(|x| x == reason)
    }

    #[test]
    fn honest_email_by_band() {
        let a = honest_email();
        assert_eq!(email(Band::Clean, &a).outcome, Outcome::Allow);
        assert_eq!(email(Band::Elevated, &a).outcome, Outcome::Gray);
        // Trust 100 is at least 90, so tier 3 is Gray, not ConfirmUser, at Restricted.
        let r = email(Band::Restricted, &a);
        assert_eq!(r.outcome, Outcome::Gray);
        assert!(has_reason(&r, "band.restricted"));
        assert_eq!(email(Band::Lockdown, &a).outcome, Outcome::ConfirmUser);
    }

    #[test]
    fn honest_email_reasons() {
        let r = email(Band::Clean, &honest_email());
        for reason in [
            "plan.step2",
            "budget.ok",
            "to.trace_ok",
            "subject.dlp_ok",
            "body.dlp_ok",
            "band.clean",
        ] {
            assert!(
                has_reason(&r, reason),
                "{reason} missing from {:?}",
                r.reasons
            );
        }
    }

    #[test]
    fn restricted_tier3_with_lower_trust_destination_needs_the_user() {
        // A destination the plan accepts but whose trust is under 90.
        let mut plan = band_plan();
        plan.steps[1].args.get_mut("to").unwrap().from = Some(vec!["prompt".parse().unwrap()]);
        let a = email_with(|a| {
            a.insert("to".into(), with_values(vec![traced(Origin::Prompt, 89)]));
        });
        let m = manifest(EMAIL_SEND);
        let r = run_with(&plan, 2, "email.send", &m, 0, Band::Restricted, &a);
        assert_eq!(r.outcome, Outcome::ConfirmUser);
        let a = email_with(|a| {
            a.insert("to".into(), with_values(vec![traced(Origin::Prompt, 90)]));
        });
        let r = run_with(&plan, 2, "email.send", &m, 0, Band::Restricted, &a);
        assert_eq!(r.outcome, Outcome::Gray);
    }

    #[test]
    fn restricted_tier3_needs_every_destination_to_be_high_trust() {
        let mut plan = band_plan();
        plan.steps[1].args.get_mut("to").unwrap().from = Some(vec!["prompt".parse().unwrap()]);
        let a = email_with(|a| {
            a.insert(
                "to".into(),
                with_values(vec![
                    traced(Origin::Prompt, 100),
                    traced(Origin::Prompt, 50),
                ]),
            );
        });
        let r = run_with(
            &plan,
            2,
            "email.send",
            &manifest(EMAIL_SEND),
            0,
            Band::Restricted,
            &a,
        );
        assert_eq!(r.outcome, Outcome::ConfirmUser);
    }

    #[test]
    fn untraced_destination_is_a_takeover() {
        let a = email_with(|a| {
            a.insert("to".into(), with_values(vec![Traced::untraced()]));
        });
        for band in [Band::Clean, Band::Lockdown] {
            let r = email(band, &a);
            assert_eq!(denied(&r), DenyCode::UntrustedDestination);
            assert!(denied(&r).is_takeover());
            assert!(has_reason(&r, "to.trace_untrusted"));
        }
    }

    #[test]
    fn destination_traced_only_to_a_step_output_is_a_takeover() {
        let a = email_with(|a| {
            a.insert("to".into(), with_values(vec![from_step(95)]));
        });
        let r = email(Band::Clean, &a);
        assert_eq!(denied(&r), DenyCode::UntrustedDestination);
        assert!(denied(&r).is_takeover());
    }

    #[test]
    fn one_bad_destination_value_spoils_the_list() {
        let a = email_with(|a| {
            a.insert("to".into(), with_values(vec![boss(), Traced::untraced()]));
        });
        assert_eq!(
            denied(&email(Band::Clean, &a)),
            DenyCode::UntrustedDestination
        );
    }

    #[test]
    fn the_right_source_with_too_little_trust_is_refused() {
        // web.open url from the prompt has no min_trust; give the rule one and check it is applied.
        let mut plan = band_plan();
        plan.steps[0].args.get_mut("url").unwrap().min_trust = Some(Trust::new(80));
        let m = manifest(WEB_OPEN);
        let low = args(vec![("url", with_values(vec![traced(Origin::Prompt, 79)]))]);
        let ok = args(vec![("url", with_values(vec![traced(Origin::Prompt, 80)]))]);
        let r = run_with(&plan, 1, "web.open", &m, 0, Band::Clean, &low);
        assert_eq!(denied(&r), DenyCode::UntrustedDestination);
        let r = run_with(&plan, 1, "web.open", &m, 0, Band::Clean, &ok);
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn raw_link_in_body_is_a_takeover() {
        let a = email_with(|a| {
            a.get_mut("body").unwrap().raw_destinations = 1;
        });
        let r = email(Band::Clean, &a);
        assert_eq!(denied(&r), DenyCode::RawDestination);
        assert!(denied(&r).is_takeover());
        assert!(has_reason(&r, "body.raw_destination"));
    }

    #[test]
    fn raw_destinations_only_matter_for_content_of_egress_tools() {
        // notes.write is not egress: a link in its body is not a raw destination.
        let a = args(vec![
            ("target", with_values(vec![traced(Origin::Prompt, 100)])),
            (
                "body",
                ArgFacts {
                    raw_destinations: 2,
                    ..ArgFacts::default()
                },
            ),
        ]);
        let r = run_with(
            &band_plan(),
            4,
            "notes.write",
            &manifest(NOTES_WRITE),
            0,
            Band::Clean,
            &a,
        );
        assert_eq!(r.outcome, Outcome::Allow);
        // A destination argument is traced, not scanned for raw links.
        let a = email_with(|a| {
            a.get_mut("to").unwrap().raw_destinations = 1;
        });
        assert_eq!(email(Band::Clean, &a).outcome, Outcome::Allow);
    }

    #[test]
    fn cc_present_is_forbidden_even_when_well_traced() {
        let a = email_with(|a| {
            a.insert("cc".into(), with_values(vec![boss()]));
        });
        let r = email(Band::Clean, &a);
        assert_eq!(denied(&r), DenyCode::ForbiddenArg);
        assert!(!denied(&r).is_takeover());
        assert!(has_reason(&r, "cc.forbidden"));
    }

    #[test]
    fn attachments_present_is_forbidden() {
        let a = email_with(|a| {
            a.insert("attachments".into(), ArgFacts::default());
        });
        assert_eq!(denied(&email(Band::Clean, &a)), DenyCode::ForbiddenArg);
    }

    #[test]
    fn forbidden_arg_wins_over_untrusted_destination_by_name_order() {
        // `cc` sorts before `to`, so the forbidden argument is reported first.
        let a = email_with(|a| {
            a.insert("cc".into(), with_values(vec![boss()]));
            a.insert("to".into(), with_values(vec![Traced::untraced()]));
        });
        assert_eq!(denied(&email(Band::Clean, &a)), DenyCode::ForbiddenArg);
    }

    #[test]
    fn arguments_are_checked_in_name_order() {
        // `body` sorts before `to`: a credential in the body is reported before an untraced destination.
        let a = email_with(|a| {
            a.insert("to".into(), with_values(vec![Traced::untraced()]));
            a.get_mut("body").unwrap().contains_credential = true;
        });
        assert_eq!(denied(&email(Band::Clean, &a)), DenyCode::ConfidentialData);
        // `to` sorts before `subject`? No: `subject` < `to`, so an unknown ref in `to` loses to one in `subject`.
        let a = email_with(|a| {
            a.insert("to".into(), with_values(vec![Traced::untraced()]));
            a.get_mut("subject").unwrap().raw_destinations = 1;
        });
        assert_eq!(denied(&email(Band::Clean, &a)), DenyCode::RawDestination);
    }

    #[test]
    fn step_three_is_off_plan() {
        let plan = Plan::from_yaml(DEMO_PLAN).unwrap();
        let r = run_with(
            &plan,
            3,
            "email.send",
            &manifest(EMAIL_SEND),
            0,
            Band::Clean,
            &honest_email(),
        );
        assert_eq!(denied(&r), DenyCode::OffPlan);
        assert!(denied(&r).is_takeover());
    }

    #[test]
    fn tool_mismatch_is_off_plan() {
        // Step 2 is email.send; the request names web.open (with a matching manifest).
        let r = run_with(
            &band_plan(),
            2,
            "web.open",
            &manifest(WEB_OPEN),
            0,
            Band::Clean,
            &args(vec![(
                "url",
                with_values(vec![traced(Origin::Prompt, 100)]),
            )]),
        );
        assert_eq!(denied(&r), DenyCode::OffPlan);
        // A manifest that is not the named tool's is refused too.
        let r = run_with(
            &band_plan(),
            2,
            "email.send",
            &manifest(WEB_OPEN),
            0,
            Band::Clean,
            &honest_email(),
        );
        assert_eq!(denied(&r), DenyCode::OffPlan);
    }

    #[test]
    fn off_plan_wins_over_everything() {
        let a = email_with(|a| {
            a.insert("cc".into(), ArgFacts::default());
            a.get_mut("body").unwrap().contains_credential = true;
            a.get_mut("body").unwrap().unknown_refs = 3;
        });
        let r = run_with(
            &band_plan(),
            99,
            "email.send",
            &manifest(EMAIL_SEND),
            50,
            Band::Lockdown,
            &a,
        );
        assert_eq!(denied(&r), DenyCode::OffPlan);
    }

    #[test]
    fn budget_is_enforced_before_arguments() {
        let url = args(vec![(
            "url",
            with_values(vec![traced(Origin::Prompt, 100)]),
        )]);
        assert_eq!(web(Band::Clean, 2, &url).outcome, Outcome::Allow);
        let r = web(Band::Clean, 3, &url);
        assert_eq!(denied(&r), DenyCode::BudgetExhausted);
        assert!(!denied(&r).is_takeover());
        assert!(has_reason(&r, "budget.exhausted"));
        // Budget wins over a bad argument.
        let bad = args(vec![("url", with_values(vec![Traced::untraced()]))]);
        assert_eq!(
            denied(&web(Band::Clean, 3, &bad)),
            DenyCode::BudgetExhausted
        );
        // A budget of 1 is used up by the first call.
        let r = run_with(
            &band_plan(),
            2,
            "email.send",
            &manifest(EMAIL_SEND),
            1,
            Band::Clean,
            &honest_email(),
        );
        assert_eq!(denied(&r), DenyCode::BudgetExhausted);
    }

    #[test]
    fn credential_in_body_is_confidential_data() {
        let a = email_with(|a| {
            a.get_mut("body").unwrap().contains_credential = true;
        });
        let r = email(Band::Clean, &a);
        assert_eq!(denied(&r), DenyCode::ConfidentialData);
        assert!(!denied(&r).is_takeover());
        assert!(has_reason(&r, "body.credential"));
    }

    #[test]
    fn dlp_no_secret() {
        for (level, ok) in [
            (Confidential::Public, true),
            (Confidential::Internal, true),
            (Confidential::Private, true),
            (Confidential::Secret, false),
        ] {
            let a = email_with(|a| a.get_mut("subject").unwrap().confidential = level);
            let r = email(Band::Clean, &a);
            if ok {
                assert_eq!(r.outcome, Outcome::Allow, "{level:?}");
            } else {
                assert_eq!(denied(&r), DenyCode::ConfidentialData, "{level:?}");
            }
        }
    }

    #[test]
    fn dlp_no_private_and_public_only() {
        for (dlp, limits) in [
            (
                Dlp::NoPrivate,
                [
                    (Confidential::Public, true),
                    (Confidential::Internal, true),
                    (Confidential::Private, false),
                    (Confidential::Secret, false),
                ],
            ),
            (
                Dlp::PublicOnly,
                [
                    (Confidential::Public, true),
                    (Confidential::Internal, false),
                    (Confidential::Private, false),
                    (Confidential::Secret, false),
                ],
            ),
        ] {
            let mut plan = band_plan();
            plan.steps[1].args.get_mut("body").unwrap().dlp = Some(dlp);
            for (level, ok) in limits {
                let a = email_with(|a| a.get_mut("body").unwrap().confidential = level);
                let r = run_with(
                    &plan,
                    2,
                    "email.send",
                    &manifest(EMAIL_SEND),
                    0,
                    Band::Clean,
                    &a,
                );
                if ok {
                    assert_eq!(r.outcome, Outcome::Allow, "{dlp:?} {level:?}");
                } else {
                    assert_eq!(denied(&r), DenyCode::ConfidentialData, "{dlp:?} {level:?}");
                }
            }
        }
    }

    #[test]
    fn no_dlp_rule_means_no_secret_and_credentials_still_deny() {
        let mut plan = band_plan();
        plan.steps[1].args.get_mut("body").unwrap().dlp = None;
        let m = manifest(EMAIL_SEND);
        let a = email_with(|a| a.get_mut("body").unwrap().confidential = Confidential::Private);
        let r = run_with(&plan, 2, "email.send", &m, 0, Band::Clean, &a);
        assert_eq!(r.outcome, Outcome::Allow);
        let a = email_with(|a| a.get_mut("body").unwrap().confidential = Confidential::Secret);
        let r = run_with(&plan, 2, "email.send", &m, 0, Band::Clean, &a);
        assert_eq!(denied(&r), DenyCode::ConfidentialData);
        let a = email_with(|a| a.get_mut("body").unwrap().contains_credential = true);
        let r = run_with(&plan, 2, "email.send", &m, 0, Band::Clean, &a);
        assert_eq!(denied(&r), DenyCode::ConfidentialData);
    }

    #[test]
    fn unknown_ref_is_denied() {
        for name in ["to", "body", "subject"] {
            let a = email_with(|a| a.get_mut(name).unwrap().unknown_refs = 1);
            let r = email(Band::Clean, &a);
            assert_eq!(denied(&r), DenyCode::UnknownRef, "{name}");
            assert!(!denied(&r).is_takeover());
            assert!(has_reason(&r, &format!("{name}.unknown_ref")));
        }
    }

    #[test]
    fn unknown_ref_is_checked_before_the_trace() {
        let a = email_with(|a| {
            let to = a.get_mut("to").unwrap();
            to.values = vec![Traced::untraced()];
            to.unknown_refs = 1;
        });
        assert_eq!(denied(&email(Band::Clean, &a)), DenyCode::UnknownRef);
    }

    #[test]
    fn embedded_refs_need_a_may_embed_rule_that_they_satisfy() {
        let embedded = |trust: u8| {
            email_with(|a| {
                a.get_mut("body").unwrap().embedded = vec![from_step(trust)];
            })
        };
        // The plan allows step.1 at trust 60.
        assert_eq!(email(Band::Clean, &embedded(60)).outcome, Outcome::Allow);
        assert_eq!(email(Band::Clean, &embedded(95)).outcome, Outcome::Allow);
        let r = email(Band::Clean, &embedded(59));
        assert_eq!(denied(&r), DenyCode::UntrustedDestination);
        assert!(has_reason(&r, "body.embed_untrusted"));
        // An embedded ref from a source the rule does not name.
        let a = email_with(|a| {
            a.get_mut("body").unwrap().embedded = vec![traced(
                Origin::Step {
                    step: 7,
                    field: "links".into(),
                },
                100,
            )];
        });
        assert_eq!(
            denied(&email(Band::Clean, &a)),
            DenyCode::UntrustedDestination
        );
        // Every embedded ref must pass, not just one.
        let a = email_with(|a| {
            a.get_mut("body").unwrap().embedded = vec![from_step(90), from_step(10)];
        });
        assert_eq!(
            denied(&email(Band::Clean, &a)),
            DenyCode::UntrustedDestination
        );
    }

    #[test]
    fn embedded_ref_without_a_may_embed_rule_is_untrusted() {
        // The subject has `dlp` but no `may_embed`.
        let a = email_with(|a| {
            a.get_mut("subject").unwrap().embedded = vec![from_step(100)];
        });
        assert_eq!(
            denied(&email(Band::Clean, &a)),
            DenyCode::UntrustedDestination
        );
        // An argument with no rule at all behaves the same.
        let mut plan = band_plan();
        plan.steps[1].args.remove("body");
        let a = email_with(|a| {
            a.get_mut("body").unwrap().embedded = vec![from_step(100)];
        });
        let r = run_with(
            &plan,
            2,
            "email.send",
            &manifest(EMAIL_SEND),
            0,
            Band::Clean,
            &a,
        );
        assert_eq!(denied(&r), DenyCode::UntrustedDestination);
    }

    #[test]
    fn destination_of_a_tier1_tool_without_a_from_rule_is_untrusted() {
        let mut plan = band_plan();
        plan.steps[0].args.clear();
        let url = args(vec![(
            "url",
            with_values(vec![traced(Origin::Prompt, 100)]),
        )]);
        let r = run_with(
            &plan,
            1,
            "web.open",
            &manifest(WEB_OPEN),
            0,
            Band::Clean,
            &url,
        );
        assert_eq!(denied(&r), DenyCode::UntrustedDestination);
        assert!(has_reason(&r, "url.no_from_rule"));
    }

    #[test]
    fn web_open_url_from_the_prompt_is_allowed_in_every_band() {
        let url = args(vec![(
            "url",
            with_values(vec![traced(Origin::Prompt, 100)]),
        )]);
        for band in [
            Band::Clean,
            Band::Elevated,
            Band::Restricted,
            Band::Lockdown,
        ] {
            assert_eq!(web(band, 0, &url).outcome, Outcome::Allow, "{band:?}");
        }
    }

    #[test]
    fn web_open_url_from_a_step_is_refused_by_the_plan() {
        // The plan lets the url come from the prompt only.
        let url = args(vec![("url", with_values(vec![from_step(100)]))]);
        let r = web(Band::Clean, 0, &url);
        assert_eq!(denied(&r), DenyCode::UntrustedDestination);
    }

    #[test]
    fn web_open_url_from_a_step_at_lockdown_is_band_limited() {
        // A plan that does allow step sources, so only the band can refuse.
        let mut plan = band_plan();
        plan.steps[0].args.get_mut("url").unwrap().from = Some(vec![
            "prompt".parse().unwrap(),
            "step.1.links".parse().unwrap(),
        ]);
        plan.steps[0].args.get_mut("url").unwrap().min_trust = Some(Trust::new(50));
        let m = manifest(WEB_OPEN);
        let url = args(vec![("url", with_values(vec![from_step(70)]))]);
        for (band, outcome) in [
            (Band::Clean, Outcome::Allow),
            (Band::Elevated, Outcome::Allow),
            (Band::Restricted, Outcome::Gray),
            (Band::Lockdown, Outcome::Deny(DenyCode::BandLimit)),
        ] {
            let r = run_with(&plan, 1, "web.open", &m, 0, band, &url);
            assert_eq!(r.outcome, outcome, "{band:?}");
        }
        let r = run_with(&plan, 1, "web.open", &m, 0, Band::Lockdown, &url);
        assert!(has_reason(&r, "band.limit"));
        assert!(!DenyCode::BandLimit.is_takeover());
    }

    #[test]
    fn clean_side_needs_a_clean_match_for_every_value() {
        let mut plan = band_plan();
        plan.steps[0].args.get_mut("url").unwrap().from = Some(vec![
            "prompt".parse().unwrap(),
            "step.1.links".parse().unwrap(),
        ]);
        plan.steps[0].args.get_mut("url").unwrap().min_trust = Some(Trust::new(50));
        let m = manifest(WEB_OPEN);
        // One value is clean, the other came only from a step.
        let mixed = args(vec![(
            "url",
            with_values(vec![traced(Origin::Prompt, 100), from_step(70)]),
        )]);
        let r = run_with(&plan, 1, "web.open", &m, 0, Band::Lockdown, &mixed);
        assert_eq!(r.outcome, Outcome::Deny(DenyCode::BandLimit));
        // A value found both in the prompt and in a step output counts as clean-side.
        let both = args(vec![(
            "url",
            with_values(vec![Traced {
                matches: vec![
                    matched(
                        Origin::Step {
                            step: 1,
                            field: "links".into(),
                        },
                        70,
                        Confidential::Public,
                    ),
                    matched(Origin::UserData, 70, Confidential::Public),
                ],
            }]),
        )]);
        let r = run_with(&plan, 1, "web.open", &m, 0, Band::Lockdown, &both);
        // UserData is not an allowed source, but the step match satisfies the plan.
        assert_eq!(r.outcome, Outcome::Allow);
    }

    #[test]
    fn tier0_is_allowed_in_every_band() {
        let a = args(vec![("title", ArgFacts::default())]);
        for band in [
            Band::Clean,
            Band::Elevated,
            Band::Restricted,
            Band::Lockdown,
        ] {
            let r = run_with(
                &band_plan(),
                3,
                "notes.read",
                &manifest(NOTES_READ),
                0,
                band,
                &a,
            );
            assert_eq!(r.outcome, Outcome::Allow, "{band:?}");
        }
    }

    #[test]
    fn tier2_by_band() {
        let a = args(vec![
            ("target", with_values(vec![traced(Origin::Prompt, 100)])),
            ("body", ArgFacts::default()),
        ]);
        for (band, outcome) in [
            (Band::Clean, Outcome::Allow),
            (Band::Elevated, Outcome::Gray),
            (Band::Restricted, Outcome::Gray),
            (Band::Lockdown, Outcome::ConfirmUser),
        ] {
            let r = run_with(
                &band_plan(),
                4,
                "notes.write",
                &manifest(NOTES_WRITE),
                0,
                band,
                &a,
            );
            assert_eq!(r.outcome, outcome, "{band:?}");
        }
    }

    #[test]
    fn tier3_by_band_with_high_trust_destination_matches_the_table() {
        let a = honest_email();
        for (band, outcome) in [
            (Band::Clean, Outcome::Allow),
            (Band::Elevated, Outcome::Gray),
            (Band::Restricted, Outcome::Gray),
            (Band::Lockdown, Outcome::ConfirmUser),
        ] {
            assert_eq!(email(band, &a).outcome, outcome, "{band:?}");
        }
    }

    #[test]
    fn code_denials_are_the_same_in_every_band() {
        let a = email_with(|a| {
            a.insert("cc".into(), ArgFacts::default());
        });
        for band in [
            Band::Clean,
            Band::Elevated,
            Band::Restricted,
            Band::Lockdown,
        ] {
            assert_eq!(denied(&email(band, &a)), DenyCode::ForbiddenArg, "{band:?}");
        }
    }

    #[test]
    fn takeover_signals() {
        for code in [
            DenyCode::OffPlan,
            DenyCode::UntrustedDestination,
            DenyCode::RawDestination,
        ] {
            assert!(code.is_takeover(), "{code:?}");
        }
        for code in [
            DenyCode::BudgetExhausted,
            DenyCode::ForbiddenArg,
            DenyCode::ConfidentialData,
            DenyCode::UnknownRef,
            DenyCode::BandLimit,
        ] {
            assert!(!code.is_takeover(), "{code:?}");
        }
    }

    #[test]
    fn argument_not_in_the_manifest_is_refused() {
        let a = email_with(|a| {
            a.insert("zzz".into(), ArgFacts::default());
        });
        assert_eq!(denied(&email(Band::Clean, &a)), DenyCode::ForbiddenArg);
    }

    #[test]
    fn reasons_never_carry_argument_values() {
        // Reasons come from fixed strings and argument names only; check the shape on a few rulings.
        let rulings = [
            email(Band::Clean, &honest_email()),
            email(
                Band::Lockdown,
                &email_with(|a| {
                    a.insert("to".into(), with_values(vec![Traced::untraced()]));
                }),
            ),
        ];
        for r in rulings {
            for reason in &r.reasons {
                assert!(
                    reason.bytes().all(|b| b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'.'
                        || b == b'_'),
                    "{reason}"
                );
            }
        }
    }

    #[test]
    fn ruling_round_trips_through_json() {
        let r = email(Band::Restricted, &honest_email());
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Ruling>(&json).unwrap(), r);
        let r = Ruling {
            outcome: Outcome::Deny(DenyCode::OffPlan),
            reasons: vec!["plan.no_step".into()],
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("off_plan"));
        assert_eq!(serde_json::from_str::<Ruling>(&json).unwrap(), r);
    }
}
