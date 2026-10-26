//! The Plan of Record (design spec 4.3): what the user's task allows, signed before any untrusted content is read.
//! Everything not in the plan is denied.

use crate::crypto::{self, Digest};
use crate::error::{Error, Result, invalid};
use crate::ids::{PlanId, TaskId, ToolName};
use crate::label::{RegionType, Trust};
use crate::manifest::{ArgRole, Catalog};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// Where a plan lets an argument's value come from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum SourcePath {
    /// The user's prompt.
    Prompt,
    /// Data the user attached.
    UserData,
    /// `store.<name>` or `store.<name>.<key>`: the operator's stored data, such as contacts.
    Store { name: String, key: Option<String> },
    /// `step.<n>` or `step.<n>.<field>`: output of an earlier step.
    Step { step: u32, field: Option<String> },
}

fn is_store_part(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_field(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

impl FromStr for SourcePath {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let bad = || invalid("invalid source path");
        let parts: Vec<&str> = s.split('.').collect();
        match parts.as_slice() {
            ["prompt"] => Ok(SourcePath::Prompt),
            ["user_data"] => Ok(SourcePath::UserData),
            ["store", name] | ["store", name, _] => {
                let key = parts.get(2).copied();
                if is_store_part(name) && key.is_none_or(is_store_part) {
                    Ok(SourcePath::Store {
                        name: (*name).to_owned(),
                        key: key.map(str::to_owned),
                    })
                } else {
                    Err(bad())
                }
            }
            ["step", n] | ["step", n, _] => {
                let step: u32 = n.parse().map_err(|_| bad())?;
                let field = parts.get(2).copied();
                if step.to_string() == *n && field.is_none_or(is_field) {
                    Ok(SourcePath::Step {
                        step,
                        field: field.map(str::to_owned),
                    })
                } else {
                    Err(bad())
                }
            }
            _ => Err(bad()),
        }
    }
}

impl fmt::Display for SourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourcePath::Prompt => f.write_str("prompt"),
            SourcePath::UserData => f.write_str("user_data"),
            SourcePath::Store { name, key: None } => write!(f, "store.{name}"),
            SourcePath::Store {
                name,
                key: Some(key),
            } => write!(f, "store.{name}.{key}"),
            SourcePath::Step { step, field: None } => write!(f, "step.{step}"),
            SourcePath::Step {
                step,
                field: Some(field),
            } => write!(f, "step.{step}.{field}"),
        }
    }
}

impl TryFrom<String> for SourcePath {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<SourcePath> for String {
    fn from(p: SourcePath) -> String {
        p.to_string()
    }
}

/// How much confidential data a content argument may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dlp {
    /// Nothing labelled `secret`.
    NoSecret,
    /// Nothing labelled `private` or `secret`.
    NoPrivate,
    /// Only `public`.
    PublicOnly,
}

/// Permission for a content argument to embed refs (such as a link in an email body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Embed {
    pub from: Vec<SourcePath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_trust: Option<Trust>,
}

/// The plan's rule for one argument of a step.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Vec<SourcePath>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_trust: Option<Trust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlp: Option<Dlp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub may_embed: Option<Embed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbid: Option<bool>,
}

impl ArgRule {
    /// True when the argument must be absent.
    pub fn is_forbidden(&self) -> bool {
        self.forbid == Some(true)
    }
}

/// One allowed tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: u32,
    pub tool: ToolName,
    #[serde(default)]
    pub args: BTreeMap<String, ArgRule>,
    /// The most calls this step may make (1-1000).
    pub budget: u32,
}

/// What may change without asking the user again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Amendments {
    /// Amendments up to this tier are automatic. Higher tiers and new destinations always need the user.
    pub auto_max_tier: u8,
}

/// The signed plan for one task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub plan: PlanId,
    pub task: TaskId,
    pub prompt_hash: Digest,
    /// The region types the task may read.
    pub reads: BTreeSet<RegionType>,
    pub steps: Vec<Step>,
    pub amendments: Amendments,
}

impl Plan {
    /// Parses YAML, rejecting unknown fields. Call [`Plan::validate`] before trusting it.
    pub fn from_yaml(text: &str) -> Result<Self> {
        Ok(serde_yaml_ng::from_str(text)?)
    }

    pub fn digest(&self) -> Result<Digest> {
        crypto::digest(self)
    }

    /// Checks the plan against the catalog (design spec 4.3).
    pub fn validate(&self, catalog: &Catalog) -> Result<()> {
        if self.reads.contains(&RegionType::Hidden) {
            return Err(invalid("hidden is never allowed in reads"));
        }
        if self.amendments.auto_max_tier > 3 {
            return Err(invalid("auto_max_tier must be 0-3"));
        }
        let mut ids = BTreeSet::new();
        for (index, step) in self.steps.iter().enumerate() {
            if !ids.insert(step.id) {
                return Err(invalid("step ids must be unique"));
            }
            if !(1..=1000).contains(&step.budget) {
                return Err(invalid("budget must be 1-1000"));
            }
            let manifest = catalog
                .get(&step.tool)
                .ok_or_else(|| invalid("step uses a tool that is not in the catalog"))?;

            for (name, rule) in &step.args {
                let spec = manifest
                    .args
                    .get(name)
                    .ok_or_else(|| invalid("rule for an argument the tool does not have"))?;
                if rule.is_forbidden()
                    && (rule.from.is_some()
                        || rule.min_trust.is_some()
                        || rule.dlp.is_some()
                        || rule.may_embed.is_some())
                {
                    return Err(invalid("a forbidden argument cannot have other rules"));
                }
                if let Some(from) = &rule.from {
                    self.check_sources(from, index, catalog)?;
                    if rule.min_trust.is_none()
                        && from.iter().any(|p| matches!(p, SourcePath::Step { .. }))
                    {
                        return Err(invalid("a step source needs min_trust"));
                    }
                }
                if rule.dlp.is_some() && spec.role != ArgRole::Content {
                    return Err(invalid("dlp applies only to content arguments"));
                }
                if let Some(embed) = &rule.may_embed {
                    self.check_sources(&embed.from, index, catalog)?;
                    if embed.min_trust.is_none()
                        && embed
                            .from
                            .iter()
                            .any(|p| matches!(p, SourcePath::Step { .. }))
                    {
                        return Err(invalid("a step source in may_embed needs min_trust"));
                    }
                }
            }

            if manifest.tier >= 1 {
                for (name, spec) in &manifest.args {
                    if spec.role != ArgRole::Destination {
                        continue;
                    }
                    let constrained = step.args.get(name).is_some_and(|r| {
                        r.is_forbidden() || r.from.as_ref().is_some_and(|f| !f.is_empty())
                    });
                    if !constrained {
                        return Err(invalid(
                            "every destination argument of a tier 1+ tool needs from or forbid",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Data only flows forward: a `step.N` source must be an earlier step, and `step.N.field` must be an output
    /// that step's tool has.
    fn check_sources(&self, sources: &[SourcePath], index: usize, catalog: &Catalog) -> Result<()> {
        for source in sources {
            let SourcePath::Step { step, field } = source else {
                continue;
            };
            let earlier = self.steps[..index]
                .iter()
                .find(|s| s.id == *step)
                .ok_or_else(|| invalid("a step source must be an earlier step"))?;
            if let Some(field) = field {
                let manifest = catalog
                    .get(&earlier.tool)
                    .ok_or_else(|| invalid("earlier step uses an unknown tool"))?;
                if !manifest.output.contains_key(field) {
                    return Err(invalid(
                        "a step source names an output the tool does not have",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ToolManifest;

    const WEB_OPEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/web.open.yaml"
    ));
    const EMAIL_SEND: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/email.send.yaml"
    ));

    const PLAN: &str = "
plan: P-test
task: T-test
prompt_hash: sha256:0000000000000000000000000000000000000000000000000000000000000000
reads: [operator_content, product_listing, editorial, ugc_review]
steps:
  - id: 1
    tool: web.open
    args:
      url: {from: [prompt]}
    budget: 3
  - id: 2
    tool: email.send
    args:
      to:          {from: [store.contacts.boss]}
      cc:          {forbid: true}
      attachments: {forbid: true}
      subject:     {dlp: no_secret}
      body:        {dlp: no_secret, may_embed: {from: [step.1], min_trust: 60}}
    budget: 1
amendments:
  auto_max_tier: 1
";

    fn catalog() -> Catalog {
        Catalog::from_manifests([
            ToolManifest::from_yaml(WEB_OPEN).unwrap(),
            ToolManifest::from_yaml(EMAIL_SEND).unwrap(),
        ])
        .unwrap()
    }

    fn plan() -> Plan {
        Plan::from_yaml(PLAN).unwrap()
    }

    fn check(edit: impl FnOnce(&mut Plan)) -> Result<()> {
        let mut p = plan();
        edit(&mut p);
        p.validate(&catalog())
    }

    #[test]
    fn source_paths_parse_and_print() {
        for text in [
            "prompt",
            "user_data",
            "store.contacts",
            "store.contacts.boss",
            "step.1",
            "step.12.results",
            "step.0",
            "store.a1_b.k_2",
        ] {
            let p: SourcePath = text.parse().unwrap();
            assert_eq!(p.to_string(), text);
        }
        assert_eq!(
            "store.contacts.boss".parse::<SourcePath>().unwrap(),
            SourcePath::Store {
                name: "contacts".into(),
                key: Some("boss".into())
            }
        );
        assert_eq!(
            "step.2.links".parse::<SourcePath>().unwrap(),
            SourcePath::Step {
                step: 2,
                field: Some("links".into())
            }
        );
        for bad in [
            "",
            "Prompt",
            "prompt.x",
            "user_data.x",
            "store",
            "store.",
            "store.a.b.c",
            "store.A",
            "store..x",
            "step",
            "step.",
            "step.x",
            "step.01",
            "step.-1",
            "step.1.",
            "step.1.Field",
            "step.1.a.b",
            "step.99999999999",
            "web.example",
            " prompt",
        ] {
            assert!(bad.parse::<SourcePath>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn parses_the_demo_shape() {
        let p = plan();
        assert_eq!(p.steps.len(), 2);
        assert_eq!(p.steps[1].args["body"].dlp, Some(Dlp::NoSecret));
        assert_eq!(
            p.steps[1].args["body"]
                .may_embed
                .as_ref()
                .unwrap()
                .min_trust,
            Some(Trust::new(60))
        );
        assert!(p.steps[1].args["cc"].is_forbidden());
        assert_eq!(p.amendments.auto_max_tier, 1);
        assert!(p.reads.contains(&RegionType::UgcReview));
        p.validate(&catalog()).unwrap();
        assert_eq!(p.digest().unwrap(), plan().digest().unwrap());
    }

    #[test]
    fn yaml_rejects_unknown_fields_and_bad_values() {
        assert!(Plan::from_yaml(&format!("{PLAN}extra: 1\n")).is_err());
        assert!(Plan::from_yaml(&PLAN.replace("budget: 3", "budget: 3\n    priority: 9")).is_err());
        assert!(
            Plan::from_yaml(&PLAN.replace("{from: [prompt]}", "{from: [prompt], trust: 100}"))
                .is_err()
        );
        assert!(
            Plan::from_yaml(&PLAN.replace("auto_max_tier: 1", "auto_max_tier: 1\n  extra: 2"))
                .is_err()
        );
        assert!(
            Plan::from_yaml(&PLAN.replace("dlp: no_secret, may", "dlp: nothing, may")).is_err()
        );
        assert!(Plan::from_yaml(&PLAN.replace("from: [prompt]", "from: [web.evil]")).is_err());
        assert!(Plan::from_yaml(&PLAN.replace("min_trust: 60", "min_trust: 160")).is_err());
        assert!(Plan::from_yaml(&PLAN.replace("[operator_content,", "[bogus_region,")).is_err());
        assert!(Plan::from_yaml(&PLAN.replace("sha256:000", "sha256:XYZ")).is_err());
        assert!(Plan::from_yaml(&PLAN.replace("web.open", "Web Open")).is_err());
    }

    #[test]
    fn step_ids_must_be_unique() {
        assert!(check(|p| p.steps[1].id = 1).is_err());
        assert!(check(|p| p.steps[1].id = 7).is_ok());
    }

    #[test]
    fn budgets_run_from_1_to_1000() {
        assert!(check(|p| p.steps[0].budget = 0).is_err());
        assert!(check(|p| p.steps[0].budget = 1).is_ok());
        assert!(check(|p| p.steps[0].budget = 1000).is_ok());
        assert!(check(|p| p.steps[0].budget = 1001).is_err());
    }

    #[test]
    fn tools_must_exist() {
        assert!(check(|p| p.steps[0].tool = "web.search".parse().unwrap()).is_err());
        let empty = Catalog::new();
        assert!(plan().validate(&empty).is_err());
    }

    #[test]
    fn constrained_args_must_exist_on_the_tool() {
        assert!(
            check(|p| {
                p.steps[0].args.insert(
                    "proxy".into(),
                    ArgRule {
                        forbid: Some(true),
                        ..ArgRule::default()
                    },
                );
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[1].args.insert(
                    "bcc".into(),
                    ArgRule {
                        forbid: Some(true),
                        ..ArgRule::default()
                    },
                );
            })
            .is_err()
        );
    }

    #[test]
    fn step_sources_must_point_backward() {
        let from_step = |n: u32, field: Option<&str>| ArgRule {
            from: Some(vec![SourcePath::Step {
                step: n,
                field: field.map(str::to_owned),
            }]),
            min_trust: Some(Trust::new(40)),
            ..ArgRule::default()
        };
        assert!(
            check(|p| {
                p.steps[0].args.insert("url".into(), from_step(2, None));
            })
            .is_err(),
            "step 1 cannot read step 2"
        );
        assert!(
            check(|p| {
                p.steps[0].args.insert("url".into(), from_step(1, None));
            })
            .is_err(),
            "a step cannot read itself"
        );
        assert!(
            check(|p| {
                p.steps[0].args.insert("url".into(), from_step(9, None));
            })
            .is_err(),
            "unknown step"
        );
        assert!(
            check(|p| {
                p.steps[1]
                    .args
                    .insert("to".into(), from_step(1, Some("links")));
            })
            .is_ok()
        );
        // Earlier by position, not by id number.
        assert!(
            check(|p| {
                p.steps[0].id = 20;
                p.steps[1].id = 5;
                p.steps[1]
                    .args
                    .get_mut("body")
                    .unwrap()
                    .may_embed
                    .as_mut()
                    .unwrap()
                    .from = vec![SourcePath::Step {
                    step: 20,
                    field: None,
                }];
            })
            .is_ok()
        );
        assert!(
            check(|p| {
                p.steps[0].id = 20;
                p.steps[1].id = 5;
                p.steps[0].args.insert("url".into(), from_step(5, None));
            })
            .is_err()
        );
    }

    #[test]
    fn step_sources_must_name_real_output_fields() {
        let to_from = |field: &str| ArgRule {
            from: Some(vec![SourcePath::Step {
                step: 1,
                field: Some(field.to_owned()),
            }]),
            min_trust: Some(Trust::new(40)),
            ..ArgRule::default()
        };
        assert!(
            check(|p| {
                p.steps[1].args.insert("to".into(), to_from("links"));
            })
            .is_ok()
        );
        assert!(
            check(|p| {
                p.steps[1].args.insert("to".into(), to_from("results"));
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[1]
                    .args
                    .get_mut("body")
                    .unwrap()
                    .may_embed
                    .as_mut()
                    .unwrap()
                    .from = vec![SourcePath::Step {
                    step: 1,
                    field: Some("nope".into()),
                }];
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[1]
                    .args
                    .get_mut("body")
                    .unwrap()
                    .may_embed
                    .as_mut()
                    .unwrap()
                    .from = vec![SourcePath::Step {
                    step: 1,
                    field: Some("page".into()),
                }];
            })
            .is_ok()
        );
    }

    #[test]
    fn hidden_is_never_readable() {
        assert!(
            check(|p| {
                p.reads.insert(RegionType::Hidden);
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.reads.clear();
            })
            .is_ok()
        );
    }

    #[test]
    fn tier_one_plus_destinations_need_from_or_forbid() {
        // Missing entirely.
        assert!(
            check(|p| {
                p.steps[0].args.remove("url");
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[1].args.remove("to");
            })
            .is_err()
        );
        // The optional destination `cc` is still a destination.
        assert!(
            check(|p| {
                p.steps[1].args.remove("cc");
            })
            .is_err()
        );
        // Rules that are not from or forbid do not count.
        assert!(
            check(|p| {
                p.steps[1].args.insert(
                    "cc".into(),
                    ArgRule {
                        dlp: None,
                        min_trust: Some(Trust::new(50)),
                        ..ArgRule::default()
                    },
                );
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[1].args.insert(
                    "cc".into(),
                    ArgRule {
                        forbid: Some(false),
                        ..ArgRule::default()
                    },
                );
            })
            .is_err()
        );
        // An empty source list allows nothing and does not count as constrained.
        assert!(
            check(|p| {
                p.steps[1].args.insert(
                    "to".into(),
                    ArgRule {
                        from: Some(vec![]),
                        ..ArgRule::default()
                    },
                );
            })
            .is_err()
        );
        // A non-destination argument needs no rule.
        assert!(
            check(|p| {
                p.steps[1].args.remove("subject");
                p.steps[1].args.remove("body");
                p.steps[1].args.remove("attachments");
            })
            .is_ok()
        );
    }

    #[test]
    fn dlp_only_on_content_args() {
        assert!(
            check(|p| {
                p.steps[1].args.get_mut("to").unwrap().dlp = Some(Dlp::NoPrivate);
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[0].args.get_mut("url").unwrap().dlp = Some(Dlp::PublicOnly);
            })
            .is_err()
        );
        for dlp in [Dlp::NoSecret, Dlp::NoPrivate, Dlp::PublicOnly] {
            assert!(
                check(|p| {
                    p.steps[1].args.get_mut("subject").unwrap().dlp = Some(dlp);
                })
                .is_ok()
            );
        }
    }

    #[test]
    fn step_sources_need_a_trust_floor() {
        let step_src = vec![SourcePath::Step {
            step: 1,
            field: Some("links".into()),
        }];
        assert!(
            check(|p| {
                p.steps[1].args.insert(
                    "to".into(),
                    ArgRule {
                        from: Some(step_src.clone()),
                        ..ArgRule::default()
                    },
                );
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[1].args.insert(
                    "to".into(),
                    ArgRule {
                        from: Some(step_src.clone()),
                        min_trust: Some(Trust::new(20)),
                        ..ArgRule::default()
                    },
                );
            })
            .is_ok()
        );
        // Prompt and store sources do not need one.
        assert!(
            check(|p| {
                p.steps[0].args.insert(
                    "url".into(),
                    ArgRule {
                        from: Some(vec![SourcePath::Prompt]),
                        ..ArgRule::default()
                    },
                );
            })
            .is_ok()
        );
        // The same floor applies to refs embedded from a step.
        assert!(
            check(|p| {
                p.steps[1]
                    .args
                    .get_mut("body")
                    .unwrap()
                    .may_embed
                    .as_mut()
                    .unwrap()
                    .min_trust = None;
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[1]
                    .args
                    .get_mut("body")
                    .unwrap()
                    .may_embed
                    .as_mut()
                    .unwrap()
                    .from = vec![SourcePath::Prompt];
                p.steps[1]
                    .args
                    .get_mut("body")
                    .unwrap()
                    .may_embed
                    .as_mut()
                    .unwrap()
                    .min_trust = None;
            })
            .is_ok()
        );
    }

    #[test]
    fn forbid_cannot_be_combined_with_other_rules() {
        assert!(
            check(|p| {
                p.steps[1].args.get_mut("cc").unwrap().from = Some(vec![SourcePath::Prompt]);
            })
            .is_err()
        );
        assert!(
            check(|p| {
                p.steps[1].args.get_mut("attachments").unwrap().min_trust = Some(Trust::new(10));
            })
            .is_err()
        );
    }

    #[test]
    fn amendment_tier_is_bounded() {
        assert!(check(|p| p.amendments.auto_max_tier = 3).is_ok());
        assert!(check(|p| p.amendments.auto_max_tier = 4).is_err());
    }
}
