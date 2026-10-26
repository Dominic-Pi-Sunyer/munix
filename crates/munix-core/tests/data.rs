//! The shipped manifests and the demo plan parse, validate and fit together.

#![allow(clippy::unwrap_used)]

use munix_core::manifest::{Catalog, ToolManifest};
use munix_core::plan::{Dlp, Plan};
use munix_core::request::Request;
use serde_json::json;
use std::path::PathBuf;

fn repo_file(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn catalog() -> Catalog {
    Catalog::from_manifests([
        ToolManifest::from_yaml(&repo_file("manifests/web.open.yaml")).unwrap(),
        ToolManifest::from_yaml(&repo_file("manifests/email.send.yaml")).unwrap(),
    ])
    .unwrap()
}

#[test]
fn web_open_manifest() {
    let m = ToolManifest::from_yaml(&repo_file("manifests/web.open.yaml")).unwrap();
    assert_eq!(m.tool.as_str(), "web.open");
    assert_eq!(m.tier, 1);
    assert!(m.egress);
    assert!(m.credentials.is_none());
    assert_eq!(m.args.len(), 1);
    assert_eq!(m.args["url"].ty.to_string(), "url");
    assert_eq!(m.output["page"].ty.to_string(), "text");
    assert_eq!(m.output["links"].ty.to_string(), "url[]");
    for field in ["page", "links"] {
        assert_eq!(
            serde_json::to_value(m.output[field].region).unwrap(),
            json!("unclassified")
        );
        assert_eq!(
            serde_json::to_value(m.output[field].confidential).unwrap(),
            json!("public")
        );
    }
    m.digest().unwrap();
}

#[test]
fn email_send_manifest() {
    let m = ToolManifest::from_yaml(&repo_file("manifests/email.send.yaml")).unwrap();
    assert_eq!(m.tool.as_str(), "email.send");
    assert_eq!(m.tier, 3);
    assert!(m.egress);
    assert_eq!(
        m.credentials.as_ref().unwrap().as_str(),
        "vault://mail/demo"
    );
    assert_eq!(m.args["to"].ty.to_string(), "email[]");
    assert_eq!(m.args["to"].max, Some(5));
    assert!(!m.args["to"].optional);
    assert_eq!(m.args["cc"].max, Some(5));
    assert!(m.args["cc"].optional);
    assert_eq!(m.args["subject"].max_len, Some(200));
    assert!(m.args["subject"].single_line);
    assert_eq!(m.args["body"].max_len, Some(20000));
    assert!(!m.args["body"].single_line);
    assert_eq!(m.args["attachments"].ty.to_string(), "ref[]");
    assert_eq!(m.args["attachments"].max, Some(10));
    assert!(m.args["attachments"].optional);
    assert_eq!(m.output["message_id"].ty.to_string(), "id");
    assert_eq!(
        serde_json::to_value(m.output["message_id"].region).unwrap(),
        json!("operator_content")
    );
    assert_eq!(
        serde_json::to_value(m.output["message_id"].confidential).unwrap(),
        json!("internal")
    );
    m.digest().unwrap();
}

#[test]
fn demo_plan_validates_against_the_manifests() {
    let plan = Plan::from_yaml(&repo_file("examples/demo-plan.yaml")).unwrap();
    plan.validate(&catalog()).unwrap();
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(plan.steps[0].tool.as_str(), "web.open");
    assert_eq!(plan.steps[1].tool.as_str(), "email.send");
    let email = &plan.steps[1].args;
    assert!(email["cc"].is_forbidden());
    assert!(email["attachments"].is_forbidden());
    assert_eq!(email["subject"].dlp, Some(Dlp::NoSecret));
    assert_eq!(email["body"].dlp, Some(Dlp::NoSecret));
    assert_eq!(
        email["to"].from.as_ref().unwrap()[0].to_string(),
        "store.contacts.boss"
    );
    assert_eq!(
        email["body"]
            .may_embed
            .as_ref()
            .unwrap()
            .min_trust
            .unwrap()
            .value(),
        60
    );
    assert_eq!(plan.reads.len(), 4);
    assert_eq!(
        plan.prompt_hash.as_str(),
        format!("sha256:{}", "0".repeat(64))
    );
}

#[test]
fn demo_plan_fails_against_a_weaker_catalog() {
    let plan = Plan::from_yaml(&repo_file("examples/demo-plan.yaml")).unwrap();
    assert!(plan.validate(&Catalog::new()).is_err());
}

#[test]
fn requests_for_the_demo_steps_pass_shape_checks() {
    let cat = catalog();
    let open: Request = serde_json::from_value(json!({
        "task": "T-demo", "plan": "P-demo", "step": 1, "tool": "web.open",
        "args": {"url": "http://pixelmart.test:8080/x"}
    }))
    .unwrap();
    open.check_shape(cat.get(&open.tool).unwrap()).unwrap();

    let send: Request = serde_json::from_value(json!({
        "task": "T-demo", "plan": "P-demo", "step": 2, "tool": "email.send",
        "args": {"to": ["ref:c1"], "subject": "PixelMart reviews", "body": "Summary: ref:u4"}
    }))
    .unwrap();
    send.check_shape(cat.get(&send.tool).unwrap()).unwrap();

    let bad: Request = serde_json::from_value(json!({
        "task": "T-demo", "plan": "P-demo", "step": 1, "tool": "web.open",
        "args": {"url": "http://127.0.0.1/admin"}
    }))
    .unwrap();
    assert!(bad.check_shape(cat.get(&bad.tool).unwrap()).is_err());
}
