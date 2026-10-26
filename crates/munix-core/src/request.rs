//! A request from Agent A to the Gate (design spec 4.4) and its first check against the manifest.

use crate::ids::{PlanId, RefId, TaskId, ToolName};
use crate::manifest::{ArgSpec, ToolManifest};
use crate::validate::{Scalar, is_clean_text, is_valid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// The most elements a list argument may have when its manifest sets no `max`.
pub const DEFAULT_LIST_MAX: u32 = 100;
/// Integers beyond this magnitude are not exactly representable in JSON consumers, so they are refused.
const MAX_SAFE_INT: i64 = (1 << 53) - 1;

/// What the agent asks for. Unknown fields are rejected, so the agent cannot add a field like `"trust": 100`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub task: TaskId,
    pub plan: PlanId,
    pub step: u32,
    pub tool: ToolName,
    pub args: BTreeMap<String, Value>,
}

/// A coarse reason a request is malformed. Detail goes to the ledger, not to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationCode {
    ToolMismatch,
    UnknownArg,
    MissingArg,
    WrongType,
    TooMany,
    TooLong,
    NotInEnum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Violation {
    /// The argument at fault; absent for `tool_mismatch`.
    pub arg: Option<String>,
    pub code: ViolationCode,
}

impl Request {
    /// Checks the request against the tool's manifest: right tool, no unknown arguments, no missing required ones,
    /// and every value of the right shape. Returns every violation found.
    pub fn check_shape(&self, manifest: &ToolManifest) -> Result<(), Vec<Violation>> {
        if self.tool != manifest.tool {
            return Err(vec![Violation {
                arg: None,
                code: ViolationCode::ToolMismatch,
            }]);
        }
        let mut violations = Vec::new();
        for name in self.args.keys() {
            if !manifest.args.contains_key(name) {
                violations.push(Violation {
                    arg: Some(name.clone()),
                    code: ViolationCode::UnknownArg,
                });
            }
        }
        for (name, spec) in &manifest.args {
            match self.args.get(name) {
                None if !spec.optional => {
                    violations.push(Violation {
                        arg: Some(name.clone()),
                        code: ViolationCode::MissingArg,
                    });
                }
                None => {}
                Some(value) => {
                    if let Err(code) = check_arg_value(spec, value) {
                        violations.push(Violation {
                            arg: Some(name.clone()),
                            code,
                        });
                    }
                }
            }
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

/// Checks one argument value against its spec. String-shaped scalars accept a `ref:` id in place of the value.
pub fn check_arg_value(spec: &ArgSpec, v: &Value) -> Result<(), ViolationCode> {
    if !spec.ty.list {
        return check_scalar(spec, v, spec.max);
    }
    let Value::Array(items) = v else {
        return Err(ViolationCode::WrongType);
    };
    if items.len() > spec.max.unwrap_or(DEFAULT_LIST_MAX) as usize {
        return Err(ViolationCode::TooMany);
    }
    items
        .iter()
        .try_for_each(|item| check_scalar(spec, item, None))
}

fn check_scalar(spec: &ArgSpec, v: &Value, value_max: Option<u32>) -> Result<(), ViolationCode> {
    let scalar = spec.ty.scalar;
    match scalar {
        Scalar::Bool => v.is_boolean().then_some(()).ok_or(ViolationCode::WrongType),
        Scalar::Int => {
            let n = v.as_i64().ok_or(ViolationCode::WrongType)?;
            if n.unsigned_abs() > MAX_SAFE_INT as u64 {
                Err(ViolationCode::WrongType)
            } else if value_max.is_some_and(|max| n > i64::from(max)) {
                Err(ViolationCode::TooMany)
            } else {
                Ok(())
            }
        }
        Scalar::Number => {
            let Value::Number(n) = v else {
                return Err(ViolationCode::WrongType);
            };
            if (n.is_i64() || n.is_u64())
                && !n
                    .as_i64()
                    .is_some_and(|i| i.unsigned_abs() <= MAX_SAFE_INT as u64)
            {
                return Err(ViolationCode::WrongType);
            }
            let f = n
                .as_f64()
                .filter(|f| f.is_finite())
                .ok_or(ViolationCode::WrongType)?;
            if value_max.is_some_and(|max| f > f64::from(max)) {
                Err(ViolationCode::TooMany)
            } else {
                Ok(())
            }
        }
        Scalar::Enum => {
            let s = v.as_str().ok_or(ViolationCode::WrongType)?;
            if spec.values.iter().any(|allowed| allowed == s) {
                Ok(())
            } else {
                Err(ViolationCode::NotInEnum)
            }
        }
        Scalar::Text
        | Scalar::Email
        | Scalar::Url
        | Scalar::Phone
        | Scalar::Id
        | Scalar::Ref
        | Scalar::Date => {
            let s = v.as_str().ok_or(ViolationCode::WrongType)?;
            if s.parse::<RefId>().is_ok() {
                return Ok(());
            }
            if spec
                .max_len
                .is_some_and(|max| s.chars().count() > max as usize)
            {
                return Err(ViolationCode::TooLong);
            }
            if scalar == Scalar::Text && spec.single_line && !is_clean_text(s, true) {
                return Err(ViolationCode::WrongType);
            }
            if is_valid(scalar, s) {
                Ok(())
            } else {
                Err(ViolationCode::WrongType)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EMAIL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../manifests/email.send.yaml"
    ));

    fn manifest() -> ToolManifest {
        ToolManifest::from_yaml(EMAIL).unwrap()
    }

    fn request(args: Value) -> Request {
        serde_json::from_value(
            json!({"task": "T-1", "plan": "P-1", "step": 2, "tool": "email.send", "args": args}),
        )
        .unwrap()
    }

    fn good_args() -> Value {
        json!({"to": ["ref:c1"], "subject": "Monitor pick", "body": "Top pick: ref:u4 (4.6 stars across 1,200 reviews)."})
    }

    fn codes(args: Value) -> Vec<(Option<String>, ViolationCode)> {
        match request(args).check_shape(&manifest()) {
            Ok(()) => vec![],
            Err(v) => v.into_iter().map(|v| (v.arg, v.code)).collect(),
        }
    }

    fn spec(ty: &str) -> ArgSpec {
        serde_json::from_value(json!({"type": ty, "role": "control"})).unwrap()
    }

    #[test]
    fn spec_example_passes() {
        assert!(request(good_args()).check_shape(&manifest()).is_ok());
    }

    #[test]
    fn raw_values_pass_too() {
        let args = json!({
            "to": ["boss@example.com", "ref:c2"], "cc": ["a@pixelmart.test"], "subject": "Hi", "body": "multi\nline body",
            "attachments": ["ref:f1"]
        });
        assert_eq!(codes(args), vec![]);
    }

    #[test]
    fn request_rejects_unknown_fields() {
        let wire = json!({"task": "T-1", "plan": "P-1", "step": 2, "tool": "email.send", "args": {}, "trust": 100});
        assert!(serde_json::from_value::<Request>(wire).is_err());
        let wire =
            json!({"task": "T 1", "plan": "P-1", "step": 2, "tool": "email.send", "args": {}});
        assert!(serde_json::from_value::<Request>(wire).is_err());
    }

    #[test]
    fn tool_mismatch() {
        let mut r = request(good_args());
        r.tool = "web.open".parse().unwrap();
        assert_eq!(
            r.check_shape(&manifest()),
            Err(vec![Violation {
                arg: None,
                code: ViolationCode::ToolMismatch
            }])
        );
    }

    #[test]
    fn unknown_and_missing_args() {
        let mut args = good_args();
        args["bcc"] = json!(["x@example.com"]);
        assert_eq!(
            codes(args),
            vec![(Some("bcc".into()), ViolationCode::UnknownArg)]
        );
        let mut args = good_args();
        args.as_object_mut().unwrap().remove("body");
        assert_eq!(
            codes(args),
            vec![(Some("body".into()), ViolationCode::MissingArg)]
        );
        // Optional arguments may be absent; null is not "absent".
        let mut args = good_args();
        args["cc"] = Value::Null;
        assert_eq!(
            codes(args),
            vec![(Some("cc".into()), ViolationCode::WrongType)]
        );
        assert_eq!(codes(json!({})).len(), 3);
    }

    #[test]
    fn wrong_types() {
        for (field, value) in [
            ("to", json!("boss@example.com")),
            ("to", json!([5])),
            ("to", json!(["not an email"])),
            ("to", json!(["boss@127.0.0.1"])),
            ("to", json!([["boss@example.com"]])),
            ("subject", json!(7)),
            ("subject", json!(["a"])),
            ("subject", json!("line\nbreak")),
            ("subject", json!("zero\u{200b}width")),
            ("body", json!("bidi \u{202e}text")),
            ("body", json!({"text": "x"})),
            ("attachments", json!(["not a ref"])),
            ("attachments", json!(["REF:a"])),
            ("attachments", json!("ref:a")),
        ] {
            let mut args = good_args();
            args[field] = value.clone();
            assert_eq!(
                codes(args),
                vec![(Some(field.into()), ViolationCode::WrongType)],
                "{field}={value}"
            );
        }
    }

    #[test]
    fn too_many() {
        let mut args = good_args();
        args["to"] = json!(["ref:a", "ref:b", "ref:c", "ref:d", "ref:e", "ref:f"]);
        assert_eq!(
            codes(args),
            vec![(Some("to".into()), ViolationCode::TooMany)]
        );
        let mut args = good_args();
        args["to"] = json!(["ref:a", "ref:b", "ref:c", "ref:d", "ref:e"]);
        assert_eq!(codes(args), vec![]);
        let mut args = good_args();
        args["attachments"] = json!((0..11).map(|i| format!("ref:f{i}")).collect::<Vec<_>>());
        assert_eq!(
            codes(args),
            vec![(Some("attachments".into()), ViolationCode::TooMany)]
        );
    }

    #[test]
    fn too_long_counts_chars() {
        let mut args = good_args();
        args["subject"] = json!("s".repeat(201));
        assert_eq!(
            codes(args),
            vec![(Some("subject".into()), ViolationCode::TooLong)]
        );
        let mut args = good_args();
        args["subject"] = json!("s".repeat(200));
        assert_eq!(codes(args), vec![]);
        // 200 multi-byte characters are 200 chars, not 600 bytes.
        let mut args = good_args();
        args["subject"] = json!("\u{65e5}".repeat(200));
        assert_eq!(codes(args), vec![]);
        let mut args = good_args();
        args["body"] = json!("b".repeat(20_001));
        assert_eq!(
            codes(args),
            vec![(Some("body".into()), ViolationCode::TooLong)]
        );
        // An over-long value is TooLong even when it is also invalid.
        let mut s = spec("text");
        s.max_len = Some(3);
        assert_eq!(
            check_arg_value(&s, &json!("abc\u{0}")),
            Err(ViolationCode::TooLong)
        );
    }

    #[test]
    fn collects_every_violation() {
        let args = json!({"to": "x", "subject": "a\nb", "extra": 1});
        let found = codes(args);
        assert!(found.contains(&(Some("extra".into()), ViolationCode::UnknownArg)));
        assert!(found.contains(&(Some("body".into()), ViolationCode::MissingArg)));
        assert!(found.contains(&(Some("to".into()), ViolationCode::WrongType)));
        assert!(found.contains(&(Some("subject".into()), ViolationCode::WrongType)));
    }

    #[test]
    fn refs_stand_in_for_string_shaped_values() {
        for ty in ["text", "email", "url", "phone", "id", "ref", "date"] {
            assert_eq!(check_arg_value(&spec(ty), &json!("ref:x1")), Ok(()), "{ty}");
        }
        for ty in ["bool", "int", "number"] {
            assert_eq!(
                check_arg_value(&spec(ty), &json!("ref:x1")),
                Err(ViolationCode::WrongType),
                "{ty}"
            );
        }
        let mut e = spec("enum");
        e.values = vec!["a".into()];
        assert_eq!(
            check_arg_value(&e, &json!("ref:x1")),
            Err(ViolationCode::NotInEnum)
        );
        // A ref glued to other text is just text, and fails as a URL.
        assert_eq!(
            check_arg_value(&spec("url"), &json!("ref:x1 ")),
            Err(ViolationCode::WrongType)
        );
    }

    #[test]
    fn scalar_shapes() {
        assert_eq!(
            check_arg_value(&spec("url"), &json!("http://pixelmart.test:8080/x")),
            Ok(())
        );
        assert_eq!(
            check_arg_value(&spec("url"), &json!("http://localhost/")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("phone"), &json!("+14155550123")),
            Ok(())
        );
        assert_eq!(
            check_arg_value(&spec("phone"), &json!("12")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(check_arg_value(&spec("id"), &json!("abc-1")), Ok(()));
        assert_eq!(
            check_arg_value(&spec("id"), &json!("a/b")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("date"), &json!("2026-02-30")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(check_arg_value(&spec("date"), &json!("2026-02-28")), Ok(()));
        assert_eq!(
            check_arg_value(&spec("ref"), &json!("plain")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("text"), &json!(null)),
            Err(ViolationCode::WrongType)
        );
    }

    #[test]
    fn single_line_text() {
        let mut s = spec("text");
        assert_eq!(check_arg_value(&s, &json!("a\nb")), Ok(()));
        s.single_line = true;
        assert_eq!(
            check_arg_value(&s, &json!("a\nb")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&s, &json!("a\rb")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(check_arg_value(&s, &json!("a b")), Ok(()));
    }

    #[test]
    fn bool_int_number() {
        assert_eq!(check_arg_value(&spec("bool"), &json!(true)), Ok(()));
        assert_eq!(
            check_arg_value(&spec("bool"), &json!("true")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("bool"), &json!(1)),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(check_arg_value(&spec("int"), &json!(5)), Ok(()));
        assert_eq!(check_arg_value(&spec("int"), &json!(-5)), Ok(()));
        assert_eq!(
            check_arg_value(&spec("int"), &json!(5.5)),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("int"), &json!(5.0)),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("int"), &json!("5")),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(check_arg_value(&spec("number"), &json!(5.5)), Ok(()));
        assert_eq!(check_arg_value(&spec("number"), &json!(5)), Ok(()));
        assert_eq!(
            check_arg_value(&spec("number"), &json!("5")),
            Err(ViolationCode::WrongType)
        );
    }

    #[test]
    fn integers_beyond_2_pow_53_are_wrong_type() {
        let limit: i64 = (1 << 53) - 1;
        assert_eq!(check_arg_value(&spec("int"), &json!(limit)), Ok(()));
        assert_eq!(check_arg_value(&spec("int"), &json!(-limit)), Ok(()));
        assert_eq!(
            check_arg_value(&spec("int"), &json!(limit + 1)),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("int"), &json!(-limit - 1)),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("int"), &json!(i64::MIN)),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("int"), &json!(u64::MAX)),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("number"), &json!(limit + 1)),
            Err(ViolationCode::WrongType)
        );
        assert_eq!(
            check_arg_value(&spec("number"), &json!(u64::MAX)),
            Err(ViolationCode::WrongType)
        );
    }

    #[test]
    fn max_bounds_int_and_number_values() {
        let mut s = spec("int");
        s.max = Some(10);
        assert_eq!(check_arg_value(&s, &json!(10)), Ok(()));
        assert_eq!(check_arg_value(&s, &json!(11)), Err(ViolationCode::TooMany));
        let mut n = spec("number");
        n.max = Some(1);
        assert_eq!(check_arg_value(&n, &json!(1.0)), Ok(()));
        assert_eq!(
            check_arg_value(&n, &json!(1.5)),
            Err(ViolationCode::TooMany)
        );
    }

    #[test]
    fn enums() {
        let mut e = spec("enum");
        e.values = vec!["fast".into(), "slow".into()];
        assert_eq!(check_arg_value(&e, &json!("fast")), Ok(()));
        assert_eq!(
            check_arg_value(&e, &json!("Fast")),
            Err(ViolationCode::NotInEnum)
        );
        assert_eq!(
            check_arg_value(&e, &json!("fast ")),
            Err(ViolationCode::NotInEnum)
        );
        assert_eq!(
            check_arg_value(&e, &json!(1)),
            Err(ViolationCode::WrongType)
        );
    }

    #[test]
    fn lists_without_max_are_capped() {
        let l = spec("id[]");
        let items = |n: usize| json!((0..n).map(|i| format!("i{i}")).collect::<Vec<_>>());
        assert_eq!(
            check_arg_value(&l, &items(DEFAULT_LIST_MAX as usize)),
            Ok(())
        );
        assert_eq!(
            check_arg_value(&l, &items(DEFAULT_LIST_MAX as usize + 1)),
            Err(ViolationCode::TooMany)
        );
        assert_eq!(check_arg_value(&l, &json!([])), Ok(()));
        assert_eq!(
            check_arg_value(&l, &json!("i1")),
            Err(ViolationCode::WrongType)
        );
    }

    #[test]
    fn violation_wire_form() {
        let v = Violation {
            arg: Some("to".into()),
            code: ViolationCode::TooMany,
        };
        assert_eq!(
            serde_json::to_value(&v).unwrap(),
            json!({"arg": "to", "code": "too_many"})
        );
        assert_eq!(
            serde_json::to_value(ViolationCode::NotInEnum).unwrap(),
            json!("not_in_enum")
        );
        assert_eq!(
            serde_json::to_value(ViolationCode::ToolMismatch).unwrap(),
            json!("tool_mismatch")
        );
    }
}
