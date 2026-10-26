use serde_json::{Map, Value};

/// Keywords that survive sanitizing. Everything else (`$schema`, `title`, `default`, `examples`, `format`,
/// numeric and string bounds, ...) is dropped because strict structured-output backends reject or ignore it.
const KEEP: &[&str] = &[
    "type",
    "properties",
    "items",
    "enum",
    "const",
    "anyOf",
    "$ref",
    "$defs",
    "definitions",
    "description",
];

/// Rewrites a JSON Schema so strict structured-output backends accept it: every object schema gets
/// `additionalProperties: false` and lists all its properties in `required` (alphabetical: serde_json sorts keys). `oneOf` becomes `anyOf`.
/// Callers still validate the reply against their own types; this only shapes what the backend is asked for.
pub fn sanitize_schema(schema: &Value) -> Value {
    let Value::Object(map) = schema else {
        return schema.clone();
    };
    let mut out = Map::new();
    for (key, value) in map {
        let key = if key == "oneOf" {
            "anyOf"
        } else {
            key.as_str()
        };
        if !KEEP.contains(&key) || (key == "anyOf" && out.contains_key("anyOf")) {
            continue;
        }
        let cleaned = match key {
            "properties" | "$defs" | "definitions" => sanitize_map(value),
            "items" => match value {
                Value::Array(list) => Value::Array(list.iter().map(sanitize_schema).collect()),
                other => sanitize_schema(other),
            },
            "anyOf" => match value {
                Value::Array(list) => Value::Array(list.iter().map(sanitize_schema).collect()),
                other => other.clone(),
            },
            _ => value.clone(),
        };
        out.insert(key.to_string(), cleaned);
    }
    if is_object_schema(&out) {
        let required: Vec<Value> = match out.get("properties") {
            Some(Value::Object(props)) => props.keys().map(|k| Value::String(k.clone())).collect(),
            _ => Vec::new(),
        };
        out.insert("required".to_string(), Value::Array(required));
        out.insert("additionalProperties".to_string(), Value::Bool(false));
    }
    Value::Object(out)
}

/// A map of name -> schema (`properties`, `$defs`): the names are data, only the values are schemas.
fn sanitize_map(value: &Value) -> Value {
    match value {
        Value::Object(entries) => Value::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), sanitize_schema(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn is_object_schema(map: &Map<String, Value>) -> bool {
    match map.get("type") {
        Some(Value::String(t)) => t == "object",
        Some(Value::Array(types)) => types.iter().any(|t| t == "object"),
        _ => map.contains_key("properties"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn closes_objects_and_requires_every_property() {
        let out = sanitize_schema(&json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Verdict",
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["approve", "deny"], "default": "deny"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 200, "description": "why"}
            },
            "required": ["verdict"]
        }));
        assert_eq!(
            out,
            json!({
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["approve", "deny"]},
                    "reason": {"type": "string", "description": "why"}
                },
                "required": ["reason", "verdict"],
                "additionalProperties": false
            })
        );
    }

    #[test]
    fn recurses_into_arrays_nested_objects_anyof_and_defs() {
        let out = sanitize_schema(&json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "object", "properties": {"n": {"type": "integer", "minimum": 0, "format": "uint"}}}
                },
                "either": {"anyOf": [{"$ref": "#/$defs/Leaf"}, {"type": "null"}]},
                "inner": {"type": "object", "properties": {"deep": {"type": "object", "properties": {"x": {"const": 1}}}}}
            },
            "$defs": {"Leaf": {"type": "object", "properties": {"id": {"type": "string", "examples": ["a"]}}}}
        }));
        let item = &out["properties"]["items"]["items"];
        assert_eq!(item["additionalProperties"], json!(false));
        assert_eq!(item["required"], json!(["n"]));
        assert_eq!(item["properties"]["n"], json!({"type": "integer"}));
        assert!(out["properties"]["items"].get("minItems").is_none());
        assert_eq!(
            out["properties"]["either"]["anyOf"][0],
            json!({"$ref": "#/$defs/Leaf"})
        );
        assert_eq!(out["$defs"]["Leaf"]["required"], json!(["id"]));
        assert_eq!(out["$defs"]["Leaf"]["additionalProperties"], json!(false));
        assert!(
            out["$defs"]["Leaf"]["properties"]["id"]
                .get("examples")
                .is_none()
        );
        let deep = &out["properties"]["inner"]["properties"]["deep"];
        assert_eq!(deep["required"], json!(["x"]));
        assert_eq!(deep["additionalProperties"], json!(false));
        assert_eq!(out["required"], json!(["either", "inner", "items"]));
    }

    #[test]
    fn a_property_called_like_a_keyword_is_kept() {
        let out = sanitize_schema(
            &json!({"type": "object", "properties": {"title": {"type": "string"}, "default": {"type": "string"}}}),
        );
        assert_eq!(out["required"], json!(["default", "title"]));
        assert!(out["properties"].get("title").is_some());
    }

    #[test]
    fn one_of_becomes_any_of_and_non_schemas_pass_through() {
        let out = sanitize_schema(
            &json!({"oneOf": [{"type": "string"}, {"type": "object", "properties": {}}]}),
        );
        assert_eq!(out["anyOf"][1]["additionalProperties"], json!(false));
        assert!(out.get("oneOf").is_none());
        assert_eq!(sanitize_schema(&json!(true)), json!(true));
    }
}
