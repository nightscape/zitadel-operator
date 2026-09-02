use crate::schema::{ActionHandlerSpec, ConditionKind};
use serde_json::Value;

use super::jq::Program;

pub struct Evaluation {
    /// The envelope Zitadel should use. Equal to the input whenever the handler
    /// does not apply or a jq program failed.
    pub payload: Value,
    /// Whether `when` matched. A handler that does not apply has no side effect.
    pub applies: bool,
    /// Set when a jq program failed to compile or run.
    pub error: Option<String>,
}

/// Runs `when` and `transform` over the payload Zitadel sent.
///
/// This sits in the login path, so no failure here may change what Zitadel does:
/// a program that will not compile, throws, or produces nothing leaves the
/// payload alone and reports the reason for the caller to log.
pub fn evaluate(spec: &ActionHandlerSpec, payload: &Value) -> Evaluation {
    let unchanged = |error: String| Evaluation {
        payload: payload.clone(),
        applies: false,
        error: Some(error),
    };

    if let Some(when) = &spec.when {
        let program = match Program::compile(when) {
            Ok(program) => program,
            Err(e) => return unchanged(format!("when: {e}")),
        };
        match program.test(payload) {
            Ok(true) => {}
            Ok(false) => {
                return Evaluation {
                    payload: payload.clone(),
                    applies: false,
                    error: None,
                }
            }
            Err(e) => return unchanged(format!("when: {e}")),
        }
    }

    let Some(transform) = &spec.transform else {
        return Evaluation {
            payload: payload.clone(),
            applies: true,
            error: None,
        };
    };

    let program = match Program::compile(transform) {
        Ok(program) => program,
        Err(e) => return unchanged(format!("transform: {e}")),
    };
    match program.run(payload) {
        Ok(transformed) => Evaluation {
            payload: transformed,
            applies: true,
            error: None,
        },
        // The handler still applies: a transform that failed must not also
        // cancel the grant the same resource asked for.
        Err(e) => Evaluation {
            payload: payload.clone(),
            applies: true,
            error: Some(format!("transform: {e}")),
        },
    }
}

/// What to answer Zitadel with, or `None` for an empty body.
///
/// Zitadel only reads a response body it actually got (`if len(resp) > 0`), so
/// an empty body is the exact way to say "use what you had". A request execution
/// unmarshals the body into the request and a response execution into the
/// response, so an answer carries that member alone, never the envelope.
pub fn answer(kind: ConditionKind, original: &Value, evaluated: &Value) -> Option<Value> {
    if original == evaluated {
        return None;
    }
    match kind {
        ConditionKind::Request => evaluated.get("request").cloned(),
        ConditionKind::Response => evaluated.get("response").cloned(),
        ConditionKind::Function => Some(evaluated.clone()),
        ConditionKind::Event => None,
    }
}

/// Resolves the user the `grantRoles` effect applies to.
pub fn user_id(expression: &str, payload: &Value) -> Result<String, String> {
    let program = Program::compile(expression).map_err(|e| e.to_string())?;
    match program.run(payload).map_err(|e| e.to_string())? {
        Value::String(id) if !id.is_empty() => Ok(id),
        other => Err(format!("userIdFrom yielded {other} instead of a user id")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ActionCondition, EventCondition, GrantRoles, MethodCondition};
    use serde_json::json;

    const FILL_USERNAME: &str = r#"
        if (.request.idpLinks[0].userName // "") == "" then
          .request.idpLinks[0].userName = .request.idpLinks[0].userId
        else . end
    "#;

    fn spec(when: Option<&str>, transform: Option<&str>) -> ActionHandlerSpec {
        ActionHandlerSpec {
            condition: ActionCondition {
                request: Some(MethodCondition {
                    method: "/zitadel.user.v2.UserService/AddHumanUser".to_string(),
                }),
                ..Default::default()
            },
            when: when.map(String::from),
            transform: transform.map(String::from),
            grant_roles: None,
        }
    }

    fn payload(links: Value) -> Value {
        json!({
            "fullMethod": "/zitadel.user.v2.UserService/AddHumanUser",
            "instanceID": "344648897353744526",
            "orgID": "344648897353810062",
            "request": { "username": "user@example.com", "idpLinks": links },
        })
    }

    #[test]
    fn fills_an_empty_idp_link_username() {
        let payload = payload(json!([{ "idpId": "388841422012287118", "userId": "abc123", "userName": "" }]));
        let result = evaluate(&spec(None, Some(FILL_USERNAME)), &payload);

        assert_eq!(result.error, None);
        assert!(result.applies);
        assert_eq!(
            result.payload["request"]["idpLinks"][0]["userName"],
            json!("abc123")
        );
    }

    #[test]
    fn fills_a_missing_idp_link_username() {
        let payload = payload(json!([{ "idpId": "388841422012287118", "userId": "abc123" }]));
        let result = evaluate(&spec(None, Some(FILL_USERNAME)), &payload);

        assert_eq!(result.error, None);
        assert_eq!(
            result.payload["request"]["idpLinks"][0]["userName"],
            json!("abc123")
        );
    }

    #[test]
    fn leaves_a_set_username_alone() {
        let payload = payload(json!([{ "idpId": "1", "userId": "abc123", "userName": "already-set" }]));
        let result = evaluate(&spec(None, Some(FILL_USERNAME)), &payload);

        assert_eq!(result.error, None);
        assert_eq!(result.payload, payload);
    }

    #[test]
    fn missing_idp_links_leave_the_payload_alone() {
        let mut payload = payload(json!([]));
        payload["request"].as_object_mut().unwrap().remove("idpLinks");
        let result = evaluate(&spec(None, Some(FILL_USERNAME)), &payload);

        // Indexing null yields null in jq, and assigning through it fails.
        assert!(result.error.is_some(), "expected a reported failure");
        assert_eq!(result.payload, payload);
        assert!(result.applies);
    }

    #[test]
    fn an_empty_idp_links_array_leaves_the_payload_alone() {
        let payload = payload(json!([]));
        let result = evaluate(&spec(None, Some(FILL_USERNAME)), &payload);

        assert_eq!(result.payload["request"]["idpLinks"], json!([]));
    }

    #[test]
    fn a_throwing_transform_returns_the_input() {
        let payload = payload(json!([{ "userId": "abc123" }]));
        let result = evaluate(&spec(None, Some(r#"error("boom")"#)), &payload);

        assert!(result.error.is_some(), "expected a reported failure");
        assert_eq!(result.payload, payload);
    }

    #[test]
    fn an_uncompilable_transform_returns_the_input() {
        let payload = payload(json!([{ "userId": "abc123" }]));
        let result = evaluate(&spec(None, Some("this is not | jq (")), &payload);

        assert!(matches!(result.error, Some(ref e) if e.contains("does not compile")));
        assert_eq!(result.payload, payload);
        assert!(!result.applies, "a handler that cannot compile must not take effect");
    }

    #[test]
    fn an_empty_transform_returns_the_input() {
        let payload = payload(json!([{ "userId": "abc123" }]));
        let result = evaluate(&spec(None, Some("empty")), &payload);

        assert_eq!(result.error, Some("transform: jq program produced no output".to_string()));
        assert_eq!(result.payload, payload);
    }

    #[test]
    fn a_matching_when_lets_the_transform_run() {
        let payload = payload(json!([{ "idpId": "388841422012287118", "userId": "abc123" }]));
        let when = r#".request.idpLinks[0].idpId == "388841422012287118""#;
        let result = evaluate(&spec(Some(when), Some(FILL_USERNAME)), &payload);

        assert!(result.applies);
        assert_eq!(result.payload["request"]["idpLinks"][0]["userName"], json!("abc123"));
    }

    #[test]
    fn a_non_matching_when_skips_the_transform() {
        let payload = payload(json!([{ "idpId": "999", "userId": "abc123" }]));
        let when = r#".request.idpLinks[0].idpId == "388841422012287118""#;
        let result = evaluate(&spec(Some(when), Some(FILL_USERNAME)), &payload);

        assert!(!result.applies);
        assert_eq!(result.error, None);
        assert_eq!(result.payload, payload);
    }

    #[test]
    fn a_failing_when_skips_the_transform() {
        let payload = payload(json!([{ "userId": "abc123" }]));
        let result = evaluate(&spec(Some(r#"error("boom")"#), Some(FILL_USERNAME)), &payload);

        assert!(!result.applies);
        assert!(result.error.is_some());
        assert_eq!(result.payload, payload);
    }

    #[test]
    fn a_null_when_does_not_match() {
        let payload = payload(json!([{ "userId": "abc123" }]));
        let result = evaluate(&spec(Some(".request.missing"), Some(FILL_USERNAME)), &payload);

        assert!(!result.applies);
        assert_eq!(result.error, None);
    }

    #[test]
    fn a_handler_without_a_transform_applies_unchanged() {
        let payload = payload(json!([{ "userId": "abc123" }]));
        let result = evaluate(&spec(None, None), &payload);

        assert!(result.applies);
        assert_eq!(result.payload, payload);
    }

    #[test]
    fn the_answer_carries_only_the_manipulated_member() {
        let original = payload(json!([{ "userId": "abc123" }]));
        let evaluated = evaluate(&spec(None, Some(FILL_USERNAME)), &original).payload;

        assert_eq!(
            answer(ConditionKind::Request, &original, &evaluated),
            Some(evaluated["request"].clone())
        );
        assert_eq!(answer(ConditionKind::Event, &original, &evaluated), None);
        assert_eq!(
            answer(ConditionKind::Function, &original, &evaluated),
            Some(evaluated.clone())
        );
    }

    #[test]
    fn an_untouched_payload_is_answered_with_no_body() {
        let original = payload(json!([{ "userId": "abc", "userName": "set" }]));
        let evaluated = evaluate(&spec(None, Some(FILL_USERNAME)), &original).payload;

        assert_eq!(answer(ConditionKind::Request, &original, &evaluated), None);
    }

    #[test]
    fn a_response_execution_answers_with_the_response() {
        let original = json!({ "request": { "a": 1 }, "response": { "userId": "u1" } });
        let evaluated = json!({ "request": { "a": 1 }, "response": { "userId": "u2" } });
        assert_eq!(
            answer(ConditionKind::Response, &original, &evaluated),
            Some(json!({ "userId": "u2" }))
        );
    }

    #[test]
    fn grant_roles_is_rejected_on_a_request_condition() {
        let mut spec = spec(None, None);
        spec.grant_roles = Some(GrantRoles {
            project_name: "ggk".to_string(),
            project_namespace: None,
            role_keys: vec!["user".to_string()],
            user_id_from: ".response.userId".to_string(),
        });

        let rejected = spec.validate().expect_err("a request condition has no user to grant to");
        assert!(rejected.contains("grantRoles"), "unhelpful message: {rejected}");

        // The same effect on a response condition is exactly what it is for.
        spec.condition = ActionCondition {
            response: Some(MethodCondition {
                method: "/zitadel.user.v2.UserService/AddHumanUser".to_string(),
            }),
            ..Default::default()
        };
        assert_eq!(spec.validate(), Ok(ConditionKind::Response));

        spec.condition = ActionCondition {
            event: Some(EventCondition { event: "user.human.added".to_string() }),
            ..Default::default()
        };
        assert_eq!(spec.validate(), Ok(ConditionKind::Event));
    }

    #[test]
    fn a_condition_must_name_exactly_one_trigger() {
        let mut spec = spec(None, None);
        spec.condition.response = Some(MethodCondition { method: "/x".to_string() });
        assert!(spec.validate().is_err(), "two triggers must not be accepted");

        spec.condition = ActionCondition::default();
        assert!(spec.validate().is_err(), "no trigger must not be accepted");
    }

    #[test]
    fn the_grant_user_comes_from_the_payload() {
        let payload = json!({ "response": { "userId": "u1" } });
        assert_eq!(user_id(".response.userId", &payload), Ok("u1".to_string()));
        assert!(user_id(".response.missing", &payload).is_err());
        assert!(user_id(".response", &payload).is_err());
        assert!(user_id("(", &payload).is_err());
    }
}
