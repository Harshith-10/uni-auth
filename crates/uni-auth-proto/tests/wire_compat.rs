use uni_auth_proto::*;
use serde_json::json;
use time::OffsetDateTime;

#[test]
fn test_user_wire_serialization_exact_camel_case() {
    let now = OffsetDateTime::now_utc();
    let user = UserWire {
        id: "usr_12345".to_string(),
        name: "Test User".to_string(),
        email: "user@example.com".to_string(),
        email_verified: false,
        image: Some("https://example.com/avatar.png".to_string()),
        created_at: now,
        updated_at: now,
        role: None,
        banned: None,
        ban_reason: None,
        ban_expires: None,
    };

    let val = serde_json::to_value(&user).unwrap();

    // Assert exact camelCase keys
    assert_eq!(val["id"], "usr_12345");
    assert_eq!(val["name"], "Test User");
    assert_eq!(val["email"], "user@example.com");
    assert_eq!(val["emailVerified"], false);
    assert_eq!(val["image"], "https://example.com/avatar.png");
    assert!(val.get("createdAt").is_some());
    assert!(val.get("updatedAt").is_some());

    // Assert snake_case fields do NOT appear
    assert!(val.get("email_verified").is_none());
    assert!(val.get("created_at").is_none());
    assert!(val.get("updated_at").is_none());
    assert!(val.get("password").is_none());
}

#[test]
fn test_user_wire_deserialization_from_fixture() {
    let fixture = json!({
        "id": "u_98765",
        "name": "Jane Doe",
        "email": "jane@example.com",
        "emailVerified": true,
        "image": null,
        "createdAt": "2026-01-15T12:00:00Z",
        "updatedAt": "2026-01-15T12:30:00Z"
    });

    let user: UserWire = serde_json::from_value(fixture).unwrap();
    assert_eq!(user.id, "u_98765");
    assert_eq!(user.name, "Jane Doe");
    assert_eq!(user.email, "jane@example.com");
    assert!(user.email_verified);
    assert_eq!(user.image, None);
    assert_eq!(user.role, None);
}

#[test]
fn test_session_wire_serialization_and_deserialization() {
    let fixture = json!({
        "id": "sess_abc",
        "userId": "usr_12345",
        "token": "tok_xyz789",
        "expiresAt": "2026-02-15T12:00:00Z",
        "ipAddress": "127.0.0.1",
        "userAgent": "Mozilla/5.0",
        "createdAt": "2026-01-15T12:00:00Z",
        "updatedAt": "2026-01-15T12:00:00Z"
    });

    let session: SessionWire = serde_json::from_value(fixture).unwrap();
    assert_eq!(session.id, "sess_abc");
    assert_eq!(session.user_id, "usr_12345");
    assert_eq!(session.token, "tok_xyz789");
    assert_eq!(session.ip_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));
    assert_eq!(session.impersonated_by, None);

    let serialized = serde_json::to_value(&session).unwrap();
    assert_eq!(serialized["userId"], "usr_12345");
    assert_eq!(serialized["expiresAt"], "2026-02-15T12:00:00Z");
    assert!(serialized.get("user_id").is_none());
    assert!(serialized.get("expires_at").is_none());
}

#[test]
fn test_admin_wire_models_and_requests() {
    let user_fixture = json!({
        "id": "usr_admin_1",
        "name": "System Admin",
        "email": "admin@example.com",
        "emailVerified": true,
        "role": "admin",
        "banned": false,
        "createdAt": "2026-01-15T12:00:00Z",
        "updatedAt": "2026-01-15T12:30:00Z"
    });
    let user: UserWire = serde_json::from_value(user_fixture).unwrap();
    assert_eq!(user.role.as_deref(), Some("admin"));
    assert_eq!(user.banned, Some(false));

    let set_role_single: AdminSetRoleRequest = serde_json::from_value(json!({
        "userId": "u_1",
        "role": "admin"
    }))
    .unwrap();
    assert_eq!(set_role_single.role.to_csv(), "admin");

    let set_role_multi: AdminSetRoleRequest = serde_json::from_value(json!({
        "userId": "u_1",
        "role": ["admin", "user"]
    }))
    .unwrap();
    assert_eq!(set_role_multi.role.to_csv(), "admin,user");
}

#[test]
fn test_sign_up_request_and_response_wire_format() {
    let req_json = json!({
        "name": "Alex Smith",
        "email": "alex@example.com",
        "password": "supersecretpass",
        "callbackURL": "http://localhost:3000/verify",
        "rememberMe": true
    });

    let req: SignUpEmailRequest = serde_json::from_value(req_json).unwrap();
    assert_eq!(req.name, "Alex Smith");
    assert_eq!(req.email, "alex@example.com");
    assert_eq!(req.password, "supersecretpass");
    assert_eq!(
        req.callback_url.as_deref(),
        Some("http://localhost:3000/verify")
    );
    assert_eq!(req.remember_me, Some(true));

    let res_json = json!({
        "token": "sess_token_123",
        "user": {
            "id": "usr_alex",
            "name": "Alex Smith",
            "email": "alex@example.com",
            "emailVerified": false,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z"
        }
    });

    let res: SignUpResponse = serde_json::from_value(res_json).unwrap();
    assert_eq!(res.token.as_deref(), Some("sess_token_123"));
    assert_eq!(res.user.id, "usr_alex");
}

#[test]
fn test_sign_in_request_and_response_wire_format() {
    let req_json = json!({
        "email": "alex@example.com",
        "password": "supersecretpass",
        "callbackURL": "/dashboard",
        "rememberMe": false
    });

    let req: SignInEmailRequest = serde_json::from_value(req_json).unwrap();
    assert_eq!(req.email, "alex@example.com");
    assert_eq!(req.callback_url.as_deref(), Some("/dashboard"));
    assert_eq!(req.remember_me, Some(false));

    let res_json = json!({
        "redirect": false,
        "token": "session_tok_456",
        "url": null,
        "user": {
            "id": "usr_alex",
            "name": "Alex Smith",
            "email": "alex@example.com",
            "emailVerified": true,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z"
        }
    });

    let res: SignInResponse = serde_json::from_value(res_json).unwrap();
    assert!(!res.redirect);
    assert_eq!(res.token, "session_tok_456");
    assert_eq!(res.url, None);
    assert_eq!(res.user.id, "usr_alex");
}

#[test]
fn test_get_session_response_shape() {
    let res_json = json!({
        "session": {
            "id": "sess_1",
            "userId": "usr_1",
            "token": "tok_1",
            "expiresAt": "2026-03-01T00:00:00Z",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z"
        },
        "user": {
            "id": "usr_1",
            "name": "User One",
            "email": "one@example.com",
            "emailVerified": true,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z"
        }
    });

    let session_and_user: SessionAndUserResponse = serde_json::from_value(res_json).unwrap();
    assert_eq!(session_and_user.session.token, "tok_1");
    assert_eq!(session_and_user.user.email, "one@example.com");

    // Also verify Option<SessionAndUserResponse> deserializes null
    let unauthenticated: Option<SessionAndUserResponse> = serde_json::from_str("null").unwrap();
    assert_eq!(unauthenticated, None);
}

#[test]
fn test_social_sign_in_request_and_response() {
    let req_json = json!({
        "provider": "github",
        "callbackURL": "http://localhost:5173/auth/callback",
        "newUserCallbackURL": "http://localhost:5173/welcome",
        "errorCallbackURL": "http://localhost:5173/error",
        "disableRedirect": true
    });

    let req: SignInSocialRequest = serde_json::from_value(req_json).unwrap();
    assert_eq!(req.provider, "github");
    assert_eq!(
        req.callback_url.as_deref(),
        Some("http://localhost:5173/auth/callback")
    );
    assert_eq!(
        req.new_user_callback_url.as_deref(),
        Some("http://localhost:5173/welcome")
    );
    assert_eq!(req.disable_redirect, Some(true));

    let res_json = json!({
        "redirect": false,
        "url": "https://github.com/login/oauth/authorize?client_id=123"
    });

    let res: SignInSocialResponse = serde_json::from_value(res_json).unwrap();
    assert!(!res.redirect);
    assert!(res.url.starts_with("https://github.com"));
}

#[test]
fn test_one_time_token_payloads() {
    let verify_req_json = json!({
        "token": "ott_random_32_characters_token"
    });
    let verify_req: OneTimeTokenVerifyRequest = serde_json::from_value(verify_req_json).unwrap();
    assert_eq!(verify_req.token, "ott_random_32_characters_token");

    let gen_res_json = json!({
        "token": "ott_freshly_generated_token"
    });
    let gen_res: OneTimeTokenGenerateResponse = serde_json::from_value(gen_res_json).unwrap();
    assert_eq!(gen_res.token, "ott_freshly_generated_token");
}

#[test]
fn test_auth_error_envelope() {
    let err_json = json!({
        "message": "Invalid email or password",
        "code": "INVALID_EMAIL_OR_PASSWORD",
        "status": 401
    });

    let err: AuthErrorResponse = serde_json::from_value(err_json).unwrap();
    assert_eq!(err.message, "Invalid email or password");
    assert_eq!(
        err.code.as_deref(),
        Some(error_codes::INVALID_EMAIL_OR_PASSWORD)
    );
    assert_eq!(err.status, Some(401));
}

#[test]
fn test_update_user_and_delete_user_wire_format() {
    // 1. Omitted image -> None
    let omitted_json = json!({ "name": "Alice" });
    let req1: UpdateUserRequest = serde_json::from_value(omitted_json).unwrap();
    assert_eq!(req1.name.as_deref(), Some("Alice"));
    assert_eq!(req1.image, None);

    // 2. Explicit null image -> Some(None)
    let null_json = json!({ "name": "Alice", "image": null });
    let req2: UpdateUserRequest = serde_json::from_value(null_json).unwrap();
    assert_eq!(req2.image, Some(None));

    // 3. String image -> Some(Some(url))
    let str_json = json!({ "image": "https://example.com/avatar.png" });
    let req3: UpdateUserRequest = serde_json::from_value(str_json).unwrap();
    assert_eq!(
        req3.image,
        Some(Some("https://example.com/avatar.png".to_string()))
    );

    // 4. Captures unknown field (like email)
    let extra_json = json!({ "email": "new@example.com" });
    let req4: UpdateUserRequest = serde_json::from_value(extra_json).unwrap();
    assert!(req4.extra.contains_key("email"));

    // 5. DeleteUserResponse
    let del_json = json!({ "success": true, "message": "User deleted" });
    let del_res: DeleteUserResponse = serde_json::from_value(del_json).unwrap();
    assert!(del_res.success);
    assert_eq!(del_res.message, "User deleted");
}
