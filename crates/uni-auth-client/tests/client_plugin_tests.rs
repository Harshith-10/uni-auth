//! Integration tests for transport, AuthClientPlugin interceptors,
//! $sessionSignal reactivity, and AdminClientExt / OneTimeTokenClientExt extension traits.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use time::Duration;
use tokio::net::TcpListener;

use uni_auth_axum::{AuthState, auth_router};
use uni_auth_client::plugin::{AuthClientPlugin, ClientSignalListener, SESSION_SIGNAL};
use uni_auth_client::transport::{ClientRequestContext, ClientResponseContext};
use uni_auth_client::{
    AdminClientExt, AuthClient, ClientError, MockTokenStorage, OneTimeTokenClientExt,
    TokenStorage,
};
use uni_auth_core::models::AdminUpdateUserFields;
use uni_auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};
use uni_auth_proto::{AdminCreateUserRequest, RoleValue};
use axum::Router;

async fn start_test_server() -> (String, Arc<AuthService>) {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let config = AuthConfig {
        secret: b"auth-client-stage6-secret-32b-key".to_vec(),
        base_url: "http://127.0.0.1:0/api/auth".to_string(),
        session_expires_in: Duration::days(7),
        ott_expires_in: Duration::minutes(3),
        reset_password_expires_in: Duration::hours(1),
        verify_email_expires_in: Duration::hours(24),
        auto_sign_in: true,
        require_email_verification: false,
        min_password_length: 8,
        max_password_length: 128,
        delete_user_enabled: true,
        defer_session_refresh: false,
    };

    let service = Arc::new(AuthService::new(config, adapter));
    let state = AuthState::new(Arc::clone(&service));
    let app = Router::new().nest("/api/auth", auth_router(state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/api/auth");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base_url, service)
}

struct TestLoggingPlugin {
    pub request_count: AtomicUsize,
    pub response_count: AtomicUsize,
    pub last_request_path: std::sync::RwLock<Option<String>>,
}

impl Default for TestLoggingPlugin {
    fn default() -> Self {
        Self {
            request_count: AtomicUsize::new(0),
            response_count: AtomicUsize::new(0),
            last_request_path: std::sync::RwLock::new(None),
        }
    }
}

impl AuthClientPlugin for TestLoggingPlugin {
    fn id(&self) -> &'static str {
        "test-logging"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn on_request(&self, ctx: &mut ClientRequestContext) -> Result<(), ClientError> {
        self.request_count.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut lock) = self.last_request_path.write() {
            *lock = Some(ctx.path.clone());
        }
        Ok(())
    }

    fn on_response(&self, _ctx: &ClientResponseContext) -> Result<(), ClientError> {
        self.response_count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn signal_listeners(&self) -> Vec<ClientSignalListener> {
        Vec::new()
    }
}

#[tokio::test]
async fn test_client_plugin_interceptors() {
    let (base_url, _) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let logging_plugin = Arc::new(TestLoggingPlugin::default());

    let client = AuthClient::new(base_url, storage as Arc<dyn TokenStorage>)
        .with_plugin_arc(logging_plugin.clone());

    // 1. Send request
    let _ = client
        .sign_up_email(
            "Plugin User",
            "plugin@example.com",
            "mypassword123",
            Some(true),
        )
        .await
        .unwrap();

    // 2. Verify on_request and on_response were executed
    assert_eq!(logging_plugin.request_count.load(Ordering::SeqCst), 1);
    assert_eq!(logging_plugin.response_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        logging_plugin.last_request_path.read().unwrap().as_deref(),
        Some("/sign-up/email")
    );
}

#[tokio::test]
async fn test_reactive_session_signal_listener() {
    let (base_url, _) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = AuthClient::new(base_url, storage as Arc<dyn TokenStorage>);

    let signal_received = Arc::new(AtomicBool::new(false));
    let flag_clone = signal_received.clone();

    client.subscribe_signal(move |sig| {
        if sig == SESSION_SIGNAL {
            flag_clone.store(true, Ordering::SeqCst);
        }
    });

    assert!(!signal_received.load(Ordering::SeqCst));

    // Sign up fires $sessionSignal automatically
    client
        .sign_up_email(
            "Signal User",
            "signal@example.com",
            "mypassword123",
            Some(true),
        )
        .await
        .unwrap();

    assert!(signal_received.load(Ordering::SeqCst));
}

#[tokio::test]
async fn test_admin_client_ext_facade_and_local_rbac() {
    let (base_url, service) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = AuthClient::new(base_url, storage as Arc<dyn TokenStorage>);

    // 1. Local client-side RBAC evaluation (zero network roundtrip)
    let mut admin_check = HashMap::new();
    admin_check.insert(
        "user".to_string(),
        vec!["ban".to_string(), "delete".to_string()],
    );
    assert!(client.admin().check_role_permission("admin", &admin_check));
    assert!(!client.admin().check_role_permission("user", &admin_check));

    // 2. Sign up admin user
    let admin_res = client
        .sign_up_email(
            "Root Admin",
            "root_admin@example.com",
            "rootpass123",
            Some(true),
        )
        .await
        .unwrap();

    service
        .adapter()
        .update_user_admin(
            &admin_res.user.id,
            AdminUpdateUserFields {
                role: Some("admin".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // 3. Extension trait: client.admin().create_user(...)
    let created = client
        .admin()
        .create_user(AdminCreateUserRequest {
            email: "sub_user@example.com".to_string(),
            password: Some("subpass123".to_string()),
            name: "Sub User".to_string(),
            role: Some(RoleValue::Single("user".to_string())),
            data: None,
        })
        .await
        .unwrap();
    assert_eq!(created.user.email, "sub_user@example.com");

    // 4. Extension trait: client.admin().impersonate_user and stop_impersonating
    let imp = client
        .admin()
        .impersonate_user(&created.user.id)
        .await
        .unwrap();
    assert_eq!(imp.user.email, "sub_user@example.com");
    assert_eq!(
        imp.session.impersonated_by.as_deref(),
        Some(admin_res.user.id.as_str())
    );

    let restored = client.admin().stop_impersonating().await.unwrap();
    assert_eq!(restored.user.email, "root_admin@example.com");
}

#[tokio::test]
async fn test_one_time_token_client_ext_facade() {
    let (base_url, _) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = AuthClient::new(base_url, storage as Arc<dyn TokenStorage>);

    client
        .sign_up_email(
            "OTT Client",
            "ott_client@example.com",
            "pass12345",
            Some(true),
        )
        .await
        .unwrap();

    // Extension trait: client.one_time_token().generate()
    let ott_res = client.one_time_token().generate().await.unwrap();
    assert!(!ott_res.token.is_empty());

    // Extension trait: client.one_time_token().verify()
    let verify_res = client
        .one_time_token()
        .verify(&ott_res.token)
        .await
        .unwrap();
    assert_eq!(verify_res.user.email, "ott_client@example.com");
}

#[tokio::test]
async fn test_client_with_plugin_deduplication() {
    struct TestClientPlugin {
        id: &'static str,
        tag: usize,
    }
    impl AuthClientPlugin for TestClientPlugin {
        fn id(&self) -> &'static str {
            self.id
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    let storage = Arc::new(MockTokenStorage::new());
    let client = AuthClient::new(
        "http://localhost:3000".to_string(),
        storage as Arc<dyn TokenStorage>,
    )
    .with_plugin(TestClientPlugin {
        id: "custom",
        tag: 1,
    })
    .with_plugin(TestClientPlugin {
        id: "custom",
        tag: 2,
    });

    let plugins = client.plugins();
    let matching: Vec<_> = plugins.iter().filter(|p| p.id() == "custom").collect();
    assert_eq!(matching.len(), 1);
    let p = matching[0]
        .as_any()
        .downcast_ref::<TestClientPlugin>()
        .unwrap();
    assert_eq!(p.tag, 2);
}

#[tokio::test]
async fn test_auth_store_automatic_reaction_to_impersonation_and_ott() {
    use uni_auth_client::store::{AuthStatus, AuthStore};

    let (base_url, service) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = Arc::new(AuthClient::new(
        base_url,
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));

    let store = AuthStore::new(Arc::clone(&client));

    // Admin signs up
    let admin_res = client
        .sign_up_email(
            "Admin User",
            "admin_store@example.com",
            "adminpass123",
            Some(true),
        )
        .await
        .unwrap();

    // Promote to admin role
    service
        .adapter()
        .update_user_admin(
            &admin_res.user.id,
            AdminUpdateUserFields {
                role: Some("admin".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Create target user
    let target_res = client
        .admin()
        .create_user(AdminCreateUserRequest {
            name: "Target User".to_string(),
            email: "target_store@example.com".to_string(),
            password: Some("targetpass123".to_string()),
            role: Some(RoleValue::Single("user".to_string())),
            data: Some(serde_json::Map::new()),
        })
        .await
        .unwrap();

    // Impersonate target user via client.admin() DIRECTLY (no store method called)
    let _imp = client
        .admin()
        .impersonate_user(&target_res.user.id)
        .await
        .unwrap();

    // AuthStore should automatically reflect the impersonated session via SessionSignalEvent!
    assert!(store.is_authenticated());
    if let AuthStatus::Authenticated { user, session } = store.status() {
        assert_eq!(user.email, "target_store@example.com");
        assert_eq!(
            session.impersonated_by.as_deref(),
            Some(admin_res.user.id.as_str())
        );
    } else {
        panic!("Store should be authenticated with impersonated session");
    }

    // Stop impersonating via client.admin() DIRECTLY
    client.admin().stop_impersonating().await.unwrap();

    // AuthStore should automatically restore root admin session!
    if let AuthStatus::Authenticated { user, session } = store.status() {
        assert_eq!(user.email, "admin_store@example.com");
        assert!(session.impersonated_by.is_none());
    } else {
        panic!("Store should be authenticated with admin session");
    }
}
