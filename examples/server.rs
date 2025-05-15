use argon2::{
    password_hash::{SaltString, PasswordHasher},
    Argon2,
};
use axum::{
    error_handling::HandleErrorLayer,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};
use tower::{BoxError, ServiceBuilder};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 创建应用状态
    let app_state = AppState::new();

    // 创建路由
    let app = Router::new()
        .route("/users", get(get_users).post(create_user))
        .route("/users/{id}", get(get_user).put(update_user).delete(delete_user))
        .route("/health", get(health));

    // 添加中间件
    let app = app
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tokio::time::error::Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("未处理的内部错误: {error}"),
                        ))
                    }
                }))
                .timeout(Duration::from_secs(10))
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(app_state);

    // 启动服务器
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("监听端口 {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

// 用户模型
#[derive(Clone, Debug, Serialize, Deserialize)]
struct User {
    id: u64,
    email: String,
    #[serde(skip_serializing)]
    password: String,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// 创建用户请求
#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    email: String,
    password: String,
    name: String,
}

// 更新用户请求
#[derive(Debug, Deserialize)]
struct UpdateUserRequest {
    email: Option<String>,
    password: Option<String>,
    name: Option<String>,
}

// 应用状态
#[derive(Clone)]
struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    next_id: AtomicU64,
    users: DashMap<u64, User>,
    argon2: Argon2<'static>,
}

impl AppState {
    fn new() -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                next_id: AtomicU64::new(1),
                users: DashMap::new(),
                argon2: Argon2::default(),
            }),
        }
    }

    fn get_user(&self, id: u64) -> Option<User> {
        self.inner.users.get(&id).map(|user| user.clone())
    }

    fn create_user(&self, req: CreateUserRequest) -> Result<User, String> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self
            .inner
            .argon2
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|e| format!("密码哈希失败: {}", e))?
            .to_string();

        let id = self
            .inner
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let now = Utc::now();
        let user = User {
            id,
            email: req.email,
            password: password_hash,
            name: req.name,
            created_at: now,
            updated_at: now,
        };

        self.inner.users.insert(id, user.clone());
        Ok(user)
    }

    fn update_user(&self, id: u64, req: UpdateUserRequest) -> Result<Option<User>, String> {
        if let Some(mut user) = self.inner.users.get_mut(&id) {
            if let Some(email) = req.email {
                user.email = email;
            }

            if let Some(name) = req.name {
                user.name = name;
            }

            if let Some(password) = req.password {
                let salt = SaltString::generate(&mut OsRng);
                let password_hash = self
                    .inner
                    .argon2
                    .hash_password(password.as_bytes(), &salt)
                    .map_err(|e| format!("密码哈希失败: {}", e))?
                    .to_string();
                user.password = password_hash;
            }

            user.updated_at = Utc::now();
            let updated_user = user.clone();
            Ok(Some(updated_user))
        } else {
            Ok(None)
        }
    }

    fn delete_user(&self, id: u64) -> Option<User> {
        self.inner.users.remove(&id).map(|(_, user)| user)
    }

    fn health(&self) -> &'static str {
        "健康状态: 正常"
    }
}

// API 处理函数
async fn get_users(State(state): State<AppState>) -> impl IntoResponse {
    let users: Vec<User> = state.inner.users.iter().map(|entry| entry.clone()).collect();
    Json(users)
}

async fn get_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<User>, StatusCode> {
    state
        .get_user(id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    state
        .create_user(req)
        .map(|user| (StatusCode::CREATED, Json(user)))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}

async fn update_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    match state.update_user(id, req) {
        Ok(Some(user)) => Ok(Json(user)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "用户不存在".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

async fn delete_user(
    Path(id): Path<u64>,
    State(state): State<AppState>,
) -> Result<Json<User>, StatusCode> {
    state
        .delete_user(id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn health(State(state): State<AppState>) -> &'static str {
    state.health()
} 