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
use tracing::info;
use std::{
    net::SocketAddr, sync::{atomic::AtomicU64, Arc}, time::Duration
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
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap();
    info!("Server running on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

// 用户模型
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: u64,
    pub email: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// 创建用户请求
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub name: String,
}

// 更新用户请求
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub name: Option<String>,
}

// 应用状态
#[derive(Clone)]
pub struct AppState {
    pub(crate) inner: Arc<AppStateInner>,
}

pub(crate) struct AppStateInner {
    pub(crate) next_id: AtomicU64,
    pub(crate) users: DashMap<u64, User>,
    pub(crate) argon2: Argon2<'static>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                next_id: AtomicU64::new(1),
                users: DashMap::new(),
                argon2: Argon2::default(),
            }),
        }
    }

    pub fn get_users(&self) -> Vec<User> {
        self.inner.users.iter().map(|entry| entry.clone()).collect()
    }

    pub fn get_user(&self, id: u64) -> Option<User> {
        self.inner.users.get(&id).map(|user| user.clone())
    }

    pub fn create_user(&self, req: CreateUserRequest) -> Result<User, anyhow::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self
            .inner
            .argon2
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|_| anyhow::anyhow!("Failed to hash password"))?
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

    pub fn update_user(&self, id: u64, req: UpdateUserRequest) -> Result<Option<User>, String> {
        if let Some(mut entry) = self.inner.users.get_mut(&id) {
            println!("找到用户 ID: {}", id);
            let mut user = entry.value().clone();

            // 更新字段
            if let Some(email) = req.email {
                println!("更新邮箱为: {}", email);
                user.email = email;
            }

            if let Some(name) = req.name {
                println!("更新名称为: {}", name);
                user.name = name;
            }

            if let Some(password) = req.password {
                println!("开始更新密码");
                match hash_password(&self.inner.argon2, &password) {
                    Ok(hashed) => {
                        user.password = hashed;
                        println!("密码更新完成");
                    }
                    Err(e) => {
                        println!("密码更新失败: {}", e);
                        return Err(format!("密码更新失败: {}", e));
                    }
                }
            }

            user.updated_at = Utc::now();
            println!("更新时间戳");
            
            // 更新存储
            println!("保存更新后的用户信息");
            *entry.value_mut() = user.clone();
            Ok(Some(user))
        } else {
            println!("未找到用户 ID: {}", id);
            Ok(None)
        }
    }

    pub fn delete_user(&self, id: u64) -> Option<User> {
        self.inner.users.remove(&id).map(|(_, user)| user)
    }

    pub fn health(&self) -> &'static str {
        "健康状态: 正常"
    }
}

// API 处理函数
async fn get_users(State(state): State<AppState>) -> impl IntoResponse {
    let users: Vec<User> = state.inner.users.iter().map(|entry| entry.clone()).collect();
    Json(users)
}

fn hash_password(argon2: &Argon2<'static>, password: &str) -> Result<String, anyhow::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("Failed to hash password"))?
        .to_string();
    Ok(password_hash)
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> AppState {
        AppState::new()
    }

    fn create_test_user(state: &AppState, email: &str, name: &str) -> User {
        let req = CreateUserRequest {
            email: email.to_string(),
            password: "password123".to_string(),
            name: name.to_string(),
        };
        state.create_user(req).unwrap()
    }

    #[test]
    fn test_get_users() {
        let state = setup();
        
        // 创建多个测试用户
        let user1 = create_test_user(&state, "user1@example.com", "User One");
        let user2 = create_test_user(&state, "user2@example.com", "User Two");
        let user3 = create_test_user(&state, "user3@example.com", "User Three");

        // 获取所有用户
        let users: Vec<User> = state.inner.users.iter().map(|entry| entry.clone()).collect();
        
        // 验证用户数量
        assert_eq!(users.len(), 3);

        // 验证用户信息
        assert!(users.iter().any(|u| u.id == user1.id && u.email == user1.email && u.name == user1.name));
        assert!(users.iter().any(|u| u.id == user2.id && u.email == user2.email && u.name == user2.name));
        assert!(users.iter().any(|u| u.id == user3.id && u.email == user3.email && u.name == user3.name));
    }

    #[test]
    fn test_create_user() {
        let state = setup();
        let req = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            name: "Test User".to_string(),
        };

        let result = state.create_user(req).unwrap();
        assert_eq!(result.email, "test@example.com");
        assert_eq!(result.name, "Test User");
        assert_eq!(result.id, 1);
    }

    #[test]
    fn test_get_user() {
        let state = setup();
        let req = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            name: "Test User".to_string(),
        };

        let created_user = state.create_user(req).unwrap();
        let retrieved_user = state.get_user(created_user.id).unwrap();

        assert_eq!(retrieved_user.id, created_user.id);
        assert_eq!(retrieved_user.email, created_user.email);
        assert_eq!(retrieved_user.name, created_user.name);
    }

    #[test]
    fn test_update_user() {
        let state = setup();
        let req = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            name: "Test User".to_string(),
        };

        let created_user = state.create_user(req).unwrap();
        
        let update_req = UpdateUserRequest {
            email: Some("updated@example.com".to_string()),
            password: None,
            name: Some("Updated Name".to_string()),
        };

        let updated_user = state.update_user(created_user.id, update_req).unwrap().unwrap();
        
        assert_eq!(updated_user.email, "updated@example.com");
        assert_eq!(updated_user.name, "Updated Name");
        assert_eq!(updated_user.id, created_user.id);
    }

    #[test]
    fn test_delete_user() {
        let state = setup();
        let req = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            name: "Test User".to_string(),
        };

        let created_user = state.create_user(req).unwrap();
        let deleted_user = state.delete_user(created_user.id).unwrap();
        
        assert_eq!(deleted_user.id, created_user.id);
        assert!(state.get_user(created_user.id).is_none());
    }

    #[test]
    fn test_get_nonexistent_user() {
        let state = setup();
        assert!(state.get_user(999).is_none());
    }

    #[test]
    fn test_update_nonexistent_user() {
        let state = setup();
        let update_req = UpdateUserRequest {
            email: Some("updated@example.com".to_string()),
            password: None,
            name: Some("Updated Name".to_string()),
        };

        let result = state.update_user(999, update_req).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_delete_nonexistent_user() {
        let state = setup();
        assert!(state.delete_user(999).is_none());
    }

    #[test]
    fn test_health_check() {
        let state = setup();
        assert_eq!(state.health(), "健康状态: 正常");
    }
} 