use simple_proxy::{AppState, CreateUserRequest, UpdateUserRequest, User};
use tokio;

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> AppState {
        AppState::new()
    }

    async fn create_test_user(state: &AppState, email: &str, name: &str) -> User {
        let req = CreateUserRequest {
            email: email.to_string(),
            password: "password123".to_string(),
            name: name.to_string(),
        };
        state.create_user(req).unwrap()
    }

    #[tokio::test]
    async fn test_get_users() {
        let state = setup();
        
        // 创建多个测试用户
        let user1 = create_test_user(&state, "user1@example.com", "User One").await;
        let user2 = create_test_user(&state, "user2@example.com", "User Two").await;
        let user3 = create_test_user(&state, "user3@example.com", "User Three").await;

        // 获取所有用户
        let users = state.get_users();
        
        // 验证用户数量
        assert_eq!(users.len(), 3);

        // 验证用户信息
        assert!(users.iter().any(|u| u.id == user1.id && u.email == user1.email && u.name == user1.name));
        assert!(users.iter().any(|u| u.id == user2.id && u.email == user2.email && u.name == user2.name));
        assert!(users.iter().any(|u| u.id == user3.id && u.email == user3.email && u.name == user3.name));
    }

    #[tokio::test]
    async fn test_create_user() {
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

    #[tokio::test]
    async fn test_get_user() {
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

    #[tokio::test]
    async fn test_update_user() {
        let state = setup();
        let req = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            name: "Test User".to_string(),
        };

        let created_user = state.create_user(req).unwrap();
        
        let update_req = UpdateUserRequest {
            email: Some("updated@example.com".to_string()),
            password: Some("password321".to_string()),
            name: Some("Updated Name".to_string()),
        };

        let updated_user = state.update_user(created_user.id, update_req).unwrap().unwrap();
        
        // 验证更新后的用户信息
        assert_eq!(updated_user.email, "updated@example.com");
        assert_eq!(updated_user.name, "Updated Name");
        assert_eq!(updated_user.id, created_user.id);
        
        // 验证是否能获取到更新后的用户
        let retrieved_user = state.get_user(created_user.id).unwrap();
        assert_eq!(retrieved_user.email, "updated@example.com");
        assert_eq!(retrieved_user.name, "Updated Name");
        assert_eq!(retrieved_user.id, created_user.id);
    }

    #[tokio::test]
    async fn test_delete_user() {
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

    #[tokio::test]
    async fn test_get_nonexistent_user() {
        let state = setup();
        assert!(state.get_user(999).is_none());
    }

    #[tokio::test]
    async fn test_update_nonexistent_user() {
        let state = setup();
        let update_req = UpdateUserRequest {
            email: Some("updated@example.com".to_string()),
            password: None,
            name: Some("Updated Name".to_string()),
        };

        let result = state.update_user(999, update_req).unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_user() {
        let state = setup();
        assert!(state.delete_user(999).is_none());
    }
} 