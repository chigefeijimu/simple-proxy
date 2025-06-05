pub use crate::server::{AppState, CreateUserRequest, UpdateUserRequest, User};
use pingora::prelude::*;
use async_trait::async_trait;
use tracing::info;

mod server {
    include!("../examples/server.rs");
} 

pub struct SimpleProxy {}

#[async_trait]
impl ProxyHttp for SimpleProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {
        ()
    }

    async fn upstream_peer(&self, _session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let peer = HttpPeer::new("127.0.0.1:3000".to_string(), false, "127.0.0.1".to_string());
        info!("upstream_peer: {}", peer.to_string());
        Ok(Box::new(peer))
    }
}