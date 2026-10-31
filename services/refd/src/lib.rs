//! `refd` 库入口：装配配置、服务状态与 HTTP 路由，供二进制与集成测试共用。

pub mod config;
mod handlers;
mod jwks;
pub mod state;
mod time;

use std::sync::Arc;

use axum::Router;

pub use config::Config;
pub use state::AppState;

/// 构建完整的 `refd` 路由（含健康探针）。
pub fn router(state: Arc<AppState>) -> Router {
    handlers::router(state)
}
