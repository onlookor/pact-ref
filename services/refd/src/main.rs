//! `refd` 服务入口：加载配置、装配状态并监听 HTTP。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use pact_refd::config::AuthMode;
use pact_refd::{router, AppState, Config};

const CONFIG_ENV: &str = "REFD_CONFIG";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("refd: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let path = config_path()?;
    let config = Config::load(&path)?;
    if config.auth.mode == AuthMode::Static {
        eprintln!(
            "refd: WARNING auth.mode = static is for bootstrap or controlled networks only; \
             OIDC is not implemented in v1"
        );
    }
    let bind: SocketAddr = config.server.bind.parse().map_err(|_| {
        format!(
            "server.bind is not a socket address: {}",
            config.server.bind
        )
    })?;

    let state = Arc::new(AppState::from_config(config)?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("build runtime: {error}"))?;

    runtime.block_on(serve(state, bind))
}

fn config_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::args().nth(1) {
        return Ok(PathBuf::from(path));
    }
    match std::env::var(CONFIG_ENV) {
        Ok(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => Err(format!(
            "usage: pact-refd <refd.toml> (or set {CONFIG_ENV})"
        )),
    }
}

async fn serve(state: Arc<AppState>, bind: SocketAddr) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind {bind}: {error}"))?;
    println!("refd listening on http://{bind}");
    axum::serve(listener, router(state))
        .await
        .map_err(|error| format!("serve: {error}"))
}
