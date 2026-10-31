//! HTTP 路由与 handler：传输约束、认证、scope/ACL、adapter 调用与审计闭环。

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use http_body_util::{BodyExt, Limited};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use pact_ref_auth::Identity;
use pact_ref_core::{
    AuditEvent, ReferenceError, ReferenceForm, Resolution, ResolveIntent, ResolveRequest,
};
use pact_ref_resolver::ResolverRegistry;

use crate::config::validate_selector;
use crate::state::AppState;
use crate::time::{new_trace_id, now_plus, rfc3339};

/// 请求体上限 64 KiB。
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// 单请求上限 30s。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// `handle` 默认有效期 300s。
const HANDLE_TTL_SECONDS: u64 = 300;

/// 构建路由。业务端点只接受 POST；其余方法返回统一错误信封。
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/resolve", any(resolve))
        .route("/v1/describe", any(describe))
        .with_state(state)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn readyz(State(state): State<Arc<AppState>>) -> StatusCode {
    if state.audit.available() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn resolve(State(state): State<Arc<AppState>>, request: Request) -> Response {
    business(state, request, Operation::Resolve).await
}

async fn describe(State(state): State<Arc<AppState>>, request: Request) -> Response {
    business(state, request, Operation::Describe).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Resolve,
    Describe,
}

impl Operation {
    fn scope(self) -> &'static str {
        match self {
            Self::Resolve => pact_ref_auth::SCOPE_RESOLVE,
            Self::Describe => pact_ref_auth::SCOPE_DESCRIBE,
        }
    }

    fn audit_operation(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Describe => "describe",
        }
    }
}

/// 认证 → scope → 传输 → 业务 → 审计。审计失败默认覆盖为 `500 AuditUnavailable`。
async fn business(state: Arc<AppState>, request: Request, operation: Operation) -> Response {
    let (parts, body) = request.into_parts();
    let trace_id = match trace_header(&parts.headers) {
        TraceHeader::Valid(value) => value,
        TraceHeader::Absent => new_trace_id(),
        TraceHeader::Invalid => {
            let generated = new_trace_id();
            return error_response(
                StatusCode::BAD_REQUEST,
                Code::INVALID_REQUEST,
                "X-Trace-Id must match [A-Za-z0-9._:-]{1,128}",
                &generated,
                false,
                None,
            );
        }
    };

    if parts.method != Method::POST {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            Code::METHOD_NOT_ALLOWED,
            "only POST is allowed",
            &trace_id,
            false,
            None,
        );
    }

    let identity = match state
        .authenticator
        .authenticate(authorization(&parts.headers))
    {
        Ok(identity) => identity,
        Err(_) => return unauthorized(&trace_id),
    };

    let mut context = AuditContext::new(
        trace_id.clone(),
        identity.subject.clone(),
        operation.audit_operation(),
    );

    let outcome = run_business(
        &state,
        &identity,
        &parts.headers,
        body,
        operation,
        &mut context,
    )
    .await;

    let (response, status) = match outcome {
        Ok(response) => (response, "ok"),
        Err(error) => {
            let status = error.code;
            (error.into_response(&trace_id), status)
        }
    };

    match state.audit.record(&context.event(status)) {
        Ok(()) => response,
        Err(error) => {
            if state.audit_fail_open {
                eprintln!("refd: audit sink failure (fail_open = true): {error}");
                response
            } else {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Code::AUDIT_UNAVAILABLE,
                    "audit sink unavailable",
                    &trace_id,
                    true,
                    None,
                )
            }
        }
    }
}

async fn run_business(
    state: &AppState,
    identity: &Identity,
    headers: &HeaderMap,
    body: Body,
    operation: Operation,
    context: &mut AuditContext,
) -> Result<Response, ApiError> {
    if !identity.has_scope(operation.scope()) {
        return Err(ApiError::forbidden("missing endpoint scope"));
    }
    ensure_json(headers)?;
    let bytes = read_body(body).await?;

    match operation {
        Operation::Resolve => handle_resolve(state, identity, &bytes, context).await,
        Operation::Describe => handle_describe(state, identity, &bytes, context),
    }
}

async fn handle_resolve(
    state: &AppState,
    identity: &Identity,
    bytes: &[u8],
    context: &mut AuditContext,
) -> Result<Response, ApiError> {
    let wire: ResolveWire = parse_json(bytes)?;
    validate_selector("domain", &wire.domain).map_err(|_| invalid_selector("domain"))?;
    validate_selector("type", &wire.type_name).map_err(|_| invalid_selector("type"))?;
    let reference = parse_reference(&wire.reference)?;

    context.reference = Some(wire.reference.clone());
    context.domain = Some(wire.domain.clone());
    context.type_name = Some(wire.type_name.clone());
    context.operation = wire.intent.operation().to_owned();

    if let Some(expected) = &wire.expected_digest {
        validate_expected_digest(expected)?;
    }
    if let Some(token_id) = &wire.pact_token_id {
        validate_pact_token_id(token_id)?;
        context.token_id = Some(token_id.clone());
    }

    let scheme = reference.scheme().unwrap_or_default();
    if !state.acl.allows(
        &identity.subject,
        &wire.domain,
        &wire.type_name,
        scheme,
        wire.intent.operation(),
    ) {
        return Err(ApiError::forbidden("object ACL denied"));
    }

    let profile = state
        .profile(&wire.domain, &wire.type_name)
        .ok_or_else(ApiError::not_found)?;
    if !profile.schemes.iter().any(|allowed| allowed == scheme) {
        return Err(ApiError::invalid_reference(
            "scheme is not allowed by the contract",
        ));
    }

    let request = ResolveRequest {
        domain: wire.domain,
        type_name: wire.type_name,
        reference,
        actor: identity.subject.clone(),
        intent: wire.intent,
        expected_digest: wire.expected_digest.clone(),
        pact_token_id: wire.pact_token_id.clone(),
    };
    let resolution = call_adapter(&state.resolvers, request).await?;

    let contract_id = if resolution.contract_id.is_empty() {
        profile.descriptor.contract_id.clone()
    } else {
        resolution.contract_id.clone()
    };
    let version = if resolution.version.is_empty() {
        profile.descriptor.version.clone()
    } else {
        resolution.version.clone()
    };
    let media_type = if resolution.media_type.is_empty() {
        profile.descriptor.media_type.clone()
    } else {
        resolution.media_type.clone()
    };

    if let Some(expected) = &wire.expected_digest {
        match &resolution.digest {
            Some(actual) if actual == expected => {}
            Some(actual) => return Err(ApiError::digest_mismatch(expected, actual)),
            None => {
                return Err(ApiError::upstream_failure(
                    "adapter returned no digest to verify",
                ))
            }
        }
    }

    context.contract_id = Some(contract_id.clone());
    context.result_digest = resolution.digest.clone();

    let (expires_at, handle) = match wire.intent {
        ResolveIntent::Read => {
            let handle = resolution
                .handle
                .ok_or_else(|| ApiError::upstream_failure("adapter returned no handle"))?;
            (Some(now_plus(HANDLE_TTL_SECONDS)), Some(handle))
        }
        ResolveIntent::Verify => (None, None),
    };

    let body = ResolutionBody {
        contract_id,
        version,
        media_type,
        digest: resolution.digest,
        expires_at,
        handle,
    };
    Ok(json_response(StatusCode::OK, &context.trace_id, &body))
}

fn handle_describe(
    state: &AppState,
    identity: &Identity,
    bytes: &[u8],
    context: &mut AuditContext,
) -> Result<Response, ApiError> {
    let wire: DescribeWire = parse_json(bytes)?;
    validate_selector("domain", &wire.domain).map_err(|_| invalid_selector("domain"))?;
    validate_selector("type", &wire.type_name).map_err(|_| invalid_selector("type"))?;
    let reference = parse_reference(&wire.reference)?;

    context.reference = Some(wire.reference);
    context.domain = Some(wire.domain.clone());
    context.type_name = Some(wire.type_name.clone());
    context.operation = "describe".to_owned();

    let scheme = reference.scheme().unwrap_or_default();
    if !state.acl.allows(
        &identity.subject,
        &wire.domain,
        &wire.type_name,
        scheme,
        "describe",
    ) {
        return Err(ApiError::forbidden("object ACL denied"));
    }

    let profile = state
        .profile(&wire.domain, &wire.type_name)
        .ok_or_else(ApiError::not_found)?;
    if !profile.schemes.iter().any(|allowed| allowed == scheme) {
        return Err(ApiError::invalid_reference(
            "scheme is not allowed by the contract",
        ));
    }

    context.contract_id = Some(profile.descriptor.contract_id.clone());
    Ok(json_response(
        StatusCode::OK,
        &context.trace_id,
        &profile.descriptor,
    ))
}

async fn call_adapter(
    resolvers: &Arc<ResolverRegistry>,
    request: ResolveRequest,
) -> Result<Resolution, ApiError> {
    let resolvers = Arc::clone(resolvers);
    let task = tokio::task::spawn_blocking(move || resolvers.resolve(&request));
    match tokio::time::timeout(REQUEST_TIMEOUT, task).await {
        Err(_) => Err(ApiError::upstream_timeout()),
        Ok(Err(_)) => Err(ApiError::internal("adapter task failed")),
        Ok(Ok(Ok(resolution))) => Ok(resolution),
        Ok(Ok(Err(error))) => Err(map_reference_error(error)),
    }
}

/// 只映射为固定消息，避免把内部端点或上游细节透给调用方。
fn map_reference_error(error: ReferenceError) -> ApiError {
    match error {
        ReferenceError::DigestMismatch { expected, actual } => {
            ApiError::digest_mismatch(&expected, &actual)
        }
        ReferenceError::NotFound(_) => ApiError::not_found(),
        ReferenceError::Unauthorized(_) => ApiError::forbidden("upstream denied access"),
        ReferenceError::Expired(_) => ApiError::expired(),
        ReferenceError::Timeout(_) => ApiError::upstream_timeout(),
        ReferenceError::Upstream(_) => ApiError::upstream_failure("upstream failure"),
        ReferenceError::Internal(_) => ApiError::internal("adapter internal error"),
        ReferenceError::Empty
        | ReferenceError::UnknownScheme(_)
        | ReferenceError::UnsupportedIdentifier(_)
        | ReferenceError::InvalidRequest(_) => {
            ApiError::invalid_reference("reference cannot be resolved")
        }
    }
}

// ---------------------------------------------------------------------------
// 传输
// ---------------------------------------------------------------------------

enum TraceHeader {
    Absent,
    Valid(String),
    Invalid,
}

fn trace_header(headers: &HeaderMap) -> TraceHeader {
    let Some(value) = headers
        .get("x-trace-id")
        .and_then(|value| value.to_str().ok())
    else {
        return if headers.contains_key("x-trace-id") {
            TraceHeader::Invalid
        } else {
            TraceHeader::Absent
        };
    };
    if is_valid_trace_id(value) {
        TraceHeader::Valid(value.to_owned())
    } else {
        TraceHeader::Invalid
    }
}

fn is_valid_trace_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn authorization(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
}

fn ensure_json(headers: &HeaderMap) -> Result<(), ApiError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(ApiError::unsupported_media_type())
    }
}

async fn read_body(body: Body) -> Result<axum::body::Bytes, ApiError> {
    let limited = Limited::new(body, MAX_BODY_BYTES);
    match limited.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) => {
            if error
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                Err(ApiError::request_too_large())
            } else {
                Err(ApiError::invalid_request("failed to read request body"))
            }
        }
    }
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes)
        .map_err(|_| ApiError::invalid_request("body must be JSON with known fields only"))
}

fn unauthorized(trace_id: &str) -> Response {
    let mut response = error_response(
        StatusCode::UNAUTHORIZED,
        Code::UNAUTHORIZED,
        "missing or invalid bearer credential",
        trace_id,
        false,
        None,
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"pact-ref\""),
    );
    response
}

fn json_response<T: Serialize>(status: StatusCode, trace_id: &str, body: &T) -> Response {
    let mut response = (status, Json(body)).into_response();
    apply_common_headers(&mut response, trace_id);
    response
}

fn error_response(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    trace_id: &str,
    retryable: bool,
    detail: Option<serde_json::Value>,
) -> Response {
    let body = ErrorBody {
        code,
        message,
        trace_id: trace_id.to_owned(),
        retryable,
        detail,
    };
    let mut response = (status, Json(body)).into_response();
    apply_common_headers(&mut response, trace_id);
    if code == Code::METHOD_NOT_ALLOWED {
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
    }
    response
}

fn apply_common_headers(response: &mut Response, trace_id: &str) {
    if let Ok(value) = HeaderValue::from_str(trace_id) {
        response.headers_mut().insert("x-trace-id", value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    trace_id: String,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolutionBody {
    contract_id: String,
    version: String,
    media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
}

// ---------------------------------------------------------------------------
// 请求校验
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResolveWire {
    domain: String,
    #[serde(rename = "type")]
    type_name: String,
    reference: String,
    intent: ResolveIntent,
    #[serde(default)]
    expected_digest: Option<String>,
    #[serde(default)]
    pact_token_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DescribeWire {
    domain: String,
    #[serde(rename = "type")]
    type_name: String,
    reference: String,
}

fn parse_reference(raw: &str) -> Result<ReferenceForm, ApiError> {
    match ReferenceForm::classify(Some(raw)) {
        Ok(form) if form.is_uri() => Ok(form),
        _ => Err(ApiError::invalid_reference(
            "reference must be an absolute URI in v1",
        )),
    }
}

fn validate_expected_digest(value: &str) -> Result<(), ApiError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ApiError::invalid_request(
            "expectedDigest must be sha256:<64 lowercase hex>",
        ));
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ApiError::invalid_request(
            "expectedDigest must be sha256:<64 lowercase hex>",
        ))
    }
}

fn validate_pact_token_id(value: &str) -> Result<(), ApiError> {
    if value.is_empty()
        || value.chars().count() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Err(ApiError::invalid_request(
            "pactTokenId must match [A-Za-z0-9._:-]{1,128}",
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 错误与审计
// ---------------------------------------------------------------------------

struct Code;

impl Code {
    const INVALID_REQUEST: &'static str = "InvalidRequest";
    const INVALID_REFERENCE: &'static str = "InvalidReference";
    const UNAUTHORIZED: &'static str = "Unauthorized";
    const FORBIDDEN: &'static str = "Forbidden";
    const NOT_FOUND: &'static str = "NotFound";
    const METHOD_NOT_ALLOWED: &'static str = "MethodNotAllowed";
    const DIGEST_MISMATCH: &'static str = "DigestMismatch";
    const EXPIRED: &'static str = "Expired";
    const REQUEST_TOO_LARGE: &'static str = "RequestTooLarge";
    const UNSUPPORTED_MEDIA_TYPE: &'static str = "UnsupportedMediaType";
    const INTERNAL: &'static str = "Internal";
    const AUDIT_UNAVAILABLE: &'static str = "AuditUnavailable";
    const UPSTREAM_FAILURE: &'static str = "UpstreamFailure";
    const UPSTREAM_TIMEOUT: &'static str = "UpstreamTimeout";
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retryable: bool,
    detail: Option<serde_json::Value>,
}

impl ApiError {
    fn invalid_request(message: &'static str) -> Self {
        Self::with_message(StatusCode::BAD_REQUEST, Code::INVALID_REQUEST, message)
    }

    fn invalid_reference(message: &'static str) -> Self {
        Self::with_message(StatusCode::BAD_REQUEST, Code::INVALID_REFERENCE, message)
    }

    fn forbidden(message: &'static str) -> Self {
        Self::with_message(StatusCode::FORBIDDEN, Code::FORBIDDEN, message)
    }

    fn not_found() -> Self {
        Self::with_message(
            StatusCode::NOT_FOUND,
            Code::NOT_FOUND,
            "reference is not registered",
        )
    }

    fn request_too_large() -> Self {
        Self::with_message(
            StatusCode::PAYLOAD_TOO_LARGE,
            Code::REQUEST_TOO_LARGE,
            "request body exceeds 64 KiB",
        )
    }

    fn unsupported_media_type() -> Self {
        Self::with_message(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Code::UNSUPPORTED_MEDIA_TYPE,
            "only application/json is accepted",
        )
    }

    fn expired() -> Self {
        Self::with_message(StatusCode::GONE, Code::EXPIRED, "reference has expired")
    }

    fn internal(message: &'static str) -> Self {
        Self::with_message(StatusCode::INTERNAL_SERVER_ERROR, Code::INTERNAL, message)
    }

    fn upstream_failure(message: &'static str) -> Self {
        Self::with_message(StatusCode::BAD_GATEWAY, Code::UPSTREAM_FAILURE, message)
    }

    fn upstream_timeout() -> Self {
        Self::with_message(
            StatusCode::GATEWAY_TIMEOUT,
            Code::UPSTREAM_TIMEOUT,
            "upstream timed out",
        )
    }

    fn digest_mismatch(expected: &str, actual: &str) -> Self {
        let mut error = Self::with_message(
            StatusCode::CONFLICT,
            Code::DIGEST_MISMATCH,
            "resolved artifact digest does not match expectedDigest",
        );
        error.detail = Some(serde_json::json!({
            "expected": expected,
            "actual": actual,
        }));
        error
    }

    fn with_message(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            retryable: false,
            detail: None,
        }
    }

    fn into_response(self, trace_id: &str) -> Response {
        error_response(
            self.status,
            self.code,
            self.message,
            trace_id,
            self.retryable,
            self.detail,
        )
    }
}

/// `domain` / `type` 校验失败统一为固定消息，不回显请求内容。
fn invalid_selector(label: &str) -> ApiError {
    let message = match label {
        "domain" => "domain must be 1..=255 characters without control characters",
        _ => "type must be 1..=255 characters without control characters",
    };
    ApiError::invalid_request(message)
}

struct AuditContext {
    trace_id: String,
    actor: String,
    reference: Option<String>,
    domain: Option<String>,
    type_name: Option<String>,
    contract_id: Option<String>,
    operation: String,
    token_id: Option<String>,
    result_digest: Option<String>,
}

impl AuditContext {
    fn new(trace_id: String, actor: String, operation: &str) -> Self {
        Self {
            trace_id,
            actor,
            reference: None,
            domain: None,
            type_name: None,
            contract_id: None,
            operation: operation.to_owned(),
            token_id: None,
            result_digest: None,
        }
    }

    fn event(&self, status: &str) -> AuditEvent {
        AuditEvent {
            trace_id: self.trace_id.clone(),
            token_id: self.token_id.clone(),
            actor: self.actor.clone(),
            reference: self.reference.clone().unwrap_or_default(),
            domain: self.domain.clone(),
            type_name: self.type_name.clone(),
            contract_id: self.contract_id.clone(),
            operation: Some(self.operation.clone()),
            status: status.to_owned(),
            result_digest: self.result_digest.clone(),
            timestamp: rfc3339(std::time::SystemTime::now()),
        }
    }
}
