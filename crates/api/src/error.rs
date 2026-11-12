// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every error leaves the API as {"error": "code", "message": "text"}.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use tracing::error;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Stable machine-readable code, e.g. "forbidden", "mfa_required".
    pub error: String,
    pub message: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
        }
    }
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }
    pub fn bad_request(code: &'static str, m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, m)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "log in first")
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", m)
    }
    /// Used for resources of other tenants too: never confirm they exist.
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "no such resource")
    }
    pub fn conflict(code: &'static str, m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, m)
    }
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.code.to_string(),
            message: self.message,
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(d) = &e {
            if d.is_unique_violation() {
                return ApiError::conflict("conflict", "already exists");
            }
            if d.code().as_deref() == Some("42501") {
                // insufficient_privilege / RLS rejection: never leak details
                return ApiError::not_found();
            }
        }
        error!("database: {e}");
        ApiError::internal()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        error!("{e:#}");
        ApiError::internal()
    }
}
