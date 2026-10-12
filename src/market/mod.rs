//! Versioned training and service domain. The existing scientific and receipt
//! namespaces stay intact; definitions do not create financial or work facts.
use super::*;
use axum::extract::{Path as RoutePath, Query};
use serde::Deserialize;

mod catalog;
pub mod money;

pub const CATALOG: &str = include_str!("../../web/data/market-catalog-v1.json");

pub(super) fn decimal(v: &Value, key: &str) -> Result<u128> {
    money::atoms(v[key].as_str().ok_or("INVALID_INPUT: integer atoms string")?)
}

fn response(data: Value) -> Value {
    json!({"schemaVersion":1,"requestId":random_suffix().unwrap_or_else(|_|"unavailable".into()),"serverTime":now(),"data":data})
}

pub(super) struct MarketError(String);
impl From<String> for MarketError { fn from(value:String)->Self {Self(value)} }
impl IntoResponse for MarketError {
    fn into_response(self)->Response {
        let requested=self.0.split(':').next().unwrap_or("INTERNAL");
        let (code,status,message,retryable)=match requested {
            "NOT_FOUND"=>("NOT_FOUND",StatusCode::NOT_FOUND,"The requested market object does not exist.",false),
            "INVALID_INPUT"=>("UNSUPPORTED_INPUT",StatusCode::BAD_REQUEST,"The input does not match the supported schema.",false),
            "AUTHORIZATION"|"BAD_SIGNATURE"=>("AUTHORIZATION",StatusCode::FORBIDDEN,"Authorize this action with its permitted identity.",false),
            "NOT_CONFIGURED"=>("NOT_CONFIGURED",StatusCode::SERVICE_UNAVAILABLE,"The required asset or deployment is not configured.",false),
            "CONFLICT"|"IDEMPOTENCY_CONFLICT"=>("IDEMPOTENCY_CONFLICT",StatusCode::CONFLICT,"This request identity is already bound to different content.",false),
            "INSUFFICIENT_FLY"|"PAYMENT_REQUIRED"=>("INSUFFICIENT_FLY",StatusCode::PAYMENT_REQUIRED,"The available FLY balance does not cover the authorized request.",false),
            "RESOURCE_LIMIT"|"BACKPRESSURE"=>("RESOURCE_LIMIT",StatusCode::TOO_MANY_REQUESTS,"The bounded execution or queue limit has been reached.",true),
            _=>("INTERNAL",StatusCode::INTERNAL_SERVER_ERROR,"The request could not be completed. Its durable state has been retained.",false)
        };
        (status,Json(json!({"schemaVersion":1,"requestId":random_suffix().unwrap_or_default(),"serverTime":now(),"error":{"code":code,"message":message,"retryable":retryable,"nextStep":"Query the original object before creating another request."}}))).into_response()
    }
}

#[derive(Default, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub cursor: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub hardware: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

async fn public(
    State(a): State<Arc<Authority>>,
    RoutePath(path): RoutePath<String>,
    Query(q): Query<ListQuery>,
) -> std::result::Result<Json<Value>, MarketError> {
    blocking(a, move |a| a.market_public(&path, &q)).await.map(|v| Json(response(v))).map_err(|e|MarketError(e.0))
}

pub fn routes() -> Router<Arc<Authority>> {
    Router::new().route("/api/market/v1/{*path}", get(public))
}
