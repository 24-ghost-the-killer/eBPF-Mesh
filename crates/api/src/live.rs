// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET /tenants/{tid}/live: one frame per second with the tenant's traffic
//! (spec section 13.4).
//!
//! The API subscribes to `stats.>` once and keeps the latest message of each
//! PoP. Every WebSocket gets its own one-second ticker and only ever sees the
//! rows of the tenant its caller was authorised for.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::response::Response;
use futures::StreamExt;
use serde::Serialize;
use tracing::warn;
use utoipa::ToSchema;

use sentinel_common::msg::StatsMsg;
use sentinel_common::stats::{traffic_class, TrafficClass};
use sentinel_common::units::now_unix_ms;

use crate::auth::{require, Caller, Role};
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::AppState;

/// A PoP's stats older than this are left out (PoP gone or partitioned).
const STALE: Duration = Duration::from_secs(5);

type Latest = HashMap<String, (Instant, Arc<StatsMsg>)>;

/// Latest `stats.<pop>` message per PoP, and the active attacks per tenant.
#[derive(Clone, Default)]
pub struct LiveHub {
    pops: Arc<RwLock<Latest>>,
    attacks: Arc<RwLock<HashMap<i64, Vec<ActiveAttack>>>>,
}

/// An attack in progress (spec 13.4: the overview shows them live).
#[derive(Clone, Debug, Serialize, ToSchema, PartialEq)]
pub struct ActiveAttack {
    pub id: i64,
    pub vector: String,
    /// Unix ms.
    pub started_at: i64,
    pub pps: f64,
    pub bps: f64,
    pub peak_pps: f64,
    /// Share of the attack traffic the PoPs drop (0..1).
    pub dropped_ratio: f64,
}

impl LiveHub {
    pub fn update(&self, msg: StatsMsg) {
        let mut g = self.pops.write().expect("live hub lock");
        g.insert(msg.pop.clone(), (Instant::now(), Arc::new(msg)));
    }

    pub fn set_attack(&self, tenant: i64, a: ActiveAttack) {
        let mut g = self.attacks.write().expect("live hub lock");
        let v = g.entry(tenant).or_default();
        v.retain(|x| x.id != a.id);
        v.push(a);
    }

    pub fn clear_attack(&self, tenant: i64, id: i64) {
        let mut g = self.attacks.write().expect("live hub lock");
        if let Some(v) = g.get_mut(&tenant) {
            v.retain(|x| x.id != id);
        }
    }

    fn fresh(&self) -> Vec<Arc<StatsMsg>> {
        let g = self.pops.read().expect("live hub lock");
        let mut v: Vec<_> = g
            .values()
            .filter(|(t, _)| t.elapsed() < STALE)
            .map(|(_, m)| m.clone())
            .collect();
        v.sort_by(|a, b| a.pop.cmp(&b.pop));
        v
    }

    /// The frame for one tenant, built only from that tenant's rows.
    pub fn frame(&self, tenant: i64) -> LiveFrame {
        let mut total = Rates::default();
        let mut verdicts: HashMap<String, (f64, f64)> = HashMap::new();
        let mut pops = Vec::new();
        for m in self.fresh() {
            let mut r = Rates::default();
            for row in m.entries.iter().filter(|r| i64::from(r.tenant) == tenant) {
                r.add(&row.verdict, row.pps, row.bps);
                let e = verdicts.entry(row.verdict.clone()).or_default();
                e.0 += row.pps;
                e.1 += row.bps;
            }
            total.merge(&r);
            pops.push(PopRates {
                pop: m.pop.clone(),
                rates: r,
            });
        }
        let mut verdicts: Vec<VerdictRate> = verdicts
            .into_iter()
            .filter(|(_, (p, b))| *p > 0.0 || *b > 0.0)
            .map(|(verdict, (pps, bps))| VerdictRate { verdict, pps, bps })
            .collect();
        verdicts.sort_by(|a, b| a.verdict.cmp(&b.verdict));
        let attacks = self
            .attacks
            .read()
            .expect("live hub lock")
            .get(&tenant)
            .cloned()
            .unwrap_or_default();
        LiveFrame {
            ts: now_unix_ms(),
            total,
            pops,
            verdicts,
            attacks,
        }
    }
}

/// Packets and bits per second, split the way the overview graph shows them.
#[derive(Clone, Debug, Default, Serialize, ToSchema, PartialEq)]
pub struct Rates {
    /// Everything that arrived for the tenant's protected IPs.
    pub in_pps: f64,
    pub in_bps: f64,
    /// Traffic the filters reject: dropped in mitigate mode, only counted
    /// in observe mode.
    pub filtered_pps: f64,
    pub filtered_bps: f64,
    /// in - filtered: what reaches (or would reach) the origin.
    pub clean_pps: f64,
    pub clean_bps: f64,
    /// The origin's replies forwarded by the PoPs (return tunnel).
    pub return_pps: f64,
    pub return_bps: f64,
}

impl Rates {
    fn add(&mut self, verdict: &str, pps: f64, bps: f64) {
        let class = traffic_class(verdict);
        match class {
            TrafficClass::Return => {
                self.return_pps += pps;
                self.return_bps += bps;
            }
            TrafficClass::Other => {}
            TrafficClass::Clean | TrafficClass::Filtered => {
                self.in_pps += pps;
                self.in_bps += bps;
                if class == TrafficClass::Filtered {
                    self.filtered_pps += pps;
                    self.filtered_bps += bps;
                } else {
                    self.clean_pps += pps;
                    self.clean_bps += bps;
                }
            }
        }
    }

    fn merge(&mut self, o: &Rates) {
        self.in_pps += o.in_pps;
        self.in_bps += o.in_bps;
        self.filtered_pps += o.filtered_pps;
        self.filtered_bps += o.filtered_bps;
        self.clean_pps += o.clean_pps;
        self.clean_bps += o.clean_bps;
        self.return_pps += o.return_pps;
        self.return_bps += o.return_bps;
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PopRates {
    pub pop: String,
    #[serde(flatten)]
    pub rates: Rates,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerdictRate {
    pub verdict: String,
    pub pps: f64,
    pub bps: f64,
}

/// One WebSocket message (JSON text frame), once per second.
#[derive(Debug, Serialize, ToSchema)]
pub struct LiveFrame {
    /// Unix ms.
    pub ts: u64,
    pub total: Rates,
    /// One entry per PoP that reported in the last 5 seconds.
    pub pops: Vec<PopRates>,
    /// Non-zero rates per verdict (all PoPs).
    pub verdicts: Vec<VerdictRate>,
    /// Attacks in progress.
    pub attacks: Vec<ActiveAttack>,
}

/// Browsers send cookies with cross-site WebSocket handshakes only when
/// SameSite allows it; the session cookie is SameSite=Strict, and the Origin
/// check closes the gap for older browsers (cross-site WebSocket hijacking).
fn origin_ok(state: &AppState, headers: &HeaderMap) -> bool {
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        None => true, // not a browser (API key clients)
        Some(o) => o == state.public_origin.as_str(),
    }
}

/// Live traffic for the overview (WebSocket, 1 frame per second, JSON).
#[utoipa::path(get, path = "/api/v1/tenants/{tid}/live", tag = "traffic",
    params(("tid" = i64, Path)),
    responses((status = 101, description = "WebSocket; text frames carry LiveFrame JSON",
        body = LiveFrame), (status = 403, body = ErrorBody), (status = 404, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn live(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if !origin_ok(&state, &headers) {
        return Err(ApiError::forbidden("cross-origin WebSocket"));
    }
    require(c.role(&state.pool, tid).await?, Role::Viewer)?;
    let hub = state.live.clone();
    let session = c.session.as_ref().map(|s| s.hash.clone());
    let pool = state.pool.clone();
    Ok(ws.on_upgrade(move |socket| stream(socket, hub, tid, session, pool)))
}

async fn stream(
    socket: WebSocket,
    hub: LiveHub,
    tid: i64,
    session: Option<String>,
    pool: sqlx::PgPool,
) {
    let (mut tx, mut rx) = socket.split();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut checks = 0u32;
    loop {
        tokio::select! {
            _ = tick.tick() => {
                // Re-check the session every 30 s: logout or expiry ends the
                // stream (membership removal is checked the same way).
                checks += 1;
                if checks.is_multiple_of(30) {
                    if let Some(h) = &session {
                        let alive: Option<bool> = sqlx::query_scalar(
                            "SELECT true FROM sessions s JOIN memberships m ON m.user_id = s.user_id \
                             WHERE s.token_hash = $1 AND s.expires_at > now() AND m.tenant_id = $2",
                        )
                        .bind(h)
                        .bind(tid)
                        .fetch_optional(&pool)
                        .await
                        .unwrap_or(None);
                        if alive.is_none() {
                            break;
                        }
                    }
                }
                let body = match serde_json::to_string(&hub.frame(tid)) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("live frame: {e}");
                        break;
                    }
                };
                if futures::SinkExt::send(&mut tx, Message::Text(body.into())).await.is_err() {
                    break;
                }
            }
            m = rx.next() => match m {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {} // ignore client messages
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::msg::{StatsRow, SCHEMA_V};

    fn row(tenant: u32, verdict: &str, pps: f64) -> StatsRow {
        StatsRow {
            tenant,
            verdict: verdict.into(),
            pkts: 0,
            bytes: 0,
            pps,
            bps: pps * 8000.0,
        }
    }

    fn msg(pop: &str, entries: Vec<StatsRow>) -> StatsMsg {
        StatsMsg {
            kind: "stats".into(),
            v: SCHEMA_V,
            pop: pop.into(),
            ts: 0,
            interval_ms: 1000,
            sample_rate: 1,
            events_lost: 0,
            entries,
        }
    }

    #[test]
    fn frames_only_contain_the_tenant() {
        let hub = LiveHub::default();
        hub.update(msg(
            "a",
            vec![
                row(7, "pass", 100.0),
                row(7, "drop_block", 40.0),
                row(7, "tx_syn_challenge", 10.0),
                row(7, "tx_return", 90.0),
                row(8, "pass", 5000.0),
                row(8, "drop_ratelimit", 9000.0),
            ],
        ));
        hub.update(msg("b", vec![row(7, "pass", 1.0), row(9, "pass", 3.0)]));
        let f = hub.frame(7);
        assert_eq!(f.pops.len(), 2);
        assert_eq!(f.total.in_pps, 151.0);
        assert_eq!(f.total.filtered_pps, 50.0);
        assert_eq!(f.total.clean_pps, 101.0);
        assert_eq!(f.total.return_pps, 90.0);
        assert_eq!(f.pops[1].rates.in_pps, 1.0);
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("5000") && !json.contains("9000"), "{json}");
        assert!(!f.verdicts.iter().any(|v| v.verdict == "drop_ratelimit"));

        hub.set_attack(
            7,
            ActiveAttack {
                id: 3,
                vector: "udp_flood".into(),
                started_at: 0,
                pps: 1.0,
                bps: 8.0,
                peak_pps: 2.0,
                dropped_ratio: 0.5,
            },
        );
        assert_eq!(hub.frame(7).attacks.len(), 1);
        assert!(hub.frame(8).attacks.is_empty(), "attacks are per tenant");
        hub.clear_attack(7, 3);
        assert!(hub.frame(7).attacks.is_empty());

        let none = hub.frame(1);
        assert_eq!(none.total, Rates::default());
        assert!(none.verdicts.is_empty());
    }
}
