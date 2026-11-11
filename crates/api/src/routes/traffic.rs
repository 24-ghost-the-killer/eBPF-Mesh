// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET /tenants/{tid}/traffic: history per PoP from ClickHouse traffic_1m
//! (spec 9.2, ADR 0024). The tenant id comes from the authorised path and is
//! passed as a typed query parameter, never spliced into SQL.

use std::collections::BTreeMap;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use sentinel_common::stats::{traffic_class, TrafficClass};
use sentinel_common::units::now_unix_ms;

use crate::auth::{require, Caller, Role};
use crate::config::Config;
use crate::error::{ApiError, ApiResult, ErrorBody};
use crate::AppState;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TrafficQuery {
    /// Unix ms (default: `to` - 1 hour).
    #[param(required = false)]
    pub from: Option<i64>,
    /// Unix ms (default: now).
    #[param(required = false)]
    pub to: Option<i64>,
    /// Seconds per point, a multiple of 60 (default 60).
    #[param(required = false)]
    pub step: Option<u32>,
}

#[derive(Serialize, ToSchema, Default, Clone, PartialEq, Debug)]
pub struct TrafficPoint {
    /// Unix ms at the start of the step.
    pub ts: i64,
    /// Average rates over the step (sampled estimates).
    pub in_pps: f64,
    pub in_bps: f64,
    pub filtered_pps: f64,
    pub clean_pps: f64,
}

#[derive(Serialize, ToSchema, Debug)]
pub struct PopSeries {
    pub pop: String,
    pub points: Vec<TrafficPoint>,
}

#[derive(Serialize, ToSchema, Debug)]
pub struct Traffic {
    pub from: i64,
    pub to: i64,
    pub step: u32,
    pub pops: Vec<PopSeries>,
}

#[derive(Deserialize, Debug)]
pub struct Row {
    pub ts: i64,
    pub pop: String,
    pub verdict: String,
    pub pkts: u64,
    pub bytes: u64,
}

const QUERY: &str = "SELECT toInt64(toUnixTimestamp(toStartOfInterval(minute, toIntervalSecond({step:UInt32})))) * 1000 AS ts, \
     pop, verdict, sum(pkts) AS pkts, sum(bytes) AS bytes FROM traffic_1m \
     WHERE tenant = {tenant:UInt32} AND minute >= toDateTime({from:UInt32}) AND minute < toDateTime({to:UInt32}) \
     GROUP BY ts, pop, verdict ORDER BY ts, pop FORMAT JSONEachRow";

/// Validates and fills in the time window: (from ms, to ms, step s).
pub fn window(q: &TrafficQuery, now_ms: i64) -> Result<(i64, i64, u32), String> {
    let step = q.step.unwrap_or(60);
    if step == 0 || !step.is_multiple_of(60) || step > 86_400 {
        return Err("step must be a multiple of 60 up to 86400".into());
    }
    let to = q.to.unwrap_or(now_ms);
    let from = q.from.unwrap_or(to - 3_600_000);
    if from < 0 || from >= to {
        return Err("from must be before to".into());
    }
    if to - from > 31 * 86_400_000 {
        return Err("at most 31 days".into());
    }
    if (to - from) / 1000 / i64::from(step) > 2000 {
        return Err("too many points: use a larger step".into());
    }
    Ok((from, to, step))
}

/// Folds ClickHouse rows into per-PoP series of rates.
pub fn fold(rows: &[Row], step: u32) -> Vec<PopSeries> {
    let mut m: BTreeMap<&str, BTreeMap<i64, TrafficPoint>> = BTreeMap::new();
    let s = f64::from(step);
    for r in rows {
        let class = traffic_class(&r.verdict);
        if !matches!(class, TrafficClass::Clean | TrafficClass::Filtered) {
            continue;
        }
        let p = m
            .entry(&r.pop)
            .or_default()
            .entry(r.ts)
            .or_insert(TrafficPoint {
                ts: r.ts,
                ..Default::default()
            });
        let pps = r.pkts as f64 / s;
        p.in_pps += pps;
        p.in_bps += r.bytes as f64 * 8.0 / s;
        if class == TrafficClass::Filtered {
            p.filtered_pps += pps;
        } else {
            p.clean_pps += pps;
        }
    }
    m.into_iter()
        .map(|(pop, pts)| PopSeries {
            pop: pop.to_string(),
            points: pts.into_values().collect(),
        })
        .collect()
}

async fn query(
    cfg: &Config,
    tenant: i64,
    from: i64,
    to: i64,
    step: u32,
) -> anyhow::Result<Vec<Row>> {
    let ch = cfg.clickhouse.as_ref().expect("checked by caller");
    let password = Config::env(&ch.password_env)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client
        .post(&ch.url)
        .query(&[
            ("database", ch.database.as_str()),
            ("readonly", "1"),
            ("param_tenant", &tenant.to_string()),
            ("param_from", &(from / 1000).to_string()),
            ("param_to", &(to / 1000).to_string()),
            ("param_step", &step.to_string()),
        ])
        .header("X-ClickHouse-User", &ch.user)
        .header("X-ClickHouse-Key", password)
        .body(QUERY)
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "ClickHouse {status}: {}",
            text.chars().take(300).collect::<String>()
        );
    }
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Row>(l).map_err(anyhow::Error::from))
        .collect()
}

/// Traffic history per PoP (from ClickHouse traffic_1m).
#[utoipa::path(get, path = "/api/v1/tenants/{tid}/traffic", tag = "traffic",
    params(("tid" = i64, Path), TrafficQuery),
    responses((status = 200, body = Traffic), (status = 400, body = ErrorBody),
        (status = 404, body = ErrorBody), (status = 503, body = ErrorBody)),
    security(("session" = []), ("api_key" = [])))]
pub async fn traffic(
    State(state): State<AppState>,
    c: Caller,
    Path(tid): Path<i64>,
    Query(q): Query<TrafficQuery>,
) -> ApiResult<Json<Traffic>> {
    require(c.role(&state.pool, tid).await?, Role::Viewer)?;
    let (from, to, step) =
        window(&q, now_unix_ms() as i64).map_err(|e| ApiError::bad_request("invalid_window", e))?;
    if state.cfg.clickhouse.is_none() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "traffic history is not configured",
        ));
    }
    let rows = query(&state.cfg, tid, from, to, step).await.map_err(|e| {
        tracing::warn!("traffic query: {e:#}");
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "traffic history is unavailable",
        )
    })?;
    Ok(Json(Traffic {
        from,
        to,
        step,
        pops: fold(&rows, step),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(from: Option<i64>, to: Option<i64>, step: Option<u32>) -> TrafficQuery {
        TrafficQuery { from, to, step }
    }

    #[test]
    fn windows() {
        let now = 10_000_000_000;
        assert_eq!(
            window(&q(None, None, None), now),
            Ok((now - 3_600_000, now, 60))
        );
        assert!(window(&q(None, None, Some(30)), now).is_err());
        assert!(window(&q(Some(now), Some(now), None), now).is_err());
        assert!(window(&q(Some(0), Some(32 * 86_400_000), Some(86_400)), now).is_err());
        assert!(
            window(&q(Some(now - 7 * 86_400_000), None, Some(60)), now).is_err(),
            "too many points"
        );
        assert!(window(&q(Some(now - 7 * 86_400_000), None, Some(600)), now).is_ok());
    }

    #[test]
    fn folding() {
        let r = |ts: i64, pop: &str, verdict: &str, pkts: u64| Row {
            ts,
            pop: pop.into(),
            verdict: verdict.into(),
            pkts,
            bytes: pkts * 100,
        };
        let rows = vec![
            r(0, "pop-1", "pass", 600),
            r(0, "pop-1", "drop_block", 1200),
            r(0, "pop-1", "tx_return", 6000),
            r(60_000, "pop-1", "pass", 60),
            r(0, "pop-2", "pass", 120),
        ];
        let s = fold(&rows, 60);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].pop, "pop-1");
        assert_eq!(s[0].points.len(), 2);
        assert_eq!(s[0].points[0].in_pps, 30.0);
        assert_eq!(s[0].points[0].filtered_pps, 20.0);
        assert_eq!(s[0].points[0].clean_pps, 10.0);
        assert_eq!(s[0].points[0].in_bps, 30.0 * 800.0);
        assert_eq!(s[1].points[0].in_pps, 2.0);
    }
}
